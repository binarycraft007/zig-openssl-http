const std = @import("std");
const c = @import("openssl");

pub const ServerContext = struct {
    ssl_ctx: *c.SSL_CTX,
    bio_method: *c.BIO_METHOD,

    pub fn init(cert_path: [:0]const u8, key_path: [:0]const u8) !ServerContext {
        const ssl_ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse
            return error.OpenSslContextFailed;
        errdefer c.SSL_CTX_free(ssl_ctx);

        if (c.SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_path.ptr) != 1) {
            return error.InvalidCertificate;
        }
        if (c.SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path.ptr, c.SSL_FILETYPE_PEM) != 1) {
            return error.InvalidPrivateKey;
        }
        if (c.SSL_CTX_check_private_key(ssl_ctx) != 1) {
            return error.KeyMismatch;
        }

        c.SSL_CTX_set_alpn_select_cb(ssl_ctx, alpnSelectCb, null);

        const bio_method = try createBioMethod();
        errdefer c.BIO_meth_free(bio_method);

        return .{
            .ssl_ctx = ssl_ctx,
            .bio_method = bio_method,
        };
    }

    pub fn deinit(self: *ServerContext) void {
        c.BIO_meth_free(self.bio_method);
        c.SSL_CTX_free(self.ssl_ctx);
    }
};

const BioContext = struct {
    net_in: *std.Io.Reader,
    net_out: *std.Io.Writer,
};

fn bioWrite(bio: ?*c.BIO, data: [*c]const u8, len: c_int) callconv(.c) c_int {
    if (len <= 0 or data == null) return 0;
    const ctx: *BioContext = @ptrCast(@alignCast(c.BIO_get_data(bio)));
    const slice = data[0..@intCast(len)];

    ctx.net_out.writeAll(slice) catch return -1;
    return len;
}

fn bioRead(bio: ?*c.BIO, out: [*c]u8, len: c_int) callconv(.c) c_int {
    if (len <= 0 or out == null) return 0;
    const ctx: *BioContext = @ptrCast(@alignCast(c.BIO_get_data(bio)));
    const buf = out[0..@intCast(len)];

    var vec: [1][]u8 = .{buf};
    const n = ctx.net_in.readVec(&vec) catch |err| switch (err) {
        error.EndOfStream => return 0,
        error.ReadFailed => return -1,
    };
    return @intCast(n);
}

fn bioCtrl(bio: ?*c.BIO, cmd: c_int, num: c_long, ptr: ?*anyopaque) callconv(.c) c_long {
    _ = num;
    _ = ptr;
    const ctx: *BioContext = @ptrCast(@alignCast(c.BIO_get_data(bio)));
    return switch (cmd) {
        c.BIO_CTRL_FLUSH => blk: {
            ctx.net_out.flush() catch break :blk 0;
            break :blk 1;
        },
        else => 0,
    };
}

fn createBioMethod() !*c.BIO_METHOD {
    const meth = c.BIO_meth_new(c.BIO_TYPE_SOURCE_SINK, "zig_std_io") orelse
        return error.OutOfMemory;
    errdefer c.BIO_meth_free(meth);

    if (c.BIO_meth_set_write(meth, bioWrite) != 1 or
        c.BIO_meth_set_read(meth, bioRead) != 1 or
        c.BIO_meth_set_ctrl(meth, bioCtrl) != 1)
    {
        return error.OpenSslBioInitFailed;
    }
    return meth;
}

/// Wraps an OpenSSL `*c.SSL` session as a `std.Io.Reader` and `std.Io.Writer`.
/// Must remain pinned at a stable memory address after `accept()` is called.
pub const Connection = struct {
    ssl: *c.SSL,
    bio_ctx: BioContext,
    reader: std.Io.Reader,
    writer: std.Io.Writer,

    pub fn init(
        ctx: *const ServerContext,
        net_in: *std.Io.Reader,
        net_out: *std.Io.Writer,
        read_buf: []u8,
        write_buf: []u8,
    ) !Connection {
        const ssl = c.SSL_new(ctx.ssl_ctx) orelse return error.OpenSslSessionFailed;
        return .{
            .ssl = ssl,
            .bio_ctx = .{
                .net_in = net_in,
                .net_out = net_out,
            },
            .reader = .{
                .vtable = &.{ .stream = stream },
                .buffer = read_buf,
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .vtable = &.{
                    .drain = drain,
                    .flush = flush,
                },
                .buffer = write_buf,
                .end = 0,
            },
        };
    }

    pub fn accept(self: *Connection, ctx: *const ServerContext) !void {
        const bio = c.BIO_new(ctx.bio_method) orelse return error.OpenSslBioFailed;
        c.BIO_set_data(bio, &self.bio_ctx);
        c.BIO_set_init(bio, 1);
        c.SSL_set_bio(self.ssl, bio, bio); // `ssl` takes ownership of `bio`

        if (c.SSL_accept(self.ssl) != 1) {
            logOpenSslErrors("SSL_accept");
            return error.TlsHandshakeFailed;
        }
    }

    pub fn deinit(self: *Connection) void {
        _ = c.SSL_shutdown(self.ssl);
        self.bio_ctx.net_out.flush() catch {};
        c.SSL_free(self.ssl);
    }

    fn stream(
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Connection = @alignCast(@fieldParentPtr("reader", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        if (dest.len == 0) return 0;

        const chunk_len: c_int = @intCast(@min(dest.len, std.math.maxInt(c_int)));
        const rc = c.SSL_read(self.ssl, dest.ptr, chunk_len);
        if (rc > 0) {
            const n: usize = @intCast(rc);
            w.advance(n);
            return n;
        }

        const err = c.SSL_get_error(self.ssl, rc);
        if (err == c.SSL_ERROR_ZERO_RETURN) {
            return error.EndOfStream;
        }
        return error.ReadFailed;
    }

    fn drain(
        w: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *Connection = @alignCast(@fieldParentPtr("writer", w));

        const buffered = w.buffered();
        if (buffered.len != 0) {
            const n = try sslWriteSlice(self.ssl, buffered);
            return w.consume(n);
        }

        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            if (slice.len == 0) continue;
            const n = try sslWriteSlice(self.ssl, slice);
            consumed += n;
            if (n < slice.len) return consumed;
        }

        const pattern = data[data.len - 1];
        if (pattern.len > 0) {
            for (0..splat) |_| {
                const n = try sslWriteSlice(self.ssl, pattern);
                consumed += n;
                if (n < pattern.len) return consumed;
            }
        }
        return consumed;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        try std.Io.Writer.defaultFlush(w);
        const self: *Connection = @alignCast(@fieldParentPtr("writer", w));
        try self.bio_ctx.net_out.flush();
    }

    fn sslWriteSlice(ssl: *c.SSL, slice: []const u8) std.Io.Writer.Error!usize {
        const chunk_len: c_int = @intCast(@min(slice.len, std.math.maxInt(c_int)));
        const rc = c.SSL_write(ssl, slice.ptr, chunk_len);
        if (rc > 0) return @intCast(rc);
        return error.WriteFailed;
    }
};

fn alpnSelectCb(
    ssl: ?*c.SSL,
    out: [*c][*c]const u8,
    outlen: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    _ = arg;

    // Wire format: 1-byte length prefix followed by protocol name
    const server_protos = "\x08http/1.1";
    var selected: [*c]u8 = null;
    if (c.SSL_select_next_proto(
        &selected,
        outlen,
        server_protos.ptr,
        server_protos.len,
        in,
        inlen,
    ) == c.OPENSSL_NPN_NEGOTIATED) {
        out.* = selected;
        return c.SSL_TLSEXT_ERR_OK;
    }

    // Use SSL_TLSEXT_ERR_ALERT_FATAL to reject clients without http/1.1,
    // or SSL_TLSEXT_ERR_NOACK to ignore ALPN and proceed anyway.
    return c.SSL_TLSEXT_ERR_NOACK;
}

fn logOpenSslErrors(context: []const u8) void {
    var code = c.ERR_get_error();
    while (code != 0) : (code = c.ERR_get_error()) {
        var buf: [256]u8 = undefined;
        c.ERR_error_string_n(code, &buf, buf.len);
        std.log.err("OpenSSL ({s}): {s}", .{ context, std.mem.sliceTo(&buf, 0) });
    }
}
