const std = @import("std");
const tls = @import("tls.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var tls_ctx: tls.ServerContext = try .init("certs/cert.pem", "certs/key.pem");
    defer tls_ctx.deinit();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 8443);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    std.log.info("HTTPS server listening on https://127.0.0.1:8443", .{});

    var group: std.Io.Group = .init;
    defer group.cancel(io);

    while (true) {
        const conn = listener.accept(io) catch |err| {
            std.log.err("accept failed: {s}", .{@errorName(err)});
            continue;
        };
        group.concurrent(io, handleConnection, .{ io, conn, &tls_ctx }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                std.log.warn("server at capacity, dropping connection", .{});
                var c = conn;
                c.close(io);
            },
        };
    }
}

fn handleConnection(
    io: std.Io,
    conn_val: std.Io.net.Stream,
    tls_ctx: *const tls.ServerContext,
) void {
    var conn = conn_val;
    defer conn.close(io);

    var done: std.Io.Event = .unset;

    var fut = io.concurrent(runConnectionTask, .{ io, &conn, tls_ctx, &done }) catch {
        return;
    };

    done.waitTimeout(io, .{
        .duration = .{ .clock = .awake, .raw = .fromSeconds(30) },
    }) catch |err| switch (err) {
        error.Timeout => std.log.warn("connection timed out", .{}),
        error.Canceled => {},
    };

    fut.cancel(io);
}

fn runConnectionTask(
    io: std.Io,
    conn: *std.Io.net.Stream,
    tls_ctx: *const tls.ServerContext,
    done: *std.Io.Event,
) void {
    defer done.set(io);

    serveConnection(io, conn, tls_ctx) catch |err| {
        std.log.warn("connection error: {s}", .{@errorName(err)});
    };
}

fn serveConnection(
    io: std.Io,
    conn: *std.Io.net.Stream,
    tls_ctx: *const tls.ServerContext,
) !void {
    var net_read_buf: [16 * 1024]u8 = undefined;
    var net_write_buf: [16 * 1024]u8 = undefined;
    var net_reader = conn.reader(io, &net_read_buf);
    var net_writer = conn.writer(io, &net_write_buf);

    var http_read_buf: [8192]u8 = undefined;
    var http_write_buf: [8192]u8 = undefined;

    var tls_conn: tls.Connection = try .init(
        tls_ctx,
        &net_reader.interface,
        &net_writer.interface,
        &http_read_buf,
        &http_write_buf,
    );
    defer tls_conn.deinit();

    try tls_conn.accept(tls_ctx);

    var http_server = std.http.Server.init(&tls_conn.reader, &tls_conn.writer);
    while (true) {
        var req = http_server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => break,
            else => return err,
        };
        try routeRequest(&req);
    }
}

fn routeRequest(req: *std.http.Server.Request) !void {
    if (std.mem.eql(u8, req.head.target, "/")) {
        try req.respond("Hello over HTTPS from Zig 0.17.1 + OpenSSL!\n", .{});
    } else if (std.mem.eql(u8, req.head.target, "/health")) {
        try req.respond("{\"status\":\"ok\"}\n", .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json" },
            },
        });
    } else {
        try req.respond("Not Found\n", .{ .status = .not_found });
    }
}

test {
    _ = tls;
}
