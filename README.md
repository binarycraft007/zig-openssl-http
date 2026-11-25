# zig-openssl-http

An example HTTPS server written in **Zig 0.17.1** that integrates **OpenSSL** with Zig’s standard library **`std.http.Server`** and **`std.Io`** (`std.Io.net`, `std.Io.Group`, `std.Io.Event`), using the external `translate-c` package instead of removed `@cImport`.

## How It Works

`std.http.Server` takes a `*std.Io.Reader` and `*std.Io.Writer` rather than a raw socket or `std.Io` runtime handle. This project bridges both sides of OpenSSL so all network I/O still flows through Zig’s `std.Io`:

```text
std.http.Server
  ├── in:  *std.Io.Reader  ──► tls.Connection.reader (vtable.stream -> SSL_read)
  └── out: *std.Io.Writer  ──► tls.Connection.writer (vtable.drain/flush -> SSL_write)
                                     │
                               OpenSSL (*SSL)
                                     │
                         Custom OpenSSL BIO_METHOD
                    (bread / bwrite / BIO_CTRL_FLUSH)
                                     │
                    std.Io.net.Stream (reader / writer)
```

### Features
- **Full `std.Io` integration:** OpenSSL reads and writes ciphertext through `std.Io.net.Stream.Reader` / `Writer` via a custom `BIO_METHOD` instead of bypassing `std.Io` with `SSL_set_fd`.
- **Zig 0.17.1 C interop:** Uses the official `translate-c` build package in `build.zig` (`src/openssl.h`).
- **ALPN negotiation:** Selects `http/1.1` via `SSL_CTX_set_alpn_select_cb`.
- **Structured concurrency & timeouts:** Accepts connections into a `std.Io.Group` and enforces per-connection deadlines with `io.concurrent` + `std.Io.Event.waitTimeout`.
- **OpenSSL diagnostics:** Drains and logs OpenSSL’s error queue (`ERR_get_error`) on setup and handshake failures.

---

## Requirements

- **Zig:** `0.17.1`
- **OpenSSL:** development headers and libraries (`libssl`, `libcrypto`)
  - Debian/Ubuntu: `sudo apt install libssl-dev`
  - Arch Linux: `sudo pacman -S openssl`
  - Fedora: `sudo dnf install openssl-devel`
  - macOS (Homebrew): `brew install openssl`

---

## Project Structure

```text
zig-openssl-http/
├── build.zig          # Configures translate-c for OpenSSL and links ssl/crypto
├── build.zig.zon      # Package manifest (includes translate-c dependency)
├── certs/
│   ├── cert.pem       # TLS certificate chain (self-signed for local dev)
│   └── key.pem        # Private key
└── src/
    ├── c.h      # OpenSSL headers passed to translate-c
    ├── tls.zig        # ServerContext, custom BIO_METHOD, and Reader/Writer wrapper
    └── main.zig       # TCP listener, Group task spawning, timeouts, HTTP routes
```

---

## Quick Start

### 1. Generate a local development certificate

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -subj "/CN=localhost"
```

### 2. Build and run

```sh
zig build run
```

The server listens on `https://127.0.0.1:8443`.

### 3. Test the endpoints

```sh
curl -vk https://127.0.0.1:8443/
curl -k https://127.0.0.1:8443/health
```

Expected output from `/` includes:
- TLS 1.3 handshake completion
- `ALPN: server accepted http/1.1`
- `Hello over HTTPS from Zig 0.17.1 + OpenSSL!`

### 4. Run unit tests

```sh
zig build test
```

---

## Implementation Notes

- **Address stability (`@fieldParentPtr`):** Both `std.Io.net.Stream.Reader`/`Writer` and `tls.Connection` rely on intrusive `@fieldParentPtr` pointers. Never copy `net_reader.interface`, `net_writer.interface`, or `tls.Connection` by value after initialization.
- **Explicit flushing:** `SSL_write` does not automatically emit `BIO_CTRL_FLUSH`, so `tls.Connection.writer` overrides `.flush` (calling `std.Io.Writer.defaultFlush` followed by `net_out.flush()`), and `bioCtrl` handles `BIO_CTRL_FLUSH` so TLS handshakes and buffered HTTP responses never stall in userspace buffers.
- **Thread/task safety per connection:** OpenSSL `*SSL` instances do not support concurrent `SSL_read` and `SSL_write` without external locking. This fits standard HTTP/1.1 request/response loops out of the box; if you upgrade a connection to a full-duplex protocol (e.g., WebSockets), guard `SSL` access or serialize reads/writes.
