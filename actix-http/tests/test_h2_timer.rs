use std::{io, time::Duration};

use actix_http::{error::Error, HttpService, Response};
use actix_server::Server;
use tokio::io::AsyncWriteExt;

#[tokio::test(flavor = "local")]
async fn h2_ping_pong() -> io::Result<()> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);

    let lst = std::net::TcpListener::bind("127.0.0.1:0")?;

    let addr = lst.local_addr().unwrap();

    let join = std::thread::spawn(move || {
        actix_rt::System::new().block_on(async move {
            let srv = Server::build()
                .disable_signals()
                .workers(1)
                .listen("h2_ping_pong", lst, || {
                    HttpService::build()
                        .keep_alive(Duration::from_secs(3))
                        .h2(|_| async { Ok::<_, Error>(Response::ok()) })
                        .tcp()
                })?
                .run();

            tx.send(srv.handle()).unwrap();

            srv.await
        })
    });

    let handle = rx.recv().unwrap();

    let (sync_tx, rx) = std::sync::mpsc::sync_channel(1);

    // use a separate thread for h2 client so it can be blocked.
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let stream = tokio::net::TcpStream::connect(addr).await.unwrap();

                let (mut tx, conn) = h2::client::handshake(stream).await.unwrap();

                tokio::spawn(async move { conn.await.unwrap() });

                let (res, _) = tx.send_request(::http::Request::new(()), true).unwrap();
                let res = res.await.unwrap();

                assert_eq!(res.status().as_u16(), 200);

                sync_tx.send(()).unwrap();

                // intentionally block the client thread so it can not answer ping pong.
                std::thread::sleep(std::time::Duration::from_secs(1000));
            })
    });

    rx.recv().unwrap();

    let now = std::time::Instant::now();

    // stop server gracefully. this step would take up to 30 seconds.
    handle.stop(true).await;

    // join server thread. only when connection are all gone this step would finish.
    join.join().unwrap()?;

    // check the time used for join server thread so it's known that the server shutdown
    // is from keep alive and not server graceful shutdown timeout.
    assert!(now.elapsed() < std::time::Duration::from_secs(30));

    Ok(())
}

#[tokio::test(flavor = "local")]
async fn h2_handshake_timeout() -> io::Result<()> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);

    let lst = std::net::TcpListener::bind("127.0.0.1:0")?;

    let addr = lst.local_addr().unwrap();

    let join = std::thread::spawn(move || {
        actix_rt::System::new().block_on(async move {
            let srv = Server::build()
                .disable_signals()
                .workers(1)
                .listen("h2_ping_pong", lst, || {
                    HttpService::build()
                        .keep_alive(Duration::from_secs(30))
                        // set first request timeout to 5 seconds.
                        // this is the timeout used for http2 handshake.
                        .client_request_timeout(Duration::from_secs(5))
                        .h2(|_| async { Ok::<_, Error>(Response::ok()) })
                        .tcp()
                })?
                .run();

            tx.send(srv.handle()).unwrap();

            srv.await
        })
    });

    let handle = rx.recv().unwrap();

    let (sync_tx, rx) = std::sync::mpsc::sync_channel(1);

    // use a separate thread for tcp client so it can be blocked.
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

                // do not send the last new line intentionally.
                // This should hang the server handshake
                let malicious_buf = b"PRI * HTTP/2.0\r\n\r\nSM\r\n";
                stream.write_all(malicious_buf).await.unwrap();
                stream.flush().await.unwrap();

                sync_tx.send(()).unwrap();

                // intentionally block the client thread so it sit idle and not do handshake.
                std::thread::sleep(std::time::Duration::from_secs(1000));

                drop(stream)
            })
    });

    rx.recv().unwrap();

    let now = std::time::Instant::now();

    // stop server gracefully. this step would take up to 30 seconds.
    handle.stop(true).await;

    // join server thread. only when connection are all gone this step would finish.
    join.join().unwrap()?;

    // check the time used for join server thread so it's known that the server shutdown
    // is from handshake timeout and not server graceful shutdown timeout.
    assert!(now.elapsed() < std::time::Duration::from_secs(30));

    Ok(())
}

/// Starts an h2 server with a 1 s keep-alive whose handler answers `/slow` with six chunks
/// half a second apart (3 s in all) and anything else with an empty 200.
fn idle_server() -> (std::net::SocketAddr, actix_server::ServerHandle) {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let lst = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = lst.local_addr().unwrap();

    std::thread::spawn(move || {
        actix_rt::System::new().block_on(async move {
            let srv = Server::build()
                .disable_signals()
                .workers(1)
                .listen("h2_idle", lst, || {
                    HttpService::build()
                        .keep_alive(Duration::from_secs(1))
                        .h2(|req: actix_http::Request| async move {
                            if req.path() == "/body" {
                                return Ok::<_, Error>(
                                    Response::ok().set_body("hello").map_into_boxed_body(),
                                );
                            }
                            if req.path() != "/slow" {
                                return Ok::<_, Error>(Response::ok());
                            }
                            let body = async_stream::stream! {
                                for _ in 0..6 {
                                    actix_rt::time::sleep(Duration::from_millis(500)).await;
                                    yield Ok::<_, Error>(bytes::Bytes::from_static(b"chunk"));
                                }
                            };
                            Ok::<_, Error>(
                                Response::ok()
                                    .set_body(actix_http::body::BodyStream::new(body))
                                    .map_into_boxed_body(),
                            )
                        })
                        .tcp()
                })
                .unwrap()
                .run();

            tx.send(srv.handle()).unwrap();
            srv.await
        })
    });

    (addr, rx.recv().unwrap())
}

/// Opens an h2 connection whose client side is driven (so it answers PINGs) in a task, and
/// returns the request handle and the task that ends when the server closes the connection.
async fn idle_client(
    addr: std::net::SocketAddr,
) -> (
    h2::client::SendRequest<bytes::Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (tx, conn) = h2::client::handshake(stream).await.unwrap();
    let closed = tokio::spawn(async move {
        conn.await
            .expect("connection closed with an error rather than a clean GOAWAY");
    });
    (tx, closed)
}

fn get(path: &str) -> ::http::Request<()> {
    ::http::Request::get(format!("http://localhost{path}"))
        .body(())
        .unwrap()
}

/// A connection with no open stream is closed after keep-alive even though its client answers
/// every PING, both after a request and when it never sends one.
#[actix_rt::test]
async fn h2_idle_connection_answering_pings_is_closed() {
    let (addr, handle) = idle_server();

    let (mut tx, closed) = idle_client(addr).await;
    let (res, _) = tx.send_request(get("/"), true).unwrap();
    assert_eq!(res.await.unwrap().status().as_u16(), 200);
    // several PING rounds fit in the wait; without the idle close the connection outlives it.
    tokio::time::timeout(Duration::from_secs(5), closed)
        .await
        .expect("idle connection still open after 5 s")
        .unwrap();

    let (_tx, closed) = idle_client(addr).await;
    tokio::time::timeout(Duration::from_secs(5), closed)
        .await
        .expect("connection that never opened a stream still open after 5 s")
        .unwrap();

    handle.stop(false).await;
}

/// A stream that outlasts keep-alive is never cut by the idle close, and the idle period
/// starts once it ends.
#[actix_rt::test]
async fn h2_open_stream_outlasting_keep_alive_is_not_cut() {
    let (addr, handle) = idle_server();

    let (mut tx, closed) = idle_client(addr).await;
    let (res, _) = tx.send_request(get("/slow"), true).unwrap();
    let res = res.await.unwrap();
    assert_eq!(res.status().as_u16(), 200);

    let mut body = res.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("stream cut before its body finished");
        let _ = body.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, b"chunk".repeat(6));
    assert!(!closed.is_finished(), "closed while the stream was open");

    tokio::time::timeout(Duration::from_secs(5), closed)
        .await
        .expect("connection still open 5 s after its last stream ended")
        .unwrap();

    handle.stop(false).await;
}

/// What a raw h2 client saw before the server closed the connection or its limit passed.
#[derive(Debug)]
struct Held {
    /// How long the connection stayed open, or `None` if it outlived the limit.
    closed_after: Option<Duration>,
    goaways: usize,
}

/// h2's fixed payload for the PING it sends during graceful shutdown.
const SHUTDOWN_PING: [u8; 8] = [0x0b, 0x7b, 0xa2, 0xf0, 0x8b, 0x9b, 0xfe, 0x54];

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = len.to_be_bytes()[1..].to_vec();
    out.extend([kind, flags]);
    out.extend(stream.to_be_bytes());
    out.extend(payload);
    out
}

/// A hand-written h2 client, so the test decides which PINGs it acks and what window it
/// advertises (the h2 crate acks every PING). It acks SETTINGS and every PING except h2's
/// shutdown one unless `ack_shutdown`; with `zero_window` it advertises
/// SETTINGS_INITIAL_WINDOW_SIZE = 0 and never sends WINDOW_UPDATE; with `path` it sends one
/// GET for it. Returns once the server closes the connection or after `limit`.
fn raw_hold(
    addr: std::net::SocketAddr,
    ack_shutdown: bool,
    zero_window: bool,
    path: Option<&str>,
    limit: Duration,
) -> Held {
    use std::io::{ErrorKind, Read, Write};

    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let start = std::time::Instant::now();
    let closed = |goaways| Held {
        closed_after: Some(start.elapsed()),
        goaways,
    };

    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let settings: &[u8] = if zero_window {
        &[0, 4, 0, 0, 0, 0]
    } else {
        &[]
    };
    hello.extend(frame(0x4, 0, 0, settings));
    if let Some(path) = path {
        // :method GET and :scheme http indexed, :path and :authority as literals.
        let mut block = vec![0x82, 0x86, 0x04, path.len() as u8];
        block.extend(path.as_bytes());
        block.extend([0x01, 9]);
        block.extend(b"localhost");
        // END_HEADERS | END_STREAM
        hello.extend(frame(0x1, 0x4 | 0x1, 1, &block));
    }
    sock.write_all(&hello).unwrap();

    let mut buf = Vec::new();
    let mut goaways = 0;
    let mut chunk = [0u8; 4096];
    while start.elapsed() < limit {
        match sock.read(&mut chunk) {
            Ok(0) => return closed(goaways),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue
            }
            Err(_) => return closed(goaways),
        }

        while buf.len() >= 9 {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if buf.len() < 9 + len {
                break;
            }
            let (kind, flags) = (buf[3], buf[4]);
            let payload = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);

            let reply = match kind {
                0x4 if flags & 0x1 == 0 => Some(frame(0x4, 0x1, 0, &[])),
                0x6 if flags & 0x1 == 0 && (ack_shutdown || payload != SHUTDOWN_PING) => {
                    Some(frame(0x6, 0x1, 0, &payload))
                }
                0x7 => {
                    goaways += 1;
                    None
                }
                _ => None,
            };
            if let Some(reply) = reply {
                if sock.write_all(&reply).is_err() {
                    return closed(goaways);
                }
            }
        }
    }

    Held {
        closed_after: None,
        goaways,
    }
}

/// Runs `raw_hold` against the 1 s keep-alive server with an 8 s limit.
async fn hold(
    addr: std::net::SocketAddr,
    ack_shutdown: bool,
    zero_window: bool,
    path: Option<&'static str>,
) -> Held {
    tokio::task::spawn_blocking(move || {
        raw_hold(
            addr,
            ack_shutdown,
            zero_window,
            path,
            Duration::from_secs(8),
        )
    })
    .await
    .unwrap()
}

/// Asserts the connection was closed within `within` of opening, after `goaways` GOAWAYs.
fn assert_closed(held: &Held, within: Duration, goaways: usize) {
    let closed = held
        .closed_after
        .unwrap_or_else(|| panic!("connection held past the limit: {held:?}"));
    assert!(
        closed < within,
        "closed after {closed:?}, want under {within:?}"
    );
    assert_eq!(held.goaways, goaways, "{held:?}");
}

/// The cooperative case through the raw client, so each test below differs from it in one
/// thing: GOAWAY at keep-alive (1 s), the shutdown PING acked, the final GOAWAY, close.
#[actix_rt::test]
async fn h2_raw_client_acking_every_ping_is_closed() {
    let (addr, handle) = idle_server();
    assert_closed(
        &hold(addr, true, false, None).await,
        Duration::from_secs(2),
        2,
    );
    handle.stop(false).await;
}

/// A client that acks the keep-alive PINGs but never h2's shutdown PING is still closed, with
/// and without a request first. h2 0.3 sends no user PING while its shutdown PING waits for an
/// ack (`proto/ping_pong.rs`, `send_pending_ping`), so the keep-alive PING goes unanswered and
/// its deadline closes the connection one keep-alive after the GOAWAY. hisn #4284.
#[actix_rt::test]
async fn h2_idle_connection_withholding_shutdown_ping_ack_is_closed() {
    let (addr, handle) = idle_server();
    assert_closed(
        &hold(addr, false, false, None).await,
        Duration::from_secs(4),
        1,
    );
    assert_closed(
        &hold(addr, false, false, Some("/")).await,
        Duration::from_secs(4),
        1,
    );
    handle.stop(false).await;
}

/// A client that advertises a zero window and asks for a non-empty body holds the connection:
/// the response waits on `poll_capacity` with no deadline, so its stream counts as open and the
/// idle close never starts. hisn #4284; the fix route is not yet decided.
#[actix_rt::test]
#[ignore = "reproduces hisn #4284: a zero-window stream holds the connection"]
async fn h2_zero_window_stream_does_not_hold_connection() {
    let (addr, handle) = idle_server();
    let held = hold(addr, true, true, Some("/body")).await;
    assert!(held.closed_after.is_some(), "{held:?}");
    let held = hold(addr, false, true, Some("/body")).await;
    assert!(held.closed_after.is_some(), "{held:?}");
    handle.stop(false).await;
}
