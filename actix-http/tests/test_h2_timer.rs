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
