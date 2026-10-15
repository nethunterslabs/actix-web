//! HTTP/2 protocol.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Poll, Waker},
};

use actix_codec::{AsyncRead, AsyncWrite};
use bytes::{Bytes, BytesMut};
use futures_core::{ready, Stream};
use h2::{
    server::{Builder, Connection, Handshake},
    RecvStream,
};
use tokio::time::{sleep_until, Sleep};

use crate::{
    config::ServiceConfig,
    error::{DispatchError, PayloadError},
};

mod dispatcher;
mod service;

pub use self::{dispatcher::Dispatcher, service::H2Service};

/// HTTP/2 peer stream.
///
/// While the dispatcher's task for the request runs, a [`Drain`] reads the stream on the
/// handler's behalf: empty DATA frames are discarded as they arrive, and data is held here
/// until the handler reads it. Without it, h2 0.3 queues every empty DATA frame of a body
/// nobody is reading, and an empty frame takes no flow-control window, so the queue grows
/// with what the peer sends (RUSTSEC-2026-0258). What is held here is bounded by the
/// stream's flow-control window, because capacity is released only when the handler reads
/// the data.
pub struct Payload {
    shared: Arc<Mutex<Shared>>,
}

struct Shared {
    stream: RecvStream,
    /// Data drained from the stream that the handler has not read yet.
    held: Held,
    /// An error the drain met, for the handler's next read.
    error: Option<PayloadError>,
    /// The drain has seen the end of the stream, or an error.
    ended: bool,
    /// A [`Drain`] is reading the stream for this payload.
    draining: bool,
    /// The task waiting to read, woken when the drain holds data or the end.
    reader: Option<Waker>,
}

/// Drained data, kept as the chunk it arrived in while there is only one, so a handler that
/// keeps up with its body costs no copy.
enum Held {
    Nothing,
    One(Bytes),
    Many(BytesMut),
}

impl Held {
    fn push(&mut self, chunk: Bytes) {
        *self = match std::mem::replace(self, Held::Nothing) {
            Held::Nothing => Held::One(chunk),
            Held::One(first) => {
                let mut many = BytesMut::with_capacity(first.len() + chunk.len());
                many.extend_from_slice(&first);
                many.extend_from_slice(&chunk);
                Held::Many(many)
            }
            Held::Many(mut many) => {
                many.extend_from_slice(&chunk);
                Held::Many(many)
            }
        };
    }

    fn take(&mut self) -> Option<Bytes> {
        match std::mem::replace(self, Held::Nothing) {
            Held::Nothing => None,
            Held::One(chunk) => Some(chunk),
            Held::Many(many) => Some(many.freeze()),
        }
    }
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Payload {
    pub(crate) fn new(stream: RecvStream) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared {
                stream,
                held: Held::Nothing,
                error: None,
                ended: false,
                draining: false,
                reader: None,
            })),
        }
    }

    /// A payload and the [`Drain`] that reads its stream while the handler does not.
    pub(crate) fn with_drain(stream: RecvStream) -> (Self, Drain) {
        let payload = Self::new(stream);
        lock(&payload.shared).draining = true;
        let drain = Drain {
            shared: Arc::downgrade(&payload.shared),
        };
        (payload, drain)
    }
}

impl Stream for Payload {
    type Item = Result<Bytes, PayloadError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut shared = lock(&self.shared);
        let shared = &mut *shared;

        let chunk = match shared.held.take() {
            Some(chunk) => chunk,
            None if shared.error.is_some() => return Poll::Ready(shared.error.take().map(Err)),
            None if shared.ended => return Poll::Ready(None),
            None if shared.draining => {
                // the drain is registered with the stream and wakes this task
                if !shared
                    .reader
                    .as_ref()
                    .is_some_and(|reader| reader.will_wake(cx.waker()))
                {
                    shared.reader = Some(cx.waker().clone());
                }
                return Poll::Pending;
            }
            None => loop {
                match ready!(Pin::new(&mut shared.stream).poll_data(cx)) {
                    Some(Ok(chunk)) if chunk.is_empty() => continue,
                    Some(Ok(chunk)) => break chunk,
                    Some(Err(err)) => return Poll::Ready(Some(Err(err.into()))),
                    None => return Poll::Ready(None),
                }
            },
        };

        match shared.stream.flow_control().release_capacity(chunk.len()) {
            Ok(()) => Poll::Ready(Some(Ok(chunk))),
            Err(err) => Poll::Ready(Some(Err(err.into()))),
        }
    }
}

/// Reads a request's stream for its [`Payload`] while the handler runs. Completes at the end
/// of the stream or once the payload is dropped; dropping it hands the stream back to the
/// payload, which then reads it itself.
pub(crate) struct Drain {
    shared: Weak<Mutex<Shared>>,
}

impl Future for Drain {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Some(shared) = self.shared.upgrade() else {
            return Poll::Ready(());
        };
        let mut shared = lock(&shared);
        let shared = &mut *shared;

        let mut held_more = false;
        let done = loop {
            match Pin::new(&mut shared.stream).poll_data(cx) {
                Poll::Pending => break false,
                Poll::Ready(Some(Ok(chunk))) => {
                    // an empty frame carries nothing for the handler; dropping it here is
                    // what keeps h2 from queuing it
                    if !chunk.is_empty() {
                        shared.held.push(chunk);
                        held_more = true;
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    shared.error = Some(err.into());
                    shared.ended = true;
                    break true;
                }
                Poll::Ready(None) => {
                    shared.ended = true;
                    break true;
                }
            }
        };

        if held_more || done {
            if let Some(reader) = shared.reader.take() {
                reader.wake();
            }
        }

        if done {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            let mut shared = lock(&shared);
            shared.draining = false;
            if let Some(reader) = shared.reader.take() {
                reader.wake();
            }
        }
    }
}

pub(crate) fn handshake_with_timeout<T>(io: T, config: &ServiceConfig) -> HandshakeWithTimeout<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = Builder::new();
    builder
        .initial_window_size(config.h2_initial_window_size())
        .initial_connection_window_size(config.h2_initial_connection_window_size());

    if let Some(size) = config.h2_max_header_list_size() {
        builder.max_header_list_size(size);
    }

    if let Some(max) = config.h2_max_concurrent_streams() {
        builder.max_concurrent_streams(max);
    }

    HandshakeWithTimeout {
        handshake: builder.handshake(io),
        timer: config
            .client_request_deadline()
            .map(|deadline| Box::pin(sleep_until(deadline.into()))),
    }
}

pub(crate) struct HandshakeWithTimeout<T: AsyncRead + AsyncWrite + Unpin> {
    handshake: Handshake<T>,
    timer: Option<Pin<Box<Sleep>>>,
}

impl<T> Future for HandshakeWithTimeout<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(Connection<T, Bytes>, Option<Pin<Box<Sleep>>>), DispatchError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match Pin::new(&mut this.handshake).poll(cx)? {
            // return the timer on success handshake; its slot can be re-used for h2 ping-pong
            Poll::Ready(conn) => Poll::Ready(Ok((conn, this.timer.take()))),
            Poll::Pending => match this.timer.as_mut() {
                Some(timer) => {
                    ready!(timer.as_mut().poll(cx));
                    Poll::Ready(Err(DispatchError::SlowRequestTimeout))
                }
                None => Poll::Pending,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_impl_all;
    use tokio::net::TcpStream;

    use super::*;

    assert_impl_all!(Payload: Unpin, Send, Sync);

    async fn client_settings(
        config: ServiceConfig,
    ) -> (
        h2::client::SendRequest<Bytes>,
        h2::client::Connection<TcpStream, Bytes>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        actix_rt::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            let (mut conn, _timer) = handshake_with_timeout(io, &config).await.unwrap();
            while let Some(Ok((_req, mut res))) = conn.accept().await {
                let _ = res.send_response(http::Response::new(()), true);
            }
        });

        let io = TcpStream::connect(addr).await.unwrap();
        let (send, mut conn) = h2::client::handshake(io).await.unwrap();

        // drive the connection until the server's first SETTINGS frame has been applied
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while conn.max_concurrent_send_streams() == usize::MAX
            && tokio::time::Instant::now() < deadline
        {
            tokio::select! {
                _ = &mut conn => break,
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
            }
        }

        (send, conn)
    }

    #[actix_rt::test]
    async fn max_concurrent_streams_is_advertised() {
        let config = crate::ServiceConfigBuilder::new()
            .h2_max_concurrent_streams(Some(100))
            .build();

        let (_send, conn) = client_settings(config).await;
        assert_eq!(conn.max_concurrent_send_streams(), 100);
    }

    #[actix_rt::test]
    async fn max_header_list_size_is_enforced() {
        let config = crate::ServiceConfigBuilder::new()
            .h2_max_header_list_size(Some(16 * 1024))
            .build();

        let (send, conn) = client_settings(config).await;
        actix_rt::spawn(async move {
            let _ = conn.await;
        });
        let mut send = send.ready().await.unwrap();

        let small = http::Request::get("http://localhost/").body(()).unwrap();
        let (res, _) = send.send_request(small, true).unwrap();
        assert_eq!(res.await.unwrap().status(), http::StatusCode::OK);

        let mut big = http::Request::get("http://localhost/").body(()).unwrap();
        for i in 0..20 {
            big.headers_mut().insert(
                http::HeaderName::try_from(format!("x-big-{i}")).unwrap(),
                http::HeaderValue::from_str(&"a".repeat(1024)).unwrap(),
            );
        }
        let mut send = send.ready().await.unwrap();
        let refused = match send.send_request(big, true) {
            Err(_) => true,
            Ok((res, _)) => match res.await {
                Err(_) => true,
                Ok(res) => res.status() != http::StatusCode::OK,
            },
        };
        assert!(refused, "a 20 KiB header list passed a 16 KiB limit");
    }

    #[actix_rt::test]
    async fn h2_limits_are_unset_by_default() {
        let config = ServiceConfig::default();
        assert_eq!(config.h2_max_header_list_size(), None);
        assert_eq!(config.h2_max_concurrent_streams(), None);

        let config = crate::ServiceConfigBuilder::new()
            .h2_max_header_list_size(Some(128 * 1024))
            .build();
        assert_eq!(config.h2_max_header_list_size(), Some(128 * 1024));
    }
}
