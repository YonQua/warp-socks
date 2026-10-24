//! HTTP/1 正向代理。普通请求按消息边界路由，CONNECT/Upgrade 才进入字节隧道。
use std::{
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{net::TcpStream, sync::mpsc, task::JoinHandle, time::Instant};

use crate::{
    outbound::{Connected, Host, Outbound},
    relay,
};

type ProxyBody = UnsyncBoxBody<Bytes, anyhow::Error>;
type Tunnel = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

pub(crate) async fn handle_client(
    client: TcpStream,
    peer: SocketAddr,
    outbound: Arc<dyn Outbound>,
    deadline: Instant,
) -> Result<()> {
    // HTTP/1 升级后不再处理 HTTP 请求，唯一隧道由当前连接直接持有。
    let (tunnel_tx, mut tunnel_rx) = mpsc::channel::<Tunnel>(1);
    let service = service_fn(move |request| {
        let outbound = Arc::clone(&outbound);
        let tunnel_tx = tunnel_tx.clone();
        async move {
            let response = match forward(request, peer, outbound, tunnel_tx).await {
                Ok(response) => response,
                Err(error) => {
                    log::warn!("HTTP 代理请求失败: peer={peer}, error={error:#}");
                    error_response(StatusCode::BAD_GATEWAY)
                }
            };
            Ok::<_, Infallible>(response)
        }
    });
    let result = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        // 客户端发送完请求后可以关闭写方向，响应仍须完整返回。
        .half_close(true)
        .header_read_timeout(deadline.saturating_duration_since(Instant::now()))
        .max_headers(64)
        .max_buf_size(16 * 1024)
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades()
        .await;
    result.context("HTTP 代理连接结束异常")?;
    if let Ok(tunnel) = tunnel_rx.try_recv() {
        tunnel.await?;
    }
    Ok(())
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn error_response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(b"Proxy request failed\n"))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

fn target(request: &Request<Incoming>) -> Result<(Host, u16, String)> {
    let uri = request.uri();
    if request.method() != Method::CONNECT && uri.scheme_str().is_some_and(|s| s != "http") {
        bail!("普通 HTTP 代理仅接受 http URI；HTTPS 请使用 CONNECT");
    }
    let authority = match uri.authority() {
        Some(authority) => authority.clone(),
        None => request
            .headers()
            .get(header::HOST)
            .context("缺少 Host")?
            .to_str()?
            .parse::<http::uri::Authority>()?,
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() || authority.as_str().contains('@') {
        bail!("非法目标主机");
    }
    let port = if request.method() == Method::CONNECT {
        authority.port_u16().context("CONNECT 缺少有效端口")?
    } else {
        if authority.as_str() == authority.host() {
            80
        } else {
            authority.port_u16().context("非法目标端口")?
        }
    };
    if port == 0 {
        bail!("非法目标端口");
    }
    Ok((Host::parse(host), port, authority.to_string()))
}

// Connection 指定的字段仅属于这一跳，不能泄露到目标或下一位客户端。
fn strip_hop_headers(headers: &mut HeaderMap, upgrade: Option<HeaderValue>) {
    let names = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_owned())
        .collect::<Vec<_>>();
    for name in names {
        headers.remove(name.as_str());
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    if let Some(value) = upgrade {
        headers.insert(header::UPGRADE, value);
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
}

async fn forward(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    outbound: Arc<dyn Outbound>,
    tunnel_tx: mpsc::Sender<Tunnel>,
) -> Result<Response<ProxyBody>> {
    let (host, port, authority) = match target(&request) {
        Ok(target) => target,
        Err(error) => {
            log::debug!("HTTP 代理目标无效: {error:#}");
            return Ok(error_response(StatusCode::BAD_REQUEST));
        }
    };
    let connected = outbound.connect_tcp(host, port).await?;
    if request.method() == Method::CONNECT {
        let upgrade = hyper::upgrade::on(&mut request);
        tunnel_tx
            .try_send(Box::pin(async move {
                let client = upgrade.await.context("CONNECT upgrade 失败")?;
                relay::tunnel_tcp(
                    peer,
                    &authority,
                    outbound.name(),
                    TokioIo::new(client),
                    connected,
                )
                .await
            }))
            .map_err(|_| anyhow::anyhow!("HTTP 连接重复升级或已关闭"))?;
        return Ok(Response::new(empty_body()));
    }

    let requested_upgrade = request.headers().get(header::UPGRADE).cloned();
    let client_upgrade = requested_upgrade
        .as_ref()
        .map(|_| hyper::upgrade::on(&mut request));
    strip_hop_headers(request.headers_mut(), requested_upgrade);
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_str(&authority)?);
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .parse::<Uri>()?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(connected.stream)).await?;
    let driver = Driver(tokio::spawn(
        async move { connection.with_upgrades().await },
    ));
    let mut response = sender.send_request(request).await?;
    let response_upgrade = response.headers().get(header::UPGRADE).cloned();
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let client_upgrade = client_upgrade.context("目标返回未请求的 Upgrade")?;
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        strip_hop_headers(response.headers_mut(), response_upgrade);
        let (parts, _) = response.into_parts();
        tunnel_tx
            .try_send(Box::pin(async move {
                let _driver = driver;
                let (client, remote) = tokio::try_join!(client_upgrade, upstream_upgrade)?;
                let connected = Connected {
                    stream: Box::new(TokioIo::new(remote)),
                    note: connected.note,
                };
                relay::tunnel_tcp(
                    peer,
                    &authority,
                    outbound.name(),
                    TokioIo::new(client),
                    connected,
                )
                .await
            }))
            .map_err(|_| anyhow::anyhow!("HTTP 连接重复升级或已关闭"))?;
        return Ok(Response::from_parts(parts, empty_body()));
    }
    strip_hop_headers(response.headers_mut(), None);
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(
        parts,
        DrivenBody {
            body,
            _driver: driver,
        }
        .boxed_unsync(),
    ))
}

// 响应体释放即取消对应上游驱动，客户端中断不会遗留后台连接。
struct Driver(JoinHandle<Result<(), hyper::Error>>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct DrivenBody {
    body: Incoming,
    _driver: Driver,
}
impl Body for DrivenBody {
    type Data = Bytes;
    type Error = anyhow::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        Pin::new(&mut self.body)
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(Into::into)))
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
