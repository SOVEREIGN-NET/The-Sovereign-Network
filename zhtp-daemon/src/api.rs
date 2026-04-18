use crate::service::ZhtpDaemonService;
use anyhow::Result;
use axum::extract::{ConnectInfo, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::{engine::general_purpose, Engine as _};
use lib_protocols::ZhtpResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<ZhtpDaemonService>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveQuery {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct ContentQuery {
    pub domain: String,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonContentResponse {
    pub domain: String,
    pub path: String,
    pub content_type: Option<String>,
    pub cache_control: Option<String>,
    pub etag: Option<String>,
    pub body_base64: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/api/v1/status", get(status))
        .route("/api/v1/domains", get(domains))
        .route("/api/v1/resolve", get(resolve_query))
        .route("/api/v1/resolve/:domain", get(resolve_path))
        .route("/api/v1/content", get(content_json))
        .route("/_next/*path", get(root_next_asset))
        .route("/images/*path", get(root_images_asset))
        .route("/favicon.ico", get(root_favicon))
        .route("/web4/content/:domain", get(raw_content_root))
        .route("/web4/content/:domain/*path", get(raw_content))
        .route("/*path", get(root_site_path))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

async fn metrics(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!(state.service.metrics()))
}

async fn status(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!(state.service.status().await))
}

async fn domains(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<serde_json::Value>, AppError> {
    let domains = state.service.list_domains(Some(addr.ip().to_string())).await?;
    Ok(Json(domains))
}

async fn resolve_query(
    State(state): State<AppState>,
    Query(query): Query<ResolveQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<serde_json::Value>, AppError> {
    let resolved = state.service.resolve_domain(&query.domain, Some(addr.ip().to_string())).await?;
    Ok(Json(resolved))
}

async fn resolve_path(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<serde_json::Value>, AppError> {
    let resolved = state.service.resolve_domain(&domain, Some(addr.ip().to_string())).await?;
    Ok(Json(resolved))
}

async fn content_json(
    State(state): State<AppState>,
    Query(query): Query<ContentQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<JsonContentResponse>, AppError> {
    let path = normalize_path(query.path.as_deref().unwrap_or("/"));
    let response = state.service.fetch_content(&query.domain, &path, Some(addr.ip().to_string())).await?;
    Ok(Json(JsonContentResponse {
        domain: query.domain,
        path,
        content_type: response.headers.content_type.clone(),
        cache_control: response.headers.cache_control.clone(),
        etag: response.headers.etag.clone(),
        body_base64: general_purpose::STANDARD.encode(response.body),
    }))
}

async fn raw_content_root(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    relay_content(state, domain, "/".to_string(), Some(addr.ip().to_string())).await
}

async fn raw_content(
    State(state): State<AppState>,
    Path((domain, path)): Path<(String, String)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    let normalized_path = normalize_path(&path);
    relay_content(state, domain, normalized_path, Some(addr.ip().to_string())).await
}

async fn root_next_asset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    relay_root_asset(state, headers, format!("/_next/{}", path), Some(addr.ip().to_string())).await
}

async fn root_images_asset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    relay_root_asset(state, headers, format!("/images/{}", path), Some(addr.ip().to_string())).await
}

async fn root_favicon(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    relay_root_asset(state, headers, "/favicon.ico".to_string(), Some(addr.ip().to_string())).await
}

async fn root_site_path(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Path(path): Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    let mut normalized = format!("/{}", path);
    if let Some(query) = uri.query() {
        normalized.push('?');
        normalized.push_str(query);
    }
    relay_root_asset(state, headers, normalized, Some(addr.ip().to_string())).await
}

async fn relay_root_asset(
    state: AppState,
    headers: HeaderMap,
    path: String,
    client_ip: Option<String>,
) -> Result<Response, AppError> {
    let domain = extract_domain_from_referer(&headers)
        .ok_or_else(|| AppError(anyhow::anyhow!("Missing or invalid Referer for root asset {}", path)))?;
    relay_content(state, domain, path, client_ip).await
}

async fn relay_content(
    state: AppState,
    domain: String,
    path: String,
    client_ip: Option<String>,
) -> Result<Response, AppError> {
    let mut response = state.service.fetch_content(&domain, &path, client_ip).await?;
    if let Some(content_type) = response.headers.content_type.as_deref() {
        if content_type.starts_with("text/html") {
            response.body = rewrite_text_response(&domain, &response.body)?;
            response.headers.content_length = Some(response.body.len() as u64);
        } else if content_type.contains("javascript")
            || content_type.contains("ecmascript")
            || content_type.starts_with("text/css")
        {
            response.body = rewrite_text_response(&domain, &response.body)?;
            response.headers.content_length = Some(response.body.len() as u64);
        }
    }
    Ok(into_http_response(response))
}

fn normalize_path(raw_path: &str) -> String {
    if raw_path.is_empty() {
        "/".to_string()
    } else if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{}", raw_path)
    }
}

fn extract_domain_from_referer(headers: &HeaderMap) -> Option<String> {
    let referer = headers.get(axum::http::header::REFERER)?.to_str().ok()?;
    let marker = "/web4/content/";
    let start = referer.find(marker)? + marker.len();
    let rest = &referer[start..];
    let domain = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|segment| !segment.is_empty())?;
    Some(domain.to_string())
}

fn into_http_response(response: ZhtpResponse) -> Response {
    let status = StatusCode::from_u16(response.status.code()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut http_response = (status, response.body).into_response();
    let headers = http_response.headers_mut();

    if let Some(content_type) = response.headers.content_type.as_deref() {
        if let Ok(value) = HeaderValue::from_str(content_type) {
            headers.insert(axum::http::header::CONTENT_TYPE, value);
        }
    }
    if let Some(cache_control) = response.headers.cache_control.as_deref() {
        if let Ok(value) = HeaderValue::from_str(cache_control) {
            headers.insert(axum::http::header::CACHE_CONTROL, value);
        }
    }
    if let Some(etag) = response.headers.etag.as_deref() {
        if let Ok(value) = HeaderValue::from_str(etag) {
            headers.insert(axum::http::header::ETAG, value);
        }
    }
    if let Some(content_length) = response.headers.content_length {
        if let Ok(value) = HeaderValue::from_str(&content_length.to_string()) {
            headers.insert(axum::http::header::CONTENT_LENGTH, value);
        }
    }
    for (name, value) in &response.headers.custom {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }

    http_response
}

fn rewrite_text_response(domain: &str, body: &[u8]) -> Result<Vec<u8>, AppError> {
    let text = String::from_utf8(body.to_vec())
        .map_err(|error| AppError(anyhow::anyhow!("Invalid UTF-8 text payload: {}", error)))?;
    let prefix = format!("/web4/content/{}", domain);
    let mut rewritten = text
        .replace("href=\"/", &format!("href=\"{}/", prefix))
        .replace("src=\"/", &format!("src=\"{}/", prefix))
        .replace("action=\"/", &format!("action=\"{}/", prefix))
        .replace("content=\"/", &format!("content=\"{}/", prefix))
        .replace("\"/_next/", &format!("\"{}/_next/", prefix))
        .replace("\"/images/", &format!("\"{}/images/", prefix))
        .replace("\"/favicon", &format!("\"{}/favicon", prefix))
        .replace("\"/feed", &format!("\"{}/feed", prefix))
        .replace("\"/profile", &format!("\"{}/profile", prefix))
        .replace("\"/settings", &format!("\"{}/settings", prefix))
        .replace("\"/wiki", &format!("\"{}/wiki", prefix))
        .replace("\"/company-info", &format!("\"{}/company-info", prefix))
        .replace("\"/tokenomics", &format!("\"{}/tokenomics", prefix))
        .replace("\"/contact", &format!("\"{}/contact", prefix))
        .replace("\"/bug-bounty", &format!("\"{}/bug-bounty", prefix))
        .replace("\"/\"", &format!("\"{}/\"", prefix))
        .replace("'/_next/", &format!("'{}/_next/", prefix))
        .replace("'/images/", &format!("'{}/images/", prefix))
        .replace("'/favicon", &format!("'{}/favicon", prefix))
        .replace("='/", &format!("='{}/", prefix))
        .replace(":/_next/", &format!(":{}/_next/", prefix));

    if rewritten.contains("<head>") {
        let base_and_shim = format!(
            "<head><base href=\"{prefix}/\"><script>(function(){{var p='{prefix}';function m(u){{try{{if(typeof u!=='string')return u;if(u.startsWith(p)||u.startsWith('http://')||u.startsWith('https://')||u.startsWith('data:')||u.startsWith('blob:')||u.startsWith('#'))return u;if(u.startsWith('/'))return p+u;return u;}}catch(_e){{return u;}}}}function hardNavigate(u){{try{{var t=typeof u==='string'?u:(u&&u.url?u.url:'');if(!t)return false;var abs=new URL(m(t),window.location.origin);var path=abs.pathname;var query=abs.search||'';if(query.indexOf('_rsc=')!==-1&&path.endsWith('.txt'))path=path.slice(0,-4);window.location.assign(path+query.replace(/([?&])_rsc=[^&]*/,'').replace(/^&/,'?'));return true;}}catch(_e){{}}return false;}}var ps=history.pushState.bind(history);history.pushState=function(s,t,u){{return ps(s,t,m(u));}};var rs=history.replaceState.bind(history);history.replaceState=function(s,t,u){{return rs(s,t,m(u));}};document.addEventListener('click',function(e){{var a=e.target&&e.target.closest?e.target.closest('a[href]'):null;if(!a)return;var h=a.getAttribute('href');if(!h||h.startsWith('http://')||h.startsWith('https://')||h.startsWith('mailto:')||h.startsWith('tel:')||h.startsWith('#'))return;a.setAttribute('href',m(h));}},true);var of=window.fetch;if(of)window.fetch=function(i,n){{var t=typeof i==='string'?i:(i&&i.url?i.url:'');if(t&&t.indexOf('_rsc=')!==-1&&hardNavigate(t))return new Promise(function(){{}});if(typeof i==='string')i=m(i);else if(i&&i.url)i=new Request(m(i.url),i);return of.call(this,i,n);}};var ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(method,url){{if(typeof url==='string'&&url.indexOf('_rsc=')!==-1&&hardNavigate(url))return;return ox.call(this,method,m(url),...Array.prototype.slice.call(arguments,2));}};}})();</script>"
        );
        rewritten = rewritten.replacen("<head>", &base_and_shim, 1);
    }
    Ok(rewritten.into_bytes())
}

pub struct AppError(anyhow::Error);

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.0.to_string(),
        }));
        (StatusCode::BAD_GATEWAY, body).into_response()
    }
}
