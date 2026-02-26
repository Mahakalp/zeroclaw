//! WebSocket agent chat handler.
//!
//! Protocol:
//! ```text
//! Client -> Server: {"type":"message","content":"Hello"}
//! Server -> Client: {"type":"chunk","content":"Hi! "}
//! Server -> Client: {"type":"tool_call","name":"shell","args":{...}}
//! Server -> Client: {"type":"tool_result","name":"shell","output":"..."}
//! Server -> Client: {"type":"done","full_response":"..."}
//! ```

use super::AppState;
use crate::auth::cloudflare_access::{
    extract_cloudflare_jwt, validate_cloudflare_token, CloudflareAuthResult,
};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::HeaderMap,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

/// Check if request is authenticated via Cloudflare Access
fn is_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    // If Cloudflare Access is not enabled, allow all
    if !state.cf_access_enabled {
        return true;
    }

    // Cloudflare Access JWT authentication required
    if let Some(ref public_key) = state.cf_access_public_key {
        if let Some(jwt) = extract_cloudflare_jwt(headers) {
            match validate_cloudflare_token(&jwt, public_key, state.cf_access_aud_tag.as_deref()) {
                CloudflareAuthResult::Authenticated(_) => return true,
                _ => {}
            }
        }
        // If cf_access_enabled but no valid JWT, reject
        return false;
    }

    true
}

/// GET /ws/chat — WebSocket upgrade for agent chat
pub async fn handle_ws_chat(
    State(state): State<AppState>,
    Query(params): Query<WsQuery>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Auth check
    if !is_authenticated(&state, &headers) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized — valid Cloudflare Access JWT required",
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state))
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => continue,
        };

        // Parse incoming message
        let parsed: serde_json::Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => {
                let err = serde_json::json!({"type": "error", "message": "Invalid JSON"});
                let _ = sender.send(Message::Text(err.to_string().into())).await;
                continue;
            }
        };

        let msg_type = parsed["type"].as_str().unwrap_or("");
        if msg_type != "message" {
            continue;
        }

        let content = parsed["content"].as_str().unwrap_or("").to_string();
        if content.is_empty() {
            continue;
        }

        match super::run_gateway_chat_with_tools(&state, &content).await {
            Ok(response) => {
                let done = serde_json::json!({
                    "type": "done",
                    "full_response": response,
                });
                if sender
                    .send(Message::Text(done.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                let message = crate::providers::sanitize_api_error(&e.to_string());
                let err = serde_json::json!({
                    "type": "error",
                    "message": message,
                });
                if sender
                    .send(Message::Text(err.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}
