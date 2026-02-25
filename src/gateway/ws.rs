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

/// Check if request is authenticated via Cloudflare Access or pairing token
fn is_authenticated(state: &AppState, headers: &HeaderMap, query_token: Option<&str>) -> bool {
    // If pairing not required, allow all
    if !state.pairing.require_pairing() {
        return true;
    }

    // Check Cloudflare Access JWT first (if enabled)
    if state.cf_access_enabled {
        if let Some(ref public_key) = state.cf_access_public_key {
            if let Some(jwt) = extract_cloudflare_jwt(headers) {
                match validate_cloudflare_token(&jwt, public_key) {
                    CloudflareAuthResult::Authenticated(_) => return true,
                    _ => {}
                }
            }
        }
    }

    // Fall back to bearer token / pairing
    let token = query_token.unwrap_or("");
    state.pairing.is_authenticated(token)
}

/// GET /ws/chat — WebSocket upgrade for agent chat
pub async fn handle_ws_chat(
    State(state): State<AppState>,
    Query(params): Query<WsQuery>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Auth via query param or Cloudflare Access JWT
    if !is_authenticated(&state, &headers, params.token.as_deref()) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "Unauthorized — provide ?token=<bearer_token>",
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

        // Parse history from frontend if provided
        let history: Vec<crate::providers::ChatMessage> =
            if let Some(history_arr) = parsed.get("history").and_then(|h| h.as_array()) {
                history_arr
                    .iter()
                    .filter_map(|m| {
                        let role = m.get("role")?.as_str()?;
                        let content = m.get("content")?.as_str()?;
                        match role {
                            "system" => Some(crate::providers::ChatMessage::system(content)),
                            "user" => Some(crate::providers::ChatMessage::user(content)),
                            "assistant" => Some(crate::providers::ChatMessage::assistant(content)),
                            _ => None,
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            };

        // Process message with the LLM provider
        let provider_label = state
            .config
            .lock()
            .default_provider
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Broadcast agent_start event
        let _ = state.event_tx.send(serde_json::json!({
            "type": "agent_start",
            "provider": provider_label,
            "model": state.model,
        }));

        // Build system prompt
        let system_prompt = {
            let config_guard = state.config.lock();
            crate::channels::build_system_prompt(
                &config_guard.workspace_dir,
                &state.model,
                &[],
                &[],
                Some(&config_guard.identity),
                None,
            )
        };

        // Build messages: system prompt + history + current message
        let mut messages = vec![crate::providers::ChatMessage::system(system_prompt)];
        messages.extend(history);
        messages.push(crate::providers::ChatMessage::user(&content));

        let multimodal_config = state.config.lock().multimodal.clone();
        let prepared =
            match crate::multimodal::prepare_messages_for_provider(&messages, &multimodal_config)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({
                        "type": "error",
                        "message": format!("Multimodal prep failed: {e}")
                    });
                    let _ = sender.send(Message::Text(err.to_string().into())).await;
                    continue;
                }
            };

        match state
            .provider
            .chat_with_history(&prepared.messages, &state.model, state.temperature)
            .await
        {
            Ok(response) => {
                // Send the full response as a done message
                let done = serde_json::json!({
                    "type": "done",
                    "full_response": response,
                });
                let _ = sender.send(Message::Text(done.to_string().into())).await;

                // Broadcast agent_end event
                let _ = state.event_tx.send(serde_json::json!({
                    "type": "agent_end",
                    "provider": provider_label,
                    "model": state.model,
                }));
            }
            Err(e) => {
                let sanitized = crate::providers::sanitize_api_error(&e.to_string());
                let err = serde_json::json!({
                    "type": "error",
                    "message": sanitized,
                });
                let _ = sender.send(Message::Text(err.to_string().into())).await;

                // Broadcast error event
                let _ = state.event_tx.send(serde_json::json!({
                    "type": "error",
                    "component": "ws_chat",
                    "message": sanitized,
                }));
            }
        }
    }
}
