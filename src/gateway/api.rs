//! REST API handlers for the web dashboard.
//!
//! All `/api/*` routes require Cloudflare Access JWT validation.

use super::AppState;
use crate::auth::cloudflare_access::{
    extract_cloudflare_jwt, validate_cloudflare_token, CloudflareAuthResult,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use serde::Deserialize;

/// Verify request uses Cloudflare Access JWT. Returns error response if unauthorized.
fn require_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (axum::http::StatusCode, Json<serde_json::Value>)> {
    // If Cloudflare Access is not enabled, allow all requests
    if !state.cf_access_enabled {
        return Ok(());
    }

    // Cloudflare Access JWT authentication required
    if let Some(ref public_key) = state.cf_access_public_key {
        if let Some(jwt) = extract_cloudflare_jwt(headers) {
            match validate_cloudflare_token(&jwt, public_key, state.cf_access_aud_tag.as_deref()) {
                CloudflareAuthResult::Authenticated(_claims) => {
                    tracing::debug!("Authenticated via Cloudflare Access JWT");
                    return Ok(());
                }
                CloudflareAuthResult::Invalid(e) => {
                    tracing::warn!("Cloudflare JWT validation failed: {}", e);
                }
                CloudflareAuthResult::NotPresent => {}
            }
        } else {
            let cf_header = headers
                .get("cf-access-jwt-assertion")
                .or_else(|| headers.get("Cf-Access-Jwt-Assertion"))
                .is_some();
            let cf_client_token = headers
                .get("cf-access-client-token")
                .or_else(|| headers.get("CF-Access-Client-Token"))
                .is_some();
            let cookie_present = headers.get(axum::http::header::COOKIE).is_some();
            tracing::warn!(
                "Cloudflare JWT missing from request headers: cf-access-jwt-assertion={}, cf-access-client-token={}, cookie_header_present={}",
                cf_header,
                cf_client_token,
                cookie_present
            );
        }
        // If cf_access_enabled but no valid JWT, reject
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Unauthorized — valid Cloudflare Access JWT required"
            })),
        ));
    }

    Ok(())
}

// ── Query parameters ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct MemoryQuery {
    pub query: Option<String>,
    pub category: Option<String>,
}

#[derive(Deserialize)]
pub struct MemoryStoreBody {
    pub key: String,
    pub content: String,
    pub category: Option<String>,
}

#[derive(Deserialize)]
pub struct CronAddBody {
    pub name: Option<String>,
    pub schedule: String,
    pub command: String,
}

#[derive(Deserialize)]
pub struct ChannelToggleBody {
    pub enabled: bool,
}

// ── Handlers ────────────────────────────────────────────────────

/// GET /api/public/status — public system status (no auth required)
pub async fn handle_api_public_status(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config.lock().clone();
    let health = crate::health::snapshot();
    let health_json = serde_json::json!({
        "status": "ok",
        "updated_at": health.updated_at,
        "uptime_seconds": health.uptime_seconds,
        "components": health.components,
    });

    let body = serde_json::json!({
        "status": "ok",
        "provider": config.default_provider,
        "model": state.model,
        "uptime_seconds": health.uptime_seconds,
        "gateway_port": config.gateway.port,
        "cf_access_enabled": state.cf_access_enabled,
        "health": health_json,
    });

    Json(body)
}

/// GET /api/status — system status overview
pub async fn handle_api_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    let health = crate::health::snapshot();

    let mut channels = serde_json::Map::new();

    for (channel, present) in config.channels_config.channels() {
        channels.insert(channel.name().to_string(), serde_json::Value::Bool(present));
    }

    let health = crate::health::snapshot();
    let health_json = serde_json::json!({
        "status": "ok",
        "updated_at": health.updated_at,
        "uptime_seconds": health.uptime_seconds,
        "components": health.components,
    });

    let body = serde_json::json!({
        "status": "ok",
        "provider": config.default_provider,
        "model": state.model,
        "temperature": state.temperature,
        "uptime_seconds": health.uptime_seconds,
        "gateway_port": config.gateway.port,
        "locale": "en",
        "memory_backend": state.mem.name(),
        "cf_access_enabled": state.cf_access_enabled,
        "channels": channels,
        "health": health_json,
    });

    Json(body).into_response()
}

/// PUT /api/channels/:name — toggle a channel on/off
pub async fn handle_api_channel_toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<ChannelToggleBody>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let mut config = state.config.lock().clone();
    let channel_name = name.to_lowercase();

    let result = match channel_name.as_str() {
        "telegram" => {
            if body.enabled && config.channels_config.telegram.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Telegram not configured. Add bot_token in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.telegram = None;
            }
            Ok(())
        }
        "discord" => {
            if body.enabled && config.channels_config.discord.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Discord not configured. Add bot_token in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.discord = None;
            }
            Ok(())
        }
        "slack" => {
            if body.enabled && config.channels_config.slack.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Slack not configured. Add bot_token in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.slack = None;
            }
            Ok(())
        }
        "whatsapp" => {
            if body.enabled && config.channels_config.whatsapp.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "WhatsApp not configured. Add credentials in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.whatsapp = None;
            }
            Ok(())
        }
        "signal" => {
            if body.enabled && config.channels_config.signal.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Signal not configured. Add credentials in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.signal = None;
            }
            Ok(())
        }
        "matrix" => {
            if body.enabled && config.channels_config.matrix.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Matrix not configured. Add credentials in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.matrix = None;
            }
            Ok(())
        }
        "imessage" => {
            if body.enabled && config.channels_config.imessage.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "iMessage not configured. Add configuration in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.imessage = None;
            }
            Ok(())
        }
        "email" => {
            if body.enabled && config.channels_config.email.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Email not configured. Add SMTP credentials in config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.email = None;
            }
            Ok(())
        }
        "webhook" => {
            if body.enabled && config.channels_config.webhook.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Webhook not configured. Add webhook config first."})),
                )
                    .into_response();
            }
            if !body.enabled {
                config.channels_config.webhook = None;
            }
            Ok(())
        }
        "cli" => {
            config.channels_config.cli = body.enabled;
            Ok(())
        }
        _ => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Unknown channel: {name}")})),
        )),
    };

    if let Err(e) = result {
        return e.into_response();
    }

    // Save and update config
    if let Err(e) = config.save().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save config: {e}")})),
        )
            .into_response();
    }

    *state.config.lock() = config;

    Json(serde_json::json!({"status": "ok"})).into_response()
}

/// GET /api/config — current config (api_key masked)
pub async fn handle_api_config_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();

    // Serialize to TOML, then mask sensitive fields
    let toml_str = match toml::to_string_pretty(&config) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to serialize config: {e}")})),
            )
                .into_response();
        }
    };

    // Mask api_key in the TOML output
    let masked = mask_sensitive_fields(&toml_str);

    Json(serde_json::json!({
        "format": "toml",
        "content": masked,
    }))
    .into_response()
}

/// PUT /api/config — update config from TOML body
pub async fn handle_api_config_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    // Parse the incoming TOML
    let new_config: crate::config::Config = match toml::from_str(&body) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid TOML: {e}")})),
            )
                .into_response();
        }
    };

    // Preserve config_path and secrets from the current in-memory config
    let (config_path, mut secrets) = {
        let current_config = state.config.lock();
        (
            current_config.config_path.clone(),
            current_config.secrets.clone(),
        )
    };

    // If encryption was enabled but there's no secret key file, disable encryption
    if secrets.encrypt {
        let secret_key_path = config_path.parent().map(|p| p.join(".secret_key"));
        if let Some(key_path) = secret_key_path {
            if !key_path.exists() {
                secrets.encrypt = false;
            }
        }
    }

    // Save to disk (config_path and secrets must be preserved)
    let mut config_to_save = new_config;
    config_to_save.config_path = config_path;
    config_to_save.secrets = secrets;

    if let Err(e) = config_to_save.save().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save config: {e}")})),
        )
            .into_response();
    }

    // Update in-memory config
    *state.config.lock() = config_to_save;

    Json(serde_json::json!({"status": "ok"})).into_response()
}

/// GET /api/config/schema — returns JSON Schema for config
pub async fn handle_api_config_schema(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let schema = schemars::schema_for!(crate::config::Config);
    let schema_json = serde_json::to_value(&schema).expect("Config has valid JsonSchema");

    Json(serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "ZeroClawConfig",
        "config": schema_json,
    }))
    .into_response()
}

/// GET /api/tools — list registered tool specs
pub async fn handle_api_tools(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    let disabled_tools = &config.autonomy.disabled_tools;

    let tools: Vec<serde_json::Value> = state
        .tools_registry
        .iter()
        .map(|spec| {
            let enabled = !disabled_tools.contains(&spec.name);
            serde_json::json!({
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
                "enabled": enabled,
            })
        })
        .collect();

    Json(serde_json::json!({"tools": tools})).into_response()
}

/// PUT /api/tools/:name — toggle a tool on/off
pub async fn handle_api_tool_toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<ChannelToggleBody>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let mut config = state.config.lock().clone();
    let tool_name = name.clone();

    if body.enabled {
        config.autonomy.disabled_tools.retain(|t| t != &tool_name);
    } else {
        if !config.autonomy.disabled_tools.contains(&tool_name) {
            config.autonomy.disabled_tools.push(tool_name);
        }
    }

    if let Err(e) = config.save().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save config: {}", e)})),
        )
            .into_response();
    }

    *state.config.lock() = config;

    Json(serde_json::json!({"status": "ok"})).into_response()
}

/// GET /api/cron — list cron jobs
pub async fn handle_api_cron_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    match crate::cron::list_jobs(&config) {
        Ok(jobs) => {
            let jobs_json: Vec<serde_json::Value> = jobs
                .iter()
                .map(|job| {
                    serde_json::json!({
                        "id": job.id,
                        "name": job.name,
                        "command": job.command,
                        "next_run": job.next_run.to_rfc3339(),
                        "last_run": job.last_run.map(|t| t.to_rfc3339()),
                        "last_status": job.last_status,
                        "enabled": job.enabled,
                    })
                })
                .collect();
            Json(serde_json::json!({"jobs": jobs_json})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to list cron jobs: {e}")})),
        )
            .into_response(),
    }
}

/// POST /api/cron — add a new cron job
pub async fn handle_api_cron_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CronAddBody>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    let schedule = crate::cron::Schedule::Cron {
        expr: body.schedule,
        tz: None,
    };

    match crate::cron::add_shell_job(&config, body.name, schedule, &body.command) {
        Ok(job) => Json(serde_json::json!({
            "status": "ok",
            "job": {
                "id": job.id,
                "name": job.name,
                "command": job.command,
                "enabled": job.enabled,
            }
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to add cron job: {e}")})),
        )
            .into_response(),
    }
}

/// DELETE /api/cron/:id — remove a cron job
pub async fn handle_api_cron_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    match crate::cron::remove_job(&config, &id) {
        Ok(()) => Json(serde_json::json!({"status": "ok"})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to remove cron job: {e}")})),
        )
            .into_response(),
    }
}

/// GET /api/integrations — list all integrations with status
pub async fn handle_api_integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    let entries = crate::integrations::registry::all_integrations();

    fn is_channel_enabled(name: &str, config: &crate::config::Config) -> Option<bool> {
        match name.to_lowercase().as_str() {
            "telegram" => Some(config.channels_config.telegram.is_some()),
            "discord" => Some(config.channels_config.discord.is_some()),
            "slack" => Some(config.channels_config.slack.is_some()),
            "whatsapp" => Some(config.channels_config.whatsapp.is_some()),
            "signal" => Some(config.channels_config.signal.is_some()),
            "matrix" => Some(config.channels_config.matrix.is_some()),
            "imessage" => Some(config.channels_config.imessage.is_some()),
            "email" => Some(config.channels_config.email.is_some()),
            "webhook" => Some(config.channels_config.webhook.is_some()),
            "cli" => Some(config.channels_config.cli),
            "dingtalk" => Some(config.channels_config.dingtalk.is_some()),
            "qq" => Some(config.channels_config.qq.is_some()),
            "lark" | "feishu" => Some(config.channels_config.feishu.is_some()),
            "nostr" => Some(config.channels_config.nostr.is_some()),
            "nextcloud talk" => Some(config.channels_config.nextcloud_talk.is_some()),
            "linq" => Some(config.channels_config.linq.is_some()),
            "mattermost" => Some(config.channels_config.mattermost.is_some()),
            "irc" => Some(config.channels_config.irc.is_some()),
            "clawdtalk" => Some(config.channels_config.clawdtalk.is_some()),
            _ => None,
        }
    }

    let integrations: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            let status = (entry.status_fn)(&config);
            let enabled = is_channel_enabled(&entry.name, &config);
            let configured = enabled.is_some();
            let mut obj = serde_json::json!({
                "name": entry.name,
                "description": entry.description,
                "category": entry.category,
                "status": status,
                "configured": configured,
            });
            if let Some(enabled_val) = enabled {
                obj["enabled"] = serde_json::json!(enabled_val);
            }
            obj
        })
        .collect();

    Json(serde_json::json!({"integrations": integrations})).into_response()
}

/// POST /api/doctor — run diagnostics
pub async fn handle_api_doctor(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let config = state.config.lock().clone();
    let results = crate::doctor::diagnose(&config);

    let ok_count = results
        .iter()
        .filter(|r| r.severity == crate::doctor::Severity::Ok)
        .count();
    let warn_count = results
        .iter()
        .filter(|r| r.severity == crate::doctor::Severity::Warn)
        .count();
    let error_count = results
        .iter()
        .filter(|r| r.severity == crate::doctor::Severity::Error)
        .count();

    Json(serde_json::json!({
        "results": results,
        "summary": {
            "ok": ok_count,
            "warnings": warn_count,
            "errors": error_count,
        }
    }))
    .into_response()
}

/// GET /api/memory — list or search memory entries
pub async fn handle_api_memory_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<MemoryQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(ref query) = params.query {
        // Search mode
        match state.mem.recall(query, 50, None).await {
            Ok(entries) => Json(serde_json::json!({"entries": entries})).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Memory recall failed: {e}")})),
            )
                .into_response(),
        }
    } else {
        // List mode
        let category = params.category.as_deref().map(|cat| match cat {
            "core" => crate::memory::MemoryCategory::Core,
            "daily" => crate::memory::MemoryCategory::Daily,
            "conversation" => crate::memory::MemoryCategory::Conversation,
            other => crate::memory::MemoryCategory::Custom(other.to_string()),
        });

        match state.mem.list(category.as_ref(), None).await {
            Ok(entries) => Json(serde_json::json!({"entries": entries})).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Memory list failed: {e}")})),
            )
                .into_response(),
        }
    }
}

/// POST /api/memory — store a memory entry
pub async fn handle_api_memory_store(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MemoryStoreBody>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let category = body
        .category
        .as_deref()
        .map(|cat| match cat {
            "core" => crate::memory::MemoryCategory::Core,
            "daily" => crate::memory::MemoryCategory::Daily,
            "conversation" => crate::memory::MemoryCategory::Conversation,
            other => crate::memory::MemoryCategory::Custom(other.to_string()),
        })
        .unwrap_or(crate::memory::MemoryCategory::Core);

    match state
        .mem
        .store(&body.key, &body.content, category, None)
        .await
    {
        Ok(()) => Json(serde_json::json!({"status": "ok"})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Memory store failed: {e}")})),
        )
            .into_response(),
    }
}

/// DELETE /api/memory/:key — delete a memory entry
pub async fn handle_api_memory_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    match state.mem.forget(&key).await {
        Ok(deleted) => {
            Json(serde_json::json!({"status": "ok", "deleted": deleted})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Memory forget failed: {e}")})),
        )
            .into_response(),
    }
}

/// GET /api/cost — cost summary
pub async fn handle_api_cost(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(ref tracker) = state.cost_tracker {
        match tracker.get_summary() {
            Ok(summary) => Json(serde_json::json!({"cost": summary})).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Cost summary failed: {e}")})),
            )
                .into_response(),
        }
    } else {
        Json(serde_json::json!({
            "cost": {
                "session_cost_usd": 0.0,
                "daily_cost_usd": 0.0,
                "monthly_cost_usd": 0.0,
                "total_tokens": 0,
                "request_count": 0,
                "by_model": {},
            }
        }))
        .into_response()
    }
}

/// GET /api/cli-tools — discovered CLI tools
pub async fn handle_api_cli_tools(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let tools = crate::tools::cli_discovery::discover_cli_tools(&[], &[]);

    Json(serde_json::json!({"cli_tools": tools})).into_response()
}

/// GET /api/health — component health snapshot
pub async fn handle_api_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let snapshot = crate::health::snapshot();
    Json(serde_json::json!({"health": snapshot})).into_response()
}

/// GET /api/providers/:provider/models — list available models for a provider
pub async fn handle_api_provider_models(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let models = match provider.to_lowercase().as_str() {
        "google" | "gemini" => vec![
            "gemini-2.0-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-2.5-pro-preview",
            "gemini-2.0-flash-lite",
        ],
        "openai" => vec!["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o1-mini"],
        "anthropic" => vec![
            "claude-sonnet-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
        ],
        "minimax" => vec!["MiniMax-M2.5"],
        "ollama" => vec!["llama3", "mistral", "codellama", "qwen2.5"],
        _ => vec![],
    };

    Json(serde_json::json!({ "models": models })).into_response()
}

// ── Helpers ─────────────────────────────────────────────────────

fn mask_sensitive_fields(toml_str: &str) -> String {
    let mut output = String::with_capacity(toml_str.len());
    for line in toml_str.lines() {
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let should_mask = matches!(
                key,
                "api_key"
                    | "bot_token"
                    | "access_token"
                    | "secret"
                    | "app_secret"
                    | "signing_secret"
            );

            if should_mask {
                output.push_str(&line[..eq_pos + 1]);
                output.push_str(" \"***MASKED***\"");
            } else {
                output.push_str(line);
            }
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

// ==================== Profiles API ====================

#[derive(Deserialize)]
pub struct ProfileCreate {
    name: String,
    description: Option<String>,
}

pub async fn handle_api_profiles_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        match db.get_profiles() {
            Ok(profiles) => Json(profiles).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        Json::<Vec<crate::config::db::Profile>>(vec![]).into_response()
    }
}

pub async fn handle_api_profiles_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ProfileCreate>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        let profile = crate::config::db::Profile {
            id: uuid::Uuid::new_v4().to_string(),
            name: payload.name,
            description: payload.description,
            is_active: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };

        match db.create_profile(&profile) {
            Ok(_) => Json(profile).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

pub async fn handle_api_profiles_activate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        match db.set_active_profile(&id) {
            Ok(_) => Json(serde_json::json!({ "status": "ok" })).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

pub async fn handle_api_profiles_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        match db.delete_profile(&id) {
            Ok(_) => Json(serde_json::json!({ "status": "ok" })).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

// ==================== Providers API ====================

#[derive(Deserialize)]
pub struct ProviderCreate {
    profile_id: String,
    name: String,
    api_key: Option<String>,
    api_url: Option<String>,
    default_model: Option<String>,
    is_enabled: Option<bool>,
    is_default: Option<bool>,
}

pub async fn handle_api_providers_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let profile_id = params.get("profile_id").cloned();

    if let Some(db) = &state.config_db {
        // Get active profile if no profile_id provided
        let pid: Option<String> = if let Some(ref pid) = profile_id {
            Some(pid.clone())
        } else {
            db.get_active_profile().ok().flatten().map(|p| p.id)
        };

        if let Some(profile_id) = pid {
            match db.get_providers(&profile_id) {
                Ok(providers) => Json(providers).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response(),
            }
        } else {
            Json::<Vec<crate::config::db::Provider>>(vec![]).into_response()
        }
    } else {
        Json::<Vec<crate::config::db::Provider>>(vec![]).into_response()
    }
}

pub async fn handle_api_providers_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ProviderCreate>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        // Use active profile if provided profile_id doesn't exist or is invalid
        let profile_id = if db.get_profile(&payload.profile_id).ok().flatten().is_some() {
            payload.profile_id.clone()
        } else {
            db.get_active_profile()
                .ok()
                .flatten()
                .map(|p| p.id)
                .unwrap_or_else(|| "default".to_string())
        };

        // Ensure default profile exists
        if db.get_profile(&profile_id).ok().flatten().is_none() {
            let default_profile = crate::config::db::Profile {
                id: "default".to_string(),
                name: "Default".to_string(),
                description: Some("Default profile".to_string()),
                is_active: true,
                created_at: chrono::Utc::now().to_rfc3339(),
                updated_at: chrono::Utc::now().to_rfc3339(),
            };
            let _ = db.create_profile(&default_profile);
        }

        let provider = crate::config::db::Provider {
            id: uuid::Uuid::new_v4().to_string(),
            profile_id,
            name: payload.name,
            api_key: payload.api_key,
            api_url: payload.api_url,
            default_model: payload.default_model,
            is_enabled: payload.is_enabled.unwrap_or(true),
            is_default: payload.is_default.unwrap_or(false),
            priority: 0,
            metadata: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };

        match db.create_provider(&provider) {
            Ok(_) => Json(provider).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

pub async fn handle_api_providers_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut payload): Json<ProviderCreate>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        // Get existing provider to preserve fields
        if let Ok(Some(existing)) = db.get_provider(&id) {
            payload.profile_id = existing.profile_id;

            let provider = crate::config::db::Provider {
                id,
                profile_id: payload.profile_id,
                name: payload.name,
                api_key: payload.api_key,
                api_url: payload.api_url,
                default_model: payload.default_model,
                is_enabled: payload.is_enabled.unwrap_or(existing.is_enabled),
                is_default: payload.is_default.unwrap_or(existing.is_default),
                priority: existing.priority,
                metadata: existing.metadata,
                created_at: existing.created_at,
                updated_at: chrono::Utc::now().to_rfc3339(),
            };

            match db.update_provider(&provider) {
                Ok(_) => Json(provider).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response(),
            }
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Provider not found" })),
            )
                .into_response()
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

pub async fn handle_api_providers_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        match db.delete_provider(&id) {
            Ok(_) => Json(serde_json::json!({ "status": "ok" })).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

// ==================== Channels API ====================

#[derive(Deserialize)]
pub struct ChannelCreate {
    profile_id: String,
    channel_type: String,
    config: String,
    is_enabled: Option<bool>,
}

pub async fn handle_api_channels_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let profile_id = params.get("profile_id").cloned();

    if let Some(db) = &state.config_db {
        let pid: Option<String> = if let Some(ref pid) = profile_id {
            Some(pid.clone())
        } else {
            db.get_active_profile().ok().flatten().map(|p| p.id)
        };

        if let Some(profile_id) = pid {
            match db.get_channels(&profile_id) {
                Ok(channels) => Json(channels).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response(),
            }
        } else {
            Json::<Vec<crate::config::db::Channel>>(vec![]).into_response()
        }
    } else {
        Json::<Vec<crate::config::db::Channel>>(vec![]).into_response()
    }
}

pub async fn handle_api_channels_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ChannelCreate>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        // Use active profile if provided profile_id doesn't exist
        let profile_id = if db.get_profile(&payload.profile_id).ok().flatten().is_some() {
            payload.profile_id.clone()
        } else {
            db.get_active_profile()
                .ok()
                .flatten()
                .map(|p| p.id)
                .unwrap_or_else(|| "default".to_string())
        };

        // Ensure default profile exists
        if db.get_profile(&profile_id).ok().flatten().is_none() {
            let default_profile = crate::config::db::Profile {
                id: "default".to_string(),
                name: "Default".to_string(),
                description: Some("Default profile".to_string()),
                is_active: true,
                created_at: chrono::Utc::now().to_rfc3339(),
                updated_at: chrono::Utc::now().to_rfc3339(),
            };
            let _ = db.create_profile(&default_profile);
        }

        let channel = crate::config::db::Channel {
            id: uuid::Uuid::new_v4().to_string(),
            profile_id,
            channel_type: payload.channel_type,
            config: payload.config,
            is_enabled: payload.is_enabled.unwrap_or(true),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };

        match db.create_channel(&channel) {
            Ok(_) => Json(channel).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

pub async fn handle_api_channels_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut payload): Json<ChannelCreate>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        if let Ok(Some(existing)) = db.get_channel(&id) {
            payload.profile_id = existing.profile_id;

            let channel = crate::config::db::Channel {
                id,
                profile_id: payload.profile_id,
                channel_type: payload.channel_type,
                config: payload.config,
                is_enabled: payload.is_enabled.unwrap_or(existing.is_enabled),
                created_at: existing.created_at,
                updated_at: chrono::Utc::now().to_rfc3339(),
            };

            match db.update_channel(&channel) {
                Ok(_) => Json(channel).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response(),
            }
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Channel not found" })),
            )
                .into_response()
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

pub async fn handle_api_channels_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    if let Some(db) = &state.config_db {
        match db.delete_channel(&id) {
            Ok(_) => Json(serde_json::json!({ "status": "ok" })).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Database not available" })),
        )
            .into_response()
    }
}

// ==================== Provider Schema API ====================

#[derive(serde::Serialize, Clone)]
pub struct ProviderSchemaField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: bool,
    pub hint: String,
    pub example: Option<String>,
}

#[derive(serde::Serialize, Clone)]
pub struct ProviderSchema {
    #[serde(rename = "type")]
    pub provider_type: String,
    pub name: String,
    pub description: String,
    pub fields: Vec<ProviderSchemaField>,
}

#[derive(serde::Serialize, Clone)]
pub struct ChannelSchemaField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: bool,
    pub hint: String,
    pub example: Option<String>,
}

#[derive(serde::Serialize, Clone)]
pub struct ChannelSchema {
    #[serde(rename = "type")]
    pub channel_type: String,
    pub name: String,
    pub description: String,
    pub fields: Vec<ChannelSchemaField>,
}

fn all_channel_schemas() -> Vec<ChannelSchema> {
    vec![
        ChannelSchema {
            channel_type: "cli".to_string(),
            name: "CLI".to_string(),
            description: "Command-line interface (always enabled)".to_string(),
            fields: vec![],
        },
        ChannelSchema {
            channel_type: "telegram".to_string(),
            name: "Telegram".to_string(),
            description: "Connect your Telegram bot".to_string(),
            fields: vec![
                ChannelSchemaField {
                    name: "bot_token".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Get from @BotFather on Telegram".to_string(),
                    example: Some("123456:ABC-DEF1234ghIkl-zyx57W2vT6EH11".to_string()),
                },
                ChannelSchemaField {
                    name: "allowed_users".to_string(),
                    field_type: "array".to_string(),
                    required: false,
                    hint: "User IDs that can interact with the bot".to_string(),
                    example: Some("[\"123456789\"]".to_string()),
                },
            ],
        },
        ChannelSchema {
            channel_type: "discord".to_string(),
            name: "Discord".to_string(),
            description: "Connect your Discord bot".to_string(),
            fields: vec![ChannelSchemaField {
                name: "bot_token".to_string(),
                field_type: "string".to_string(),
                required: true,
                hint: "Your Discord bot token".to_string(),
                example: Some("MTEw...".to_string()),
            }],
        },
        ChannelSchema {
            channel_type: "slack".to_string(),
            name: "Slack".to_string(),
            description: "Connect your Slack app".to_string(),
            fields: vec![ChannelSchemaField {
                name: "bot_token".to_string(),
                field_type: "string".to_string(),
                required: true,
                hint: "Your Slack bot token (xoxb-...)".to_string(),
                example: Some("xoxb-...".to_string()),
            }],
        },
        ChannelSchema {
            channel_type: "webhook".to_string(),
            name: "Webhook".to_string(),
            description: "Receive messages via HTTP webhook".to_string(),
            fields: vec![ChannelSchemaField {
                name: "port".to_string(),
                field_type: "number".to_string(),
                required: true,
                hint: "Port number for the webhook server".to_string(),
                example: Some("8080".to_string()),
            }],
        },
        ChannelSchema {
            channel_type: "matrix".to_string(),
            name: "Matrix".to_string(),
            description: "Connect to Matrix protocol".to_string(),
            fields: vec![
                ChannelSchemaField {
                    name: "homeserver".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Matrix homeserver URL".to_string(),
                    example: Some("https://matrix.org".to_string()),
                },
                ChannelSchemaField {
                    name: "access_token".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Matrix access token".to_string(),
                    example: Some("syt_...".to_string()),
                },
                ChannelSchemaField {
                    name: "room_id".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Room ID to join".to_string(),
                    example: Some("!room:matrix.org".to_string()),
                },
            ],
        },
        ChannelSchema {
            channel_type: "irc".to_string(),
            name: "IRC".to_string(),
            description: "Connect to IRC servers".to_string(),
            fields: vec![
                ChannelSchemaField {
                    name: "server".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "IRC server hostname".to_string(),
                    example: Some("irc.libera.chat".to_string()),
                },
                ChannelSchemaField {
                    name: "nickname".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Nickname to use".to_string(),
                    example: Some("ZeroClawBot".to_string()),
                },
            ],
        },
    ]
}

fn all_provider_schemas() -> Vec<ProviderSchema> {
    vec![
        ProviderSchema {
            provider_type: "openai".to_string(),
            name: "OpenAI".to_string(),
            description: "OpenAI API for GPT models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your OpenAI API key from platform.openai.com".to_string(),
                    example: Some("sk-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.openai.com/v1)".to_string(),
                    example: Some("https://api.openai.com/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., gpt-4o, gpt-4o-mini, o1)".to_string(),
                    example: Some("gpt-4o".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "anthropic".to_string(),
            name: "Anthropic".to_string(),
            description: "Anthropic API for Claude models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Anthropic API key from console.anthropic.com".to_string(),
                    example: Some("sk-ant-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.anthropic.com)".to_string(),
                    example: Some("https://api.anthropic.com".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., claude-sonnet-4-20250514, claude-3-5-sonnet-20241022)".to_string(),
                    example: Some("claude-sonnet-4-20250514".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "google".to_string(),
            name: "Google".to_string(),
            description: "Google Gemini API".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Google AI API key from aistudio.google.com/app".to_string(),
                    example: Some("AIza...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional)".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., gemini-2.0-flash, gemini-1.5-pro)".to_string(),
                    example: Some("gemini-2.0-flash".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "ollama".to_string(),
            name: "Ollama".to_string(),
            description: "Local Ollama server".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "API key if Ollama is configured with authentication".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Ollama server URL (defaults to http://localhost:11434)".to_string(),
                    example: Some("http://localhost:11434".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., llama3, mistral, codellama)".to_string(),
                    example: Some("llama3".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "openrouter".to_string(),
            name: "OpenRouter".to_string(),
            description: "Unified API for 200+ LLMs".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your OpenRouter API key from openrouter.ai".to_string(),
                    example: Some("sk-or-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://openrouter.ai/api/v1)".to_string(),
                    example: Some("https://openrouter.ai/api/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., anthropic/claude-3-5-sonnet, openai/gpt-4o)".to_string(),
                    example: Some("anthropic/claude-3-5-sonnet-20241022".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "groq".to_string(),
            name: "Groq".to_string(),
            description: "Fast inference for open and proprietary models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Groq API key from console.groq.com".to_string(),
                    example: Some("gsk_...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.groq.com/openai)".to_string(),
                    example: Some("https://api.groq.com/openai".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., llama-3.1-70b-versatile, mixtral-8x7b-32768)".to_string(),
                    example: Some("llama-3.1-70b-versatile".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "mistral".to_string(),
            name: "Mistral".to_string(),
            description: "Mistral AI API".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Mistral API key from console.mistral.ai".to_string(),
                    example: Some("p-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.mistral.ai/v1)".to_string(),
                    example: Some("https://api.mistral.ai/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., mistral-large-latest, pixtral-large-latest)".to_string(),
                    example: Some("mistral-large-latest".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "deepseek".to_string(),
            name: "DeepSeek".to_string(),
            description: "DeepSeek API for coding and reasoning models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your DeepSeek API key from platform.deepseek.com".to_string(),
                    example: Some("sk-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.deepseek.com)".to_string(),
                    example: Some("https://api.deepseek.com".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., deepseek-chat, deepseek-coder)".to_string(),
                    example: Some("deepseek-chat".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "xai".to_string(),
            name: "xAI".to_string(),
            description: "xAI Grok API".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your xAI API key from console.x.ai".to_string(),
                    example: Some("xai-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.x.ai)".to_string(),
                    example: Some("https://api.x.ai".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., grok-2-1212, grok-2-vision-1212)".to_string(),
                    example: Some("grok-2-1212".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "together-ai".to_string(),
            name: "Together AI".to_string(),
            description: "Managed inference for open models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Together AI API key from api.together.xyz".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.together.xyz)".to_string(),
                    example: Some("https://api.together.xyz".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., meta-llama/Llama-3.1-70B-Instruct)".to_string(),
                    example: Some("meta-llama/Llama-3.1-70B-Instruct".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "fireworks".to_string(),
            name: "Fireworks AI".to_string(),
            description: "Fast inference for open and custom models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Fireworks AI API key from fireworks.ai".to_string(),
                    example: Some("fw_...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.fireworks.ai/inference/v1)".to_string(),
                    example: Some("https://api.fireworks.ai/inference/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., accounts/fireworks/models/llama-v3-70b-instruct)".to_string(),
                    example: Some("accounts/fireworks/models/llama-v3-70b-instruct".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "perplexity".to_string(),
            name: "Perplexity".to_string(),
            description: "AI-powered search and answering".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Perplexity API key from perplexity.ai".to_string(),
                    example: Some("pplx-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.perplexity.ai)".to_string(),
                    example: Some("https://api.perplexity.ai".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., llama-3.1-sonar-large-128k-online)".to_string(),
                    example: Some("llama-3.1-sonar-large-128k-online".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "cohere".to_string(),
            name: "Cohere".to_string(),
            description: "Cohere API for command and embed models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Cohere API key from dashboard.cohere.com".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.cohere.com/compatibility)".to_string(),
                    example: Some("https://api.cohere.com/compatibility".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., command-r-plus, command-r)".to_string(),
                    example: Some("command-r-plus".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "qwen".to_string(),
            name: "Qwen".to_string(),
            description: "Alibaba Qwen models via DashScope".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Qwen/DashScope API key from dashscope.console.aliyun.com".to_string(),
                    example: Some("sk-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to regional endpoint)".to_string(),
                    example: Some("https://dashscope.aliyuncs.com/compatible-mode/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., qwen-turbo, qwen-plus, qwen-max)".to_string(),
                    example: Some("qwen-turbo".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "glm".to_string(),
            name: "GLM".to_string(),
            description: "Zhipu/GLM models via bigmodel.cn".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Zhipu/GLM API key from open.bigmodel.cn".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to regional endpoint)".to_string(),
                    example: Some("https://open.bigmodel.cn/api/paas/v4".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., glm-4, glm-4-flash)".to_string(),
                    example: Some("glm-4-flash".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "moonshot".to_string(),
            name: "Moonshot".to_string(),
            description: "Moonshot Kimi API".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Moonshot/Kimi API key from platform.moonshot.ai".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to regional endpoint)".to_string(),
                    example: Some("https://api.moonshot.ai/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., moonshot-v1-8k, moonshot-v1-128k)".to_string(),
                    example: Some("moonshot-v1-8k".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "minimax".to_string(),
            name: "MiniMax".to_string(),
            description: "MiniMax API".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your MiniMax API key from platform.minimax.io".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to regional endpoint)".to_string(),
                    example: Some("https://api.minimax.io/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., MiniMax-M2.1, MiniMax-M2.5)".to_string(),
                    example: Some("MiniMax-M2.1".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "bedrock".to_string(),
            name: "AWS Bedrock".to_string(),
            description: "Amazon Bedrock managed models".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "AWS credentials (access key) - typically uses AWS credentials chain instead".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional)".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., anthropic.claude-3-sonnet-20240229-v1:0)".to_string(),
                    example: Some("anthropic.claude-3-sonnet-20240229-v1:0".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "telnyx".to_string(),
            name: "Telnyx".to_string(),
            description: "Telnyx AI API".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Telnyx API key from portal.telnyx.com".to_string(),
                    example: Some("KEY...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional)".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "copilot".to_string(),
            name: "GitHub Copilot".to_string(),
            description: "GitHub Copilot for CLI".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your GitHub Copilot token from github.com/settings/tokens".to_string(),
                    example: Some("ghp_...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional)".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "nvidia".to_string(),
            name: "NVIDIA NIM".to_string(),
            description: "NVIDIA NIM inference endpoints".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your NVIDIA API key from build.nvidia.com".to_string(),
                    example: Some("nvapi-...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://integrate.api.nvidia.com/v1)".to_string(),
                    example: Some("https://integrate.api.nvidia.com/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use (e.g., meta/llama-3.1-70b-instruct)".to_string(),
                    example: Some("meta/llama-3.1-70b-instruct".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "phi4".to_string(),
            name: "Phi-4".to_string(),
            description: "Microsoft Phi-4 via Azure AI Foundry".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Azure AI Foundry API key".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Azure endpoint URL (e.g., https://<resource>.services.ai.azure.com)".to_string(),
                    example: Some("https://example.services.ai.azure.com".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: Some("phi-4".to_string()),
                },
            ],
        },
        ProviderSchema {
            provider_type: "lmstudio".to_string(),
            name: "LM Studio".to_string(),
            description: "Local LM Studio server".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "API key if LM Studio is configured with authentication (defaults to lm-studio)".to_string(),
                    example: Some("lm-studio".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "LM Studio server URL (defaults to http://localhost:1234/v1)".to_string(),
                    example: Some("http://localhost:1234/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "llamacpp".to_string(),
            name: "llama.cpp".to_string(),
            description: "Local llama.cpp server".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "API key if server requires authentication (defaults to llama.cpp)".to_string(),
                    example: Some("llama.cpp".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "llama.cpp server URL (defaults to http://localhost:8080/v1)".to_string(),
                    example: Some("http://localhost:8080/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "sglang".to_string(),
            name: "SGLang".to_string(),
            description: "Local SGLang server".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "API key if server requires authentication".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "SGLang server URL (defaults to http://localhost:30000/v1)".to_string(),
                    example: Some("http://localhost:30000/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "vllm".to_string(),
            name: "vLLM".to_string(),
            description: "Local vLLM server".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "API key if server requires authentication".to_string(),
                    example: None,
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "vLLM server URL (defaults to http://localhost:8000/v1)".to_string(),
                    example: Some("http://localhost:8000/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "vercel".to_string(),
            name: "Vercel AI Gateway".to_string(),
            description: "Vercel AI Gateway for model aggregation".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Vercel AI Gateway token".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://ai-gateway.vercel.sh/v1)".to_string(),
                    example: Some("https://ai-gateway.vercel.sh/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "cloudflare".to_string(),
            name: "Cloudflare AI Gateway".to_string(),
            description: "Cloudflare AI Gateway".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Cloudflare API token".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://gateway.ai.cloudflare.com/v1)".to_string(),
                    example: Some("https://gateway.ai.cloudflare.com/v1".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
        ProviderSchema {
            provider_type: "venice".to_string(),
            name: "Venice".to_string(),
            description: "Venice AI API".to_string(),
            fields: vec![
                ProviderSchemaField {
                    name: "api_key".to_string(),
                    field_type: "string".to_string(),
                    required: true,
                    hint: "Your Venice API key from venice.ai".to_string(),
                    example: Some("...".to_string()),
                },
                ProviderSchemaField {
                    name: "api_url".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Custom API endpoint (optional, defaults to https://api.venice.ai)".to_string(),
                    example: Some("https://api.venice.ai".to_string()),
                },
                ProviderSchemaField {
                    name: "default_model".to_string(),
                    field_type: "string".to_string(),
                    required: false,
                    hint: "Default model to use".to_string(),
                    example: None,
                },
            ],
        },
    ]
}

pub async fn handle_api_schema_providers_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let schemas = all_provider_schemas();
    Json(serde_json::json!({ "providers": schemas })).into_response()
}

pub async fn handle_api_schema_provider_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider_type): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let schemas = all_provider_schemas();
    let provider_type_lower = provider_type.to_lowercase();

    if let Some(schema) = schemas
        .into_iter()
        .find(|s| s.provider_type == provider_type_lower)
    {
        Json(schema).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": format!("Unknown provider type: {}", provider_type) }),
            ),
        )
            .into_response()
    }
}

pub async fn handle_api_schema_channels_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let schemas = all_channel_schemas();
    Json(serde_json::json!({ "channels": schemas })).into_response()
}

pub async fn handle_api_schema_channel_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_type): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers) {
        return e.into_response();
    }

    let schemas = all_channel_schemas();
    let channel_type_lower = channel_type.to_lowercase();

    if let Some(schema) = schemas
        .into_iter()
        .find(|s| s.channel_type == channel_type_lower)
    {
        Json(schema).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Unknown channel type: {}", channel_type) })),
        )
            .into_response()
    }
}
