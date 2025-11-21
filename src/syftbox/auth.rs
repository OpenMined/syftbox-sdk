use crate::syftbox::config::SyftBoxConfigFile;
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

const DEFAULT_SERVER_URL: &str = "https://syftbox.net";
const DEFAULT_CLIENT_URL: &str = "http://localhost:7938";

#[derive(Debug, Clone, Serialize)]
pub struct OtpRequestPayload {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OtpVerifyPayload {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OtpTokens {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct OtpVerifyOutcome {
    pub tokens: OtpTokens,
    pub resolved_config: SyftBoxConfigFile,
}

#[derive(Debug, Deserialize)]
struct ApiErrorMessage {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

pub async fn request_otp(
    email: impl AsRef<str>,
    name: Option<String>,
    server_url: Option<String>,
    client: Option<Client>,
) -> Result<()> {
    let email = email.as_ref().trim();
    if email.is_empty() {
        return Err(anyhow!("Email address is required for OTP request"));
    }

    let server = resolve_server(server_url.as_deref());
    let request_url = join_url(&server, "/auth/otp/request");
    let payload = OtpRequestPayload {
        email: email.to_string(),
        name,
    };

    let client = client.unwrap_or_default();
    let response = client
        .post(&request_url)
        .header("User-Agent", "syftbox-sdk")
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("Failed to contact {}", request_url))?;

    if !response.status().is_success() {
        return Err(build_api_error("OTP request", response).await);
    }

    Ok(())
}

pub async fn verify_otp(
    code: impl AsRef<str>,
    email: impl AsRef<str>,
    server_url: Option<String>,
    data_dir: Option<PathBuf>,
    client_url: Option<String>,
    client: Option<Client>,
) -> Result<OtpVerifyOutcome> {
    let code = code.as_ref().trim();
    if code.is_empty() {
        return Err(anyhow!("OTP code cannot be empty"));
    }

    let email = email.as_ref().trim();
    if email.is_empty() {
        return Err(anyhow!("Email address is required for OTP verification"));
    }

    let server = resolve_server(server_url.as_deref());
    let verify_url = join_url(&server, "/auth/otp/verify");
    let payload = OtpVerifyPayload {
        email: email.to_string(),
        code: code.to_string(),
    };

    let client = client.unwrap_or_default();
    let response = client
        .post(&verify_url)
        .header("User-Agent", "syftbox-sdk")
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("Failed to contact {}", verify_url))?;

    if !response.status().is_success() {
        return Err(build_api_error("OTP verification", response).await);
    }

    let tokens: OtpTokens = response
        .json()
        .await
        .context("Failed to parse OTP verification response")?;

    let data_dir = resolve_data_dir(data_dir)?;
    let client_url = resolve_client_url(client_url.as_deref());

    let resolved_config = SyftBoxConfigFile {
        data_dir: data_dir.to_string_lossy().to_string(),
        email: email.to_string(),
        server_url: server.clone(),
        client_url: Some(client_url),
        client_token: Some(tokens.access_token.clone()),
        refresh_token: Some(tokens.refresh_token.clone()),
    };

    Ok(OtpVerifyOutcome {
        tokens,
        resolved_config,
    })
}

async fn build_api_error(action: &str, response: reqwest::Response) -> anyhow::Error {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if let Ok(parsed) = serde_json::from_str::<ApiErrorMessage>(&body) {
        let message = parsed
            .message
            .or(parsed.error)
            .or(parsed.detail)
            .unwrap_or(body);
        anyhow!("{} failed ({}): {}", action, status, message)
    } else if body.is_empty() {
        anyhow!("{} failed ({})", action, status)
    } else {
        anyhow!("{} failed ({}): {}", action, status, body)
    }
}

fn join_url(base: &str, path: &str) -> String {
    let clean_base = base.trim_end_matches('/');
    let clean_path = path.trim_start_matches('/');
    format!("{}/{}", clean_base, clean_path)
}

fn resolve_server(server: Option<&str>) -> String {
    if let Some(server) = server {
        if !server.trim().is_empty() {
            return server.trim().trim_end_matches('/').to_string();
        }
    }

    if let Ok(env_server) = env::var("SYFTBOX_SERVER_URL") {
        if !env_server.trim().is_empty() {
            return env_server.trim().trim_end_matches('/').to_string();
        }
    }

    DEFAULT_SERVER_URL.to_string()
}

fn resolve_client_url(client_url: Option<&str>) -> String {
    if let Some(url) = client_url {
        if !url.trim().is_empty() {
            return url.trim().to_string();
        }
    }

    if let Ok(env_url) = env::var("SYFTBOX_CLIENT_URL") {
        if !env_url.trim().is_empty() {
            return env_url.trim().to_string();
        }
    }

    DEFAULT_CLIENT_URL.to_string()
}

fn resolve_data_dir(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        if !dir.as_os_str().is_empty() {
            return Ok(dir);
        }
    }

    if let Ok(env_dir) = env::var("SYFTBOX_DATA_DIR") {
        if !env_dir.trim().is_empty() {
            return Ok(PathBuf::from(env_dir.trim()));
        }
    }

    dirs::home_dir()
        .map(|home| home.join("SyftBox"))
        .ok_or_else(|| anyhow!("Could not determine default SyftBox data directory"))
}
