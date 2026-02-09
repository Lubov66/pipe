// src/lib.rs

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};


// JWT Authentication structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Deserialize, Debug)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default)]
    pub csrf_token: Option<String>,
}

// Combined credentials structure that supports both legacy and JWT auth
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SavedCredentials {
    pub user_id: String,
    pub user_app_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_tokens: Option<AuthTokens>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional per-profile default API base URL (used when `--api` is not explicitly set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    /// Optional default S3 endpoint override (for presigning and AWS CLI hints).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_endpoint: Option<String>,
    /// Optional default S3 region override (for presigning).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_region: Option<String>,
    /// Optional default for presigning style (true = virtual-hosted-style, false = path-style).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_virtual_hosted: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(name = "pipe", version, about = "Interact with Pipe Network")]
pub struct Cli {
    #[arg(
        long,
        default_value = "https://us-west-01-firestarter.pipenetwork.com",
        global = true,
        help = "Base URL for the Pipe Network client API"
    )]
    pub api: String,

    #[arg(
        long,
        global = true,
        help = "Path to custom config file (default: ~/.pipe-cli.json)",
        env = "PIPE_CLI_CONFIG"
    )]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage local CLI configuration (stored in the config file)
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Check prepaid credits balance (USDC) and storage quota
    #[command(aliases = ["check-deposit", "credits"])]
    CreditsStatus {
        #[arg(long)]
        user_id: Option<String>,
    },

    /// Top up prepaid credits (USDC) (guided)
    ///
    /// This creates a top-up intent, prints a Solana Pay link, and optionally submits a tx signature.
    #[command(alias = "top-up")]
    Topup {
        /// USDC amount (e.g. 10.50)
        amount: String,

        /// Optional tx signature to auto-submit after paying
        #[arg(long)]
        tx_sig: Option<String>,

        /// Disable the interactive prompt for a tx signature
        #[arg(long)]
        no_prompt: bool,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Create a prepaid credits top-up intent (USDC)
    #[command(hide = true)]
    CreditsIntent {
        /// USDC amount (e.g. 10.50)
        amount: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Submit a prepaid credits payment transaction signature for verification
    #[command(hide = true)]
    CreditsSubmit {
        intent_id: String,
        tx_sig: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Cancel a pending prepaid credits top-up intent
    #[command(hide = true)]
    CreditsCancel {
        intent_id: String,

        #[arg(long)]
        user_id: Option<String>,
    },

    /// Legacy: submit a prepaid credits top-up payment (USDC)
    #[command(hide = true)]
    SyncDeposits {
        #[arg(long)]
        user_id: Option<String>,

        /// Optional intent ID (defaults to latest from credits status)
        #[arg(long)]
        intent_id: Option<String>,

        /// Transaction signature for USDC transfer
        #[arg(long)]
        tx_sig: Option<String>,
    },

    /// Generate a Solana-compatible Ed25519 keypair file
    WalletKeygen {
        /// Output path (default: ~/.config/pipe-cli/wallet.json)
        #[arg(long)]
        output: Option<String>,

        /// Overwrite existing keypair file
        #[arg(long)]
        force: bool,
    },

    /// Authenticate via Sign In With Solana (headless)
    WalletAuth {
        /// Path to keypair JSON file (default: ~/.config/pipe-cli/wallet.json)
        #[arg(long)]
        keypair: Option<String>,
    },

    /// Create a new S3 access key
    S3KeyCreate {
        /// Output as shell export statements
        #[arg(long)]
        env: bool,
    },

    /// List S3 access keys
    S3KeyList,

    /// Delete an S3 access key
    S3KeyDelete {
        /// The access_key_id to delete
        access_key_id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Show S3 endpoint and bucket info
    S3Info,

    /// One-command bootstrap: keygen + auth + S3 key creation
    Init {
        /// Path to keypair JSON file (default: ~/.config/pipe-cli/wallet.json)
        #[arg(long)]
        keypair: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Show local CLI configuration (from the config file)
    Show,

    /// Set the default API base URL for this config profile
    SetApi { url: String },

    /// Clear the saved default API base URL
    ClearApi,

    /// Set the default S3 endpoint (used for presign + AWS CLI hints)
    SetS3Endpoint { endpoint: String },

    /// Clear the saved S3 endpoint
    ClearS3Endpoint,

    /// Set the default S3 region (used for presign)
    SetS3Region { region: String },

    /// Clear the saved S3 region
    ClearS3Region,

    /// Set whether presigned URLs default to virtual-hosted-style
    SetS3VirtualHosted { enabled: bool },

    /// Clear the saved virtual-hosted-style default
    ClearS3VirtualHosted,
}

const USDC_DECIMALS_FACTOR: i64 = 1_000_000;

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsTierEstimate {
    pub tier_name: String,
    pub cost_per_gb_usdc: f64,
    pub available_gb: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsQuota {
    pub tier_estimates: Vec<CreditsTierEstimate>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsIntentStatus {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub detected_usdc_raw: i64,
    pub credited_usdc_raw: i64,
    pub usdc_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_usdc_ata: String,
    pub reference_pubkey: String,
    pub payment_tx_sig: Option<String>,
    pub last_checked_at: Option<String>,
    pub credited_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsStatusResponse {
    pub balance_usdc_raw: i64,
    pub balance_usdc: f64,
    pub total_deposited_usdc_raw: i64,
    pub total_spent_usdc_raw: i64,
    pub last_topup_at: Option<String>,
    pub quota: CreditsQuota,
    pub intent: Option<CreditsIntentStatus>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateCreditsIntentRequest {
    pub amount_usdc_raw: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsIntentResponse {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub requested_usdc: f64,
    pub usdc_mint: String,
    pub treasury_owner_pubkey: String,
    pub treasury_usdc_ata: String,
    pub reference_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitCreditsPaymentRequest {
    pub intent_id: String,
    pub tx_sig: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitCreditsPaymentResponse {
    pub intent_id: String,
    pub status: String,
    pub requested_usdc_raw: i64,
    pub detected_usdc_raw: i64,
    pub credited_usdc_raw: i64,
    pub balance_usdc_raw: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CancelCreditsIntentRequest {
    pub intent_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreditsCancelResponse {
    pub intent_id: String,
    pub status: String,
}

// --- SIWS (Sign In With Solana) types ---

#[derive(Serialize, Debug)]
pub struct SiwsChallengeRequest {
    pub wallet_public_key: String,
}

#[derive(Deserialize, Debug)]
pub struct SiwsChallengeResponse {
    pub nonce: String,
    pub message: String,
}

#[derive(Serialize, Debug)]
pub struct SiwsVerifyRequest {
    pub wallet_public_key: String,
    pub nonce: String,
    pub message: String,
    pub signature_b64: String,
}

#[derive(Deserialize, Debug)]
pub struct SiwsVerifyResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    #[serde(default = "default_expires_in")]
    pub expires_in: i64,
    #[serde(default)]
    pub csrf_token: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

fn default_expires_in() -> i64 {
    900 // 15 minutes
}

// --- S3 key management types ---

#[derive(Deserialize, Debug)]
pub struct S3KeyCreateResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub endpoint: String,
    pub region: String,
    pub bucket_name: String,
    pub name_prefix: String,
}

#[derive(Deserialize, Debug)]
pub struct S3KeyInfo {
    pub key_name: String,
    pub access_key_id: String,
    pub bucket_id: String,
    #[serde(default)]
    pub bucket_name: Option<String>,
    pub name_prefix: String,
    #[serde(default)]
    pub capabilities: String,
    pub created_at: String,
}

#[derive(Deserialize, Debug)]
pub struct S3KeyListResponse {
    pub keys: Vec<S3KeyInfo>,
}

#[derive(Deserialize, Debug)]
pub struct S3InfoResponse {
    pub endpoint: String,
    pub region: String,
}

#[derive(Deserialize, Debug)]
pub struct BucketInfoResponse {
    pub bucket_name: String,
    #[serde(default)]
    pub public_read: bool,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
}

fn usdc_raw_to_ui(raw: i64) -> f64 {
    raw as f64 / USDC_DECIMALS_FACTOR as f64
}

fn format_usdc_ui(amount: f64) -> String {
    let s = format!("{:.6}", amount);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn parse_usdc_ui_to_raw(input: &str) -> Result<i64> {
    let trimmed = input.trim().trim_start_matches('$');
    if trimmed.is_empty() {
        return Err(anyhow!("USDC amount is required"));
    }

    let (whole, frac) = match trimmed.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (trimmed, None),
    };

    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("Invalid USDC amount: {}", input));
    }
    let whole_i64: i64 = whole
        .parse()
        .map_err(|_| anyhow!("Invalid USDC amount: {}", input))?;

    let frac_raw: i64 = match frac {
        None => 0,
        Some(f) if f.is_empty() => 0,
        Some(f) => {
            if f.len() > 6 || !f.chars().all(|c| c.is_ascii_digit()) {
                return Err(anyhow!("Invalid USDC amount (max 6 decimals): {}", input));
            }
            let padded = format!("{:0<6}", f);
            padded
                .parse::<i64>()
                .map_err(|_| anyhow!("Invalid USDC amount: {}", input))?
        }
    };

    let whole_raw = whole_i64
        .checked_mul(USDC_DECIMALS_FACTOR)
        .ok_or_else(|| anyhow!("USDC amount too large: {}", input))?;
    whole_raw
        .checked_add(frac_raw)
        .ok_or_else(|| anyhow!("USDC amount too large: {}", input))
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn refresh_token_response_parses_csrf_token() {
        let json =
            r#"{"access_token":"a","token_type":"Bearer","expires_in":123,"csrf_token":"t"}"#;
        let resp: RefreshTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.csrf_token.as_deref(), Some("t"));
    }

    #[test]
    fn auth_tokens_parse_set_password_response_shape() {
        let json = r#"{"message":"ok","access_token":"a","refresh_token":"r","token_type":"Bearer","expires_in":900,"csrf_token":"c"}"#;
        let resp: AuthTokens = serde_json::from_str(json).unwrap();
        assert_eq!(resp.csrf_token.as_deref(), Some("c"));
    }

    #[test]
    fn clap_accepts_check_deposit_alias() {
        let cli = Cli::try_parse_from(["pipe", "check-deposit"]).unwrap();
        match cli.command {
            Commands::CreditsStatus { .. } => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn clap_accepts_credits_alias() {
        let cli = Cli::try_parse_from(["pipe", "credits"]).unwrap();
        match cli.command {
            Commands::CreditsStatus { .. } => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn clap_accepts_topup_and_top_up_alias() {
        let cli = Cli::try_parse_from(["pipe", "topup", "10"]).unwrap();
        match cli.command {
            Commands::Topup {
                amount,
                tx_sig,
                no_prompt,
                user_id,
            } => {
                assert_eq!(amount, "10");
                assert!(tx_sig.is_none());
                assert!(!no_prompt);
                assert!(user_id.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::try_parse_from(["pipe", "top-up", "10"]).unwrap();
        match cli.command {
            Commands::Topup { amount, .. } => assert_eq!(amount, "10"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn extracts_tx_sig_from_solscan_url() {
        assert_eq!(
            extract_solana_tx_sig("https://solscan.io/tx/ABC?cluster=mainnet"),
            "ABC"
        );
        assert_eq!(extract_solana_tx_sig("ABC"), "ABC");
        assert_eq!(extract_solana_tx_sig(""), "");
    }
}

fn format_spl_amount_raw(raw: i64, decimals: u32) -> String {
    if decimals == 0 {
        return raw.to_string();
    }

    let factor = match 10u64.checked_pow(decimals) {
        Some(v) => v,
        None => return raw.to_string(),
    };

    let negative = raw < 0;
    let abs_u64 = match raw.checked_abs() {
        Some(v) => v as u64,
        None => (i64::MAX as u64) + 1,
    };

    let whole = abs_u64 / factor;
    let frac = abs_u64 % factor;

    let mut out = if frac == 0 {
        whole.to_string()
    } else {
        let frac_str = format!("{:0width$}", frac, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    };

    if negative {
        out.insert(0, '-');
    }
    out
}

fn solana_pay_url_raw(
    recipient_pubkey: &str,
    amount_raw: i64,
    spl_token_mint: &str,
    reference: &str,
    decimals: u32,
) -> String {
    format!(
        "solana:{}?amount={}&spl-token={}&reference={}",
        recipient_pubkey,
        format_spl_amount_raw(amount_raw, decimals),
        spl_token_mint,
        reference
    )
}

fn extract_solana_tx_sig(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return String::new();
    }

    let without_query = trimmed.split('?').next().unwrap_or(trimmed);
    let without_fragment = without_query.split('#').next().unwrap_or(without_query);
    without_fragment
        .rsplit('/')
        .next()
        .unwrap_or(without_fragment)
        .trim()
        .to_string()
}

#[cfg(test)]
mod spl_amount_format_tests {
    use super::format_spl_amount_raw;

    #[test]
    fn formats_usdc_amounts_without_rounding() {
        assert_eq!(format_spl_amount_raw(0, 6), "0");
        assert_eq!(format_spl_amount_raw(1, 6), "0.000001");
        assert_eq!(format_spl_amount_raw(1_000_000, 6), "1");
        assert_eq!(format_spl_amount_raw(1_234_500, 6), "1.2345");
    }

    #[test]
    fn formats_pipe_amounts_without_rounding() {
        assert_eq!(format_spl_amount_raw(20_000_000_000, 9), "20");
        assert_eq!(format_spl_amount_raw(100_000_000_001, 9), "100.000000001");
    }
}

async fn fetch_credits_status(
    client: &Client,
    base_url: &str,
    creds: &SavedCredentials,
) -> Result<CreditsStatusResponse> {
    for path in ["/api/credits/status", "/deposit/balance"] {
        let mut request = client.get(format!("{}{}", base_url, path));
        request = add_auth_headers(request, creds, false)?;

        let resp = request.send().await?;
        let status = resp.status();
        let text_body = resp.text().await?;

        if status.is_success() {
            return Ok(serde_json::from_str::<CreditsStatusResponse>(&text_body)?);
        }

        if status.as_u16() == 404 {
            continue;
        }

        return Err(anyhow!(
            "Credits status request failed. Status = {}, Body = {}",
            status,
            text_body
        ));
    }

    Err(anyhow!(
        "This server does not support prepaid credits endpoints"
    ))
}

fn print_credits_status(status: &CreditsStatusResponse) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                 💳 PREPAID CREDITS (USDC)                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("💰 Balance: ${} USDC", format_usdc_ui(status.balance_usdc));
    println!(
        "📊 Total Deposited: ${} USDC",
        format_usdc_ui(usdc_raw_to_ui(status.total_deposited_usdc_raw))
    );
    println!(
        "📉 Total Spent:     ${} USDC",
        format_usdc_ui(usdc_raw_to_ui(status.total_spent_usdc_raw))
    );
    if let Some(ts) = status.last_topup_at.as_deref() {
        println!("🕒 Last Top-up:     {}", ts);
    }

    println!();
    println!("📦 Available Storage:");
    println!("┌──────────────┬────────────────┬──────────────┐");
    println!("│ Tier         │ Available GB   │ USDC/GB       │");
    println!("├──────────────┼────────────────┼──────────────┤");
    for tier in &status.quota.tier_estimates {
        println!(
            "│ {:<12} │ {:>12.2} GB│ ${:>11} │",
            tier.tier_name,
            tier.available_gb,
            format_usdc_ui(tier.cost_per_gb_usdc)
        );
    }
    println!("└──────────────┴────────────────┴──────────────┘");

    if let Some(intent) = status.intent.as_ref() {
        println!();
        println!("🧾 Pending Intent:");
        println!("  Status:    {}", intent.status);
        println!("  Intent ID: {}", intent.intent_id);
        println!(
            "  Requested: ${} USDC",
            format_usdc_ui(usdc_raw_to_ui(intent.requested_usdc_raw))
        );
        if let Some(sig) = intent.payment_tx_sig.as_deref() {
            println!("  Tx Sig:    {}", sig);
        }
        println!("  Reference: {}", intent.reference_pubkey);
        if !intent.treasury_owner_pubkey.is_empty() {
            println!("  Treasury:  {}", intent.treasury_owner_pubkey);
            println!(
                "  Solana Pay: {}",
                solana_pay_url_raw(
                    &intent.treasury_owner_pubkey,
                    intent.requested_usdc_raw,
                    &intent.usdc_mint,
                    &intent.reference_pubkey,
                    6
                )
            );
        }
    }
}


pub fn get_credentials_file_path(custom_path: Option<&str>) -> PathBuf {
    if let Some(path) = custom_path {
        PathBuf::from(path)
    } else if let Some(home_dir) = dirs::home_dir() {
        home_dir.join(".pipe-cli.json")
    } else {
        PathBuf::from(".pipe-cli.json")
    }
}

// Helper function to load credentials with the current config
pub fn load_creds_with_config(config_path: Option<&str>) -> Result<SavedCredentials> {
    load_credentials_from_file(config_path)?.ok_or_else(|| {
        anyhow!(
            "No saved credentials found. Run `pipe init` or `pipe wallet-auth` first."
        )
    })
}

pub fn load_credentials_from_file(custom_path: Option<&str>) -> Result<Option<SavedCredentials>> {
    let path = get_credentials_file_path(custom_path);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path)?;
    let creds: SavedCredentials = serde_json::from_str(&data)?;
    Ok(Some(creds))
}

pub fn save_credentials_to_file(
    user_id: &str,
    user_app_key: &str,
    config_path: Option<&str>,
) -> Result<()> {
    // Try to preserve existing auth tokens if they exist
    let creds = if let Ok(Some(existing)) = load_credentials_from_file(config_path) {
        SavedCredentials {
            user_id: user_id.to_owned(),
            user_app_key: user_app_key.to_owned(),
            auth_tokens: existing.auth_tokens,
            username: existing.username,
            api_base_url: existing.api_base_url,
            s3_endpoint: existing.s3_endpoint,
            s3_region: existing.s3_region,
            s3_virtual_hosted: existing.s3_virtual_hosted,
        }
    } else {
        SavedCredentials {
            user_id: user_id.to_owned(),
            user_app_key: user_app_key.to_owned(),
            auth_tokens: None,
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
        }
    };

    save_full_credentials(&creds, config_path)
}

// Save full credentials including JWT tokens
pub fn save_full_credentials(creds: &SavedCredentials, config_path: Option<&str>) -> Result<()> {
    let path = get_credentials_file_path(config_path);
    let json = serde_json::to_string_pretty(&creds)?;
    fs::write(&path, json)?;
    println!("Credentials saved to {:?}", path);
    Ok(())
}

// Check if JWT token is expired or about to expire (within 60 seconds)
fn is_token_expired(auth_tokens: &AuthTokens) -> bool {
    if let Some(expires_at) = auth_tokens.expires_at {
        let now = Utc::now();
        let buffer = chrono::Duration::seconds(60);
        now + buffer >= expires_at
    } else {
        true // If no expiration time, assume expired
    }
}

// Refresh JWT token if needed
async fn ensure_valid_token(
    client: &Client,
    base_url: &str,
    creds: &mut SavedCredentials,
    config_path: Option<&str>,
) -> Result<()> {
    if let Some(ref auth_tokens) = creds.auth_tokens {
        if is_token_expired(auth_tokens) {
            println!("Token expired or expiring soon, refreshing...");

            let req_body = RefreshTokenRequest {
                refresh_token: auth_tokens.refresh_token.clone(),
            };

            let resp = client
                .post(format!("{}/auth/refresh", base_url))
                .json(&req_body)
                .send()
                .await?;

            if resp.status().is_success() {
                let refresh_response: RefreshTokenResponse = resp.json().await?;
                let RefreshTokenResponse {
                    access_token,
                    expires_in,
                    csrf_token,
                    ..
                } = refresh_response;

                // Calculate new expires_at timestamp
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                let expires_at = DateTime::<Utc>::from_timestamp(now + expires_in, 0)
                    .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;

                // Update auth tokens
                if let Some(ref mut auth_tokens) = creds.auth_tokens {
                    auth_tokens.access_token = access_token;
                    auth_tokens.expires_in = expires_in;
                    auth_tokens.expires_at = Some(expires_at);
                    if let Some(token) = csrf_token {
                        auth_tokens.csrf_token = Some(token);
                    }
                }

                // Save updated credentials
                save_full_credentials(creds, config_path)?;
                println!("Token refreshed successfully!");
            } else {
                // Token refresh failed, clear auth tokens
                creds.auth_tokens = None;
                save_full_credentials(creds, config_path)?;
                return Err(anyhow!("Token refresh failed, please login again"));
            }
        }
    }
    Ok(())
}

fn extract_user_id_from_jwt(access_token: &str) -> Result<String> {
    let parts: Vec<&str> = access_token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }

    let payload = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| anyhow!("Invalid JWT payload encoding: {e}"))?;

    let json: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|e| anyhow!("Invalid JWT payload JSON: {e}"))?;

    json.get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("JWT missing 'sub' claim"))
}

/// Add authentication headers including CSRF token for state-changing requests
fn add_auth_headers(
    mut request: reqwest::RequestBuilder,
    creds: &SavedCredentials,
    is_state_changing: bool,
) -> Result<reqwest::RequestBuilder> {
    let auth_tokens = creds.auth_tokens.as_ref().ok_or_else(|| {
        anyhow!(
            "JWT authentication required. Run `pipe init` or `pipe wallet-auth` first."
        )
    })?;

    request = request.header(
        "Authorization",
        format!("Bearer {}", auth_tokens.access_token),
    );

    // Add CSRF token for state-changing requests
    if is_state_changing {
        if let Some(ref csrf_token) = auth_tokens.csrf_token {
            request = request.header("X-CSRF-Token", csrf_token);
        }
    }

    Ok(request)
}

fn normalize_http_url_without_path(raw: &str, label: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{label} must not be empty"));
    }

    let url = reqwest::Url::parse(trimmed)
        .map_err(|_| anyhow!("{label} must be a valid URL (expected http/https)"))?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow!("{label} scheme must be http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!("{label} must not include username/password"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!("{label} must not include query/fragment"));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(anyhow!("{label} must not include a path"));
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("{label} must include a host"))?
        .to_ascii_lowercase();

    let port = match (scheme, url.port()) {
        ("http", Some(80)) | ("https", Some(443)) => None,
        (_, p) => p,
    };

    Ok(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

fn bucket_name_for_user_id(user_id: &str) -> String {
    format!("pipe-{user_id}")
}

#[cfg(test)]
mod cli_config_tests {
    use super::*;

    #[test]
    fn normalize_http_url_without_path_rejects_paths() {
        assert!(normalize_http_url_without_path("https://example.com/path", "API").is_err());
    }

    #[test]
    fn normalize_http_url_without_path_strips_default_ports() {
        assert_eq!(
            normalize_http_url_without_path("https://Example.com:443", "API").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalize_http_url_without_path("http://Example.com:80", "API").unwrap(),
            "http://example.com"
        );
    }

    #[test]
    fn save_credentials_preserves_cli_config_fields() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("creds.json");
        let path_str = path.to_str().unwrap();

        let initial = SavedCredentials {
            user_id: "u1".to_string(),
            user_app_key: "k1".to_string(),
            auth_tokens: None,
            username: None,
            api_base_url: Some("https://api.example.com".to_string()),
            s3_endpoint: Some("https://s3.example.com".to_string()),
            s3_region: Some("us-east-1".to_string()),
            s3_virtual_hosted: Some(true),
        };
        save_full_credentials(&initial, Some(path_str)).unwrap();

        save_credentials_to_file("u2", "k2", Some(path_str)).unwrap();
        let loaded = load_credentials_from_file(Some(path_str)).unwrap().unwrap();

        assert_eq!(loaded.user_id, "u2");
        assert_eq!(loaded.user_app_key, "k2");
        assert_eq!(
            loaded.api_base_url.as_deref(),
            Some("https://api.example.com")
        );
        assert_eq!(
            loaded.s3_endpoint.as_deref(),
            Some("https://s3.example.com")
        );
        assert_eq!(loaded.s3_region.as_deref(), Some("us-east-1"));
        assert_eq!(loaded.s3_virtual_hosted, Some(true));
    }
}

// --- Solana wallet helpers ---

fn default_keypair_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pipe-cli")
        .join("wallet.json")
}

fn generate_solana_keypair(path: &Path, force: bool) -> Result<(SigningKey, String)> {
    if path.exists() && !force {
        return Err(anyhow!(
            "Keypair file already exists: {:?}\nUse --force to overwrite.",
            path
        ));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let pubkey_b58 = bs58::encode(verifying_key.as_bytes()).into_string();

    // Build 64-byte array: secret (32) ++ public (32), same as Solana CLI id.json
    let mut keypair_bytes = Vec::with_capacity(64);
    keypair_bytes.extend_from_slice(&signing_key.to_bytes());
    keypair_bytes.extend_from_slice(verifying_key.as_bytes());

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string(&keypair_bytes)?;
    fs::write(path, &json)?;

    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok((signing_key, pubkey_b58))
}

fn load_solana_keypair(path: &Path) -> Result<(SigningKey, String)> {
    let data = fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read keypair file {:?}: {}", path, e))?;

    let bytes: Vec<u8> = serde_json::from_str(&data)
        .map_err(|e| anyhow!("Invalid keypair JSON in {:?}: {}", path, e))?;

    if bytes.len() != 64 {
        return Err(anyhow!(
            "Invalid keypair file: expected 64 bytes, got {}",
            bytes.len()
        ));
    }

    let secret_bytes: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| anyhow!("Invalid secret key bytes"))?;

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let pubkey_b58 = bs58::encode(verifying_key.as_bytes()).into_string();

    Ok((signing_key, pubkey_b58))
}

// --- SIWS authentication helper ---

async fn siws_authenticate(
    client: &Client,
    base_url: &str,
    signing_key: &SigningKey,
    pubkey_b58: &str,
    config_path: Option<&str>,
) -> Result<SavedCredentials> {
    // Step 1: Request challenge
    println!("Requesting SIWS challenge...");
    let challenge_req = SiwsChallengeRequest {
        wallet_public_key: pubkey_b58.to_string(),
    };

    let resp = client
        .post(format!("{}/auth/siws/challenge", base_url))
        .json(&challenge_req)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "SIWS challenge failed ({}): {}",
            status,
            text
        ));
    }

    let challenge: SiwsChallengeResponse = serde_json::from_str(&text)
        .map_err(|e| anyhow!("Failed to parse challenge response: {} — body: {}", e, text))?;

    // Step 2: Sign the message
    let signature = signing_key.sign(challenge.message.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Step 3: Verify
    println!("Signing challenge and verifying...");
    let verify_req = SiwsVerifyRequest {
        wallet_public_key: pubkey_b58.to_string(),
        nonce: challenge.nonce,
        message: challenge.message,
        signature_b64,
    };

    let resp = client
        .post(format!("{}/auth/siws/verify", base_url))
        .json(&verify_req)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "SIWS verification failed ({}): {}",
            status,
            text
        ));
    }

    let verify_resp: SiwsVerifyResponse = serde_json::from_str(&text)
        .map_err(|e| anyhow!("Failed to parse verify response: {} — body: {}", e, text))?;

    // Step 4: Build auth tokens with expiration
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let expires_at = DateTime::<Utc>::from_timestamp(now + verify_resp.expires_in, 0)
        .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?;

    let auth_tokens = AuthTokens {
        access_token: verify_resp.access_token.clone(),
        refresh_token: verify_resp.refresh_token,
        token_type: verify_resp.token_type,
        expires_in: verify_resp.expires_in,
        expires_at: Some(expires_at),
        csrf_token: verify_resp.csrf_token,
    };

    // Step 5: Extract user_id from JWT
    let user_id = extract_user_id_from_jwt(&verify_resp.access_token)?;

    // Step 6: Preserve existing config fields if present
    let existing = load_credentials_from_file(config_path).ok().flatten();
    let creds = SavedCredentials {
        user_id,
        user_app_key: String::new(),
        auth_tokens: Some(auth_tokens),
        username: None,
        api_base_url: existing
            .as_ref()
            .and_then(|c| c.api_base_url.clone())
            .or_else(|| Some(base_url.to_string())),
        s3_endpoint: existing.as_ref().and_then(|c| c.s3_endpoint.clone()),
        s3_region: existing.as_ref().and_then(|c| c.s3_region.clone()),
        s3_virtual_hosted: existing.as_ref().and_then(|c| c.s3_virtual_hosted),
    };

    save_full_credentials(&creds, config_path)?;
    println!("Authentication successful!");
    println!("User ID: {}", creds.user_id);
    println!(
        "Token expires at: {}",
        expires_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    Ok(creds)
}

pub async fn run_cli() -> Result<()> {
    let matches = Cli::command().get_matches();
    let api_source = matches.value_source("api");
    let cli = Cli::from_arg_matches(&matches).map_err(|e| anyhow!(e.to_string()))?;

    // Get config path from CLI or use default
    let config_path = cli.config.as_deref();

    // Create optimized HTTP client for high concurrency
    let client = Client::builder()
        .pool_max_idle_per_host(100) // Keep more connections alive
        .pool_idle_timeout(std::time::Duration::from_secs(90)) // Keep connections alive longer
        .timeout(std::time::Duration::from_secs(7200)) // 2 hour timeout for very large files (95GB+)
        .build()?;

    let mut base_url_string = cli.api.trim_end_matches('/').to_string();
    if api_source == Some(clap::parser::ValueSource::DefaultValue) {
        if let Ok(Some(creds)) = load_credentials_from_file(config_path) {
            if let Some(saved) = creds.api_base_url.as_deref() {
                let trimmed = saved.trim().trim_end_matches('/');
                if !trimmed.is_empty() {
                    base_url_string = trimmed.to_string();
                }
            }
        }
    }
    let base_url = base_url_string.as_str();

    match cli.command {
        Commands::Config { command } => {
            let config_file = get_credentials_file_path(config_path);

            match command {
                ConfigCommands::Show => {
                    println!("Config file: {:?}", config_file);
                    println!("Effective API base URL (this run): {}", base_url);

                    let Some(creds) = load_credentials_from_file(config_path)? else {
                        println!("No config/credentials found yet.");
                        println!("Run `pipe new-user` or `pipe login` first, then re-run `pipe config show`.");
                        return Ok(());
                    };

                    if let Some(u) = creds.username.as_deref() {
                        println!("Username: {}", u);
                    }
                    if !creds.user_id.is_empty() {
                        println!("User ID: {}", creds.user_id);
                        println!("Bucket: {}", bucket_name_for_user_id(&creds.user_id));
                    }

                    println!(
                        "Saved API base URL: {}",
                        creds.api_base_url.as_deref().unwrap_or("(not set)")
                    );
                    println!(
                        "Saved S3 endpoint: {}",
                        creds.s3_endpoint.as_deref().unwrap_or("(not set)")
                    );
                    println!(
                        "Saved S3 region: {}",
                        creds.s3_region.as_deref().unwrap_or("(not set)")
                    );
                    println!(
                        "Saved S3 virtual-hosted-style: {}",
                        creds
                            .s3_virtual_hosted
                            .map(|v| if v { "true" } else { "false" })
                            .unwrap_or("(not set)")
                    );
                }
                ConfigCommands::SetApi { url } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    let normalized = normalize_http_url_without_path(&url, "API base URL")?;
                    creds.api_base_url = Some(normalized.clone());
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Saved API base URL: {}", normalized);
                }
                ConfigCommands::ClearApi => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.api_base_url = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved API base URL");
                }
                ConfigCommands::SetS3Endpoint { endpoint } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    let normalized = normalize_http_url_without_path(&endpoint, "S3 endpoint")?;
                    creds.s3_endpoint = Some(normalized.clone());
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Saved S3 endpoint: {}", normalized);
                }
                ConfigCommands::ClearS3Endpoint => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_endpoint = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved S3 endpoint");
                }
                ConfigCommands::SetS3Region { region } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    let trimmed = region.trim();
                    if trimmed.is_empty() {
                        return Err(anyhow!("S3 region must not be empty"));
                    }
                    creds.s3_region = Some(trimmed.to_string());
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Saved S3 region: {}", trimmed);
                }
                ConfigCommands::ClearS3Region => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_region = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved S3 region");
                }
                ConfigCommands::SetS3VirtualHosted { enabled } => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_virtual_hosted = Some(enabled);
                    save_full_credentials(&creds, config_path)?;
                    println!(
                        "✓ Saved S3 virtual-hosted-style default: {}",
                        if enabled { "true" } else { "false" }
                    );
                }
                ConfigCommands::ClearS3VirtualHosted => {
                    let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                        anyhow!(
                            "No config/credentials file found. Run `pipe new-user` or `pipe login` first."
                        )
                    })?;
                    creds.s3_virtual_hosted = None;
                    save_full_credentials(&creds, config_path)?;
                    println!("✓ Cleared saved S3 virtual-hosted-style default");
                }
            }

            return Ok(());
        }
        Commands::Topup {
            amount,
            tx_sig,
            no_prompt,
            user_id,
        } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let amount_usdc_raw = parse_usdc_ui_to_raw(&amount)?;

            let mut request = client.post(format!("{}/api/credits/intent", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&CreateCreditsIntentRequest { amount_usdc_raw });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits intent failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let intent = serde_json::from_str::<CreditsIntentResponse>(&text_body)?;
            println!("✅ Credits intent created");
            println!("Status: {}", intent.status);
            println!("Intent ID: {}", intent.intent_id);
            println!(
                "Amount: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(intent.requested_usdc_raw))
            );
            println!("USDC mint: {}", intent.usdc_mint);
            println!("Treasury: {}", intent.treasury_owner_pubkey);
            println!("Reference: {}", intent.reference_pubkey);
            println!();
            println!(
                "Solana Pay: {}",
                solana_pay_url_raw(
                    &intent.treasury_owner_pubkey,
                    intent.requested_usdc_raw,
                    &intent.usdc_mint,
                    &intent.reference_pubkey,
                    6
                )
            );

            let mut tx_sig = tx_sig.map(|s| extract_solana_tx_sig(&s)).filter(|s| !s.is_empty());
            if tx_sig.is_none() && !no_prompt && atty::is(atty::Stream::Stdin) {
                use std::io::{self, Write};
                println!();
                println!("Paste the payment tx signature to finish (or press Enter to skip):");
                print!("tx sig> ");
                io::stdout().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                let extracted = extract_solana_tx_sig(&line);
                if !extracted.is_empty() {
                    tx_sig = Some(extracted);
                }
            }

            let Some(tx_sig) = tx_sig else {
                println!();
                println!("Next:");
                println!("  1) Pay the Solana Pay link in your wallet");
                println!("  2) Submit the tx:");
                println!("     pipe credits-submit {} <tx_sig>", intent.intent_id);
                println!("  3) Check balance:");
                println!("     pipe credits-status");
                return Ok(());
            };

            let mut request = client.post(format!("{}/api/credits/submit", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&SubmitCreditsPaymentRequest {
                intent_id: intent.intent_id.clone(),
                tx_sig,
            });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits submit failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<SubmitCreditsPaymentResponse>(&text_body)?;
            println!();
            println!("✅ Credits updated");
            println!("Intent: {}", result.intent_id);
            println!("Status: {}", result.status);
            println!(
                "Detected: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.detected_usdc_raw))
            );
            println!(
                "Credited: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.credited_usdc_raw))
            );
            println!(
                "Balance:  ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.balance_usdc_raw))
            );
        }

        Commands::CreditsStatus { user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let status = fetch_credits_status(&client, base_url, &creds).await?;
            print_credits_status(&status);
        }

        Commands::CreditsIntent { amount, user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let amount_usdc_raw = parse_usdc_ui_to_raw(&amount)?;

            let mut request = client.post(format!("{}/api/credits/intent", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&CreateCreditsIntentRequest { amount_usdc_raw });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits intent failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let intent = serde_json::from_str::<CreditsIntentResponse>(&text_body)?;
            println!("✅ Credits intent created");
            println!("Status: {}", intent.status);
            println!("Intent ID: {}", intent.intent_id);
            println!(
                "Amount: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(intent.requested_usdc_raw))
            );
            println!("USDC mint: {}", intent.usdc_mint);
            println!("Treasury: {}", intent.treasury_owner_pubkey);
            println!("Reference: {}", intent.reference_pubkey);
            println!();
            println!(
                "Solana Pay: {}",
                solana_pay_url_raw(
                    &intent.treasury_owner_pubkey,
                    intent.requested_usdc_raw,
                    &intent.usdc_mint,
                    &intent.reference_pubkey,
                    6
                )
            );
            println!();
            println!("Next:");
            println!("  1) Pay the Solana Pay link in your wallet");
            println!(
                "  2) Submit the tx: pipe credits-submit {} <tx_sig>",
                intent.intent_id
            );
        }

        Commands::CreditsSubmit {
            intent_id,
            tx_sig,
            user_id,
        } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/credits/submit", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&SubmitCreditsPaymentRequest { intent_id, tx_sig });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits submit failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<SubmitCreditsPaymentResponse>(&text_body)?;
            println!("✅ Credits updated");
            println!("Intent: {}", result.intent_id);
            println!("Status: {}", result.status);
            println!(
                "Detected: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.detected_usdc_raw))
            );
            println!(
                "Credited: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.credited_usdc_raw))
            );
            println!(
                "Balance:  ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.balance_usdc_raw))
            );
        }

        Commands::CreditsCancel { intent_id, user_id } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            let mut request = client.post(format!("{}/api/credits/cancel", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&CancelCreditsIntentRequest { intent_id });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits cancel failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<CreditsCancelResponse>(&text_body)?;
            println!(
                "✅ Intent cancelled: {} ({})",
                result.intent_id, result.status
            );
        }

        Commands::SyncDeposits {
            user_id,
            intent_id,
            tx_sig,
        } => {
            let mut creds = load_credentials_from_file(config_path)?.ok_or_else(|| {
                anyhow!("No credentials found. Please create a user or login first.")
            })?;

            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(uid) = user_id {
                creds.user_id = uid;
            }

            if tx_sig.is_none() {
                let status = fetch_credits_status(&client, base_url, &creds).await?;
                print_credits_status(&status);
                println!();
                println!("To top up credits: pipe topup 10");
                println!("To submit a payment: pipe credits-submit <intent_id> <tx_sig>");
                return Ok(());
            }

            let tx_sig = tx_sig.expect("checked above");
            let intent_id = match intent_id {
                Some(v) => v,
                None => {
                    let status = fetch_credits_status(&client, base_url, &creds).await?;
                    status.intent.map(|i| i.intent_id).ok_or_else(|| {
                        anyhow!(
                            "No pending intent found. Run `pipe topup <amount>` first."
                        )
                    })?
                }
            };

            let mut request = client.post(format!("{}/api/credits/submit", base_url));
            request = add_auth_headers(request, &creds, true)?;
            request = request.json(&SubmitCreditsPaymentRequest { intent_id, tx_sig });

            let resp = request.send().await?;
            let status = resp.status();
            let text_body = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!(
                    "Credits submit failed. Status = {}, Body = {}",
                    status,
                    text_body
                ));
            }

            let result = serde_json::from_str::<SubmitCreditsPaymentResponse>(&text_body)?;
            println!("✅ Credits updated");
            println!(
                "Credited: ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.credited_usdc_raw))
            );
            println!(
                "Balance:  ${} USDC",
                format_usdc_ui(usdc_raw_to_ui(result.balance_usdc_raw))
            );
        }

        // --- Wallet & S3 commands ---

        Commands::WalletKeygen { output, force } => {
            let path = match output {
                Some(p) => PathBuf::from(p),
                None => default_keypair_path(),
            };

            let (_signing_key, pubkey) = generate_solana_keypair(&path, force)?;
            println!("Keypair written to {:?}", path);
            println!("Public key: {}", pubkey);
        }

        Commands::WalletAuth { keypair } => {
            let path = match keypair {
                Some(p) => PathBuf::from(p),
                None => default_keypair_path(),
            };

            let (signing_key, pubkey) = load_solana_keypair(&path)?;
            println!("Loaded keypair: {}", pubkey);

            siws_authenticate(&client, base_url, &signing_key, &pubkey, config_path).await?;
        }

        Commands::S3KeyCreate { env } => {
            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let access_token = creds
                .auth_tokens
                .as_ref()
                .ok_or_else(|| anyhow!("No auth tokens. Run `pipe login` or `pipe wallet-auth` first."))?
                .access_token
                .clone();

            let resp = client
                .post(format!("{}/api/s3/keys", base_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .json(&serde_json::json!({}))
                .send()
                .await?;

            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to create S3 key ({}): {}", status, text));
            }

            let key: S3KeyCreateResponse = serde_json::from_str(&text)
                .map_err(|e| anyhow!("Failed to parse S3 key response: {} — body: {}", e, text))?;

            if env {
                println!("export AWS_ACCESS_KEY_ID={}", key.access_key_id);
                println!("export AWS_SECRET_ACCESS_KEY={}", key.secret_access_key);
                println!("export AWS_DEFAULT_REGION={}", key.region);
                println!("export AWS_ENDPOINT_URL={}", key.endpoint);
                println!("export PIPE_BUCKET={}", key.bucket_name);
            } else {
                println!("S3 Key Created:");
                println!("  Access Key ID:     {}", key.access_key_id);
                println!("  Secret Access Key: {}", key.secret_access_key);
                println!("  Endpoint:          {}", key.endpoint);
                println!("  Region:            {}", key.region);
                println!("  Bucket:            {}", key.bucket_name);
                println!("  Name Prefix:       {}", key.name_prefix);
                println!();
                println!("⚠ Save your Secret Access Key now — it will not be shown again.");
            }
        }

        Commands::S3KeyList => {
            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let access_token = creds
                .auth_tokens
                .as_ref()
                .ok_or_else(|| anyhow!("No auth tokens. Run `pipe login` or `pipe wallet-auth` first."))?
                .access_token
                .clone();

            let resp = client
                .get(format!("{}/api/s3/keys", base_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await?;

            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to list S3 keys ({}): {}", status, text));
            }

            let list: S3KeyListResponse = serde_json::from_str(&text)
                .map_err(|e| anyhow!("Failed to parse S3 key list: {} — body: {}", e, text))?;

            if list.keys.is_empty() {
                println!("No S3 keys found. Create one with `pipe s3-key-create`.");
            } else {
                println!(
                    "{:<20} {:<24} {:<20} {}",
                    "KEY NAME", "ACCESS KEY ID", "NAME PREFIX", "CREATED"
                );
                println!("{}", "-".repeat(84));
                for k in &list.keys {
                    println!(
                        "{:<20} {:<24} {:<20} {}",
                        k.key_name, k.access_key_id, k.name_prefix, k.created_at
                    );
                }
            }
        }

        Commands::S3KeyDelete { access_key_id, yes } => {
            if !yes {
                print!("Delete S3 key {}? [y/N] ", access_key_id);
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let access_token = creds
                .auth_tokens
                .as_ref()
                .ok_or_else(|| anyhow!("No auth tokens. Run `pipe login` or `pipe wallet-auth` first."))?
                .access_token
                .clone();

            let resp = client
                .delete(format!("{}/api/s3/keys/{}", base_url, access_key_id))
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await?;

            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to delete S3 key ({}): {}", status, text));
            }

            println!("Deleted S3 key: {}", access_key_id);
        }

        Commands::S3Info => {
            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let access_token = creds
                .auth_tokens
                .as_ref()
                .ok_or_else(|| anyhow!("No auth tokens. Run `pipe login` or `pipe wallet-auth` first."))?
                .access_token
                .clone();

            // Fetch S3 info
            let resp = client
                .get(format!("{}/api/s3/info", base_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await?;

            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to get S3 info ({}): {}", status, text));
            }

            let info: S3InfoResponse = serde_json::from_str(&text)
                .map_err(|e| anyhow!("Failed to parse S3 info: {} — body: {}", e, text))?;

            // Fetch bucket info
            let resp = client
                .get(format!("{}/api/s3/bucket", base_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await?;

            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to get bucket info ({}): {}", status, text));
            }

            let bucket: BucketInfoResponse = serde_json::from_str(&text)
                .map_err(|e| anyhow!("Failed to parse bucket info: {} — body: {}", e, text))?;

            println!("S3 Info:");
            println!("  Endpoint:     {}", info.endpoint);
            println!("  Region:       {}", info.region);
            println!("  Bucket:       {}", bucket.bucket_name);
            println!("  Public Read:  {}", bucket.public_read);
            if !bucket.cors_allowed_origins.is_empty() {
                println!("  CORS Origins: {}", bucket.cors_allowed_origins.join(", "));
            }
        }

        Commands::Init { keypair } => {
            let keypair_path = match keypair {
                Some(p) => PathBuf::from(p),
                None => default_keypair_path(),
            };

            // Step 1: Generate keypair if it doesn't exist
            let (signing_key, pubkey) = if keypair_path.exists() {
                println!("Using existing keypair: {:?}", keypair_path);
                load_solana_keypair(&keypair_path)?
            } else {
                println!("Generating new keypair...");
                let result = generate_solana_keypair(&keypair_path, false)?;
                println!("Keypair written to {:?}", keypair_path);
                result
            };
            println!("Public key: {}", pubkey);

            // Step 2: Authenticate via SIWS
            let creds =
                siws_authenticate(&client, base_url, &signing_key, &pubkey, config_path).await?;

            let access_token = creds
                .auth_tokens
                .as_ref()
                .ok_or_else(|| anyhow!("Authentication did not return tokens"))?
                .access_token
                .clone();

            // Step 3: Create S3 key
            println!("Creating S3 access key...");
            let resp = client
                .post(format!("{}/api/s3/keys", base_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .json(&serde_json::json!({}))
                .send()
                .await?;

            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to create S3 key ({}): {}", status, text));
            }

            let key: S3KeyCreateResponse = serde_json::from_str(&text)
                .map_err(|e| anyhow!("Failed to parse S3 key response: {} — body: {}", e, text))?;

            // Step 4: Save S3 endpoint/region to config
            let mut updated_creds = load_credentials_from_file(config_path)?
                .unwrap_or(creds);
            updated_creds.s3_endpoint = Some(key.endpoint.clone());
            updated_creds.s3_region = Some(key.region.clone());
            save_full_credentials(&updated_creds, config_path)?;

            // Step 5: Print env vars
            println!();
            println!("# Add these to your environment:");
            println!("export AWS_ACCESS_KEY_ID={}", key.access_key_id);
            println!("export AWS_SECRET_ACCESS_KEY={}", key.secret_access_key);
            println!("export AWS_DEFAULT_REGION={}", key.region);
            println!("export AWS_ENDPOINT_URL={}", key.endpoint);
            println!("export PIPE_BUCKET={}", key.bucket_name);
            println!();
            println!("⚠ Save your Secret Access Key now — it will not be shown again.");
        }
    }

    Ok(())
}
