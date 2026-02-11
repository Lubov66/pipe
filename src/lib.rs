// src/lib.rs

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::io::IsTerminal;
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

    /// Show storage and bandwidth usage with free-tier breakdown
    #[command(alias = "billing")]
    Usage {
        /// Time period: 24h, 7d, 30d, 90d, 365d (default: 30d)
        #[arg(long, default_value = "30d")]
        period: String,

        /// Show per-tier breakdown
        #[arg(long)]
        detailed: bool,
    },

    /// Show your account profile
    #[command(alias = "whoami")]
    Profile,

    /// Log out and terminate the current session
    Logout,

    /// List or revoke active sessions
    Sessions {
        /// Revoke a session by ID (cannot revoke the current session)
        #[arg(long)]
        revoke: Option<String>,
    },

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

// --- Token usage / billing types ---

#[derive(Deserialize, Debug)]
struct UsageBreakdown {
    #[serde(default)]
    gb_transferred: f64,
    #[serde(default)]
    usdc_charged: f64,
    #[serde(default)]
    transfer_count: i64,
    #[serde(default)]
    tier_details: HashMap<String, UsageTierDetail>,
}

#[derive(Deserialize, Debug)]
struct UsageTierDetail {
    #[serde(default, rename = "tier_name")]
    _tier_name: String,
    #[serde(default)]
    transfer_count: i64,
    #[serde(default)]
    gb_transferred: f64,
}

#[derive(Deserialize, Debug)]
struct UsageTotalBreakdown {
    #[serde(default, rename = "gb_transferred")]
    _gb_transferred: f64,
    #[serde(default)]
    usdc_charged: f64,
}

#[derive(Deserialize, Debug)]
struct UsageBreakdownDetail {
    #[serde(default)]
    storage: Option<UsageBreakdown>,
    #[serde(default)]
    bandwidth: Option<UsageBreakdown>,
    #[serde(default)]
    total: Option<UsageTotalBreakdown>,
}

#[derive(Deserialize, Debug)]
struct UsageResponse {
    #[serde(default, rename = "period")]
    _period: Option<String>,
    #[serde(default)]
    breakdown: Option<UsageBreakdownDetail>,
    // Fallback: some server versions return flat (without breakdown wrapper)
    #[serde(default)]
    storage: Option<UsageBreakdown>,
    #[serde(default)]
    bandwidth: Option<UsageBreakdown>,
    #[serde(default)]
    total: Option<UsageTotalBreakdown>,
}

#[derive(Deserialize, Debug)]
struct UserProfile {
    user_id: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    wallet_public_key: Option<String>,
    #[serde(default)]
    account_state: Option<String>,
}

#[derive(Deserialize, Debug)]
struct SessionInfo {
    session_id: String,
    created_at: String,
    expires_at: String,
    #[serde(default)]
    ip_address: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    is_current: bool,
}

#[derive(Deserialize, Debug)]
struct SessionsResponse {
    sessions: Vec<SessionInfo>,
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

fn print_usage(usage: &UsageResponse, period: &str, detailed: bool) {
    println!("Usage for period: {}", period);
    println!();

    // Resolve breakdown: prefer nested, fall back to flat
    let storage = usage.breakdown.as_ref().and_then(|b| b.storage.as_ref()).or(usage.storage.as_ref());
    let bandwidth = usage.breakdown.as_ref().and_then(|b| b.bandwidth.as_ref()).or(usage.bandwidth.as_ref());
    let total = usage.breakdown.as_ref().and_then(|b| b.total.as_ref()).or(usage.total.as_ref());

    // Storage
    if let Some(storage) = storage {
        println!("  Storage:");
        println!("    Data stored:  {:.4} GB", storage.gb_transferred);
        println!("    Cost:         ${}", format_usdc_ui(storage.usdc_charged));
        if storage.usdc_charged == 0.0 && storage.gb_transferred > 0.0 {
            println!("                  (within free 1 GB tier)");
        }
    }

    println!();

    // Bandwidth
    if let Some(bandwidth) = bandwidth {
        println!("  Bandwidth (egress):");
        println!("    Transferred:  {:.4} GB", bandwidth.gb_transferred);
        println!("    Transfers:    {}", bandwidth.transfer_count);
        println!("    Cost:         ${}", format_usdc_ui(bandwidth.usdc_charged));
        if bandwidth.usdc_charged == 0.0 && bandwidth.gb_transferred > 0.0 {
            println!("                  (within free 100 GB/month tier)");
        }

        if detailed && !bandwidth.tier_details.is_empty() {
            println!();
            println!("    Per-tier breakdown:");
            println!("    {:<12} {:>10} {:>12}", "Tier", "Transfers", "GB");
            println!("    {:<12} {:>10} {:>12}", "----", "---------", "----");
            for (name, tier) in &bandwidth.tier_details {
                println!(
                    "    {:<12} {:>10} {:>12.4}",
                    name, tier.transfer_count, tier.gb_transferred
                );
            }
        }
    }

    println!();

    // Total
    if let Some(total) = total {
        println!("  Total cost:     ${}", format_usdc_ui(total.usdc_charged));
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
            if tx_sig.is_none() && !no_prompt && std::io::stdin().is_terminal() {
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

        Commands::Usage { period, detailed } => {
            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let url = format!(
                "{}/api/token-usage?period={}&detailed={}",
                base_url, period, detailed
            );
            let mut request = client.get(&url);
            request = add_auth_headers(request, &creds, false)?;

            let resp = request.send().await?;
            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to get usage ({}): {}", status, text));
            }

            let usage: UsageResponse = serde_json::from_str(&text)
                .map_err(|e| anyhow!("Failed to parse usage: {} — body: {}", e, text))?;

            print_usage(&usage, &period, detailed);
        }

        Commands::Profile => {
            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let mut request = client.get(format!("{}/user/me", base_url));
            request = add_auth_headers(request, &creds, false)?;

            let resp = request.send().await?;
            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                return Err(anyhow!("Failed to get profile ({}): {}", status, text));
            }

            let profile: UserProfile = serde_json::from_str(&text)
                .map_err(|e| anyhow!("Failed to parse profile: {} — body: {}", e, text))?;

            println!("Account Profile:");
            println!("  User ID:    {}", profile.user_id);
            if let Some(name) = &profile.username {
                println!("  Username:   {}", name);
            }
            if let Some(email) = &profile.email {
                println!("  Email:      {}", email);
            }
            if let Some(wallet) = &profile.wallet_public_key {
                println!("  Wallet:     {}", wallet);
            }
            if let Some(state) = &profile.account_state {
                println!("  State:      {}", state);
            }
        }

        Commands::Logout => {
            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            let mut request = client.post(format!("{}/auth/logout", base_url));
            request = add_auth_headers(request, &creds, true)?;

            let resp = request.send().await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await?;
                return Err(anyhow!("Logout failed ({}): {}", status, text));
            }

            // Clear local tokens
            creds.auth_tokens = None;
            save_full_credentials(&creds, config_path)?;
            println!("Logged out successfully. Local tokens cleared.");
        }

        Commands::Sessions { revoke } => {
            let mut creds = load_creds_with_config(config_path)?;
            ensure_valid_token(&client, base_url, &mut creds, config_path).await?;

            if let Some(session_id) = revoke {
                // Revoke a session
                let mut request =
                    client.delete(format!("{}/auth/sessions/{}", base_url, session_id));
                request = add_auth_headers(request, &creds, true)?;

                let resp = request.send().await?;
                let status = resp.status();
                let text = resp.text().await?;
                if !status.is_success() {
                    return Err(anyhow!("Failed to revoke session ({}): {}", status, text));
                }
                println!("Session {} revoked.", session_id);
            } else {
                // List sessions
                let mut request = client.get(format!("{}/auth/sessions", base_url));
                request = add_auth_headers(request, &creds, false)?;

                let resp = request.send().await?;
                let status = resp.status();
                let text = resp.text().await?;
                if !status.is_success() {
                    return Err(anyhow!("Failed to list sessions ({}): {}", status, text));
                }

                let sessions_resp: SessionsResponse = serde_json::from_str(&text)
                    .map_err(|e| anyhow!("Failed to parse sessions: {} — body: {}", e, text))?;

                if sessions_resp.sessions.is_empty() {
                    println!("No active sessions.");
                } else {
                    println!("Active Sessions:");
                    println!();
                    for s in &sessions_resp.sessions {
                        let current = if s.is_current { " (current)" } else { "" };
                        println!("  Session:    {}{}", s.session_id, current);
                        println!("  Created:    {}", s.created_at);
                        println!("  Expires:    {}", s.expires_at);
                        if let Some(ip) = &s.ip_address {
                            println!("  IP:         {}", ip);
                        }
                        if let Some(ua) = &s.user_agent {
                            println!("  User-Agent: {}", ua);
                        }
                        println!();
                    }
                    println!("{} session(s) total.", sessions_resp.sessions.len());
                    println!();
                    println!("To revoke a session: pipe sessions --revoke <session_id>");
                }
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

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod usdc_parsing_tests {
    use super::*;

    #[test]
    fn parse_whole_number() {
        assert_eq!(parse_usdc_ui_to_raw("10").unwrap(), 10_000_000);
    }

    #[test]
    fn parse_with_decimals() {
        assert_eq!(parse_usdc_ui_to_raw("10.50").unwrap(), 10_500_000);
        assert_eq!(parse_usdc_ui_to_raw("0.001").unwrap(), 1_000);
        assert_eq!(parse_usdc_ui_to_raw("0.000001").unwrap(), 1);
    }

    #[test]
    fn parse_with_dollar_sign() {
        assert_eq!(parse_usdc_ui_to_raw("$25").unwrap(), 25_000_000);
        assert_eq!(parse_usdc_ui_to_raw("$1.50").unwrap(), 1_500_000);
    }

    #[test]
    fn parse_with_whitespace() {
        assert_eq!(parse_usdc_ui_to_raw("  10  ").unwrap(), 10_000_000);
        assert_eq!(parse_usdc_ui_to_raw(" $5.25 ").unwrap(), 5_250_000);
    }

    #[test]
    fn parse_trailing_dot() {
        assert_eq!(parse_usdc_ui_to_raw("10.").unwrap(), 10_000_000);
    }

    #[test]
    fn parse_zero() {
        assert_eq!(parse_usdc_ui_to_raw("0").unwrap(), 0);
        assert_eq!(parse_usdc_ui_to_raw("0.000000").unwrap(), 0);
    }

    #[test]
    fn parse_max_decimals() {
        assert_eq!(parse_usdc_ui_to_raw("1.123456").unwrap(), 1_123_456);
    }

    #[test]
    fn rejects_too_many_decimals() {
        assert!(parse_usdc_ui_to_raw("1.1234567").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_usdc_ui_to_raw("").is_err());
        assert!(parse_usdc_ui_to_raw("$").is_err());
    }

    #[test]
    fn rejects_negative() {
        assert!(parse_usdc_ui_to_raw("-5").is_err());
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(parse_usdc_ui_to_raw("abc").is_err());
        assert!(parse_usdc_ui_to_raw("10.5x").is_err());
    }

    #[test]
    fn rejects_overflow() {
        assert!(parse_usdc_ui_to_raw("10000000000000").is_err());
    }

    #[test]
    fn roundtrip_format_parse() {
        let raw = 12_345_678i64;
        let ui = usdc_raw_to_ui(raw);
        let formatted = format!("{:.6}", ui);
        let parsed_back = parse_usdc_ui_to_raw(&formatted).unwrap();
        assert_eq!(parsed_back, raw);
    }
}

#[cfg(test)]
mod jwt_tests {
    use super::*;

    fn make_jwt(sub: &str) -> String {
        let header = general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"{}","exp":9999999999}}"#, sub));
        format!("{}.{}.fakesig", header, payload)
    }

    #[test]
    fn extracts_user_id() {
        let token = make_jwt("user-abc-123");
        assert_eq!(extract_user_id_from_jwt(&token).unwrap(), "user-abc-123");
    }

    #[test]
    fn extracts_uuid_user_id() {
        let token = make_jwt("7c1ff9a9-934a-4c4c-b04b-7aac44cdafb3");
        assert_eq!(
            extract_user_id_from_jwt(&token).unwrap(),
            "7c1ff9a9-934a-4c4c-b04b-7aac44cdafb3"
        );
    }

    #[test]
    fn rejects_invalid_format() {
        assert!(extract_user_id_from_jwt("not-a-jwt").is_err());
        assert!(extract_user_id_from_jwt("a.b").is_err());
        assert!(extract_user_id_from_jwt("").is_err());
    }

    #[test]
    fn rejects_invalid_base64_payload() {
        assert!(extract_user_id_from_jwt("a.!!!.c").is_err());
    }

    #[test]
    fn rejects_missing_sub_claim() {
        let header = general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"exp":9999999999}"#);
        let token = format!("{}.{}.sig", header, payload);
        assert!(extract_user_id_from_jwt(&token).is_err());
    }

    #[test]
    fn rejects_non_string_sub() {
        let header = general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":12345}"#);
        let token = format!("{}.{}.sig", header, payload);
        assert!(extract_user_id_from_jwt(&token).is_err());
    }
}

#[cfg(test)]
mod token_expiry_tests {
    use super::*;

    fn make_auth_tokens(expires_at: Option<DateTime<Utc>>) -> AuthTokens {
        AuthTokens {
            access_token: "test".to_string(),
            refresh_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 900,
            expires_at,
            csrf_token: None,
        }
    }

    #[test]
    fn expired_when_no_expiration() {
        let tokens = make_auth_tokens(None);
        assert!(is_token_expired(&tokens));
    }

    #[test]
    fn expired_when_in_the_past() {
        let past = Utc::now() - chrono::Duration::hours(1);
        let tokens = make_auth_tokens(Some(past));
        assert!(is_token_expired(&tokens));
    }

    #[test]
    fn expired_within_60s_buffer() {
        let soon = Utc::now() + chrono::Duration::seconds(30);
        let tokens = make_auth_tokens(Some(soon));
        assert!(is_token_expired(&tokens));
    }

    #[test]
    fn not_expired_well_in_future() {
        let future = Utc::now() + chrono::Duration::hours(1);
        let tokens = make_auth_tokens(Some(future));
        assert!(!is_token_expired(&tokens));
    }

    #[test]
    fn boundary_at_exactly_61s() {
        let boundary = Utc::now() + chrono::Duration::seconds(61);
        let tokens = make_auth_tokens(Some(boundary));
        assert!(!is_token_expired(&tokens));
    }
}

#[cfg(test)]
mod keypair_tests {
    use super::*;

    #[test]
    fn generate_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-wallet.json");

        let (gen_key, gen_pubkey) = generate_solana_keypair(&path, false).unwrap();
        assert!(path.exists());

        let (load_key, load_pubkey) = load_solana_keypair(&path).unwrap();
        assert_eq!(gen_pubkey, load_pubkey);
        assert_eq!(gen_key.to_bytes(), load_key.to_bytes());
    }

    #[test]
    fn generate_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("wallet.json");
        let (_key, pubkey) = generate_solana_keypair(&path, false).unwrap();
        assert!(path.exists());
        assert!(!pubkey.is_empty());
    }

    #[test]
    fn generate_rejects_existing_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        generate_solana_keypair(&path, false).unwrap();
        assert!(generate_solana_keypair(&path, false).is_err());
    }

    #[test]
    fn generate_overwrites_with_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let (_, pub1) = generate_solana_keypair(&path, false).unwrap();
        let (_, pub2) = generate_solana_keypair(&path, true).unwrap();
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn load_rejects_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        assert!(load_solana_keypair(&path).is_err());
    }

    #[test]
    fn load_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, "[1,2,3]").unwrap();
        assert!(load_solana_keypair(&path).is_err());
    }

    #[test]
    fn load_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, "not json").unwrap();
        assert!(load_solana_keypair(&path).is_err());
    }

    #[test]
    fn pubkey_is_valid_base58() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let (_, pubkey) = generate_solana_keypair(&path, false).unwrap();
        assert!(pubkey.len() >= 32 && pubkey.len() <= 44);
        assert!(bs58::decode(&pubkey).into_vec().is_ok());
    }

    #[test]
    fn keypair_can_sign_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let (signing_key, _) = generate_solana_keypair(&path, false).unwrap();

        let message = b"test message for SIWS";
        let signature = signing_key.sign(message);

        let verifying_key: VerifyingKey = (&signing_key).into();
        assert!(verifying_key.verify_strict(message, &signature).is_ok());
    }
}

#[cfg(test)]
mod usage_response_tests {
    use super::*;

    #[test]
    fn parse_nested_breakdown_format() {
        let json = r#"{
            "user_id": "abc",
            "period": "30d",
            "breakdown": {
                "storage": {
                    "gb_transferred": 0.5,
                    "usdc_charged": 0.0,
                    "transfer_count": 10,
                    "tier_details": {}
                },
                "bandwidth": {
                    "gb_transferred": 50.0,
                    "usdc_charged": 0.0,
                    "transfer_count": 200,
                    "tier_details": {
                        "Normal": {
                            "tier_name": "Normal",
                            "transfer_count": 200,
                            "gb_transferred": 50.0
                        }
                    }
                },
                "total": {
                    "gb_transferred": 50.5,
                    "usdc_charged": 0.0
                }
            }
        }"#;

        let resp: UsageResponse = serde_json::from_str(json).unwrap();
        let bd = resp.breakdown.as_ref().unwrap();
        let storage = bd.storage.as_ref().unwrap();
        let bandwidth = bd.bandwidth.as_ref().unwrap();

        assert!((storage.gb_transferred - 0.5).abs() < f64::EPSILON);
        assert_eq!(storage.usdc_charged, 0.0);
        assert!((bandwidth.gb_transferred - 50.0).abs() < f64::EPSILON);
        assert_eq!(bandwidth.transfer_count, 200);
        assert!(bandwidth.tier_details.contains_key("Normal"));
        assert_eq!(bandwidth.tier_details["Normal"].transfer_count, 200);
    }

    #[test]
    fn parse_flat_format_fallback() {
        let json = r#"{
            "storage": {
                "gb_transferred": 1.0,
                "usdc_charged": 0.025,
                "transfer_count": 5,
                "tier_details": {}
            },
            "bandwidth": {
                "gb_transferred": 150.0,
                "usdc_charged": 0.05,
                "transfer_count": 300,
                "tier_details": {}
            },
            "total": {
                "gb_transferred": 151.0,
                "usdc_charged": 0.075
            }
        }"#;

        let resp: UsageResponse = serde_json::from_str(json).unwrap();
        assert!(resp.breakdown.is_none());
        let storage = resp.storage.as_ref().unwrap();
        assert!((storage.gb_transferred - 1.0).abs() < f64::EPSILON);
        let bandwidth = resp.bandwidth.as_ref().unwrap();
        assert!((bandwidth.usdc_charged - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_empty_response() {
        let json = r#"{}"#;
        let resp: UsageResponse = serde_json::from_str(json).unwrap();
        assert!(resp.breakdown.is_none());
        assert!(resp.storage.is_none());
        assert!(resp.bandwidth.is_none());
        assert!(resp.total.is_none());
    }

    #[test]
    fn parse_zero_usage() {
        let json = r#"{
            "user_id": "abc",
            "period": "30d",
            "breakdown": {
                "storage": { "gb_transferred": 0.0, "usdc_charged": 0.0, "transfer_count": 0, "tier_details": {} },
                "bandwidth": { "gb_transferred": 0.0, "usdc_charged": 0.0, "transfer_count": 0, "tier_details": {} },
                "total": { "gb_transferred": 0.0, "usdc_charged": 0.0 }
            }
        }"#;

        let resp: UsageResponse = serde_json::from_str(json).unwrap();
        let bd = resp.breakdown.unwrap();
        assert_eq!(bd.storage.unwrap().transfer_count, 0);
        assert_eq!(bd.bandwidth.unwrap().transfer_count, 0);
        assert_eq!(bd.total.unwrap().usdc_charged, 0.0);
    }
}

#[cfg(test)]
mod profile_response_tests {
    use super::*;

    #[test]
    fn parse_full_profile() {
        let json = r#"{
            "user_id": "7c1ff9a9-934a-4c4c-b04b-7aac44cdafb3",
            "username": "alice",
            "email": "alice@example.com",
            "wallet_public_key": "ABcD1234pubkey",
            "account_state": "active",
            "user_app_key": "",
            "fees_exempt": false
        }"#;
        let p: UserProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p.user_id, "7c1ff9a9-934a-4c4c-b04b-7aac44cdafb3");
        assert_eq!(p.username.as_deref(), Some("alice"));
        assert_eq!(p.wallet_public_key.as_deref(), Some("ABcD1234pubkey"));
        assert_eq!(p.account_state.as_deref(), Some("active"));
    }

    #[test]
    fn parse_minimal_profile() {
        let json = r#"{"user_id": "abc"}"#;
        let p: UserProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p.user_id, "abc");
        assert!(p.username.is_none());
        assert!(p.email.is_none());
        assert!(p.wallet_public_key.is_none());
    }
}

#[cfg(test)]
mod sessions_response_tests {
    use super::*;

    #[test]
    fn parse_sessions_list() {
        let json = r#"{
            "sessions": [
                {
                    "session_id": "sess-001",
                    "created_at": "2026-02-10T12:00:00Z",
                    "expires_at": "2026-02-17T12:00:00Z",
                    "ip_address": "1.2.3.4",
                    "user_agent": "pipe-cli/1.0",
                    "is_current": true
                },
                {
                    "session_id": "sess-002",
                    "created_at": "2026-02-09T08:00:00Z",
                    "expires_at": "2026-02-16T08:00:00Z",
                    "ip_address": "5.6.7.8",
                    "user_agent": "curl/8.0",
                    "is_current": false
                }
            ],
            "count": 2
        }"#;
        let resp: SessionsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.sessions.len(), 2);
        assert!(resp.sessions[0].is_current);
        assert_eq!(resp.sessions[0].session_id, "sess-001");
        assert!(!resp.sessions[1].is_current);
    }

    #[test]
    fn parse_empty_sessions() {
        let json = r#"{"sessions": [], "count": 0}"#;
        let resp: SessionsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.sessions.is_empty());
    }

    #[test]
    fn parse_session_without_optional_fields() {
        let json = r#"{
            "sessions": [{
                "session_id": "s1",
                "created_at": "2026-02-10T00:00:00Z",
                "expires_at": "2026-02-17T00:00:00Z"
            }]
        }"#;
        let resp: SessionsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.sessions.len(), 1);
        assert!(resp.sessions[0].ip_address.is_none());
        assert!(resp.sessions[0].user_agent.is_none());
        assert!(!resp.sessions[0].is_current);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use wiremock::matchers::{method, path, header_exists};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_test_creds() -> SavedCredentials {
        let future_expiry = Utc::now() + chrono::Duration::hours(1);
        SavedCredentials {
            user_id: "test-user".to_string(),
            user_app_key: "".to_string(),
            auth_tokens: Some(AuthTokens {
                access_token: "valid-token".to_string(),
                refresh_token: "refresh".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 900,
                expires_at: Some(future_expiry),
                csrf_token: None,
            }),
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
        }
    }

    #[tokio::test]
    async fn siws_full_auth_flow() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/siws/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "nonce": "test-nonce-123",
                "message": "Sign this message to authenticate"
            })))
            .mount(&server)
            .await;

        let user_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let jwt_payload = general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"{}","exp":9999999999}}"#, user_id));
        let fake_jwt = format!(
            "{}.{}.fakesig",
            general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#),
            jwt_payload
        );

        Mock::given(method("POST"))
            .and(path("/auth/siws/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": fake_jwt,
                "refresh_token": "refresh-token-xyz",
                "token_type": "Bearer",
                "expires_in": 900,
                "csrf_token": "csrf-abc"
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let kp_path = dir.path().join("wallet.json");
        let (signing_key, pubkey_b58) = generate_solana_keypair(&kp_path, false).unwrap();

        let client = Client::new();
        let config_path = dir.path().join("creds.json");
        let config_str = config_path.to_str().unwrap();

        let creds = siws_authenticate(
            &client,
            &server.uri(),
            &signing_key,
            &pubkey_b58,
            Some(config_str),
        )
        .await
        .unwrap();

        assert_eq!(creds.user_id, user_id);
        assert!(creds.auth_tokens.is_some());
        let tokens = creds.auth_tokens.unwrap();
        assert!(tokens.access_token.contains("fakesig"));
        assert_eq!(tokens.csrf_token, Some("csrf-abc".to_string()));
        assert!(tokens.expires_at.is_some());

        let loaded = load_credentials_from_file(Some(config_str)).unwrap().unwrap();
        assert_eq!(loaded.user_id, user_id);
    }

    #[tokio::test]
    async fn siws_challenge_failure() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/siws/challenge"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let kp_path = dir.path().join("wallet.json");
        let (signing_key, pubkey_b58) = generate_solana_keypair(&kp_path, false).unwrap();
        let client = Client::new();

        let result = siws_authenticate(&client, &server.uri(), &signing_key, &pubkey_b58, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("challenge failed"));
    }

    #[tokio::test]
    async fn fetch_credits_status_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/credits/status"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "balance_usdc_raw": 5_000_000,
                "balance_usdc": 5.0,
                "total_deposited_usdc_raw": 10_000_000,
                "total_spent_usdc_raw": 5_000_000,
                "last_topup_at": "2026-01-15T10:00:00Z",
                "quota": {
                    "tier_estimates": [
                        {"tier_name": "Normal", "cost_per_gb_usdc": 0.025, "available_gb": 200.0}
                    ]
                },
                "intent": null
            })))
            .mount(&server)
            .await;

        let future_expiry = Utc::now() + chrono::Duration::hours(1);
        let creds = SavedCredentials {
            user_id: "test-user".to_string(),
            user_app_key: "".to_string(),
            auth_tokens: Some(AuthTokens {
                access_token: "valid-token".to_string(),
                refresh_token: "refresh".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 900,
                expires_at: Some(future_expiry),
                csrf_token: None,
            }),
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
        };

        let client = Client::new();
        let status = fetch_credits_status(&client, &server.uri(), &creds).await.unwrap();

        assert_eq!(status.balance_usdc_raw, 5_000_000);
        assert!((status.balance_usdc - 5.0).abs() < f64::EPSILON);
        assert_eq!(status.total_deposited_usdc_raw, 10_000_000);
        assert_eq!(status.quota.tier_estimates.len(), 1);
        assert_eq!(status.quota.tier_estimates[0].tier_name, "Normal");
        assert!(status.intent.is_none());
    }

    #[tokio::test]
    async fn fetch_credits_falls_back_to_deposit_balance() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/credits/status"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/deposit/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "balance_usdc_raw": 1_000_000,
                "balance_usdc": 1.0,
                "total_deposited_usdc_raw": 1_000_000,
                "total_spent_usdc_raw": 0,
                "quota": { "tier_estimates": [] },
                "intent": null
            })))
            .mount(&server)
            .await;

        let future_expiry = Utc::now() + chrono::Duration::hours(1);
        let creds = SavedCredentials {
            user_id: "test".to_string(),
            user_app_key: "".to_string(),
            auth_tokens: Some(AuthTokens {
                access_token: "tok".to_string(),
                refresh_token: "ref".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 900,
                expires_at: Some(future_expiry),
                csrf_token: None,
            }),
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
        };

        let client = Client::new();
        let status = fetch_credits_status(&client, &server.uri(), &creds).await.unwrap();
        assert_eq!(status.balance_usdc_raw, 1_000_000);
    }

    #[tokio::test]
    async fn token_refresh_flow() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 900,
                "csrf_token": "new-csrf"
            })))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("creds.json");
        let config_str = config_path.to_str().unwrap();

        let past = Utc::now() - chrono::Duration::hours(1);
        let mut creds = SavedCredentials {
            user_id: "test".to_string(),
            user_app_key: "".to_string(),
            auth_tokens: Some(AuthTokens {
                access_token: "old-token".to_string(),
                refresh_token: "valid-refresh".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 900,
                expires_at: Some(past),
                csrf_token: None,
            }),
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
        };
        save_full_credentials(&creds, Some(config_str)).unwrap();

        let client = Client::new();
        ensure_valid_token(&client, &server.uri(), &mut creds, Some(config_str))
            .await
            .unwrap();

        let tokens = creds.auth_tokens.as_ref().unwrap();
        assert_eq!(tokens.access_token, "new-access-token");
        assert_eq!(tokens.csrf_token, Some("new-csrf".to_string()));
        assert!(tokens.expires_at.unwrap() > Utc::now());

        let loaded = load_credentials_from_file(Some(config_str)).unwrap().unwrap();
        assert_eq!(loaded.auth_tokens.unwrap().access_token, "new-access-token");
    }

    #[tokio::test]
    async fn token_refresh_failure_clears_tokens() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/refresh"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("creds.json");
        let config_str = config_path.to_str().unwrap();

        let past = Utc::now() - chrono::Duration::hours(1);
        let mut creds = SavedCredentials {
            user_id: "test".to_string(),
            user_app_key: "".to_string(),
            auth_tokens: Some(AuthTokens {
                access_token: "expired".to_string(),
                refresh_token: "bad-refresh".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 900,
                expires_at: Some(past),
                csrf_token: None,
            }),
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
        };
        save_full_credentials(&creds, Some(config_str)).unwrap();

        let client = Client::new();
        let result = ensure_valid_token(&client, &server.uri(), &mut creds, Some(config_str)).await;
        assert!(result.is_err());
        assert!(creds.auth_tokens.is_none());
    }

    #[tokio::test]
    async fn s3_key_list_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/s3/keys"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "key_name": "key1",
                        "access_key_id": "AKID1234",
                        "bucket_id": "bucket-123",
                        "bucket_name": "my-bucket",
                        "name_prefix": "users/test/",
                        "capabilities": "readWrite",
                        "created_at": "2026-01-01T00:00:00Z"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let future_expiry = Utc::now() + chrono::Duration::hours(1);
        let creds = SavedCredentials {
            user_id: "test".to_string(),
            user_app_key: "".to_string(),
            auth_tokens: Some(AuthTokens {
                access_token: "tok".to_string(),
                refresh_token: "ref".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 900,
                expires_at: Some(future_expiry),
                csrf_token: None,
            }),
            username: None,
            api_base_url: None,
            s3_endpoint: None,
            s3_region: None,
            s3_virtual_hosted: None,
        };

        let client = Client::new();
        let mut request = client.get(format!("{}/api/s3/keys", server.uri()));
        request = add_auth_headers(request, &creds, false).unwrap();
        let resp = request.send().await.unwrap();
        let keys: S3KeyListResponse = resp.json().await.unwrap();

        assert_eq!(keys.keys.len(), 1);
        assert_eq!(keys.keys[0].access_key_id, "AKID1234");
        assert_eq!(keys.keys[0].bucket_name, Some("my-bucket".to_string()));
    }

    #[tokio::test]
    async fn profile_returns_account_info() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/user/me"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user_id": "abc-123",
                "username": "testuser",
                "email": "test@example.com",
                "wallet_public_key": "SoLaNaPubKey123",
                "account_state": "active",
                "fees_exempt": false
            })))
            .mount(&server)
            .await;

        let creds = make_test_creds();
        let client = Client::new();
        let mut request = client.get(format!("{}/user/me", server.uri()));
        request = add_auth_headers(request, &creds, false).unwrap();
        let resp = request.send().await.unwrap();
        let profile: UserProfile = resp.json().await.unwrap();

        assert_eq!(profile.user_id, "abc-123");
        assert_eq!(profile.username.as_deref(), Some("testuser"));
        assert_eq!(profile.wallet_public_key.as_deref(), Some("SoLaNaPubKey123"));
    }

    #[tokio::test]
    async fn logout_clears_session() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/logout"))
            .and(header_exists("Authorization"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message": "Logged out successfully"})),
            )
            .mount(&server)
            .await;

        let creds = make_test_creds();
        let client = Client::new();
        let mut request = client.post(format!("{}/auth/logout", server.uri()));
        request = add_auth_headers(request, &creds, true).unwrap();
        let resp = request.send().await.unwrap();

        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn sessions_list_and_identify_current() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/auth/sessions"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessions": [
                    {
                        "session_id": "sess-current",
                        "created_at": "2026-02-10T12:00:00Z",
                        "expires_at": "2026-02-17T12:00:00Z",
                        "ip_address": "1.2.3.4",
                        "is_current": true
                    },
                    {
                        "session_id": "sess-old",
                        "created_at": "2026-02-09T00:00:00Z",
                        "expires_at": "2026-02-16T00:00:00Z",
                        "ip_address": "5.6.7.8",
                        "is_current": false
                    }
                ],
                "count": 2
            })))
            .mount(&server)
            .await;

        let creds = make_test_creds();
        let client = Client::new();
        let mut request = client.get(format!("{}/auth/sessions", server.uri()));
        request = add_auth_headers(request, &creds, false).unwrap();
        let resp = request.send().await.unwrap();
        let sessions: SessionsResponse = resp.json().await.unwrap();

        assert_eq!(sessions.sessions.len(), 2);
        assert!(sessions.sessions[0].is_current);
        assert_eq!(sessions.sessions[0].session_id, "sess-current");
        assert!(!sessions.sessions[1].is_current);
    }

    #[tokio::test]
    async fn session_revoke_rejects_current() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/auth/sessions/sess-current"))
            .respond_with(ResponseTemplate::new(400).set_body_json(
                serde_json::json!({"error": "Cannot revoke current session. Use logout instead."}),
            ))
            .mount(&server)
            .await;

        let creds = make_test_creds();
        let client = Client::new();
        let mut request = client.delete(format!("{}/auth/sessions/sess-current", server.uri()));
        request = add_auth_headers(request, &creds, true).unwrap();
        let resp = request.send().await.unwrap();

        assert_eq!(resp.status().as_u16(), 400);
    }
}
