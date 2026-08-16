//! Demonstrates production-ready key management with file-based persistence.
//!
//! This example shows how to use webgates for a real production scenario:
//! - First run: Keys are auto-generated and saved to disk
//! - Subsequent runs: Existing keys are loaded from disk
//! - Public key path is automatically derived (.pub extension)
//!
//! Run with: `cargo run --example production_keygen`

use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use webgates_codecs::Codec as _;
use webgates_codecs::jwt::{
    JsonWebTokenOptions, JwtClaims, RegisteredClaims, authority::JwtAuthority,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct AppClaims {
    user_id: String,
    role: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Production JWT Key Management Example\n");

    // Create a temporary directory for this demo
    let temp_dir = std::env::temp_dir().join("webgates_example");
    fs::create_dir_all(&temp_dir)?;

    let key_path = temp_dir.join("jwt_key");

    // Clean up from any previous run for demo purposes
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(format!("{}.pub", key_path.display()));

    println!("Key storage path: {}", key_path.display());
    println!("───────────────────────────────────────────────────────────────");

    // ===== FIRST RUN: Generate and save keys =====
    println!("\n[RUN 1] First startup - generating and saving keys\n");

    let options_1 = JsonWebTokenOptions::from_private_key_path(&key_path).await?;
    let codec_1 = webgates_codecs::jwt::JsonWebToken::new_with_options(options_1);

    // Check that files were created
    assert!(key_path.exists(), "Private key file should exist");
    let pub_path = format!("{}.pub", key_path.display());
    assert!(
        fs::metadata(&pub_path).is_ok(),
        "Public key file should exist"
    );
    println!("✓ Keys generated and saved:");
    println!("  - Private: {}", key_path.display());
    println!("  - Public:  {}", pub_path);

    // Create and sign a token
    let app_claims = AppClaims {
        user_id: "user1@example.com".to_string(),
        role: "admin".to_string(),
    };

    let expiration = (Utc::now().timestamp() as u64) + 3600;
    let registered = RegisteredClaims::new("test-issuer", expiration);
    let claims = JwtClaims::new(app_claims, registered);

    let token_1 = codec_1.encode(&claims)?;
    let token_1_str = String::from_utf8_lossy(&token_1);
    println!(
        "\n✓ Issued JWT with first key pair: {}...",
        &token_1_str[..50.min(token_1_str.len())]
    );

    // ===== SECOND RUN: Load existing keys =====
    println!("\n───────────────────────────────────────────────────────────────");
    println!("[RUN 2] Second startup - loading existing keys\n");

    let options_2 = JsonWebTokenOptions::from_private_key_path(&key_path).await?;
    let codec_2 = webgates_codecs::jwt::JsonWebToken::new_with_options(options_2);

    println!("✓ Keys loaded from disk (no generation)");

    // Verify: token signed with first key can be verified by second key
    let decoded: JwtClaims<AppClaims> = codec_2.decode(&token_1)?;
    println!("✓ Token from RUN 1 verified successfully by RUN 2");
    println!(
        "  User: {}, Role: {}",
        decoded.custom_claims.user_id, decoded.custom_claims.role
    );

    // Issue a new token with the second codec
    let token_2 = codec_2.encode(&claims)?;
    let token_2_str = String::from_utf8_lossy(&token_2);
    println!(
        "\n✓ Issued JWT with second key pair: {}...",
        &token_2_str[..50.min(token_2_str.len())]
    );

    // Verify: both tokens can be decoded by both codecs (same key pair)
    let _decoded_2: JwtClaims<AppClaims> = codec_1.decode(&token_2)?;
    println!("✓ Token from RUN 2 verified successfully by RUN 1");

    // ===== AUTHORITY BUNDLE (Full auth server) =====
    println!("\n───────────────────────────────────────────────────────────────");
    println!("[AUTH SERVER] Using JwtAuthority for JWKS publication\n");

    let auth_key_path = temp_dir.join("auth_server_key");
    let _ = fs::remove_file(&auth_key_path);
    let _ = fs::remove_file(format!("{}.pub", auth_key_path.display()));

    let authority =
        JwtAuthority::<JwtClaims<AppClaims>>::from_private_key_path(&auth_key_path).await?;

    println!("✓ Authority initialized");
    println!("  Key ID (kid): {}", authority.key_id());
    println!(
        "  JWKS keys: {}",
        authority.jwks_provider().document().keys.len()
    );

    let signing_codec = authority.codec();
    let auth_token = signing_codec.encode(&claims)?;
    let auth_token_str = String::from_utf8_lossy(&auth_token);
    println!(
        "✓ Authority-signed token: {}...",
        &auth_token_str[..50.min(auth_token_str.len())]
    );

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("Summary:");
    println!("  ✓ Production-ready key management");
    println!("  ✓ Auto-save on first run");
    println!("  ✓ Auto-load on subsequent runs");
    println!("  ✓ Public key path auto-derived (.pub)");
    println!("  ✓ Keys persist across restarts");
    println!("  ✓ Perfect for Kubernetes, Docker, systemd");
    println!("═══════════════════════════════════════════════════════════════");

    // Cleanup
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(format!("{}.pub", key_path.display()));
    let _ = fs::remove_file(&auth_key_path);
    let _ = fs::remove_file(format!("{}.pub", auth_key_path.display()));
    let _ = fs::remove_dir(&temp_dir);

    Ok(())
}
