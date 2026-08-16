//! Demonstrates the improved developer experience with automatic key generation.
//!
//! This example shows how webgates now generates fresh ES384 key pairs on demand,
//! eliminating the need for hardcoded keys or complex key management in development.
//!
//! Run with: `cargo run --example dev_keygen`

use chrono::Utc;
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
    println!("🔑 WebGates JWT Key Generation Example\n");

    // ===== APPROACH 1: Using Default (fresh keys every time) =====
    println!("Approach 1: Default constructor generates fresh keys");
    println!("{}", "-".repeat(60));

    let options_default = JsonWebTokenOptions::default();
    let codec = webgates_codecs::jwt::JsonWebToken::new_with_options(options_default);

    let app_claims = AppClaims {
        user_id: "alice@example.com".to_string(),
        role: "admin".to_string(),
    };

    let expiration = (Utc::now().timestamp() as u64) + 3600;
    let registered = RegisteredClaims::new("example-issuer", expiration);
    let claims = JwtClaims::new(app_claims, registered);

    let token = codec.encode(&claims)?;
    let token_str = String::from_utf8_lossy(&token);
    println!(
        "✓ Encoded JWT: {}...",
        &token_str[..50.min(token_str.len())]
    );
    println!("  This token is now usable for local development!\n");

    // Decode to verify
    let decoded: JwtClaims<AppClaims> = codec.decode(&token)?;
    println!(
        "✓ Decoded successfully: user_id = {}",
        decoded.custom_claims.user_id
    );

    // ===== APPROACH 2: Explicit generate_for_testing() =====
    println!("\n{}", "-".repeat(60));
    println!("Approach 2: Explicit generate_for_testing() method\n");

    let fresh_options = JsonWebTokenOptions::generate_for_testing()?;
    let fresh_codec = webgates_codecs::jwt::JsonWebToken::new_with_options(fresh_options);

    let fresh_token = fresh_codec.encode(&claims)?;
    let fresh_token_str = String::from_utf8_lossy(&fresh_token);
    println!(
        "✓ Generated fresh token: {}...",
        &fresh_token_str[..50.min(fresh_token_str.len())]
    );

    // Tokens from different key pairs won't validate with each other
    let decode_result = codec.decode(&fresh_token);
    match decode_result {
        Err(_) => println!("✓ Correctly rejected token from different key pair"),
        Ok(_) => println!("✗ Unexpectedly accepted token from different key pair"),
    }

    // ===== APPROACH 3: Authority with fresh keys =====
    println!("\n{}", "-".repeat(60));
    println!("Approach 3: JwtAuthority::generate_for_testing()\n");

    let authority = JwtAuthority::<JwtClaims<AppClaims>>::generate_for_testing()?;
    let signing_codec = authority.codec();
    let jwks = authority.jwks_provider();

    let authority_token = signing_codec.encode(&claims)?;
    let auth_token_str = String::from_utf8_lossy(&authority_token);
    println!(
        "✓ Authority-signed token: {}...",
        &auth_token_str[..50.min(auth_token_str.len())]
    );
    println!("✓ JWKS endpoint ready with kid: {}", authority.key_id());
    println!("✓ JWKS document keys: {}", jwks.document().keys.len());

    println!("\n{}", "=".repeat(60));
    println!("Summary:");
    println!("  ✓ No hardcoded keys");
    println!("  ✓ Fresh key pair on each run");
    println!("  ✓ Perfect for tests and dev");
    println!("  ✓ Production path: JsonWebTokenOptions::from_es384_pem()");
    println!("{}", "=".repeat(60));

    Ok(())
}
