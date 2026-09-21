//! Demonstrates automatic key generation for development applications.
//!
//! This example shows how webgates now generates fresh ES384 key pairs on demand,
//! eliminating the need for hardcoded keys or complex key management in development.

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

    // ===== APPROACH 1: JsonWebTokenOptions with explicit generation =====
    println!("Approach 1: JsonWebTokenOptions::generate_for_testing()");
    println!("{}\n", "-".repeat(60));

    let options = JsonWebTokenOptions::generate_for_testing()?;
    let codec = webgates_codecs::jwt::JsonWebToken::new_with_options(options);

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
    println!("  Fresh keys generated, perfect for tests\n");

    // Decode to verify
    let decoded: JwtClaims<AppClaims> = codec.decode(&token)?;
    println!(
        "✓ Decoded successfully: user_id = {}\n",
        decoded.custom_claims.user_id
    );

    // ===== APPROACH 2: Demonstrating key isolation =====
    println!("Approach 2: Keys are isolated between instances\n");
    println!("{}", "-".repeat(60));

    // Generate a completely different key pair
    let different_options = JsonWebTokenOptions::generate_for_testing()?;
    let different_codec = webgates_codecs::jwt::JsonWebToken::new_with_options(different_options);

    // Create a token with the first codec
    let original_token = codec.encode(&claims)?;

    // Try to decode it with a different codec (should fail - different keys)
    let decode_result = different_codec.decode(&original_token);
    match decode_result {
        Err(_) => println!("✓ Different codec rejected token (signature mismatch)"),
        Ok(_) => println!("✗ Unexpected: token validated across different key pairs"),
    }

    // Show that the different codec can create its own tokens
    let different_token = different_codec.encode(&claims)?;
    let different_token_str = String::from_utf8_lossy(&different_token);
    println!(
        "✓ Approach 2 created token with different keys: {}...",
        &different_token_str[..50.min(different_token_str.len())]
    );
    println!("  Each call to generate_for_testing() creates unique keys\n");

    // ===== APPROACH 3: JwtAuthority for signing + JWKS publication =====
    println!("Approach 3: JwtAuthority::generate_for_testing()");
    println!("{}", "-".repeat(60));

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
    println!("  Perfect for full auth servers with JWKS publication\n");

    println!("{}", "=".repeat(60));
    println!("Summary:");
    println!("  ✓ No hardcoded keys");
    println!("  ✓ Fresh key pair on each run");
    println!("  ✓ Perfect for tests and dev");
    println!("  ✓ Production path: JsonWebTokenOptions::from_private_key_path()");
    println!("  ✓ Explicit generation makes intent clear");
    println!("{}", "=".repeat(60));

    Ok(())
}
