use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, AeadCore, OsRng};
use clap::Parser;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;
use anyhow::{Result, Context};
use base64::{engine::general_purpose, Engine as _};

#[derive(Parser, Debug)]
#[command(author, version, about = "High-security payload crypter - unique runtime key every build")]
struct Args {
    /// Path to plaintext payload (JS)
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory for encrypted artifacts
    #[arg(short, long, default_value = "./out")]
    output: PathBuf,

    /// Optional build ID / patch tag
    #[arg(short, long)]
    patch: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CryptOutput {
    version: u32,
    patch_id: String,
    /// Base64 ciphertext (nonce || ciphertext || tag)
    ciphertext: String,
    /// Key is NEVER written to disk in plaintext in production.
    /// For the Worker we store a wrapped form or only the hash + remote oracle.
    key_hash: String,
    /// This field is only present in local/dev builds.
    /// Production builds strip the raw key and rely on the webhook oracle.
    #[serde(skip_serializing_if = "Option::is_none")]
    debug_key: Option<String>,
    created_at: u64,
}

fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bit
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {:?}", e))?;

    // nonce (12) || ciphertext+tag
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let plaintext = fs::read(&args.input)
        .with_context(|| format!("failed to read input {}", args.input.display()))?;

    let key = generate_key();
    let key_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hex::encode(hasher.finalize())
    };

    let encrypted = encrypt(&plaintext, &key)?;

    let patch_id = args.patch.unwrap_or_else(|| {
        let mut id = [0u8; 8];
        OsRng.fill_bytes(&mut id);
        hex::encode(id)
    });

    let output = CryptOutput {
        version: 1,
        patch_id: patch_id.clone(),
        ciphertext: general_purpose::STANDARD.encode(&encrypted),
        key_hash,
        debug_key: Some(hex::encode(key)), // strip this in CI for production
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    fs::create_dir_all(&args.output)?;

    let out_path = args.output.join(format!("payload_{}.json", patch_id));
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, json)?;

    // Also write raw key to a separate file that should NEVER be committed
    let key_path = args.output.join(format!(".key_{}.hex", patch_id));
    fs::write(&key_path, hex::encode(key))?;

    println!("[crypter] patch_id     : {}", patch_id);
    println!("[crypter] key_hash     : {}", output.key_hash);
    println!("[crypter] ciphertext   : {} bytes", encrypted.len());
    println!("[crypter] output       : {}", out_path.display());
    println!("[crypter] raw key file : {} (DO NOT COMMIT)", key_path.display());

    Ok(())
}
