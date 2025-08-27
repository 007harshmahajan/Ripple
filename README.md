# Ripple Token Transfer Library

A Rust library for Ripple Testnet token operations implementing the required interview test functionality.

## Requirements Implemented

### Part 1: Token Transfer and Verification
1. **`send_token(user1_secret, user2_address, issuer_address, currency_code, amount)`** - Sends tokens from user1 to user2
2. **`verify_token_transfer(user1_address, user2_address, issuer_address, currency_code, amount, transaction_hash)`** - Verifies token transfers

### Part 2: Offline Transaction Signing
3. **`sign_transfer_offline(user1_secret, user2_address, issuer_address, currency_code, amount, sequence)`** - Creates signed transaction blobs without submitting
4. **`submit_signed_transaction(tx_blob, testnet_url)`** - Submits signed transactions using different connections

## Usage

```rust
use junior_rust::{send_token, verify_token_transfer, sign_transfer_offline, submit_signed_transaction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Send token
    let result = send_token(
        "user1_secret_key",
        "user2_address",
        "issuer_address", 
        "USD",
        "100"
    ).await?;
    
    // Verify transfer
    let verified = verify_token_transfer(
        "user1_address",
        "user2_address",
        "issuer_address",
        "USD", 
        "100",
        &result.transaction_hash
    ).await?;
    
    Ok(())
}
```

## Dependencies

```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
hex = "0.4"
base64 = "0.21"
reqwest = { version = "0.11", features = ["json"] }
sha256 = "1.1"
```

## Testing

```bash
cargo test
```

## Notes

- Uses Ripple Testnet: `https://s.altnet.rippletest.net:51234`
- Mock implementation for demonstration purposes
- All required functions implemented and tested
