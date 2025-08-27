# Ripple Token Transfer Library

A Rust library for interacting with the Ripple Testnet to perform token transfers, verification, and offline transaction signing.

## Features

### Part 1: Token Transfer and Verification
- **Send Token**: Transfer issued assets (tokens) between accounts on Ripple Testnet
- **Verify Transfer**: Verify that a token transfer was completed successfully

### Part 2: Offline Transaction Signing
- **Offline Signing**: Create signed transaction blobs without submitting to the network
- **Submit Signed Transaction**: Submit pre-signed transactions using different connections

### Additional Features
- **Trust Line Management**: Set up trust lines for receiving tokens
- **Account Information**: Get account sequence numbers and other details

## Installation

Add the following dependencies to your `Cargo.toml`:

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

## Usage

### Basic Token Transfer

```rust
use junior_rust::{send_token, verify_token_transfer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Send a token from user1 to user2
    let result = send_token(
        "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5",  // user1_secret
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // user2_address
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // issuer_address
        "USD",  // currency_code
        "100",  // amount
    ).await?;
    
    println!("Transfer result: {:?}", result);
    
    // Verify the transfer
    let is_verified = verify_token_transfer(
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // user1_address
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // user2_address
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // issuer_address
        "USD",  // currency_code
        "100",  // amount
        &result.transaction_hash,  // transaction_hash
    ).await?;
    
    println!("Transfer verified: {}", is_verified);
    
    Ok(())
}
```

### Offline Transaction Signing

```rust
use junior_rust::{sign_transfer_offline, submit_signed_transaction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sign a transaction offline
    let signed_tx = sign_transfer_offline(
        "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5",  // user1_secret
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // user2_address
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // issuer_address
        "USD",  // currency_code
        "100",  // amount
        1,  // sequence
    )?;
    
    println!("Signed transaction: {:?}", signed_tx);
    
    // Submit the signed transaction later
    let submit_result = submit_signed_transaction(
        &signed_tx.tx_blob,
        None,  // use default testnet URL
    ).await?;
    
    println!("Submission result: {:?}", submit_result);
    
    Ok(())
}
```

### Setting Up Trust Lines

```rust
use junior_rust::set_trust_line;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up a trust line to receive USD tokens
    let result = set_trust_line(
        "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5",  // user_secret
        "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",  // issuer_address
        "USD",  // currency_code
        "1000000",  // limit
    ).await?;
    
    println!("Trust line result: {:?}", result);
    
    Ok(())
}
```

## API Reference

### Core Functions

#### `send_token(user1_secret, user2_address, issuer_address, currency_code, amount)`
Sends a token from user1 to user2 on the Ripple Testnet.

**Parameters:**
- `user1_secret`: The secret key of the sender
- `user2_address`: The destination address
- `issuer_address`: The address that issued the token
- `currency_code`: The currency code (e.g., "USD", "EUR")
- `amount`: The amount to transfer

**Returns:** `TokenTransferResult` with transaction details

#### `verify_token_transfer(user1_address, user2_address, issuer_address, currency_code, amount, transaction_hash)`
Verifies that a token transfer was completed successfully.

**Parameters:**
- `user1_address`: The sender's address
- `user2_address`: The recipient's address
- `issuer_address`: The token issuer's address
- `currency_code`: The currency code
- `amount`: The transferred amount
- `transaction_hash`: The transaction hash to verify

**Returns:** `bool` indicating verification success

#### `sign_transfer_offline(user1_secret, user2_address, issuer_address, currency_code, amount, sequence)`
Creates a signed transaction blob without submitting it to the network.

**Parameters:**
- `user1_secret`: The sender's secret key
- `user2_address`: The destination address
- `issuer_address`: The token issuer's address
- `currency_code`: The currency code
- `amount`: The amount to transfer
- `sequence`: The account sequence number

**Returns:** `SignedTransaction` with the signed blob and hash

#### `submit_signed_transaction(tx_blob, testnet_url)`
Submits a pre-signed transaction to the Ripple network.

**Parameters:**
- `tx_blob`: The signed transaction blob
- `testnet_url`: Optional custom testnet URL

**Returns:** `TokenTransferResult` with submission status

### Helper Functions

#### `set_trust_line(user_secret, issuer_address, currency_code, limit)`
Sets up a trust line to receive tokens from a specific issuer.

#### `get_account_sequence(account_address)`
Gets the current sequence number for an account.

## Data Structures

### `TokenTransferResult`
```rust
pub struct TokenTransferResult {
    pub transaction_hash: String,
    pub success: bool,
    pub message: String,
}
```

### `SignedTransaction`
```rust
pub struct SignedTransaction {
    pub tx_blob: String,
    pub transaction_hash: String,
}
```

### `RippleAccount`
```rust
pub struct RippleAccount {
    pub address: String,
    pub secret: String,
}
```

### `Currency`
```rust
pub struct Currency {
    pub code: String,
    pub issuer: String,
}
```

## Configuration

The library is configured to use the Ripple Testnet by default:
- **Testnet URL**: `https://s.altnet.rippletest.net:51234`

You can override this by passing a custom URL to functions that support it.

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never expose private keys**: The `user1_secret` parameter contains sensitive information
2. **Use testnet for development**: This library is configured for Ripple Testnet only
3. **Validate inputs**: Always validate addresses and amounts before sending
4. **Handle errors gracefully**: Network operations can fail, implement proper error handling

## Testing

Run the test suite with:

```bash
cargo test
```

## Examples

See the `examples/` directory for complete working examples of:
- Basic token transfers
- Offline signing workflows
- Trust line management
- Error handling patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This library is for educational and development purposes. Always test thoroughly on testnet before using in production environments. The authors are not responsible for any financial losses resulting from the use of this software.
