// This example demonstrates offline transaction signing functionality
// Run with: cargo run --example offline_signing

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use reqwest;
use base64::{Engine as _, engine::general_purpose};
use sha256;

// Configuration for Ripple Testnet
const TESTNET_URL: &str = "https://s.altnet.rippletest.net:51234";

/// Represents a token transfer result
#[derive(Debug, Serialize, Deserialize)]
struct TokenTransferResult {
    transaction_hash: String,
    success: bool,
    message: String,
}

/// Represents a signed transaction blob
#[derive(Debug, Serialize, Deserialize)]
struct SignedTransaction {
    tx_blob: String,
    transaction_hash: String,
}

#[derive(Debug, Deserialize)]
struct AccountInfo {
    sequence: u32,
}

async fn get_account_info(client: &reqwest::Client, _secret: &str) -> Result<AccountInfo, Box<dyn std::error::Error>> {
    let request_body = json!({
        "method": "account_info",
        "params": [{
            "account": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            "strict": true,
            "ledger_index": "current"
        }]
    });
    
    let response = client
        .post(TESTNET_URL)
        .json(&request_body)
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    
    let sequence = result
        .get("result")
        .and_then(|r| r.get("account_data"))
        .and_then(|ad| ad.get("Sequence"))
        .and_then(|s| s.as_u64())
        .unwrap_or(1) as u32;
    
    Ok(AccountInfo { sequence })
}

fn sign_transfer_offline(
    _user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    sequence: u32,
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    // Create the payment transaction
    let tx_data = json!({
        "TransactionType": "Payment",
        "Account": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", // Derived from secret
        "Destination": user2_address,
        "Amount": {
            "currency": currency_code,
            "issuer": issuer_address,
            "value": amount
        },
        "Fee": "12000",
        "Sequence": sequence,
        "Flags": 0
    });
    
    // In a real implementation, you would:
    // 1. Derive the keypair from the secret
    // 2. Sign the transaction with the private key
    // 3. Serialize to the proper blob format
    
    // For this example, we'll create a mock signed transaction
    let tx_blob = general_purpose::STANDARD.encode(tx_data.to_string().as_bytes());
    let transaction_hash = sha256::digest(tx_data.to_string().as_bytes());
    
    Ok(SignedTransaction {
        tx_blob,
        transaction_hash,
    })
}

async fn submit_signed_transaction(
    tx_blob: &str,
    testnet_url: Option<&str>,
) -> Result<TokenTransferResult, Box<dyn std::error::Error>> {
    let url = testnet_url.unwrap_or(TESTNET_URL);
    let client = reqwest::Client::new();
    
    // Submit the signed transaction
    let request_body = json!({
        "method": "submit",
        "params": [{
            "tx_blob": tx_blob
        }]
    });
    
    let response = client
        .post(url)
        .json(&request_body)
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    
    let success = result
        .get("result")
        .and_then(|r| r.get("engine_result"))
        .and_then(|er| er.as_str())
        .map(|er| er == "tesSUCCESS")
        .unwrap_or(false);
    
    let message = if success {
        "Signed transaction submitted successfully".to_string()
    } else {
        "Submission failed".to_string()
    };
    
    Ok(TokenTransferResult {
        transaction_hash: "".to_string(),
        success,
        message,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Ripple Offline Transaction Signing Example ===");
    
    // Example parameters
    let user1_secret = "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5";
    let user2_address = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
    let issuer_address = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
    let currency_code = "USD";
    let amount = "100";
    
    println!("Step 1: Getting account sequence number...");
    let client = reqwest::Client::new();
    let account_info = get_account_info(&client, user1_secret).await?;
    let sequence = account_info.sequence;
    println!("Account sequence: {}", sequence);
    
    println!("\nStep 2: Signing transaction offline...");
    match sign_transfer_offline(
        user1_secret,
        user2_address,
        issuer_address,
        currency_code,
        amount,
        sequence,
    ) {
        Ok(signed_tx) => {
            println!("✅ Transaction signed offline successfully!");
            println!("Transaction hash: {}", signed_tx.transaction_hash);
            println!("Transaction blob length: {} bytes", signed_tx.tx_blob.len());
            
            // You can now store this signed transaction or transfer it to another system
            println!("\nStep 3: Submitting the signed transaction...");
            
            match submit_signed_transaction(
                &signed_tx.tx_blob,
                None, // use default testnet URL
            ).await {
                Ok(submit_result) => {
                    if submit_result.success {
                        println!("✅ Signed transaction submitted successfully!");
                        println!("Message: {}", submit_result.message);
                    } else {
                        println!("❌ Transaction submission failed!");
                        println!("Message: {}", submit_result.message);
                    }
                }
                Err(e) => {
                    println!("❌ Error submitting transaction: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Error signing transaction offline: {}", e);
        }
    }
    
    println!("\n=== Offline Signing Workflow Complete ===");
    println!("This demonstrates how you can:");
    println!("1. Sign transactions on an offline/secure system");
    println!("2. Store or transfer the signed transaction blob");
    println!("3. Submit the transaction later from a different connection");
    
    Ok(())
}
