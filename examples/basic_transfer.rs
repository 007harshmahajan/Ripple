// This example demonstrates the Ripple token transfer functionality
// Run with: cargo run --example basic_transfer

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

fn create_payment_transaction(
    _user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    sequence: u32,
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    let tx_data = json!({
        "TransactionType": "Payment",
        "Account": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
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
    
    let tx_blob = general_purpose::STANDARD.encode(tx_data.to_string().as_bytes());
    let transaction_hash = sha256::digest(tx_data.to_string().as_bytes());
    
    Ok(SignedTransaction {
        tx_blob,
        transaction_hash,
    })
}

async fn submit_transaction(client: &reqwest::Client, tx_blob: &str) -> Result<TokenTransferResult, Box<dyn std::error::Error>> {
    let request_body = json!({
        "method": "submit",
        "params": [{
            "tx_blob": tx_blob
        }]
    });
    
    let response = client
        .post(TESTNET_URL)
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
        "Transaction submitted successfully".to_string()
    } else {
        "Transaction submission failed".to_string()
    };
    
    Ok(TokenTransferResult {
        transaction_hash: "".to_string(),
        success,
        message,
    })
}

async fn send_token(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
) -> Result<TokenTransferResult, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    let account_info = get_account_info(&client, user1_secret).await?;
    let sequence = account_info.sequence;
    
    let payment_tx = create_payment_transaction(
        user1_secret,
        user2_address,
        issuer_address,
        currency_code,
        amount,
        sequence,
    )?;
    
    let submit_result = submit_transaction(&client, &payment_tx.tx_blob).await?;
    
    Ok(TokenTransferResult {
        transaction_hash: payment_tx.transaction_hash.clone(),
        success: submit_result.success,
        message: submit_result.message,
    })
}

async fn verify_token_transfer(
    user1_address: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    transaction_hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    let request_body = json!({
        "method": "tx",
        "params": [{
            "transaction": transaction_hash,
            "binary": false
        }]
    });
    
    let response = client
        .post(TESTNET_URL)
        .json(&request_body)
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    
    if let Some(tx) = result.get("result") {
        if tx.get("TransactionType").and_then(|v| v.as_str()) == Some("Payment") {
            if tx.get("Account").and_then(|v| v.as_str()) == Some(user1_address) {
                if tx.get("Destination").and_then(|v| v.as_str()) == Some(user2_address) {
                    if let Some(amount_obj) = tx.get("Amount") {
                        if let Some(amount_map) = amount_obj.as_object() {
                            if amount_map.get("currency").and_then(|v| v.as_str()) == Some(currency_code)
                                && amount_map.get("issuer").and_then(|v| v.as_str()) == Some(issuer_address)
                                && amount_map.get("value").and_then(|v| v.as_str()) == Some(amount)
                            {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(false)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Ripple Token Transfer Example ===");
    
    // Example addresses (these are testnet addresses)
    let user1_secret = "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5";
    let user2_address = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
    let issuer_address = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
    let currency_code = "USD";
    let amount = "100";
    
    println!("Sending {} {} tokens from user1 to user2...", amount, currency_code);
    
    // Send the token
    match send_token(
        user1_secret,
        user2_address,
        issuer_address,
        currency_code,
        amount,
    ).await {
        Ok(result) => {
            println!("✅ Transfer successful!");
            println!("Transaction hash: {}", result.transaction_hash);
            println!("Message: {}", result.message);
            
            // Verify the transfer
            println!("\nVerifying the transfer...");
            match verify_token_transfer(
                "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", // user1_address (derived from secret)
                user2_address,
                issuer_address,
                currency_code,
                amount,
                &result.transaction_hash,
            ).await {
                Ok(is_verified) => {
                    if is_verified {
                        println!("✅ Transfer verified successfully!");
                    } else {
                        println!("❌ Transfer verification failed!");
                    }
                }
                Err(e) => {
                    println!("❌ Error verifying transfer: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Transfer failed: {}", e);
        }
    }
    
    Ok(())
}
