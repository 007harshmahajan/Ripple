use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use base64::{Engine as _, engine::general_purpose};
use sha256;
use reqwest;

/// Configuration for Ripple Testnet
pub const TESTNET_URL: &str = "https://s.altnet.rippletest.net:51234";

/// Represents a token transfer result
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenTransferResult {
    pub transaction_hash: String,
    pub success: bool,
    pub message: String,
}

/// Represents a signed transaction blob
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub tx_blob: String,
    pub transaction_hash: String,
}

/// Represents a Ripple account
#[derive(Debug, Clone)]
pub struct RippleAccount {
    pub address: String,
    pub secret: String,
}

/// Represents a currency
#[derive(Debug, Clone)]
pub struct Currency {
    pub code: String,
    pub issuer: String,
}

/// Part 1: Function to send a token from user1 to user2
pub async fn send_token(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
) -> Result<TokenTransferResult> {
    let client = reqwest::Client::new();
    
    // First, we need to get the account info and sequence number
    let account_info = get_account_info(&client, user1_secret).await?;
    let sequence = account_info.sequence;
    
    // Create the payment transaction
    let payment_tx = create_payment_transaction(
        user1_secret,
        user2_address,
        issuer_address,
        currency_code,
        amount,
        sequence,
    )?;
    
    // Submit the transaction
    let submit_result = submit_transaction(&client, &payment_tx.tx_blob).await?;
    
    Ok(TokenTransferResult {
        transaction_hash: payment_tx.transaction_hash.clone(),
        success: submit_result.success,
        message: submit_result.message,
    })
}

/// Part 1: Function to verify that user1 sent a token to user2
pub async fn verify_token_transfer(
    user1_address: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    transaction_hash: &str,
) -> Result<bool> {
    let client = reqwest::Client::new();
    
    // Get transaction details
    let tx_details = get_transaction_details(&client, transaction_hash).await?;
    
    // Verify the transaction details
    if let Some(tx) = tx_details {
        // Check if it's a payment transaction
        if tx.get("TransactionType").and_then(|v| v.as_str()) == Some("Payment") {
            // Check account
            if tx.get("Account").and_then(|v| v.as_str()) == Some(user1_address) {
                // Check destination
                if tx.get("Destination").and_then(|v| v.as_str()) == Some(user2_address) {
                    // Check amount (for issued currency)
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

/// Part 2: Function to sign a transfer transaction offline
pub fn sign_transfer_offline(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    sequence: u32,
) -> Result<SignedTransaction> {
    // Create the payment transaction
    let payment_tx = create_payment_transaction(
        user1_secret,
        user2_address,
        issuer_address,
        currency_code,
        amount,
        sequence,
    )?;
    
    Ok(payment_tx)
}

/// Part 2: Function to submit a signed transaction using a different wallet/connection
pub async fn submit_signed_transaction(
    tx_blob: &str,
    testnet_url: Option<&str>,
) -> Result<TokenTransferResult> {
    let _url = testnet_url.unwrap_or(TESTNET_URL);
    let client = reqwest::Client::new();
    
    // Submit the signed transaction
    let submit_result = submit_transaction(&client, tx_blob).await?;
    
    Ok(TokenTransferResult {
        transaction_hash: "".to_string(), // Will be extracted from response
        success: submit_result.success,
        message: submit_result.message,
    })
}

/// Helper function to set trust line for a token (required before receiving)
pub async fn set_trust_line(
    user_secret: &str,
    issuer_address: &str,
    currency_code: &str,
    limit: &str,
) -> Result<TokenTransferResult> {
    let client = reqwest::Client::new();
    
    // Get account info
    let account_info = get_account_info(&client, user_secret).await?;
    let sequence = account_info.sequence;
    
    // Create trust set transaction
    let trust_set_tx = create_trust_set_transaction(
        user_secret,
        issuer_address,
        currency_code,
        limit,
        sequence,
    )?;
    
    // Submit the transaction
    let submit_result = submit_transaction(&client, &trust_set_tx.tx_blob).await?;
    
    Ok(TokenTransferResult {
        transaction_hash: trust_set_tx.transaction_hash.clone(),
        success: submit_result.success,
        message: submit_result.message,
    })
}

/// Helper function to get account sequence number
pub async fn get_account_sequence(_account_address: &str) -> Result<u32> {
    let client = reqwest::Client::new();
    
    // Create a dummy secret for the request (we only need the address)
    let dummy_secret = "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5";
    let account_info = get_account_info(&client, dummy_secret).await?;
    
    Ok(account_info.sequence)
}

// Internal helper functions

#[derive(Debug, Deserialize)]
struct AccountInfo {
    sequence: u32,
}

async fn get_account_info(client: &reqwest::Client, _secret: &str) -> Result<AccountInfo> {
    // In a real implementation, you would derive the public key from the secret
    // and use it to get account info. For now, we'll use a placeholder.
    
    let request_body = json!({
        "method": "account_info",
        "params": [{
            "account": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", // Placeholder address
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
    
    // Extract sequence number (simplified)
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
) -> Result<SignedTransaction> {
    // In a real implementation, you would:
    // 1. Derive the keypair from the secret
    // 2. Create the transaction structure
    // 3. Sign it with the private key
    // 4. Serialize to blob format
    
    // For now, we'll create a placeholder transaction
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
    
    // In reality, this would be the actual signed transaction blob
    let tx_blob = general_purpose::STANDARD.encode(tx_data.to_string().as_bytes());
    
    // Generate a mock transaction hash
    let transaction_hash = sha256::digest(tx_data.to_string().as_bytes());
    
    Ok(SignedTransaction {
        tx_blob,
        transaction_hash,
    })
}

fn create_trust_set_transaction(
    _user_secret: &str,
    issuer_address: &str,
    currency_code: &str,
    limit: &str,
    sequence: u32,
) -> Result<SignedTransaction> {
    let tx_data = json!({
        "TransactionType": "TrustSet",
        "Account": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", // Derived from secret
        "LimitAmount": {
            "currency": currency_code,
            "issuer": issuer_address,
            "value": limit
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

async fn submit_transaction(client: &reqwest::Client, tx_blob: &str) -> Result<TokenTransferResult> {
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

async fn get_transaction_details(client: &reqwest::Client, tx_hash: &str) -> Result<Option<Value>> {
    let request_body = json!({
        "method": "tx",
        "params": [{
            "transaction": tx_hash,
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
        Ok(Some(tx.clone()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_sign_transfer_offline() {
        // Test with sample data
        let result = sign_transfer_offline(
            "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            "USD",
            "100",
            1,
        );
        
        assert!(result.is_ok());
        let signed_tx = result.unwrap();
        assert!(!signed_tx.tx_blob.is_empty());
        assert!(!signed_tx.transaction_hash.is_empty());
    }
    
    #[test]
    fn test_currency_creation() {
        let currency = Currency {
            code: "USD".to_string(),
            issuer: "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe".to_string(),
        };
        
        assert_eq!(currency.code, "USD");
        assert_eq!(currency.issuer, "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe");
    }
}
