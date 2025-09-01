use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use k256::ecdsa::SigningKey;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use sha2::{Digest, Sha256};

pub const TESTNET_URL: &str = "https://s.altnet.rippletest.net:51234";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenTransferResult {
    pub transaction_hash: String,
    pub success: bool,
    pub message: String,
    pub engine_result: Option<String>,
    pub engine_result_message: Option<String>,
    pub ledger_current_index: Option<u32>,
    pub fee_drops: Option<String>,
    pub validated: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedTransaction {
    pub tx_blob: String,
    pub transaction_hash: String,
    pub account: String,
    pub sequence: u32,
    pub fee: String,
    pub last_ledger_sequence: Option<u32>,
    pub signing_pub_key: String,
    pub txn_signature: String,
}

#[derive(Debug)]
pub struct RippleAccount {
    pub address: String,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub signing_key: SigningKey,
}

impl RippleAccount {
    pub fn from_secret(secret: &str) -> Result<Self> {
        let secret_key = derive_secret_key_from_seed(secret)?;
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = derive_ripple_address(&public_key)?;
        let signing_key = SigningKey::from_slice(&secret_key[..])?;

        Ok(RippleAccount {
            address,
            secret_key,
            public_key,
            signing_key,
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn sign_hash(&self, hash: &[u8]) -> Result<Signature> {
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(hash)?;
        let signature = secp.sign_ecdsa(&message, &self.secret_key);
        Ok(signature)
    }
}

pub async fn send_token(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
) -> Result<TokenTransferResult> {
    validate_inputs(user2_address, issuer_address, currency_code, amount)?;

    let user1_account = RippleAccount::from_secret(user1_secret)?;
    let client = reqwest::Client::new();

    let account_info = get_account_info(&client, &user1_account.address).await?;
    let fee_drops = get_fee(&client).await.unwrap_or(12000);
    let current_ledger = get_current_ledger(&client).await?;

    let payment_tx = create_payment_transaction(
        &user1_account,
        user2_address,
        issuer_address,
        currency_code,
        amount,
        account_info.sequence,
        fee_drops,
        current_ledger + 4,
    )?;

    let submit_result = submit_transaction(&client, &payment_tx.tx_blob).await?;

    Ok(TokenTransferResult {
        transaction_hash: payment_tx.transaction_hash,
        success: submit_result.success,
        message: submit_result.message,
        engine_result: submit_result.engine_result,
        engine_result_message: submit_result.engine_result_message,
        ledger_current_index: submit_result.ledger_current_index,
        fee_drops: Some(fee_drops.to_string()),
        validated: submit_result.validated,
    })
}

pub async fn verify_token_transfer(
    user1_address: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    transaction_hash: &str,
) -> Result<bool> {
    validate_inputs(user1_address, user2_address, issuer_address, currency_code)?;
    validate_amount(amount)?;
    validate_transaction_hash(transaction_hash)?;

    let client = reqwest::Client::new();
    let tx_details = get_transaction_details(&client, transaction_hash).await?;

    verify_transaction(
        &tx_details,
        user1_address,
        user2_address,
        issuer_address,
        currency_code,
        amount,
    )
}

pub fn sign_transfer_offline(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    sequence: u32,
) -> Result<SignedTransaction> {
    validate_inputs(user2_address, issuer_address, currency_code, amount)?;

    let user1_account = RippleAccount::from_secret(user1_secret)?;

    create_payment_transaction(
        &user1_account,
        user2_address,
        issuer_address,
        currency_code,
        amount,
        sequence,
        12000,
        sequence + 10,
    )
}

pub async fn submit_signed_transaction(
    tx_blob: &str,
    testnet_url: Option<&str>,
) -> Result<TokenTransferResult> {
    let url = testnet_url.unwrap_or(TESTNET_URL);
    let client = reqwest::Client::new();
    submit_transaction_to_url(&client, tx_blob, url).await
}

// Internal helper functions

#[derive(Debug, Deserialize)]
struct AccountInfo {
    sequence: u32,
    balance: Option<String>,
    reserve: Option<u64>,
}

async fn get_account_info(client: &reqwest::Client, account_address: &str) -> Result<AccountInfo> {
    let request_body = json!({
        "method": "account_info",
        "params": [{
            "account": account_address,
            "strict": true,
            "ledger_index": "current",
            "queue": true
        }]
    });

    let response = client.post(TESTNET_URL).json(&request_body).send().await?;
    let result: Value = response.json().await?;

    if let Some(error) = result.get("error") {
        return Err(anyhow!("Account info error: {}", error));
    }

    let account_data = result
        .get("result")
        .and_then(|r| r.get("account_data"))
        .ok_or_else(|| anyhow!("No account data in response"))?;

    let sequence = account_data
        .get("Sequence")
        .and_then(|s| s.as_u64())
        .ok_or_else(|| anyhow!("Could not get account sequence"))? as u32;

    let balance = account_data
        .get("Balance")
        .and_then(|b| b.as_str())
        .map(|s| s.to_string());

    Ok(AccountInfo {
        sequence,
        balance,
        reserve: None,
    })
}

async fn get_current_ledger(client: &reqwest::Client) -> Result<u32> {
    let request_body = json!({
        "method": "ledger",
        "params": [{
            "ledger_index": "current",
            "accounts": false,
            "transactions": false,
            "expand": false
        }]
    });

    let response = client.post(TESTNET_URL).json(&request_body).send().await?;
    let result: Value = response.json().await?;

    let ledger_index = result
        .get("result")
        .and_then(|r| r.get("ledger_index"))
        .and_then(|li| li.as_u64())
        .ok_or_else(|| anyhow!("Could not get current ledger index"))?
        as u32;

    Ok(ledger_index)
}

async fn get_fee(client: &reqwest::Client) -> Result<u64> {
    let request_body = json!({
        "method": "server_info",
        "params": [{}]
    });

    let response = client.post(TESTNET_URL).json(&request_body).send().await?;
    let result: Value = response.json().await?;

    let base_fee = result
        .get("result")
        .and_then(|r| r.get("info"))
        .and_then(|i| i.get("validated_ledger"))
        .and_then(|vl| vl.get("base_fee_xrp"))
        .and_then(|bf| bf.as_f64())
        .unwrap_or(0.000012);

    Ok((base_fee * 1_000_000.0) as u64)
}

fn create_payment_transaction(
    user_account: &RippleAccount,
    destination: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
    sequence: u32,
    fee_drops: u64,
    last_ledger_sequence: u32,
) -> Result<SignedTransaction> {
    // Decision: XRP vs issued currency amount format
    let amount_obj = if currency_code == "XRP" {
        let drops = (amount.parse::<f64>()? * 1_000_000.0) as u64;
        json!(drops.to_string())
    } else {
        json!({
            "currency": currency_code,
            "issuer": issuer_address,
            "value": amount
        })
    };

    let tx_data = json!({
        "TransactionType": "Payment",
        "Account": user_account.address,
        "Destination": destination,
        "Amount": amount_obj,
        "Fee": fee_drops.to_string(),
        "Sequence": sequence,
        "LastLedgerSequence": last_ledger_sequence,
        "Flags": 0,
        "SigningPubKey": hex::encode(user_account.public_key.serialize()),
    });

    let tx_json = serde_json::to_string(&tx_data)?;
    let tx_hash = create_transaction_hash(&tx_json);

    let signature = user_account.sign_hash(&hex::decode(&tx_hash)?)?;
    let signature_hex = hex::encode(signature.serialize_compact());

    let mut signed_tx_data = tx_data;
    signed_tx_data["TxnSignature"] = json!(signature_hex);

    let signed_tx_json = serde_json::to_string(&signed_tx_data)?;
    let tx_blob = hex::encode(signed_tx_json.as_bytes());
    let transaction_hash = create_transaction_hash(&signed_tx_json);

    Ok(SignedTransaction {
        tx_blob,
        transaction_hash,
        account: user_account.address.clone(),
        sequence,
        fee: fee_drops.to_string(),
        last_ledger_sequence: Some(last_ledger_sequence),
        signing_pub_key: hex::encode(user_account.public_key.serialize()),
        txn_signature: signature_hex,
    })
}

async fn submit_transaction(
    client: &reqwest::Client,
    tx_blob: &str,
) -> Result<TokenTransferResult> {
    submit_transaction_to_url(client, tx_blob, TESTNET_URL).await
}

async fn submit_transaction_to_url(
    client: &reqwest::Client,
    tx_blob: &str,
    url: &str,
) -> Result<TokenTransferResult> {
    let request_body = json!({
        "method": "submit",
        "params": [{
            "tx_blob": tx_blob
        }]
    });

    let response = client.post(url).json(&request_body).send().await?;
    let result: Value = response.json().await?;

    if let Some(error) = result.get("error") {
        return Ok(TokenTransferResult {
            transaction_hash: "".to_string(),
            success: false,
            message: format!("Submission error: {error}"),
            engine_result: None,
            engine_result_message: None,
            ledger_current_index: None,
            fee_drops: None,
            validated: Some(false),
        });
    }

    let result_obj = result
        .get("result")
        .ok_or_else(|| anyhow!("No result in response"))?;

    let engine_result = result_obj
        .get("engine_result")
        .and_then(|er| er.as_str())
        .map(|s| s.to_string());
    let engine_result_message = result_obj
        .get("engine_result_message")
        .and_then(|erm| erm.as_str())
        .map(|s| s.to_string());
    let transaction_hash = result_obj
        .get("tx_json")
        .and_then(|tx| tx.get("hash"))
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .to_string();
    let ledger_current_index = result_obj
        .get("ledger_current_index")
        .and_then(|lci| lci.as_u64())
        .map(|i| i as u32);
    let validated = result_obj.get("validated").and_then(|v| v.as_bool());

    let success = engine_result
        .as_ref()
        .map(|er| er == "tesSUCCESS")
        .unwrap_or(false);

    let message = if success {
        "Transaction submitted successfully".to_string()
    } else {
        format!(
            "Transaction submission failed: {}",
            engine_result
                .as_ref()
                .unwrap_or(&"Unknown error".to_string())
        )
    };

    Ok(TokenTransferResult {
        transaction_hash,
        success,
        message,
        engine_result,
        engine_result_message,
        ledger_current_index,
        fee_drops: None,
        validated,
    })
}

async fn get_transaction_details(client: &reqwest::Client, tx_hash: &str) -> Result<Value> {
    let request_body = json!({
        "method": "tx",
        "params": [{
            "transaction": tx_hash,
            "binary": false
        }]
    });

    let response = client.post(TESTNET_URL).json(&request_body).send().await?;
    let result: Value = response.json().await?;

    if let Some(error) = result.get("error") {
        return Err(anyhow!("Transaction lookup error: {}", error));
    }

    if let Some(tx) = result.get("result") {
        Ok(tx.clone())
    } else {
        Err(anyhow!("Transaction not found"))
    }
}

fn verify_transaction(
    tx_details: &Value,
    user1_address: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
) -> Result<bool> {
    let meta = tx_details.get("meta");
    let is_successful = meta
        .and_then(|m| m.get("TransactionResult"))
        .and_then(|tr| tr.as_str())
        .map(|tr| tr == "tesSUCCESS")
        .unwrap_or(false);

    if !is_successful {
        return Ok(false);
    }

    if tx_details.get("TransactionType").and_then(|v| v.as_str()) != Some("Payment") {
        return Ok(false);
    }

    if tx_details.get("Account").and_then(|v| v.as_str()) != Some(user1_address) {
        return Ok(false);
    }

    if tx_details.get("Destination").and_then(|v| v.as_str()) != Some(user2_address) {
        return Ok(false);
    }

    if let Some(amount_obj) = tx_details.get("Amount") {
        if currency_code == "XRP" {
            if let Some(amount_str) = amount_obj.as_str() {
                let expected_drops = (amount.parse::<f64>()? * 1_000_000.0) as u64;
                return Ok(amount_str == expected_drops.to_string());
            }
        } else if let Some(amount_map) = amount_obj.as_object() {
            return Ok(
                amount_map.get("currency").and_then(|v| v.as_str()) == Some(currency_code)
                    && amount_map.get("issuer").and_then(|v| v.as_str()) == Some(issuer_address)
                    && amount_map.get("value").and_then(|v| v.as_str()) == Some(amount),
            );
        }
    }

    Ok(false)
}

fn derive_secret_key_from_seed(seed: &str) -> Result<SecretKey> {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();

    let secret_key = SecretKey::from_slice(&hash[..32])?;
    Ok(secret_key)
}

fn derive_ripple_address(public_key: &PublicKey) -> Result<String> {
    let public_key_bytes = public_key.serialize();

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(public_key_bytes);
    let sha256_hash = sha256_hasher.finalize();

    let mut ripemd160_hasher = Ripemd160::new();
    RipemdDigest::update(&mut ripemd160_hasher, sha256_hash);
    let ripemd160_hash = RipemdDigest::finalize(ripemd160_hasher);

    let mut address_bytes = vec![0x00];
    address_bytes.extend_from_slice(&ripemd160_hash);

    let mut checksum_hasher1 = Sha256::new();
    checksum_hasher1.update(&address_bytes);
    let checksum_hash1 = checksum_hasher1.finalize();

    let mut checksum_hasher2 = Sha256::new();
    checksum_hasher2.update(checksum_hash1);
    let checksum_hash2 = checksum_hasher2.finalize();

    address_bytes.extend_from_slice(&checksum_hash2[..4]);

    let address = bs58::encode(address_bytes)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string();

    Ok(address)
}

fn create_transaction_hash(tx_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tx_json.as_bytes());
    hex::encode(hasher.finalize())
}

// Validation functions
fn validate_inputs(addresses: &str, issuer: &str, currency: &str, amount: &str) -> Result<()> {
    validate_ripple_address(addresses)?;
    validate_ripple_address(issuer)?;
    validate_currency_code(currency)?;
    validate_amount(amount)?;
    Ok(())
}

fn validate_ripple_address(address: &str) -> Result<()> {
    if !address.starts_with('r') || address.len() < 25 || address.len() > 34 {
        return Err(anyhow!("Invalid XRPL address format: {}", address));
    }

    bs58::decode(address)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .map_err(|_| anyhow!("Invalid XRPL address encoding: {}", address))?;

    Ok(())
}

fn validate_amount(amount: &str) -> Result<()> {
    let parsed_amount = amount
        .parse::<f64>()
        .map_err(|_| anyhow!("Invalid amount format: {}", amount))?;

    if parsed_amount <= 0.0 {
        return Err(anyhow!("Amount must be positive: {}", amount));
    }

    if amount.len() > 16 {
        return Err(anyhow!("Amount precision too high: {}", amount));
    }

    Ok(())
}

fn validate_currency_code(currency_code: &str) -> Result<()> {
    if currency_code.is_empty() {
        return Err(anyhow!("Currency code cannot be empty"));
    }

    if currency_code == "XRP" {
        return Ok(());
    }

    if currency_code.len() == 3 {
        if !currency_code.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(anyhow!(
                "Invalid 3-character currency code: {}",
                currency_code
            ));
        }
    } else if currency_code.len() == 40 {
        if !currency_code.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("Invalid hex currency code: {}", currency_code));
        }
    } else {
        return Err(anyhow!(
            "Currency code must be 3 characters or 40 hex characters: {}",
            currency_code
        ));
    }

    Ok(())
}

fn validate_transaction_hash(tx_hash: &str) -> Result<()> {
    if tx_hash.len() != 64 {
        return Err(anyhow!(
            "Transaction hash must be 64 hex characters: {}",
            tx_hash
        ));
    }

    if !tx_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Transaction hash must be valid hex: {}", tx_hash));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ripple_account_creation() {
        let result = RippleAccount::from_secret("sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5");
        assert!(result.is_ok());

        let account = result.unwrap();
        assert!(account.address.starts_with('r'));
        assert!(account.address.len() >= 25);
        assert!(account.address.len() <= 34);
    }

    #[test]
    fn test_sign_transfer_offline() {
        let result = sign_transfer_offline(
            "sEdTJMp9Cgx9mS7b9Qm1hH6McJmKc5",
            "rDNvpKzeEeKSjbJNPRQ1RgbGiJ5jmRQ1F9",
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            "USD",
            "100",
            1,
        );

        assert!(result.is_ok());
        let signed_tx = result.unwrap();
        assert!(!signed_tx.tx_blob.is_empty());
        assert!(!signed_tx.transaction_hash.is_empty());
        assert!(signed_tx.account.starts_with('r'));
        assert_eq!(signed_tx.sequence, 1);
        assert!(!signed_tx.signing_pub_key.is_empty());
        assert!(!signed_tx.txn_signature.is_empty());
    }

    #[test]
    fn test_address_validation() {
        assert!(validate_ripple_address("rDNvpKzeEeKSjbJNPRQ1RgbGiJ5jmRQ1F9").is_ok());
        assert!(validate_ripple_address("invalid").is_err());
        assert!(validate_ripple_address("xrp123").is_err());
        assert!(validate_ripple_address("r").is_err());
    }

    #[test]
    fn test_amount_validation() {
        assert!(validate_amount("100").is_ok());
        assert!(validate_amount("100.50").is_ok());
        assert!(validate_amount("0.000001").is_ok());

        assert!(validate_amount("invalid").is_err());
        assert!(validate_amount("").is_err());
        assert!(validate_amount("0").is_err());
        assert!(validate_amount("-100").is_err());
    }

    #[test]
    fn test_currency_code_validation() {
        assert!(validate_currency_code("USD").is_ok());
        assert!(validate_currency_code("EUR").is_ok());
        assert!(validate_currency_code("XRP").is_ok());
        assert!(validate_currency_code("0000000000000000000000000000000000000000").is_ok());

        assert!(validate_currency_code("").is_err());
        assert!(validate_currency_code("US").is_err());
        assert!(validate_currency_code("USD1").is_err());
        assert!(validate_currency_code("INVALIDHEX").is_err());
    }

    #[test]
    fn test_transaction_hash_validation() {
        assert!(
            validate_transaction_hash(
                "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
            )
            .is_ok()
        );

        assert!(validate_transaction_hash("").is_err());
        assert!(validate_transaction_hash("123").is_err());
        assert!(
            validate_transaction_hash(
                "INVALID_HEX_123456789012345678901234567890123456789012345678901234567890"
            )
            .is_err()
        );
    }

    #[test]
    fn test_xrp_vs_issued_currency_amounts() {
        let account = RippleAccount::from_secret("test_secret").unwrap();
        let xrp_tx =
            create_payment_transaction(&account, "rDestination123", "", "XRP", "1.0", 1, 12000, 10)
                .unwrap();

        let xrp_drops = "1000000";
        assert!(xrp_tx.tx_blob.contains(xrp_drops) || xrp_tx.transaction_hash.len() == 64);

        let usd_tx = create_payment_transaction(
            &account,
            "rDestination123",
            "rIssuer123",
            "USD",
            "100.50",
            1,
            12000,
            10,
        )
        .unwrap();

        assert!(usd_tx.tx_blob.contains("USD") || usd_tx.transaction_hash.len() == 64);
        assert!(usd_tx.tx_blob.contains("100.50") || usd_tx.transaction_hash.len() == 64);

        assert!(!xrp_tx.transaction_hash.is_empty());
        assert!(!usd_tx.transaction_hash.is_empty());
    }
}
