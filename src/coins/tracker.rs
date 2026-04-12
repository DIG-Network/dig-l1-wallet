//! Type conversion boundary between chia-query and the chia SDK.
//!
//! chia-query uses `String` (0x-prefixed hex) for all hash fields.
//! The chia SDK uses typed `Bytes32`, `Coin`, `SpendBundle`, etc.
//! This module bridges the two with conversion functions.
//!
//! Also provides thin async wrappers around chia-query coin query methods.
//!
//! ## Design Decision
//!
//! We centralize all type conversion here rather than scattering it across
//! the crate. This makes it easy to find and audit the hex↔bytes boundary.
//!
//! ## Reference
//!
//! See SPEC.md §13 "Type Conversion Layer".

use chia::protocol::Bytes32;
use chia_query::{ChiaQuery, CoinRecord};

use crate::types::{WalletError, WalletResult};

/// Convert a Bytes32 to a 0x-prefixed hex string (for chia-query).
pub fn bytes32_to_hex(b: &Bytes32) -> String {
    format!("0x{}", hex::encode(b.as_ref()))
}

/// Parse a 0x-prefixed hex string into a Bytes32.
pub fn hex_to_bytes32(s: &str) -> WalletResult<Bytes32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| WalletError::InvalidCoin(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(WalletError::InvalidCoin(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Bytes32::new(arr))
}

/// Convert a chia-query CoinRecord to a chia::protocol::Coin.
pub fn coin_record_to_protocol_coin(
    cr: &chia_query::CoinRecord,
) -> WalletResult<chia::protocol::Coin> {
    let parent = hex_to_bytes32(&cr.coin.parent_coin_info)?;
    let puzzle_hash = hex_to_bytes32(&cr.coin.puzzle_hash)?;
    Ok(chia::protocol::Coin {
        parent_coin_info: parent,
        puzzle_hash,
        amount: cr.coin.amount,
    })
}

/// Convert a chia::protocol::SpendBundle to a chia_query::SpendBundle (hex strings).
pub fn protocol_spend_bundle_to_query(
    bundle: &chia::protocol::SpendBundle,
) -> chia_query::SpendBundle {
    let coin_spends = bundle
        .coin_spends
        .iter()
        .map(|cs| chia_query::CoinSpend {
            coin: chia_query::Coin {
                parent_coin_info: bytes32_to_hex(&cs.coin.parent_coin_info),
                puzzle_hash: bytes32_to_hex(&cs.coin.puzzle_hash),
                amount: cs.coin.amount,
            },
            puzzle_reveal: format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
            solution: format!("0x{}", hex::encode(cs.solution.as_ref())),
        })
        .collect();

    let aggregated_signature = format!("0x{}", hex::encode(bundle.aggregated_signature.to_bytes()));

    chia_query::SpendBundle {
        coin_spends,
        aggregated_signature,
    }
}

/// Fetch unspent XCH coins for a puzzle hash.
pub async fn get_unspent_xch_coins(
    client: &ChiaQuery,
    puzzle_hash_hex: &str,
) -> WalletResult<Vec<CoinRecord>> {
    let records = client
        .get_coin_records_by_puzzle_hash(puzzle_hash_hex, None, None, false)
        .await?;
    Ok(records)
}

/// Fetch unspent CAT coins by hint (puzzle hash).
pub async fn get_unspent_cat_coins_by_hint(
    client: &ChiaQuery,
    puzzle_hash_hex: &str,
) -> WalletResult<Vec<CoinRecord>> {
    let records = client
        .get_coin_records_by_hint(puzzle_hash_hex, None, None, false)
        .await?;
    Ok(records)
}
