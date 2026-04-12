# dig-l1-wallet

Self-custodial Chia L1 wallet crate with XCH and CAT (Chia Asset Token) support. Manages keys, encrypts secrets at rest, queries balances, selects/splits/combines coins, builds and broadcasts transactions — all through a single `L1Wallet` entry point backed by [`chia-query`](https://crates.io/crates/chia-query).

## Installation

```toml
[dependencies]
dig-l1-wallet = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use dig_l1_wallet::{L1Wallet, L1WalletConfig, CoinSelectionStrategy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = L1Wallet::new(L1WalletConfig::default()).await?;

    // Create wallet — returns 24-word mnemonic for backup
    let backup = wallet.create_wallet("my-wallet", "password").await?;
    println!("Mnemonic: {}", backup.mnemonic);
    println!("Address:  {}", backup.first_address);

    // Unlock to enable signing
    wallet.unlock("my-wallet", "password")?;

    // Query balance
    let bal = wallet.get_xch_balance("my-wallet", Some(0)).await?;
    println!("Balance: {} mojos", bal.confirmed);

    wallet.lock("my-wallet");
    Ok(())
}
```

## Public API

All methods live on the `L1Wallet` struct. Async methods require a tokio runtime.

### Wallet lifecycle

| Method | Description |
|--------|-------------|
| `L1Wallet::new(config)` | Connect to the Chia network via chia-query |
| `create_wallet(name, password)` | Generate BIP39 mnemonic, encrypt master key, create index-0 account |
| `import_from_mnemonic(name, mnemonic, password)` | Import from existing 24-word phrase |
| `import_from_secret_key(name, &[u8; 32], password)` | Import from raw BLS secret key bytes |
| `list_wallets()` | List all `.wallet` files in the wallet directory |
| `delete_wallet(name)` | Remove a wallet file from disk |
| `rename_wallet(old, new)` | Rename a wallet (file + internal name) |

### Lock / Unlock

| Method | Description |
|--------|-------------|
| `unlock(name, password)` | Decrypt master key, derive all account keys into memory |
| `lock(name)` | Drop all decrypted key material from memory |
| `is_unlocked(name)` | Check if a wallet is currently unlocked |

### Account management

Each wallet supports multiple derived accounts at `m/12381/8444/2/{index}`. Index 0 is created automatically.

| Method | Description |
|--------|-------------|
| `create_account(wallet, name)` | Derive the next account index |
| `list_accounts(wallet)` | List all accounts with address and puzzle hash |

### Balance queries

The `account_index` parameter controls scope:
- `Some(0)` — balance for derivation index 0 (the default)
- `Some(n)` — balance for a specific derivation
- `None` — aggregated balance across **all** derivations

| Method | Description |
|--------|-------------|
| `get_xch_balance(wallet, account_index)` | XCH balance in mojos |
| `get_cat_balance(wallet, account_index, asset_id)` | CAT balance by TAIL hash |

```rust
// Single derivation
let bal = wallet.get_xch_balance("my-wallet", Some(0)).await?;

// All derivations aggregated
let total = wallet.get_xch_balance("my-wallet", None).await?;
```

### Sending

Transactions require a specific derivation index (the signing key must be unambiguous).

| Method | Description |
|--------|-------------|
| `send_xch(wallet, index, to_address, amount, fee)` | Send XCH to a bech32m address |
| `send_cat(wallet, index, asset_id, to_address, amount, fee)` | Send a CAT by TAIL hash |
| `broadcast_spend_bundle(&SpendBundle)` | Broadcast a pre-built spend bundle |
| `wait_for_confirmation(coin_id, timeout)` | Poll until a coin is confirmed |
| `estimate_fee(spend_count)` | Get fee estimates for target confirmation times |

```rust
let tx = wallet.send_xch(
    "my-wallet",
    0,                          // derivation index
    "xch1destination...",       // bech32m address
    1_000_000_000_000,          // 1 XCH in mojos
    50_000_000,                 // fee in mojos
).await?;
println!("Success: {}, Status: {}", tx.success, tx.status);
```

### Coin management

Coin listing and selection support cross-derivation pooling (`account_index = None`).

| Method | Description |
|--------|-------------|
| `get_unspent_coins(wallet, account_index)` | List unspent XCH UTXOs |
| `get_unspent_cat_coins(wallet, account_index, asset_id)` | List unspent CAT UTXOs |
| `select_coins(wallet, account_index, target, strategy)` | Select coins without broadcasting |
| `select_cat_coins(wallet, account_index, asset_id, target, strategy)` | Select CAT coins |
| `combine_coins(wallet, index, coin_ids, fee)` | Merge multiple coins into one |
| `combine_cat_coins(wallet, index, asset_id, coin_ids, fee)` | Merge CAT coins |
| `split_coins(wallet, index, coin_id, count, fee)` | Split one coin into N pieces |
| `split_cat_coins(wallet, index, asset_id, coin_id, count, fee)` | Split a CAT coin |

#### Coin selection strategies

```rust
use dig_l1_wallet::CoinSelectionStrategy;

// Knapsack (default) — delegates to chia_wallet_sdk::utils::select_coins
let sel = wallet.select_coins("w", Some(0), 500_000, CoinSelectionStrategy::Knapsack).await?;

// Largest first — minimizes input count
let sel = wallet.select_coins("w", None, 500_000, CoinSelectionStrategy::LargestFirst).await?;

// Smallest first — consolidates dust
let sel = wallet.select_coins("w", None, 500_000, CoinSelectionStrategy::SmallestFirst).await?;

println!("Selected {} coins, total={}, change={}", sel.coin_count, sel.total, sel.change);
```

## Types

### Response types

| Type | Fields | Returned by |
|------|--------|-------------|
| `MnemonicBackup` | `mnemonic`, `wallet_name`, `first_address` | `create_wallet` |
| `AccountInfo` | `name`, `index`, `puzzle_hash`, `address` | `create_account`, `list_accounts` |
| `Balance` | `confirmed`, `pending`, `spendable`, `coin_count` | `get_xch_balance`, `get_cat_balance` |
| `TxResult` | `tx_id`, `status`, `success` | `send_xch`, `send_cat`, `combine_coins`, `split_coins` |
| `CoinSelection` | `coins`, `total`, `change`, `coin_count` | `select_coins`, `select_cat_coins` |

### Configuration

```rust
use dig_l1_wallet::{L1WalletConfig, NetworkType};

let config = L1WalletConfig {
    network: NetworkType::Testnet11,    // or Mainnet (default)
    wallet_dir: "/custom/path".into(),  // default: ~/.dig/wallets/
    query_config: Default::default(),   // chia-query peer/coinset config
    auto_lock_timeout_secs: 0,          // 0 = disabled
};
```

### Error handling

All methods return `Result<T, WalletError>`. Key variants:

```rust
use dig_l1_wallet::WalletError;

match result {
    Err(WalletError::WalletNotFound(name)) => { /* wallet file missing */ }
    Err(WalletError::WalletLocked) => { /* call unlock() first */ }
    Err(WalletError::InvalidPassword) => { /* wrong password */ }
    Err(WalletError::InsufficientFunds { available, required }) => { /* not enough */ }
    Err(WalletError::InvalidAddress(msg)) => { /* bad bech32m */ }
    Err(WalletError::Query(e)) => { /* chia-query / network error */ }
    _ => {}
}
```

## Architecture

```
L1Wallet (wallet.rs)           ← Public API orchestrator
  ├── keystore/                 ← Key management
  │   ├── encryption.rs         ← AES-256-GCM + Argon2id
  │   └── mnemonic.rs           ← BIP39 generation and import
  ├── keys/derivation.rs        ← HD path m/12381/8444/2/{index}
  ├── coins/                    ← Coin queries and selection
  │   ├── tracker.rs            ← chia-query wrappers + type conversion
  │   └── selection.rs          ← Knapsack, LargestFirst, SmallestFirst
  ├── transaction/              ← Spend bundle construction
  │   ├── mod.rs                ← XCH send/combine/split + BLS signing
  │   └── cat.rs                ← CAT send/combine/split + lineage proofs
  ├── storage/                  ← .wallet file I/O
  │   └── format.rs             ← WalletFile JSON schema
  └── types/                    ← Error, config, response types
```

**Blockchain access**: All chain interaction goes through `chia-query`. This crate never opens peer connections directly.

**Encryption**: Master key is encrypted with AES-256-GCM. Password is derived via Argon2id (64 MB memory, 3 iterations, 4 lanes). Decrypted keys are held in memory only while unlocked.

**Spending pattern**: Uses `SpendContext` + `StandardLayer` + `assert_concurrent_spend` from `chia-wallet-sdk`. First coin carries all conditions; remaining coins assert concurrent spend. Adapted from [DataLayer-Driver](https://github.com/DIG-Network/DataLayer-Driver).

**Signing pattern**: Maps each secret key to both original PK and synthetic PK, then matches against `RequiredSignature::from_coin_spends`. Adapted from DataLayer-Driver.

## Chia Crate Dependencies

| Crate | Version | Role |
|-------|---------|------|
| `chia` | 0.26 | BLS keys, protocol types, puzzle types |
| `chia-wallet-sdk` | 0.30 | StandardLayer, SpendContext, Conditions, RequiredSignature, Address |
| `chia-puzzle-types` | 0.26 | StandardArgs, DeriveSynthetic, CatArgs |
| `chia-query` | latest | Blockchain backend (peer + coinset.org fallback) |
| `clvmr` | 0.14 | CLVM allocator for signature extraction |

## License

MIT
