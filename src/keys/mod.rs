//! Key derivation utilities for Chia HD wallet keys.
//!
//! This module provides the core key derivation chain used throughout the wallet:
//! master key → account key → synthetic key → puzzle hash → address.
//!
//! See [`derivation`] for the full API.

pub mod derivation;

pub use derivation::*;
