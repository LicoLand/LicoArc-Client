//! Caller-owned provider implementations for standalone use.
//!
//! The crate's ports stay caller-owned; these modules are the reference
//! implementations the CLI composes. [`fs::FileCustody`] keeps secrets in one
//! atomically-replaced index file under `0600` — a local development custody
//! backend, not a product keychain. [`mem::MemoryState`] is the coupled
//! in-memory [`crate::ports::AtomicState`]; durability across restarts comes
//! from the SDK's own `Endpoint::checkpoint`/`resume` pair, which is the only
//! codec that can seal an `EndpointState`.

pub mod fs;
pub mod mem;

pub use fs::{CustodyRefusal, FileCustody};
pub use mem::MemoryState;
