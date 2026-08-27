//! Bulk import.
//!
//! The transaction boundary is `docs/M1-IMPORT.md` §1, and it is the reason
//! this is a module rather than a function:
//!
//! ```text
//! 1. read and parse the whole input                  parse.rs
//! 2. normalise and validate against current state    plan.rs
//! 3. resolve merge versus replace                    plan.rs
//! 4. write one key per NEW domain, durably           apply.rs
//! 5. one transaction: rows, snapshot, validation     apply.rs
//! 6. commit once                                     <- point of no return
//! 7. publish
//! ```
//!
//! Every returned error leaves zero rows and removes the keys this run wrote.
//! A process that is *killed* returns nothing and runs no cleanup; what that
//! leaves is documented in §1 under "What a crash leaves".

pub mod apply;
pub mod parse;
pub mod plan;

pub use parse::Conflict;
