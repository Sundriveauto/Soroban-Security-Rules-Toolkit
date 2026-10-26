//! Source discovery, parsing and a lightweight semantic model of Soroban
//! contract crates.
//!
//! The parser works purely at the source level using [`syn`]. It never
//! compiles or expands macros, so everything it reports is a heuristic view of
//! the code as written.

pub mod cargo;
pub mod discover;
pub mod model;
pub mod project;
pub mod syntax;

pub use cargo::CrateInfo;
pub use discover::{DiscoverError, DiscoverOptions};
pub use model::{AuthStatus, CallSite, CrateModel, FnDef, FnFacts, FnId, FnKind, ModelOptions, StateWrite, Witness};
pub use project::{LoadError, ParseFailure, Project, SourceFile};
pub use syntax::{LineCol, Span, StorageOp, StorageOpKind, StorageTier};
