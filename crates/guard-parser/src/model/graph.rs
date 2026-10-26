//! The resolved call graph and per-function caches.
//!
//! Call sites are resolved once when the model is built; queries that walk
//! helpers look callees up instead of re-resolving names. Results of the
//! expensive top-level queries are cached per function, since several rules
//! ask the same question about the same export.

use std::sync::OnceLock;

use super::{AuthStatus, Debit, FnId, SubjectAuth};

/// `edges[f][c]` = functions call site `c` of function `f` may refer to.
#[derive(Debug, Default)]
pub(super) struct CallGraph {
    pub(super) edges: Vec<Vec<Vec<FnId>>>,
}

/// Lazily computed, per-function query results.
#[derive(Debug, Default)]
pub(super) struct QueryCache {
    pub(super) reachable: Vec<OnceLock<Vec<FnId>>>,
    pub(super) auth_status: Vec<OnceLock<AuthStatus>>,
    pub(super) subject_auth: Vec<OnceLock<SubjectAuth>>,
    pub(super) debits: Vec<OnceLock<Vec<Debit>>>,
}

impl QueryCache {
    pub(super) fn new(n: usize) -> Self {
        QueryCache {
            reachable: (0..n).map(|_| OnceLock::new()).collect(),
            auth_status: (0..n).map(|_| OnceLock::new()).collect(),
            subject_auth: (0..n).map(|_| OnceLock::new()).collect(),
            debits: (0..n).map(|_| OnceLock::new()).collect(),
        }
    }
}
