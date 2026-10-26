//! Questions about functions that follow calls into helpers.

use super::*;

impl<'a> CrateModel<'a> {
    /// Finds where `pred` holds, either directly in `id` or in any function it
    /// (transitively) calls. `pred` returns the first matching span in a body.
    pub fn witness(&self, id: FnId, pred: &dyn Fn(&FnDef<'_>, &FnFacts) -> Option<Span>) -> Option<Witness> {
        let mut visited = HashSet::new();
        self.witness_inner(id, pred, &mut visited)
    }

    fn witness_inner(
        &self,
        id: FnId,
        pred: &dyn Fn(&FnDef<'_>, &FnFacts) -> Option<Span>,
        visited: &mut HashSet<FnId>,
    ) -> Option<Witness> {
        if !visited.insert(id) {
            return None;
        }
        if let Some(span) = pred(&self.fns[id], &self.facts[id]) {
            return Some(Witness { span, via: vec![] });
        }
        for call in &self.facts[id].calls {
            for callee in self.resolve(id, call) {
                if let Some(w) = self.witness_inner(callee, pred, visited) {
                    let mut via = vec![self.fns[callee].name.clone()];
                    via.extend(w.via);
                    return Some(Witness { span: call.span, via });
                }
            }
        }
        None
    }

    /// `true` if `id` or anything it calls performs an authorization check on at least one path.
    pub fn performs_auth(&self, id: FnId) -> bool {
        self.auth_status(id) != AuthStatus::Never
    }

    /// Whether `id`, directly or through the helpers it calls, authorizes on
    /// every path, on some paths, or never.
    ///
    /// Helpers whose names look like auth checks are followed into their bodies
    /// when the crate defines them, so an empty `fn check_admin() {}` does not count.
    pub fn auth_status(&self, id: FnId) -> AuthStatus {
        let mut visited = HashSet::new();
        self.auth_status_inner(id, &mut visited)
    }

    fn auth_status_inner(&self, id: FnId, stack: &mut HashSet<FnId>) -> AuthStatus {
        if stack.len() > MAX_DEPTH || !stack.insert(id) {
            return AuthStatus::Never;
        }
        let status = self.auth_status_body(id, stack);
        stack.remove(&id);
        status
    }

    fn auth_status_body(&self, id: FnId, visited: &mut HashSet<FnId>) -> AuthStatus {
        let def = &self.fns[id];
        let facts = &self.facts[id];
        if facts.auth_attr || def.attrs.iter().any(is_auth_attr) || !facts.auth.is_empty() {
            return AuthStatus::Always;
        }
        let mut best = if facts.cond_auth.is_empty() { AuthStatus::Never } else { AuthStatus::Sometimes };
        for call in &facts.calls {
            let callees = self.resolve(id, call);
            let status = if callees.is_empty() {
                if call.auth_named {
                    AuthStatus::Always
                } else {
                    AuthStatus::Never
                }
            } else {
                callees.iter().map(|&c| self.auth_status_inner(c, visited)).max().unwrap_or(AuthStatus::Never)
            };
            let status = if call.in_branch { status.min(AuthStatus::Sometimes) } else { status };
            if status == AuthStatus::Always {
                return AuthStatus::Always;
            }
            best = best.max(status);
        }
        best
    }

    /// Names of `id`'s parameters, in order (receiver excluded).
    pub fn param_names(&self, id: FnId) -> Vec<String> {
        self.fns[id].params().into_iter().map(|(n, _)| n).collect()
    }

    /// Which of `id`'s parameters are authorized with `require_auth`, following helpers.
    pub fn subject_auth(&self, id: FnId) -> SubjectAuth {
        self.subject_auth_inner(id, &mut HashSet::new())
    }

    fn subject_auth_inner(&self, id: FnId, stack: &mut HashSet<FnId>) -> SubjectAuth {
        if stack.len() > MAX_DEPTH || !stack.insert(id) {
            return SubjectAuth::default();
        }
        let out = self.subject_auth_body(id, stack);
        stack.remove(&id);
        out
    }

    fn subject_auth_body(&self, id: FnId, visited: &mut HashSet<FnId>) -> SubjectAuth {
        let mut out = SubjectAuth::default();
        let def = &self.fns[id];
        let facts = &self.facts[id];
        let params = self.param_names(id);
        let idx = |n: &str| params.iter().position(|p| p == n);
        if facts.auth_attr || def.attrs.iter().any(is_auth_attr) {
            out.other = true;
        }
        for subj in &facts.auth_subjects {
            match subj.as_deref().and_then(idx) {
                Some(i) => {
                    out.params.insert(i);
                }
                None => out.other = true,
            }
        }
        // Configured auth functions and auth macros have no subject.
        if facts.auth.len() + facts.cond_auth.len() > facts.auth_subjects.len() {
            out.other = true;
        }
        for call in &facts.calls {
            let callees = self.resolve(id, call);
            if callees.is_empty() {
                out.other |= call.auth_named;
                continue;
            }
            for callee in callees {
                let sub = self.subject_auth_inner(callee, visited);
                out.other |= sub.other;
                for j in sub.params {
                    match call.args.get(j).and_then(|a| a.local.as_deref()).and_then(idx) {
                        Some(i) => {
                            out.params.insert(i);
                        }
                        None => out.other = true,
                    }
                }
            }
        }
        out
    }

    /// Writes that decrease a value keyed by `id`'s parameters (`Balance(from)` set to
    /// `balance - amount`), directly or through helpers such as `spend_balance(&e, &from, amount)`.
    pub fn debits(&self, id: FnId) -> Vec<Debit> {
        self.debits_inner(id, &mut HashSet::new()).0
    }

    /// Returns debits plus "value writes": writes keyed by parameters `K` whose value is
    /// parameter `v`, which become debits when a caller passes a decreasing value as `v`.
    #[allow(clippy::type_complexity)]
    fn debits_inner(&self, id: FnId, stack: &mut HashSet<FnId>) -> (Vec<Debit>, Vec<(BTreeSet<usize>, usize)>) {
        if stack.len() > MAX_DEPTH || !stack.insert(id) {
            return (Vec::new(), Vec::new());
        }
        let out = self.debits_body(id, stack);
        stack.remove(&id);
        out
    }

    #[allow(clippy::type_complexity)]
    fn debits_body(&self, id: FnId, visited: &mut HashSet<FnId>) -> (Vec<Debit>, Vec<(BTreeSet<usize>, usize)>) {
        let mut debits = Vec::new();
        let mut value_writes = Vec::new();
        let params = self.param_names(id);
        let idx = |n: &str| params.iter().position(|p| p == n);
        let facts = &self.facts[id];
        for w in &facts.state_writes {
            let key: BTreeSet<usize> = w.key_locals.iter().filter_map(|n| idx(n)).collect();
            if key.is_empty() {
                continue;
            }
            if w.value_decreasing {
                debits.push(Debit { span: w.span, key_params: key });
            } else {
                for v in w.value_locals.iter().filter_map(|n| idx(n)) {
                    value_writes.push((key.clone(), v));
                }
            }
        }
        for call in &facts.calls {
            let map_key = |k: &BTreeSet<usize>| -> BTreeSet<usize> {
                k.iter().filter_map(|&j| call.args.get(j)?.local.as_deref().and_then(idx)).collect()
            };
            for callee in self.resolve(id, call) {
                let (sub_debits, sub_writes) = self.debits_inner(callee, visited);
                for d in sub_debits {
                    let key = map_key(&d.key_params);
                    if !key.is_empty() {
                        debits.push(Debit { span: call.span, key_params: key });
                    }
                }
                for (k, v) in sub_writes {
                    let key = map_key(&k);
                    let Some(arg) = call.args.get(v) else { continue };
                    if key.is_empty() {
                        continue;
                    }
                    if arg.decreasing {
                        debits.push(Debit { span: call.span, key_params: key });
                    } else if let Some(vi) = arg.local.as_deref().and_then(idx) {
                        value_writes.push((key, vi));
                    }
                }
            }
        }
        (debits, value_writes)
    }

    /// `true` if `id` or anything it calls reads contract storage.
    pub fn reads_storage(&self, id: FnId) -> bool {
        self.witness(id, &|_, f| f.storage_reads.first().copied()).is_some()
    }

    /// `id` and every crate function it (transitively) calls.
    pub fn reachable(&self, id: FnId) -> Vec<FnId> {
        let mut seen = vec![id];
        let mut i = 0;
        while i < seen.len() && seen.len() < 256 {
            let f = seen[i];
            for call in &self.facts[f].calls {
                for callee in self.resolve(f, call) {
                    if !seen.contains(&callee) {
                        seen.push(callee);
                    }
                }
            }
            i += 1;
        }
        seen
    }

    /// Storage keys (most specific name) written by `id` or anything it calls.
    pub fn written_keys(&self, id: FnId) -> BTreeSet<String> {
        self.reachable(id)
            .into_iter()
            .flat_map(|f| self.facts[f].state_writes.iter().filter_map(|w| w.key_idents.last().cloned()))
            .collect()
    }

    /// Keys checked by `id`'s "already initialized" guards, or `None` when any
    /// guard's key is unknown (so callers should trust the guard).
    pub fn init_guard_keys(&self, id: FnId) -> Option<BTreeSet<String>> {
        let mut keys = BTreeSet::new();
        for f in self.reachable(id) {
            for k in &self.facts[f].init_guard_keys {
                keys.insert(k.clone()?);
            }
        }
        for call in self.facts[id].calls.iter().filter(|c| c.in_condition) {
            for callee in self.resolve(id, call) {
                if !self.reads_storage(callee) {
                    continue;
                }
                let read: Vec<String> =
                    self.reachable(callee).into_iter().flat_map(|f| self.facts[f].read_keys.clone()).collect();
                if read.is_empty() {
                    return None;
                }
                keys.extend(read);
            }
        }
        Some(keys)
    }

    /// `true` if `id` has an "already initialized" style guard, directly, in a
    /// helper it calls, or by calling a storage-reading helper inside a condition.
    pub fn has_init_guard(&self, id: FnId) -> bool {
        if self.witness(id, &|_, f| f.init_guards.first().copied()).is_some() {
            return true;
        }
        self.facts[id]
            .calls
            .iter()
            .filter(|c| c.in_condition)
            .any(|c| self.resolve(id, c).into_iter().any(|callee| self.reads_storage(callee)))
    }
}
