//! RUST-007: immutable action histories and ordered deterministic evidence.
//! A non-cryptographic FNV-1a state digest is used for parity, not authentication.
use crate::match_core::{self, WORDS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub code: i32,
    pub uid: i32,
    pub meter: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub sequence: usize,
    pub action: Action,
    pub status: i32,
    pub before: u64,
    pub after: u64,
    pub chain: u64,
    pub released: [i32; 2],
    pub removed: [i32; 2],
    pub terminal: i32,
    pub winner: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub final_state: [i32; WORDS],
    pub entries: Vec<Entry>,
    pub final_chain: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    Rejected { sequence: usize, status: i32 },
    Conservation { sequence: usize },
    TerminalMutation { sequence: usize },
    NonMonotonic { sequence: usize },
}

const OFFSET: u64 = 0xcbf29ce484222325;
const PRIME: u64 = 0x100000001b3;

fn digest_bytes(bytes: impl Iterator<Item = u8>) -> u64 {
    bytes.fold(OFFSET, |acc, byte| (acc ^ u64::from(byte)).wrapping_mul(PRIME))
}

/// Canonical little-endian i32 serialization, stable across native and WASM.
pub fn state_digest(state: &[i32; WORDS]) -> u64 {
    digest_bytes(state.iter().flat_map(|word| word.to_le_bytes()))
}

fn link(previous: u64, sequence: usize, action: Action, status: i32, after: u64) -> u64 {
    let fields = [
        previous,
        sequence as u64,
        action.code as u32 as u64,
        action.uid as u32 as u64,
        action.meter as u32 as u64,
        status as u32 as u64,
        after,
    ];
    digest_bytes(fields.iter().flat_map(|value| value.to_le_bytes()))
}

/// Strict replay: any rejected transition, conservation failure or action
/// after terminal state prevents an evidence result from being issued.
pub fn replay(initial: &[i32; WORDS], actions: &[Action]) -> Result<Evidence, ReplayError> {
    let mut state = *initial;
    let mut entries = Vec::with_capacity(actions.len());
    let mut chain = state_digest(&state);
    for (sequence, &action) in actions.iter().enumerate() {
        if state[4] != 0 {
            return Err(ReplayError::TerminalMutation { sequence });
        }
        let before_state = state;
        let before = state_digest(&state);
        state[6] = action.code;
        state[7] = action.uid;
        state[8] = action.meter;
        let status = match_core::step(&mut state);
        if status != 0 {
            return Err(ReplayError::Rejected { sequence, status });
        }
        // Resource counters describe cumulative movement and cannot reverse.
        if state[228] < before_state[228] || state[229] < before_state[229]
            || state[231] < before_state[231] || state[232] < before_state[232]
            || state[233] < before_state[233]
        {
            return Err(ReplayError::NonMonotonic { sequence });
        }
        // No attack may release RAM without a corresponding removal event.
        if action.code == 4
            && ((state[231] > before_state[231] && state[228] == before_state[228])
                || (state[232] > before_state[232] && state[229] == before_state[229]))
        {
            return Err(ReplayError::Conservation { sequence });
        }
        if state[4] != 0 && state[230] == -1 {
            return Err(ReplayError::Conservation { sequence });
        }
        let after = state_digest(&state);
        chain = link(chain, sequence, action, status, after);
        entries.push(Entry {
            sequence, action, status, before, after, chain,
            released: [state[231], state[232]],
            removed: [state[228], state[229]],
            terminal: state[4], winner: state[230],
        });
    }
    Ok(Evidence { final_state: state, entries, final_chain: chain })
}

pub fn verify(initial: &[i32; WORDS], actions: &[Action], evidence: &Evidence) -> bool {
    replay(initial, actions).is_ok_and(|fresh| fresh == *evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial() -> [i32; WORDS] {
        let mut s = [0; WORDS];
        s[0] = 0;
        s[1] = 0;
        s[2] = 0;
        s[3] = 1;
        s[4] = 0;
        s[10] = 5;
        s[11] = 5;
        s[224] = 20;
        s[225] = 20;
        s[226] = 20;
        s[227] = 20;
        s[230] = -1;
        s
    }
    #[test]
    fn long_phase_history_is_reproducible() {
        let history = vec![Action {code: 3, uid: 0, meter: 0}; 64];
        let a = replay(&initial(), &history).unwrap();
        let b = replay(&initial(), &history).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.entries.len(), 64);
        assert!(verify(&initial(), &history, &a));
        assert!(a.entries.windows(2).all(|p| p[0].sequence + 1 == p[1].sequence));
    }
    #[test]
    fn changed_history_fails_verification() {
        let history = vec![Action {code: 3, uid: 0, meter: 0}; 12];
        let original = replay(&initial(), &history).unwrap();
        let mut changed = history.clone();
        changed[0].code = 99;
        assert!(!verify(&initial(), &changed, &original));
    }
    #[test]
    fn terminal_state_rejects_further_actions() {
        let mut s = initial();
        s[4] = 1;
        assert_eq!(replay(&s, &[Action {code: 3, uid: 0, meter: 0}]),
            Err(ReplayError::TerminalMutation {sequence: 0}));
    }
    #[test]
    fn state_digest_changes_with_single_word() {
        let a = initial();
        let mut b = a;
        b[224] += 1;
        assert_ne!(state_digest(&a), state_digest(&b));
    }
}
