//! Neuroscape deterministic analysis core (Rust).
//!
//! Observation only: no gameplay authority, no network, no mutable arena state.
//! This crate is an additive Rust port of bounded margin and metadata eligibility
//! semantics from the browser laboratories, not a replacement game engine.

/// The inherited quiet boundary for phase-offset residuals (radians).
pub const QUIET_THRESHOLD_RADIANS: f64 = 0.1;
/// Upper bound of a single *declared* uncertainty component.
pub const MAX_DECLARED_COMPONENT: f64 = 0.3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    ConfirmedStable,
    Indeterminate,
    ConfirmedUnstable,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MarginInterval {
    pub nominal: f64,
    pub epsilon: f64,
    pub lower: f64,
    pub upper: f64,
    pub classification: Stability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NonFinite,
    NegativeUncertainty,
    UncertaintyOutOfRange,
    EmptyResiduals,
    InvalidTimestamp,
}

pub fn bounded_margin(margin: f64, epsilon: f64) -> Result<MarginInterval, Error> {
    if !margin.is_finite() || !epsilon.is_finite() {
        return Err(Error::NonFinite);
    }
    if epsilon < 0.0 {
        return Err(Error::NegativeUncertainty);
    }
    // Three independently declared components of at most 0.3 each.
    if epsilon > 3.0 * MAX_DECLARED_COMPONENT {
        return Err(Error::UncertaintyOutOfRange);
    }
    let lower = margin - epsilon;
    let upper = margin + epsilon;
    let classification = if lower >= 0.0 {
        Stability::ConfirmedStable
    } else if upper < 0.0 {
        Stability::ConfirmedUnstable
    } else {
        Stability::Indeterminate
    };
    Ok(MarginInterval { nominal: margin, epsilon, lower, upper, classification })
}

/// Conservative signed phase margin: threshold minus the worst observed/model
/// residual. No statistical independence or error cancellation is assumed.
pub fn worst_case_margin(residuals: &[f64]) -> Result<f64, Error> {
    let mut worst = f64::NEG_INFINITY;
    if residuals.is_empty() {
        return Err(Error::EmptyResiduals);
    }
    for &r in residuals {
        if !r.is_finite() || r < 0.0 {
            return Err(Error::NonFinite);
        }
        worst = worst.max(r);
    }
    Ok(QUIET_THRESHOLD_RADIANS - worst)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UncertaintyComponents {
    pub sampling: f64,
    pub clock: f64,
    pub model: f64,
}
impl UncertaintyComponents {
    /// Straight addition is deliberately conservative; no independence claim.
    pub fn total(self) -> Result<f64, Error> {
        let values = [self.sampling, self.clock, self.model];
        for v in values {
            if !v.is_finite() {
                return Err(Error::NonFinite);
            }
            if v < 0.0 {
                return Err(Error::NegativeUncertainty);
            }
            if v > MAX_DECLARED_COMPONENT {
                return Err(Error::UncertaintyOutOfRange);
            }
        }
        Ok(values.iter().sum())
    }

    /// What-if elimination only, never authorization to discard evidence.
    pub fn without(self, axis: UncertaintyAxis) -> Self {
        match axis {
            UncertaintyAxis::Sampling => Self { sampling: 0.0, ..self },
            UncertaintyAxis::Clock => Self { clock: 0.0, ..self },
            UncertaintyAxis::Model => Self { model: 0.0, ..self },
        }
    }

    pub fn sensitivity(self, margin: f64, axis: UncertaintyAxis) -> Result<bool, Error> {
        let original = bounded_margin(margin, self.total()?)?;
        let what_if = bounded_margin(margin, self.without(axis).total()?)?;
        Ok(original.classification != what_if.classification)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncertaintyAxis { Sampling, Clock, Model }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationDossier {
    pub method: String,
    pub calibration_reference: String,
    pub timestamp: String,
    pub provenance: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceEligibility {
    IncompleteOrDeclared,
    ReadyForIndependentReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceAudit {
    pub eligibility: EvidenceEligibility,
    pub empirically_verified: bool,
    pub authority_granted: bool,
}

fn timestamp_has_offset(s: &str) -> bool {
    // Structural ISO-8601 check only, not independent timestamp attestation.
    let bytes = s.as_bytes();
    if bytes.len() < 20 || bytes.get(4) != Some(&b'-') ||
       bytes.get(7) != Some(&b'-') || bytes.get(10) != Some(&b'T') ||
       bytes.get(13) != Some(&b':') {
        return false;
    }
    let time_zone = s.ends_with('Z') ||
       (s.len() >= 6 && {
           let tail = &s[s.len()-6..];
           (tail.starts_with('+') || tail.starts_with('-')) &&
           tail.as_bytes()[3] == b':' &&
           tail[1..3].bytes().all(|c| c.is_ascii_digit()) &&
           tail[4..6].bytes().all(|c| c.is_ascii_digit())
       });
    time_zone && bytes[0..4].iter().all(u8::is_ascii_digit) &&
       bytes[5..7].iter().all(u8::is_ascii_digit) &&
       bytes[8..10].iter().all(u8::is_ascii_digit) &&
       bytes[11..13].iter().all(u8::is_ascii_digit) &&
       bytes[14..16].iter().all(u8::is_ascii_digit)
}
pub fn audit_dossier(d: &CalibrationDossier) -> EvidenceAudit {
    let complete = d.method.trim().len() >= 5 &&
        !d.calibration_reference.trim().is_empty() &&
        d.provenance.trim().len() >= 5 &&
        timestamp_has_offset(d.timestamp.trim());
    EvidenceAudit {
        eligibility: if complete { EvidenceEligibility::ReadyForIndependentReview }
                     else { EvidenceEligibility::IncompleteOrDeclared },
        empirically_verified: false,
        authority_granted: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_way_classification_boundaries() {
        assert_eq!(bounded_margin(0.2, 0.05).unwrap().classification, Stability::ConfirmedStable);
        assert_eq!(bounded_margin(-0.2, 0.05).unwrap().classification, Stability::ConfirmedUnstable);
        assert_eq!(bounded_margin(0.02, 0.05).unwrap().classification, Stability::Indeterminate);
        assert_eq!(bounded_margin(0.0, 0.0).unwrap().classification, Stability::ConfirmedStable);
        assert_eq!(bounded_margin(-0.05, 0.05).unwrap().classification, Stability::Indeterminate);
    }

    #[test]
    fn rejects_invalid_input_without_hidden_defaults() {
        assert_eq!(bounded_margin(f64::NAN, 0.1), Err(Error::NonFinite));
        assert_eq!(bounded_margin(0.0, -0.01), Err(Error::NegativeUncertainty));
        assert_eq!(bounded_margin(0.0, 0.91), Err(Error::UncertaintyOutOfRange));
        assert_eq!(worst_case_margin(&[]), Err(Error::EmptyResiduals));
        assert_eq!(worst_case_margin(&[0.01, f64::INFINITY]), Err(Error::NonFinite));
    }

    #[test]
    fn worst_case_margin_uses_largest_residual() {
        let m = worst_case_margin(&[0.03, 0.08, 0.12]).unwrap();
        assert!((m + 0.02).abs() < 1e-12);
    }

    #[test]
    fn components_remain_separate_and_conservative() {
        let components = UncertaintyComponents { sampling: 0.025, clock: 0.05, model: 0.075 };
        assert!((components.total().unwrap() - 0.15).abs() < 1e-12);
        assert!(components.sensitivity(0.1, UncertaintyAxis::Model).unwrap());
        assert_eq!(components.without(UncertaintyAxis::Clock).clock, 0.0);
        assert_eq!(components.clock, 0.05);
    }

    #[test]
    fn metadata_does_not_grant_authority() {
        let d = CalibrationDossier {
            method: "phase timing method".into(),
            calibration_reference: "CAL-001".into(),
            timestamp: "2026-11-24T19:00:00-06:00".into(),
            provenance: "declared source ancestry".into(),
        };
        let audit = audit_dossier(&d);
        assert_eq!(audit.eligibility, EvidenceEligibility::ReadyForIndependentReview);
        assert!(!audit.empirically_verified);
        assert!(!audit.authority_granted);
        let incomplete = CalibrationDossier { provenance: "".into(), ..d };
        assert_eq!(audit_dossier(&incomplete).eligibility, EvidenceEligibility::IncompleteOrDeclared);
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm;


/// Shadow of the engine's \`free = ram - committed\` calculation.
pub fn shadow_free_ram(ram: i32, committed: i32) -> i32 {
    ram.saturating_sub(committed)
}

/// Shadow of deployment gate: 5 square limit and card cost <= available RAM.
pub fn shadow_deploy_legal(free_ram: i32, card_cost: i32, occupied: i32) -> bool {
    (0..5).contains(&occupied) && card_cost >= 0 && card_cost <= free_ram
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowAttack {
    pub attacker_after: i32,
    pub defender_after: i32,
    pub meter_after: i32,
    pub attacker_destroyed: bool,
    pub defender_destroyed: bool,
}
/// A single observed attack step, with direct hit when \`blocked=false\`.
///
/// \`defender_after\` is ignored for a direct attack and \`meter_after\`
/// is ignored when a defender blocks. Matches \`predictedTarget\` semantics.
pub fn shadow_attack(
    attacker_hp: i32, defender_hp: i32, damage: i32,
    retaliation: i32, meter_hp: i32, blocked: bool,
) -> ShadowAttack {
    let attacker_after = if blocked {attacker_hp.saturating_sub(retaliation)}
                         else {attacker_hp};
    let defender_after = if blocked {defender_hp.saturating_sub(damage)}
                         else {defender_hp};
    let meter_after = if blocked {meter_hp} else {meter_hp.saturating_sub(damage)};
    ShadowAttack {
        attacker_after, defender_after, meter_after,
        attacker_destroyed: blocked && attacker_after<=0,
        defender_destroyed: blocked && defender_after<=0,
    }
}

#[cfg(test)]
mod shadow_tests {
    use super::*;
    #[test]
    fn deploy_and_ram_follow_real_engine_rules() {
        assert_eq!(shadow_free_ram(8, 5), 3);
        assert!(shadow_deploy_legal(3, 3, 4));
        assert!(!shadow_deploy_legal(3, 4, 4));
        assert!(!shadow_deploy_legal(3, 1, 5));
    }
    #[test]
    fn blocked_exchange_and_destructive_trade() {
        let a=shadow_attack(5, 4, 4, 5, 20, true);
        assert_eq!(a.attacker_after, 0);
        assert_eq!(a.defender_after, 0);
        assert!(a.attacker_destroyed && a.defender_destroyed);
        assert_eq!(a.meter_after, 20);
    }
    #[test]
    fn direct_hit_is_unretaliated() {
        let a=shadow_attack(5, 0, 7, 0, 6, false);
        assert_eq!(a.attacker_after, 5);
        assert_eq!(a.meter_after, -1);
        assert!(!a.attacker_destroyed && !a.defender_destroyed);
    }
}

pub mod replay;
