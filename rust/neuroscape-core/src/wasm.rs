//! Minimal C-ABI exports. No JS bindings dependency and no gameplay authority.
use crate::{bounded_margin, worst_case_margin, Stability, UncertaintyComponents};

#[no_mangle]
pub extern "C" fn ns_version() -> i32 {
    2
}
#[no_mangle]
pub extern "C" fn ns_margin_classification(margin: f64, epsilon: f64) -> i32 {
    match bounded_margin(margin, epsilon) {
        Ok(result) => match result.classification {
            Stability::ConfirmedStable => 0,
            Stability::Indeterminate => 1,
            Stability::ConfirmedUnstable => 2,
        },
        Err(_) => -1,
    }
}
#[no_mangle]
pub extern "C" fn ns_margin_lower(margin: f64, epsilon: f64) -> f64 {
    bounded_margin(margin, epsilon)
        .map(|v| v.lower)
        .unwrap_or(f64::NAN)
}
#[no_mangle]
pub extern "C" fn ns_margin_upper(margin: f64, epsilon: f64) -> f64 {
    bounded_margin(margin, epsilon)
        .map(|v| v.upper)
        .unwrap_or(f64::NAN)
}
#[no_mangle]
pub extern "C" fn ns_uncertainty_sum(sampling: f64, clock: f64, model: f64) -> f64 {
    UncertaintyComponents {
        sampling,
        clock,
        model,
    }
    .total()
    .unwrap_or(f64::NAN)
}
#[no_mangle]
pub extern "C" fn ns_worst_margin4(a: f64, b: f64, c: f64, d: f64) -> f64 {
    worst_case_margin(&[a, b, c, d]).unwrap_or(f64::NAN)
}
