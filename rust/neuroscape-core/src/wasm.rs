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


// RUST-003: single-step real gameplay shadow exports. No mutation.
#[no_mangle]
pub extern "C" fn ns_shadow_free_ram(ram:i32,committed:i32)->i32 {
    crate::shadow_free_ram(ram,committed)
}
#[no_mangle]
pub extern "C" fn ns_shadow_deploy_legal(free_ram:i32,card_cost:i32,occupied:i32)->i32 {
    i32::from(crate::shadow_deploy_legal(free_ram,card_cost,occupied))
}
#[no_mangle]
pub extern "C" fn ns_shadow_attacker_after(attacker_hp:i32,damage:i32,retaliation:i32,blocked:i32)->i32 {
    crate::shadow_attack(attacker_hp,0,damage,retaliation,0,blocked!=0).attacker_after
}
#[no_mangle]
pub extern "C" fn ns_shadow_defender_after(defender_hp:i32,damage:i32,blocked:i32)->i32 {
    crate::shadow_attack(0,defender_hp,damage,0,0,blocked!=0).defender_after
}
#[no_mangle]
pub extern "C" fn ns_shadow_meter_after(meter_hp:i32,damage:i32,blocked:i32)->i32 {
    crate::shadow_attack(0,0,damage,0,meter_hp,blocked!=0).meter_after
}
#[no_mangle]
pub extern "C" fn ns_shadow_attacker_destroyed(attacker_hp:i32,retaliation:i32,blocked:i32)->i32 {
    i32::from(crate::shadow_attack(attacker_hp,0,0,retaliation,0,blocked!=0).attacker_destroyed)
}
#[no_mangle]
pub extern "C" fn ns_shadow_defender_destroyed(defender_hp:i32,damage:i32,blocked:i32)->i32 {
    i32::from(crate::shadow_attack(0,defender_hp,damage,0,0,blocked!=0).defender_destroyed)
}
