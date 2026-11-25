//! RUST-006 · one copied match state, combined turn and combat transitions.
//! All actions are deterministic and executed on caller-owned WASM memory.
//! Live gameplay authority remains in the browser's JavaScript game engine.
use crate::{replay,turn};
pub const WORDS:usize=turn::WORDS;
// Reuse the RUST-005 256-word turn ABI. Extra match-only slots:
// 8: meter selector on attack (0 BF / 1 MF)
// 224,225: P BF/MF; 226,227: E BF/MF; 228,229: removed card bin counts
// 230: winner (-1 none, 0 player, 1 bot, 2 draw)
// 231,232: cumulative released RAM; 233: cumulative attack count
// action=4 means attack by immutable UID in word 7.
pub fn step(words:&mut [i32;WORDS])->i32 {
    if !(0..=1).contains(&words[0]) || !(0..=3).contains(&words[1]) ||
       [(words[12],5),(words[13],5),(words[14],8),
        (words[15],8),(words[16],8),(words[17],8)]
       .iter().any(|&(n,max)|n<0||n>max) {return -1;}
    let mut out=*words;
    let action=out[6];
    if action<=3 {
        let status=turn::step_buffer(&mut out);
        if status!=0 {return status;}
        if out[4]!=0 && out[3]>250 {out[230]=2;}
    } else if action==4 {
        if out[1]!=2 || out[4]!=0 || !(0..=1).contains(&out[8]){return -3;}
        let side=out[0] as usize;
        let players=[turn::read_player(&out,0),turn::read_player(&out,1)];
        let original=players.clone();
        let mut board=replay::Board{
            ram:[players[0].ram,players[1].ram],
            bf:[out[224],out[226]],
            mf:[out[225],out[227]],
            units:players.map(|p|p.units.into_iter().map(|u|replay::Unit{
                uid:u.uid,hp:u.hp,cost:u.card.cost,
                attack:u.card.attack,used:i32::from(u.used)
            }).collect())
        };
        let resolution=match replay::resolve(&mut board,side,out[7],out[8]) {
            Ok(value)=>value,Err(_)=>return -3
        };
        for p in 0..2 {
            let mut player=original[p].clone();
            player.units=board.units[p].iter().map(|v|{
                let mut u=original[p].units.iter().find(|u|u.uid==v.uid)
                  .copied().expect("surviving UID must be in original board");
                u.hp=v.hp;u.used=v.used!=0;u
            }).collect();
            turn::write_player(&mut out,p,&player);
        }
        out[224]=board.bf[0];out[225]=board.mf[0];
        out[226]=board.bf[1];out[227]=board.mf[1];
        out[228]+=resolution.removed[0];out[229]+=resolution.removed[1];
        out[231]+=resolution.released[0];out[232]+=resolution.released[1];
        out[233]+=1;
        if resolution.terminal {
            out[4]=1;out[230]=resolution.winner;
        }
    } else {return -2;}
    *words=out;
    0
}
#[cfg(test)]
mod tests {
 use super::*;
 fn setup()->[i32;WORDS]{
  let mut w=[0;WORDS];
  w[0]=0;w[1]=2;w[2]=0;w[3]=2;
  w[10]=5;w[11]=5;w[12]=1;w[13]=1;
  w[24]=36;w[25]=101;w[26]=2;w[27]=3;w[28]=4;w[29]=3;
  w[54]=65;w[55]=202;w[56]=3;w[57]=2;w[58]=3;w[59]=2;
  w[224]=20;w[225]=20;w[226]=20;w[227]=20;w[230]=-1;
  w
 }
 #[test]
 fn exchange_compacts_both_sides_and_conserves_ram(){
  let mut w=setup();w[6]=4;w[7]=101;w[8]=0;
  assert_eq!(step(&mut w),0);
  assert_eq!((w[12],w[13]),(0,0));
  assert_eq!((w[228],w[229]),(1,1));
  assert_eq!((w[231],w[232]),(2,3));
  assert_eq!((w[224],w[226]),(20,20));
 }
 #[test]
 fn invalid_attack_is_atomic(){
  let mut w=setup();w[6]=4;w[7]=999;w[8]=0;
  let before=w;assert_eq!(step(&mut w),-3);assert_eq!(w,before);
 }
 #[test]
 fn terminal_direct_meter_and_turn_rejection(){
  let mut w=setup();w[13]=0;w[226]=3;w[6]=4;w[7]=101;w[8]=0;
  assert_eq!(step(&mut w),0);assert_eq!(w[226],-1);
  assert_eq!((w[4],w[230]),(1,0));
  let before=w;w[6]=3;assert_eq!(step(&mut w),-3);
  assert_eq!(w[226],before[226]);
 }
 #[test]
 fn multi_step_phase_and_turn(){
  let mut w=setup();w[1]=0;w[6]=3;
  for phase in 1..=3 {assert_eq!(step(&mut w),0);assert_eq!(w[1],phase);}
  assert_eq!(step(&mut w),0);
  assert_eq!((w[0],w[1],w[3],w[2]),(1,0,3,2));
 }
}
