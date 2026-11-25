//! RUST-004 · fixed-capacity, read-only combat replay across copied card states.
//! No global state; the caller owns and frees its own independent buffer.
//! An attack never touches the real game. Each slot uses [uid,hp,cost,attack,used].
//! Every decision matches the existing JS engine's blocked/direct attack branch.
pub const REPLAY_WORDS: usize = 160;
const INPUT_P: usize = 11;
const INPUT_E: usize = 36;
const OUTPUT_P: usize = 61;
const OUTPUT_E: usize = 86;
const MAX_UNITS: usize = 5;
const FIELDS: usize = 5;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unit {
    pub uid: i32,
    pub hp: i32,
    pub cost: i32,
    pub attack: i32,
    pub used: i32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Board {
    pub ram: [i32; 2],
    pub bf: [i32; 2],
    pub mf: [i32; 2],
    pub units: [Vec<Unit>; 2],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub before_free: [i32; 2],
    pub after_free: [i32; 2],
    pub released: [i32; 2],
    pub removed: [i32; 2],
    pub attacker_after: i32,
    pub defender_after: i32,
    pub defender_uid: i32,
    pub blocked: bool,
    pub terminal: bool,
    pub winner: i32,
}
fn free(board: &Board, side: usize) -> i32 {
    board.ram[side] - board.units[side].iter().map(|u| u.cost).sum::<i32>()
}
/// Pure replay; UID lookup is stable even when preceding slots were removed.
/// Original JS uses first unused defender, then removes all nonpositive HP units.
pub fn resolve(board: &mut Board, side: usize, attacker_uid: i32, meter: i32) -> Result<Resolution, &'static str> {
    if side > 1 || (meter != 0 && meter != 1) { return Err("invalid attacker side or meter"); }
    let enemy = 1 - side;
    let a = board.units[side].iter().position(|u| u.uid == attacker_uid && u.used == 0 && u.attack > 0).ok_or("attacker unavailable")?;
    let defender = board.units[enemy].iter().position(|u| u.used == 0);
    let damage = board.units[side][a].attack;
    let before_free = [free(board, 0),free(board, 1)];
    let mut defender_after = 0;
    let mut defender_uid = -1;
    let mut attacker_after = board.units[side][a].hp;
    if let Some(d) = defender {
        let retaliation = board.units[enemy][d].attack;
        defender_uid = board.units[enemy][d].uid;
        board.units[enemy][d].hp -= damage;
        board.units[side][a].hp -= retaliation;
        attacker_after -= retaliation;
        defender_after = board.units[enemy][d].hp;
    } else if meter == 1 {
        board.mf[enemy] -= damage;
    } else {
        board.bf[enemy] -= damage;
    }
    board.units[side][a].used = 1;
    let mut removed = [0,0];
    let mut released = [0,0];
    for (idx, units) in board.units.iter_mut().enumerate() {
        for u in units.iter().filter(|u| u.hp <= 0) {
            removed[idx] += 1;
            released[idx] += u.cost;
        }
        units.retain(|u| u.hp > 0);
    }
    let after_free = [free(board,0),free(board,1)];
    if released != [after_free[0]-before_free[0],after_free[1]-before_free[1]] {
        return Err("RAM conservation");
    }
    let terminal = board.bf.iter().any(|&v| v<=0)||board.mf.iter().any(|&v| v<=0);
    let winner = if !terminal {-1} else if board.bf[enemy]<=0 || board.mf[enemy]<=0 {side as i32} else {enemy as i32};
    Ok(Resolution{before_free,after_free,released,removed,attacker_after,defender_after,defender_uid,blocked:defender.is_some(),terminal,winner})
}
fn read_unit(words: &[i32],offset:usize)->Unit {
    Unit {uid:words[offset],hp:words[offset+1],cost:words[offset+2],attack:words[offset+3],used:words[offset+4]}
}
fn write_unit(words:&mut [i32],offset:usize,u:Unit) {
    words[offset]=u.uid;
    words[offset+1]=u.hp;
    words[offset+2]=u.cost;
    words[offset+3]=u.attack;
    words[offset+4]=u.used;
}
/// Input/output contract is documented in rust/README.md.
pub fn replay_buffer(words:&mut [i32;REPLAY_WORDS])->i32 {
    let side=words[0];
    let uid=words[1];
    let meter=words[2];
    words[131]=0;
    if !(0..=1).contains(&side) || !(0..=1).contains(&meter) ||
       !(0..=5).contains(&words[9]) || !(0..=5).contains(&words[10]) {
        words[131]=-1;return -1;
    }
    let p=(0..words[9] as usize).map(|i|read_unit(words,INPUT_P+i*FIELDS)).collect();
    let e=(0..words[10] as usize).map(|i|read_unit(words,INPUT_E+i*FIELDS)).collect();
    let mut board=Board {ram:[words[3],words[4]],bf:[words[5],words[7]],mf:[words[6],words[8]],units:[p,e]};
    let out=match resolve(&mut board,side as usize,uid,meter) {
        Ok(result)=>result,Err(_)=>{words[131]=-2;return -2;}
    };
    for (s,start) in [OUTPUT_P,OUTPUT_E].into_iter().enumerate() {
        for i in 0..MAX_UNITS {
            write_unit(words,start+i*FIELDS,board.units[s].get(i).copied().unwrap_or_default());
        }
    }
    words[111]=board.units[0].len() as i32;
    words[112]=board.units[1].len() as i32;
    words[113]=out.removed[0];words[114]=out.removed[1];
    words[115]=out.released[0];words[116]=out.released[1];
    words[117]=out.before_free[0];words[118]=out.before_free[1];
    words[119]=out.after_free[0];words[120]=out.after_free[1];
    words[121]=board.bf[0];words[122]=board.mf[0];
    words[123]=board.bf[1];words[124]=board.mf[1];
    words[125]=i32::from(out.terminal);words[126]=out.winner;
    words[127]=i32::from(out.blocked);words[128]=out.defender_uid;
    words[129]=out.attacker_after;words[130]=out.defender_after;
    0
}
#[cfg(test)]
mod tests {
    use super::*;
    fn unit(uid:i32,hp:i32,cost:i32,attack:i32)->Unit {Unit{uid,hp,cost,attack,used:0}}
    #[test]
    fn destruction_releases_ram_and_preserves_survivor_identity() {
        let mut board=Board{ram:[10,10],bf:[20,20],mf:[20,20],
           units:[vec![unit(10,3,4,4),unit(11,2,2,6)],vec![unit(20,4,3,3)]]};
        let hit=resolve(&mut board,0,10,0).unwrap();
        assert_eq!(hit.removed,[1,1]);
        assert_eq!(hit.released,[4,3]);
        assert_eq!(board.units[0][0].uid,11);
        assert_eq!(hit.after_free,[8,10]);
        let follow=resolve(&mut board,0,11,0).unwrap();
        assert!(!follow.blocked);
        assert_eq!(board.bf[1],14);
        assert_eq!(follow.winner,-1);
    }
    #[test]
    fn terminal_hit_is_reported_without_mutating_source() {
        let before=Board{ram:[2,2],bf:[20,4],mf:[20,20],
          units:[vec![unit(100,3,1,5)],vec![]]};
        let mut shadow=before.clone();
        let result=resolve(&mut shadow,0,100,0).unwrap();
        assert!(result.terminal);
        assert_eq!(result.winner,0);
        assert_eq!(shadow.bf[1],-1);
        assert_eq!(before.bf[1],4);
    }
    #[test]
    fn rejects_missing_and_used_identity() {
        let mut board=Board{ram:[5,5],bf:[20,20],mf:[20,20],
          units:[vec![unit(1,2,1,2)],vec![]]};
        assert!(resolve(&mut board,0,99,0).is_err());
        resolve(&mut board,0,1,0).unwrap();
        assert!(resolve(&mut board,0,1,0).is_err());
    }
    #[test]
    fn buffer_matches_fixed_binary_contract() {
        let mut words=[0i32;REPLAY_WORDS];
        words[0]=0;words[1]=4;words[2]=0;
        words[3]=5;words[4]=4;
        words[5]=20;words[6]=20;words[7]=20;words[8]=20;
        words[9]=1;words[10]=0;
        write_unit(&mut words,INPUT_P,unit(4,3,2,6));
        assert_eq!(replay_buffer(&mut words),0);
        assert_eq!(words[123],14);
        assert_eq!(words[111],1);
        assert_eq!(words[129],3);
    }
}
