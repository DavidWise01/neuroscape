//! RUST-005 · pure four-phase turn-control shadow (no gameplay authority).
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Card {pub id:i32,pub cost:i32,pub defense:i32,pub attack:i32}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Unit {pub card:Card,pub uid:i32,pub hp:i32,pub used:bool}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Player {pub ram:i32,pub deck:Vec<Card>,pub hand:Vec<Card>,pub units:Vec<Unit>}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Turn {pub players:[Player;2],pub active:usize,pub phase:u8,pub actions:i32,pub turn:i32,pub done:bool,pub next_uid:i32}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Action {InstallRam,Draw,Deploy(usize),Next}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error {Illegal}
impl Turn {
 pub fn free(&self,p:usize)->i32 {self.players[p].ram-self.players[p].units.iter().map(|u|u.card.cost).sum::<i32>()}
 pub fn apply(&mut self,a:Action)->Result<(),Error>{
  if self.done||self.active>1||self.phase>3{return Err(Error::Illegal);}
  let p=self.active;
  match a {
   Action::InstallRam if self.phase==0&&self.actions>0&&self.players[p].ram<25=>{
    self.players[p].ram+=1;self.actions-=1;
   }
   Action::Draw if self.phase==0&&self.actions>0&&!self.players[p].deck.is_empty()=>{
    let c=self.players[p].deck.remove(0);self.players[p].hand.push(c);self.actions-=1;
   }
   Action::Deploy(i) if self.phase==1&&self.players[p].units.len()<5&&i<self.players[p].hand.len()&&self.players[p].hand[i].cost<=self.free(p)=>{
    let c=self.players[p].hand.remove(i);
    self.players[p].units.push(Unit{card:c,uid:self.next_uid,hp:c.defense,used:false});
    self.next_uid+=1;
   }
   Action::Next if self.phase<3=>{self.phase+=1;}
   Action::Next=>{
    for player in &mut self.players{for u in &mut player.units{u.hp=u.card.defense;}}
    self.active=1-p;self.phase=0;self.actions=2;self.turn+=1;
    for u in &mut self.players[self.active].units{u.used=false;}
    if self.turn>250{self.done=true;}
   }
   _=>return Err(Error::Illegal),
  }
  Ok(())
 }
}
pub const WORDS:usize=256;
// Binary layout: 0 active;1 phase;2 actions;3 turn;4 done;5 nextUID;
// 6 action (0 RAM,1 DRAW,2 DEPLOY,3 NEXT);7 hand index;
// 10,11 RAM;12,13 unit count;14,15 hand count;16,17 deck count;
// 24,54: 5 units x6 [cardID,UID,cost,defense,attack,currentHP];
// 84,116 hand, 148,180 deck: 8 cards x4 [ID,cost,defense,attack];
// 212..216 and 217..221 unit used flags.
fn card(w:&[i32],at:usize)->Card{Card{id:w[at],cost:w[at+1],defense:w[at+2],attack:w[at+3]}}
fn write_card(w:&mut[i32],at:usize,c:Card){w[at]=c.id;w[at+1]=c.cost;w[at+2]=c.defense;w[at+3]=c.attack;}
fn side_offsets(p:usize)->(usize,usize,usize){if p==0{(24,84,148)}else{(54,116,180)}}
pub(crate) fn read_player(w:&[i32],p:usize)->Player{
 let (u,h,d)=side_offsets(p);
 Player{ram:w[10+p],
  units:(0..w[12+p] as usize).map(|i|{
   let x=u+i*6;Unit{card:Card{id:w[x],cost:w[x+2],defense:w[x+3],attack:w[x+4]},uid:w[x+1],hp:w[x+5],used:w[212+p*5+i]!=0}
  }).collect(),
  hand:(0..w[14+p] as usize).map(|i|card(w,h+i*4)).collect(),
  deck:(0..w[16+p] as usize).map(|i|card(w,d+i*4)).collect()}
}
pub(crate) fn write_player(w:&mut[i32],p:usize,x:&Player){
 let (u,h,d)=side_offsets(p);
 w[10+p]=x.ram;w[12+p]=x.units.len() as i32;
 w[14+p]=x.hand.len() as i32;w[16+p]=x.deck.len() as i32;
 for i in 0..5{
  let at=u+i*6;for j in 0..6{w[at+j]=0;}w[212+p*5+i]=0;
  if let Some(unit)=x.units.get(i){
   w[at]=unit.card.id;w[at+1]=unit.uid;w[at+2]=unit.card.cost;
   w[at+3]=unit.card.defense;w[at+4]=unit.card.attack;w[at+5]=unit.hp;
   w[212+p*5+i]=i32::from(unit.used);
  }
 }
 for i in 0..8{
  for j in 0..4{w[h+i*4+j]=0;w[d+i*4+j]=0;}
  if let Some(c)=x.hand.get(i){write_card(w,h+i*4,*c);}
  if let Some(c)=x.deck.get(i){write_card(w,d+i*4,*c);}
 }
}
/// Invalid input is rejected without changing memory. No combat in this ABI;
/// use RUST-004 for each combat action.
pub fn step_buffer(w:&mut[i32;WORDS])->i32 {
 if !(0..=1).contains(&w[0])||!(0..=3).contains(&w[1]) ||
   [(w[12],5),(w[13],5),(w[14],8),(w[15],8),(w[16],8),(w[17],8)]
    .iter().any(|&(v,max)|v<0||v>max){return -1;}
 let mut t=Turn{players:[read_player(w,0),read_player(w,1)],
   active:w[0] as usize,phase:w[1] as u8,actions:w[2],
   turn:w[3],done:w[4]!=0,next_uid:w[5]};
 let a=match w[6]{0=>Action::InstallRam,1=>Action::Draw,2=>Action::Deploy(w[7] as usize),3=>Action::Next,_=>return -2};
 if t.apply(a).is_err(){return -3;}
 if t.players.iter().any(|p|p.hand.len()>8||p.deck.len()>8){return -4;}
 w[0]=t.active as i32;w[1]=t.phase as i32;w[2]=t.actions;
 w[3]=t.turn;w[4]=i32::from(t.done);w[5]=t.next_uid;
 write_player(w,0,&t.players[0]);write_player(w,1,&t.players[1]);0
}
#[cfg(test)]
mod tests{
 use super::*;
 fn c(id:i32)->Card{Card{id,cost:1,defense:3,attack:2}}
 fn p()->Player{Player{ram:0,deck:vec![c(11)],hand:vec![],units:vec![]}}
 #[test]fn cycle_and_identity(){
  let original=Turn{players:[p(),p()],active:0,phase:0,actions:2,turn:1,done:false,next_uid:7};
  let mut t=original.clone();
  t.apply(Action::InstallRam).unwrap();t.apply(Action::Draw).unwrap();
  t.apply(Action::Next).unwrap();t.apply(Action::Deploy(0)).unwrap();
  assert_eq!(t.players[0].units[0].uid,7);
  for _ in 0..3{t.apply(Action::Next).unwrap();}
  assert_eq!((t.active,t.phase,t.actions,t.turn),(1,0,2,2));
  assert_eq!(original.turn,1);
 }
 #[test]fn turn_limit(){
  let mut t=Turn{players:[p(),p()],active:0,phase:3,actions:0,turn:250,done:false,next_uid:2};
  t.apply(Action::Next).unwrap();assert!(t.done);assert_eq!(t.turn,251);
 }
 #[test]fn buffer_match(){
  let mut w=[0i32;WORDS];w[0]=0;w[1]=0;w[2]=2;w[3]=1;w[5]=7;
  w[10]=0;w[16]=1;w[148]=11;w[149]=1;w[150]=3;w[151]=2;
  w[6]=0;assert_eq!(step_buffer(&mut w),0);assert_eq!((w[10],w[2]),(1,1));
  w[6]=1;assert_eq!(step_buffer(&mut w),0);assert_eq!((w[14],w[16]),(1,0));
 }
}
