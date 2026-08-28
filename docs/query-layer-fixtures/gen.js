const fs=require('fs'),path=require('path');
const D=process.argv[2];
const rnd=(n)=>Math.floor(Math.random()*n);
const W="project deadline sleep training kiln pottery invoice runway roadmap migration latency schema onboarding retro standup budget mortgage refactor benchmark vendor contract equity vesting travel kyoto osaka ramen espresso deadlift taper hrv insomnia melatonin therapist landlord sublet visa reimbursement quarterly forecast churn cohort retention".split(" ");
const NAMES=["Sarah Johnson","sarahj","sarah@work.com","Miguel Ortiz","mortiz","Priya Raman","priya.raman@gmail.com","Tom Becker","tbecker","Yuki Tanaka"];
const sent=()=>{let s=[];for(let i=0;i<8+rnd(14);i++)s.push(W[rnd(W.length)]);return s.join(" ")+".";}
const para=(n)=>{let p=[];for(let i=0;i<n;i++)p.push(sent());return p.join(" ");}
const iso=(d)=>new Date(d).toISOString();
const T0=Date.parse("2023-01-01");
const DAY=86400000;
function w(f,fn){const s=fs.createWriteStream(path.join(D,f));fn(s);s.end();return new Promise(r=>s.on('finish',r));}

(async()=>{
// 1 oura sleep: 1100 days, occasional naps (2 periods)
await w("oura_sleep.json",s=>{s.write("[");let first=true;
 for(let d=0;d<1100;d++){const n=Math.random()<0.12?2:1;
  for(let p=0;p<n;p++){const dur=p===0?(4.5+Math.random()*4)*3600:(0.4+Math.random())*3600;
   const o={id:`s${d}_${p}`,day:iso(T0+d*DAY).slice(0,10),type:p===0?"long_sleep":"late_nap",
    bedtime_start:iso(T0+d*DAY+(p?14:0)*3600000),bedtime_end:iso(T0+d*DAY+(p?15:8)*3600000),
    total_sleep_duration:Math.round(dur),deep_sleep_duration:Math.round(dur*0.18),rem_sleep_duration:Math.round(dur*0.22),
    average_hrv:30+rnd(50),average_heart_rate:48+rnd(18),efficiency:70+rnd(28),latency:300+rnd(1500)};
   s.write((first?"":",")+JSON.stringify(o));first=false;}}
 s.write("]")});
// 2 oura heartrate 110k samples
await w("oura_heartrate.json",s=>{s.write("[");for(let i=0;i<110000;i++){const o={bpm:45+rnd(60),source:"ring",timestamp:iso(T0+i*300000)};s.write((i?",":"")+JSON.stringify(o));}s.write("]")});
// 3 oura activity + readiness
await w("oura_activity.json",s=>{s.write("[");for(let d=0;d<1100;d++){const o={day:iso(T0+d*DAY).slice(0,10),steps:2000+rnd(14000),active_calories:200+rnd(900),total_calories:1800+rnd(1200)};s.write((d?",":"")+JSON.stringify(o));}s.write("]")});
await w("oura_readiness.json",s=>{s.write("[");for(let d=0;d<1100;d++){const o={day:iso(T0+d*DAY).slice(0,10),score:40+rnd(60),temperature_deviation:(Math.random()*2-1).toFixed(2)};s.write((d?",":"")+JSON.stringify(o));}s.write("]")});
// 4 spotify 227k streams, split files
const ARTISTS=Array.from({length:1800},(_,i)=>"Artist "+i), TRACKS=Array.from({length:22000},(_,i)=>"Track "+i);
for(let f=0;f<6;f++){await w(`Streaming_History_Audio_${2019+f}_${f}.json`,s=>{s.write("[");
 for(let i=0;i<38000;i++){const pod=Math.random()<0.08;
  const o={ts:iso(T0-200*DAY+ (f*38000+i)*180000),platform:"osx",ms_played:rnd(300000),conn_country:"US",
   master_metadata_track_name:pod?null:TRACKS[rnd(TRACKS.length)],
   master_metadata_album_artist_name:pod?null:ARTISTS[rnd(ARTISTS.length)],
   master_metadata_album_album_name:pod?null:"Album "+rnd(9000),
   spotify_track_uri:pod?null:"spotify:track:"+Math.random().toString(36).slice(2,14),
   episode_name:pod?"Episode "+rnd(500):null,episode_show_name:pod?"Show "+rnd(60):null,
   reason_start:["trackdone","clickrow","fwdbtn","playbtn"][rnd(4)],reason_end:["trackdone","fwdbtn","backbtn","endplay","unknown"][rnd(5)],
   shuffle:Math.random()<0.5,skipped:Math.random()<0.3,offline:false,incognito_mode:false};
  s.write((i?",":"")+JSON.stringify(o));}s.write("]")});}
// 5 chatgpt conversations w/ mapping tree + regenerated siblings
await w("conversations.json",s=>{s.write("[");
 for(let c=0;c<2600;c++){const nodes={};let parent="root";nodes["root"]={id:"root",message:null,parent:null,children:[]};
  const turns=4+rnd(16);let last="root";
  for(let t=0;t<turns;t++){const id=`n${c}_${t}`;const role=t%2?"assistant":"user";
   nodes[id]={id,message:{id,author:{role},create_time:(T0+c*9e5)/1000,content:{content_type:"text",parts:[para(role==="user"?1:3)]},metadata:{}},parent:last,children:[]};
   nodes[last].children.push(id);
   if(Math.random()<0.15){const sib=`n${c}_${t}_r`;nodes[sib]={id:sib,message:{id:sib,author:{role},create_time:(T0+c*9e5+1000)/1000,content:{content_type:"text",parts:[para(2)]},metadata:{}},parent:last,children:[]};nodes[last].children.push(sib);}
   last=id;}
  const o={title:W[rnd(W.length)]+" "+W[rnd(W.length)],create_time:(T0+c*9e5)/1000,update_time:(T0+c*9e5)/1000,mapping:nodes,current_node:last};
  s.write((c?",":"")+JSON.stringify(o));}s.write("]")});
// 6 slack
await w("slack_messages.json",s=>{s.write("[");for(let i=0;i<90000;i++){const o={ts:(T0/1000+i*400).toFixed(6),user:NAMES[rnd(NAMES.length)],channel:["#eng","#general","#design","#random","#alerts"][rnd(5)],text:sent()};s.write((i?",":"")+JSON.stringify(o));}s.write("]")});
// 7 email
await w("email.json",s=>{s.write("[");for(let i=0;i<14000;i++){const o={id:"m"+i,date:iso(T0+i*2e6),from:NAMES[rnd(NAMES.length)],to:NAMES[rnd(NAMES.length)],subject:sent().slice(0,60),body:para(3+rnd(6))};s.write((i?",":"")+JSON.stringify(o));}s.write("]")});
// 8 bank
await w("bank_transactions.json",s=>{s.write("[");const M=["SQ *BLUE BOTTLE 9821","NETFLIX.COM","AMZN Mktp US*2H9","UBER *TRIP","WHOLEFDS #104","SPOTIFY P0A2","RENT ACH","JR EAST TOKYO","LAWSON OSAKA","DELTA AIR 006"];
 for(let i=0;i<9000;i++){const o={date:iso(T0+i*1e7).slice(0,10),merchant:M[rnd(M.length)],amount:-(Math.random()*220).toFixed(2),currency:Math.random()<0.06?"JPY":"USD",account:"chk_9021"};s.write((i?",":"")+JSON.stringify(o));}s.write("]")});
// 9 calendar
await w("calendar.json",s=>{s.write("[");for(let i=0;i<6000;i++){const o={start:iso(T0+i*15e6),end:iso(T0+i*15e6+3.6e6),title:sent().slice(0,40),attendees:[NAMES[rnd(NAMES.length)],NAMES[rnd(NAMES.length)]],status:["accepted","declined","tentative"][rnd(3)]};s.write((i?",":"")+JSON.stringify(o));}s.write("]")});
// 10 browser history
await w("browser_history.json",s=>{s.write("[");for(let i=0;i<120000;i++){const o={url:"https://site"+rnd(4000)+".com/"+W[rnd(W.length)],title:sent().slice(0,50),visit_time:iso(T0+i*4e5)};s.write((i?",":"")+JSON.stringify(o));}s.write("]")});
// 11 notes (prose)
await w("notes.json",s=>{s.write("[");for(let i=0;i<3000;i++){const o={id:"note"+i,created:iso(T0+i*8e6),title:sent().slice(0,40),body:para(6+rnd(14))};s.write((i?",":"")+JSON.stringify(o));}s.write("]")});
console.log("done");
})();
