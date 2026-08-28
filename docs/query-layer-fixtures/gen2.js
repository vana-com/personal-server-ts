const fs=require('fs'),path=require('path');const D=process.argv[2];
const rnd=n=>Math.floor(Math.random()*n);
const W="project deadline sleep training kiln pottery invoice runway roadmap migration latency schema onboarding retro standup budget mortgage refactor benchmark vendor contract equity vesting travel kyoto osaka ramen espresso deadlift taper hrv insomnia melatonin therapist landlord sublet visa reimbursement quarterly forecast churn cohort retention".split(" ");
const sent=()=>{let s=[];for(let i=0;i<8+rnd(14);i++)s.push(W[rnd(W.length)]);return s.join(" ")+".";};
const para=n=>{let p=[];for(let i=0;i<n;i++)p.push(sent());return p.join(" ");};
const T0=Date.parse("2023-01-01");
const iso=d=>new Date(d).toISOString();
function w(f,fn){const s=fs.createWriteStream(path.join(D,f));fn(s);s.end();return new Promise(r=>s.on('finish',r));}
(async()=>{
await w("conversations.json",s=>{s.write("[");
 for(let c=0;c<10400;c++){const nodes={};nodes["root"]={id:"root",message:null,parent:null,children:[]};
  const turns=4+rnd(16);let last="root";
  for(let t=0;t<turns;t++){const id=`n${c}_${t}`,role=t%2?"assistant":"user";
   nodes[id]={id,message:{id,author:{role},create_time:(T0+c*9e4)/1000,content:{content_type:"text",parts:[para(role==="user"?1:3)]},metadata:{}},parent:last,children:[]};
   nodes[last].children.push(id);
   if(Math.random()<0.15){const sib=`n${c}_${t}_r`;nodes[sib]={id:sib,message:{id:sib,author:{role},create_time:(T0+c*9e4+1000)/1000,content:{content_type:"text",parts:[para(2)]},metadata:{}},parent:last,children:[]};nodes[last].children.push(sib);}
   last=id;}
  s.write((c?",":"")+JSON.stringify({title:W[rnd(W.length)]+" "+W[rnd(W.length)],create_time:(T0+c*9e4)/1000,mapping:nodes,current_node:last}));}
 s.write("]")});
await w("notes.json",s=>{s.write("[");for(let i=0;i<12000;i++)s.write((i?",":"")+JSON.stringify({id:"note"+i,created:iso(T0+i*2e6),title:sent().slice(0,40),body:para(6+rnd(14))}));s.write("]")});
console.log("ok");})();
