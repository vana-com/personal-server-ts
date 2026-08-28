const fs=require('fs'),path=require('path');const D=process.argv[2];
const t=()=>process.hrtime.bigint();
const ms=(a,b)=>Number(b-a)/1e6;
const R=f=>JSON.parse(fs.readFileSync(path.join(D,f),'utf8'));
const out=[];
function bench(label,fn){const a=t();const r=fn();const b=t();out.push([label,ms(a,b).toFixed(0)+"ms",r]);}

// Q1: avg sleep last 30 days, naps excluded (the implicit rule)
bench("Q1 avg sleep (parse+aggregate oura_sleep)",()=>{
  const s=R("oura_sleep.json");
  const days=[...new Set(s.map(x=>x.day))].sort().slice(-30);
  const main=s.filter(x=>days.includes(x.day)&&x.type==="long_sleep");
  const avg=main.reduce((a,b)=>a+b.total_sleep_duration,0)/main.length/3600;
  const naive=s.filter(x=>days.includes(x.day));
  const navg=naive.reduce((a,b)=>a+b.total_sleep_duration,0)/naive.length/3600;
  return `correct ${avg.toFixed(2)}h n=${main.length} | naive(incl naps) ${navg.toFixed(2)}h n=${naive.length}`;});

// Q18/Q4: join spotify x oura on date
bench("Q4 join spotify(228k)xoura on date",()=>{
  const sleep=Object.fromEntries(R("oura_sleep.json").filter(x=>x.type==="long_sleep").map(x=>[x.day,x.total_sleep_duration]));
  let n=0,tot=0,buckets={low:0,high:0};
  for(let f=0;f<6;f++){const arr=R(`Streaming_History_Audio_${2019+f}_${f}.json`);
    for(const r of arr){n++;const d=r.ts.slice(0,10);const sl=sleep[d];if(sl===undefined)continue;
      tot+=r.ms_played;buckets[sl<6*3600?"low":"high"]+=r.ms_played;}}
  return `${n} streams scanned, matched-day ms low=${(buckets.low/3.6e6).toFixed(0)}h high=${(buckets.high/3.6e6).toFixed(0)}h`;});

// Q7: recurring expenses
bench("Q7 recurring merchants (bank)",()=>{
  const b=R("bank_transactions.json");const g={};
  for(const r of b){const k=r.merchant.replace(/[\d*#]+/g,"").trim();(g[k]=g[k]||[]).push(+r.amount);}
  const rec=Object.entries(g).filter(([,v])=>v.length>24).length;
  return `${b.length} txns, ${Object.keys(g).length} normalized merchants, ${rec} recurring`;});

// Q6: distinct people across slack+email+calendar w/ alias table
bench("Q6 distinct people (slack+email+calendar)",()=>{
  const alias=n=>n.toLowerCase().replace(/@.*/,"").replace(/[^a-z]/g,"");
  const set=new Set();let rows=0;
  for(const r of R("slack_messages.json")){set.add(alias(r.user));rows++;}
  for(const r of R("email.json")){set.add(alias(r.from));set.add(alias(r.to));rows++;}
  for(const r of R("calendar.json")){r.attendees.forEach(a=>set.add(alias(a)));rows++;}
  return `${rows} rows, ${set.size} resolved identities`;});

// Q5/Q8: exhaustive scan over ALL prose for a phrase
bench("Q5/Q8 exhaustive scan all prose (95MB)",()=>{
  let hits=0,units=0;
  for(const f of ["conversations.json","notes.json","email.json","slack_messages.json"]){
    const raw=fs.readFileSync(path.join(D,f),'utf8');units+=raw.length;
    let i=0;while((i=raw.indexOf("kiln",i+1))>0)hits++;}
  return `${(units/1e6).toFixed(0)}MB scanned, ${hits} literal hits`;});

// ChatGPT correct reconstruction (current_node walk) vs naive flatten
bench("ChatGPT tree walk vs naive flatten",()=>{
  const c=R("conversations.json");let correct=0,naive=0;
  for(const conv of c){naive+=Object.values(conv.mapping).filter(n=>n.message).length;
    let cur=conv.current_node;while(cur&&cur!=="root"){const n=conv.mapping[cur];if(n&&n.message)correct++;cur=n?n.parent:null;}}
  return `${c.length} convs: correct ${correct} msgs vs naive ${naive} (+${((naive/correct-1)*100).toFixed(1)}% phantom)`;});

// corpus token estimate
bench("token estimate (whole corpus)",()=>{
  let bytes=0;for(const f of fs.readdirSync(D))bytes+=fs.statSync(path.join(D,f)).size;
  return `${(bytes/1e6).toFixed(0)}MB ≈ ${(bytes/4/1e6).toFixed(1)}M tokens`;});

for(const [l,d,r] of out) console.log(`${d.padStart(7)}  ${l}\n         ${r}`);
