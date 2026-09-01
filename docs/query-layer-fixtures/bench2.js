const fs=require('fs'),path=require('path');const D=process.argv[2];
const R=f=>JSON.parse(fs.readFileSync(path.join(D,f),'utf8'));
const t=()=>process.hrtime.bigint(),ms=(a,b)=>Number(b-a)/1e6;
const tok=s=>Math.round(s/4);

// Q2: "main focus this week" — how much prose is in ONE week across all sources?
let a=t();
const convs=R("conversations.json");
const wk=new Date("2023-06-05").getTime()/1000, wke=wk+7*86400;
let bytes=0,units=0;
for(const c of convs){if(c.create_time>=wk&&c.create_time<wke){units++;
  let cur=c.current_node;while(cur&&cur!=="root"){const n=c.mapping[cur];if(n&&n.message)bytes+=JSON.stringify(n.message.content.parts).length;cur=n?n.parent:null;}}}
const sl=R("slack_messages.json").filter(r=>+r.ts>=wk&&+r.ts<wke); sl.forEach(r=>bytes+=r.text.length);
const em=R("email.json").filter(r=>Date.parse(r.date)/1000>=wk&&Date.parse(r.date)/1000<wke); em.forEach(r=>bytes+=r.body.length);
let b=t();
console.log(`Q2 one-week slice: ${units} convs + ${sl.length} slack + ${em.length} emails = ${(bytes/1e6).toFixed(2)}MB ≈ ${(tok(bytes)/1000).toFixed(0)}k tokens   [${ms(a,b).toFixed(0)}ms to assemble]`);

// Q3/Q15: whole-corpus semantic map — how many LLM units if we must judge every conversation?
a=t();
let cb=0; for(const c of convs){let cur=c.current_node;while(cur&&cur!=="root"){const n=c.mapping[cur];if(n&&n.message)cb+=JSON.stringify(n.message.content.parts).length;cur=n?n.parent:null;}}
b=t();
const perConv=cb/convs.length;
console.log(`Q3 whole-corpus map: ${convs.length} convs, ${(cb/1e6).toFixed(0)}MB ≈ ${(tok(cb)/1e6).toFixed(1)}M tokens; avg ${tok(perConv)} tok/conv  [${ms(a,b).toFixed(0)}ms]`);
console.log(`   → map-reduce = ${convs.length} calls @ ~${tok(perConv)} tok in / ~100 out`);
const inTok=tok(cb), calls=convs.length;
for(const [name,ppm] of [["haiku-class",1.0],["sonnet-class",3.0]]){
  console.log(`   → ${name}: ~$${((inTok/1e6)*ppm).toFixed(2)} input for one full pass`);}

// Materialized vs scan: does an index help?
a=t(); let tot=0; for(let f=0;f<6;f++){for(const r of R(`Streaming_History_Audio_${2019+f}_${f}.json`)) tot+=r.ms_played;} b=t();
console.log(`\nScan 228k spotify rows (parse+sum): ${ms(a,b).toFixed(0)}ms`);
