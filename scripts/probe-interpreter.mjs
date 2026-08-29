/**
 * Which JavaScript does the confined interpreter actually accept?
 *
 * The model writes ordinary modern JS. The evaluator implements a deliberate
 * subset and fails closed on the rest, so every construct it rejects is a
 * turn the model burns on a denial rather than on the question. This probe
 * costs nothing and tells us which constructs to expect trouble from.
 */
import { runConfinedScript } from "../packages/core/dist/query/tools/interpreter/index.js";

const cases = [
  ["arrow + map/filter/reduce", "const a=[1,2,3]; return a.map(x=>x*2).filter(x=>x>2).reduce((s,x)=>s+x,0)"],
  ["for..of", "let s=0; for (const x of [1,2,3]) s+=x; return s"],
  ["for..in", "let k=[]; for (const p in {a:1,b:2}) k.push(p); return k.join()"],
  ["classic for", "let s=0; for(let i=0;i<3;i++)s+=i; return s"],
  ["while", "let i=0,s=0; while(i<3){s+=i;i++} return s"],
  ["destructuring obj", "const {a,b}={a:1,b:2}; return a+b"],
  ["destructuring array", "const [a,b]=[1,2]; return a+b"],
  ["spread array", "const a=[1,2]; return [...a,3].length"],
  ["spread object", "const o={a:1}; return JSON.stringify({...o,b:2})"],
  ["template literal", "const n=2; return `n=${n}`"],
  ["optional chaining", "const o={a:{b:1}}; return o?.a?.b ?? 0"],
  ["nullish coalescing", "return (null ?? 5)"],
  ["ternary", "return 1>0?'y':'n'"],
  ["try/catch", "try{null.x}catch(e){return 'caught'}"],
  ["function decl", "function f(x){return x*2} return f(3)"],
  ["default params", "function f(x=5){return x} return f()"],
  ["rest params", "function f(...xs){return xs.length} return f(1,2,3)"],
  ["async/await", "const x = await Promise.resolve(1); return x"],
  ["Object.entries", "return Object.entries({a:1}).length"],
  ["Object.keys/values", "return Object.keys({a:1}).length + Object.values({a:1}).length"],
  ["Object.assign", "return JSON.stringify(Object.assign({},{a:1}))"],
  ["Array.from", "return Array.from([1,2]).length"],
  ["Array.isArray", "return Array.isArray([])"],
  ["sort with comparator", "return [3,1,2].sort((a,b)=>a-b).join()"],
  ["Math", "return Math.round(Math.max(1,2.6))"],
  ["Number.toFixed", "return (1.234).toFixed(2)"],
  ["parseFloat/parseInt", "return parseFloat('1.5')+parseInt('2')"],
  ["String methods", "return 'a,b'.split(',').length + 'x'.toUpperCase().length"],
  ["localeCompare", "return 'a'.localeCompare('b')"],
  ["JSON round trip", "return JSON.parse(JSON.stringify({a:1})).a"],
  ["Map", "const m=new Map(); m.set('a',1); return m.get('a')"],
  ["Set", "const s=new Set([1,1,2]); return s.size"],
  ["Date", "return new Date('2024-01-01').getUTCFullYear()"],
  ["Date.toISOString", "return new Date(0).toISOString().slice(0,10)"],
  ["regex literal", "return /a(b)/.exec('ab')[1]"],
  ["String.replace regex", "return 'aXb'.replace(/X/,'-')"],
  ["class", "class A{constructor(){this.x=1}} return new A().x"],
  ["generator", "function* g(){yield 1} return [...g()].length"],
  ["labeled break", "outer: for(const a of [1]){break outer} return 'ok'"],
  ["switch", "switch(1){case 1: return 'one'; default: return 'other'}"],
  ["do..while", "let i=0; do{i++}while(i<3); return i"],
  ["getter in object literal", "const o={get x(){return 1}}; return o.x"],
  ["computed key", "const k='a'; return ({[k]:1}).a"],
  ["Array.flat/flatMap", "return [[1],[2]].flat().length + [1].flatMap(x=>[x]).length"],
  ["Array.includes/find", "return ([1,2].includes(2) ? 1:0) + ([1,2].find(x=>x>1)||0)"],
  ["Object.fromEntries", "return Object.fromEntries([['a',1]]).a"],
  ["Array destructure in params", "return [[1,2]].map(([a,b])=>a+b)[0]"],
  ["chained optional call", "const o={f(){return 1}}; return o.f?.()"],
  ["Promise.all", "const r = await Promise.all([1,2].map(async x=>x)); return r.length"],
  ["Intl absent?", "return typeof Intl"],
  ["toLocaleDateString", "return typeof (new Date(0)).toLocaleDateString"],
];

let ok = 0;
const failures = [];
for (const [name, src] of cases) {
  try {
    const wrapped = `(async () => { ${src} })()`;
    const v = await runConfinedScript(
      `const __r = await ${wrapped}; vana.note(String(__r));`,
      { note: () => {}, result: () => {} },
      { maxSteps: 200000 },
    );
    void v;
    ok++;
  } catch (e) {
    failures.push([name, String(e.message ?? e).slice(0, 110)]);
  }
}
console.log(`accepted: ${ok}/${cases.length}`);
if (failures.length) {
  console.log("\nREJECTED:");
  for (const [n, m] of failures) console.log(`  ${n.padEnd(30)} ${m}`);
}
