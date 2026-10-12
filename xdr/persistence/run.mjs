import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runXdr} from '../../scripts/xdr-run.mjs';
import {respond} from './respond.mjs';
import {evaluateAccess} from '../../ztna/evaluate.mjs';

if(process.argv[2]!=='persistence'){
  console.error('Usage: npm run xdr:run -- persistence');
  process.exit(1);
}
const time=new Date('2026-10-13T00:00:00.000Z');
const source=new URL('../fixtures/persistence.json',import.meta.url);
const fixture=JSON.parse(await readFile(source,'utf8'));
const root=fileURLToPath(new URL('../../',import.meta.url));
const outcome=await runXdr({root,moduleKey:'persistence'});
const temp=new URL('../temporary-deny.json',import.meta.url);
const log=new URL('../alerts.log',import.meta.url);
await writeFile(temp,'[]\n');
await writeFile(log,'');
for(let i=0;i<fixture.alerts.length;i++){
  const alert=fixture.alerts[i],decision=outcome.decisions[i];
  if(alert.id!==decision.alertId)throw new Error('Unexpected fixture/result ID ordering');
  await respond(alert,decision,{now:time,persist:true});
}
const rules=JSON.parse(await readFile(temp,'utf8'));
const lines=(await readFile(log,'utf8')).trim().split('\n').filter(Boolean);
if(rules.length!==outcome.counts.block || lines.length!==outcome.counts.block+outcome.counts.alert)
  throw new Error('Mismatch between decisions, notifications and isolation candidates');

let normalBlocked=0;
for(let i=0;i<fixture.alerts.length;i++){
  const alert=fixture.alerts[i],decision=outcome.decisions[i];
  const access=await evaluateAccess(alert.data.srcip,time.getTime());
  const baselineNormal=!(alert.rule.mitre??[]).some(x=>x==='T1543'||x==='T1053') &&
    Number(alert.rule.level)<=3;
  if(baselineNormal && (decision.action==='block' || access.action==='deny'))normalBlocked++;
  if(decision.action==='block' && access.action!=='deny')throw new Error('Failed to isolate '+alert.id);
  if(decision.action==='block' &&
    (await evaluateAccess(alert.data.srcip,time.getTime()+16*60000)).action!=='allow')
    throw new Error('Expired XDR isolation still active for '+alert.id);
}
if(normalBlocked)throw new Error('Normal PC was blocked');
console.log(JSON.stringify({schema:outcome.schema,counts:outcome.counts,
  total:fixture.alerts.length,normalBlocked,alertsLogged:lines.length,
  temporaryDenyRules:rules.length}));
