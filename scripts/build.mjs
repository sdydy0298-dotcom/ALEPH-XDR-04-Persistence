import {readFile,writeFile,copyFile,mkdir} from 'node:fs/promises';
const root=new URL('../',import.meta.url);
const file=path=>new URL(path,root);
const fixture=JSON.parse(await readFile(file('xdr/fixtures/persistence.json'),'utf8'));
const result=JSON.parse(await readFile(file('xdr/persistence/result.json'),'utf8'));
const deny=JSON.parse(await readFile(file('xdr/temporary-deny.json'),'utf8'));
if(fixture.schema!=='aleph.xdr.fixture.v1'||fixture.moduleKey!=='persistence'||
   !Array.isArray(fixture.alerts)||fixture.alerts.length!==24)
  throw new Error('Official persistence training fixture contract mismatch');
if(result.schema!=='aleph.xdr.result.v1'||result.moduleKey!=='persistence'||
   !Array.isArray(result.decisions)||result.decisions.length!==fixture.alerts.length)
  throw new Error('Official result contract mismatch');
if(!Array.isArray(deny)||deny.length!==result.counts.block)
  throw new Error('Dynamic deny policies differ from BLOCK outcomes');
const samples=fixture.alerts.map(alert=>({
  id:alert.id,timestamp:alert.timestamp,
  rule:{level:alert.rule.level,mitre:alert.rule.mitre,description:alert.rule.description},
  data:{srcip:alert.data.srcip,srcuser:alert.data.srcuser??'',
    path:alert.data.path??'',count:alert.data.count??null}
}));
const results=result.decisions.map((answer,i)=>{
  const event=samples[i];
  if(answer.alertId!==event.id)throw new Error('Result alert ID mismatch');
  return {alertId:answer.alertId,action:answer.action,confidence:answer.confidence,
    reason:answer.reason,description:event.rule.description,
    source:event.data.srcip,level:event.rule.level,attempts:event.data.count,
    normal:!event.rule.mitre.some(t=>t==='T1543'||t==='T1053')&&event.rule.level<=3};
});
const report={
  schema:'aleph.xdr.result.v1',moduleKey:'persistence',
  generatedAt:'2026-10-13T00:00:00.000Z',fixtureCount:samples.length,counts:result.counts,
  normalBlocked:results.filter(item=>item.normal&&item.action==='block').length,
  temporaryDenyRules:deny.map(rule=>({
    id:rule.id,source:rule.source,alertId:rule.alertId,expiresAt:rule.expiresAt})),
  results
};
if(report.normalBlocked)throw new Error('Normal event incorrectly isolated');
await mkdir(file('public/'),{recursive:true});
await writeFile(file('public/report.json'),JSON.stringify(report,null,2)+'\n');
await writeFile(file('public/samples.json'),JSON.stringify({alerts:samples},null,2)+'\n');
for(const [from,to] of [
  ['index.html','public/index.html'],['styles.css','public/styles.css'],
  ['app.js','public/app.js'],['xdr/persistence/decide.mjs','public/decide.mjs']
])await copyFile(file(from),file(to));
console.log(JSON.stringify({siteReady:true,fixtureCount:samples.length,
  counts:result.counts,normalBlocked:report.normalBlocked}));
