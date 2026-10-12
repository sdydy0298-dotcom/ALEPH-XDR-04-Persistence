import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {decide} from '../xdr/persistence/decide.mjs';
import {readAlerts,projectAlert} from '../xdr/persistence/read-alerts.mjs';
import {respond} from '../xdr/persistence/respond.mjs';
import {checkAccess} from '../ztna/check.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';

const json=async p=>JSON.parse(await readFile(new URL('../'+p,import.meta.url),'utf8'));
const fixture=await json('xdr/fixtures/persistence.json');
const result=await json('xdr/persistence/result.json');
const clock=new Date('2026-10-13T00:00:00.000Z');
const example=(description,level=12,mitre=['T1543'],extra={})=>({
 id:'REGRESSION-01',timestamp:clock.toISOString(),
 rule:{level,mitre,description},
 data:{srcip:'198.51.100.87',srcuser:'test-user',...extra}
});

test('official unmodified Wazuh fixture has 24 events for persistence',()=>{
 assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
 assert.equal(fixture.moduleKey,'persistence');
 assert.equal(fixture.alerts.length,24);
 assert.equal(new Set(fixture.alerts.map(x=>x.id)).size,24);
 assert.ok(fixture.alerts.every(x=>x.agent?.name==='choi-bujang-pc'));
});

test('Wazuh inspection prints exactly one SAFE five-field summary per alert',async()=>{
 const events=await readAlerts();
 assert.equal(events.length,24);
 assert.ok(events.every(e=>Object.keys(e).sort().join(',')==='account,description,level,source,time'));
 assert.equal(events[0].source,'203.0.113.12');
 assert.equal(events[0].account,'user01');
 const cli=spawnSync(process.execPath,['xdr/persistence/read-alerts.mjs'],{encoding:'utf8'});
 assert.equal(cli.status,0,cli.stderr);
 const lines=cli.stdout.trim().split('\n');
 assert.equal(lines.length,24);
 assert.ok(lines.every(x=>Object.keys(JSON.parse(x)).length===5));
 const secret=projectAlert({
  rule:{level:10,description:'password=hidden-pass token=hidden-token'},
  data:{srcuser:'Bearer hidden-session',srcip:'192.0.2.3'}
 });
 assert.doesNotMatch(JSON.stringify(secret),/hidden-pass|hidden-token|hidden-session/);
});

test('original standalone judge exports decide without imports or external I/O',async()=>{
 const code=await readFile(new URL('../xdr/persistence/decide.mjs',import.meta.url),'utf8');
 assert.match(code,/export function decide\(alert\)/);
 assert.doesNotMatch(code,/^\s*import(?:\s|[{*"'(])/m);
 assert.doesNotMatch(code,/\b(?:fetch|require|readFile|writeFile|eval)\s*\(/);
 assert.ok(code.includes('const PATTERNS'));
 assert.deepEqual(decide({}),{action:'record',confidence:.06,reason:'T1543-T1053-Benign-Activity'});
});

test('official aleph.xdr.result.v1 has correct counts and per-alert decisions',()=>{
 assert.equal(result.schema,'aleph.xdr.result.v1');
 assert.equal(result.moduleKey,'persistence');
 assert.equal(result.decisions.length,24);
 const counts={block:0,alert:0,record:0};
 fixture.alerts.forEach((item,i)=>{
   const expected=decide(item);
   assert.deepEqual(result.decisions[i],{alertId:item.id,...expected},item.id);
   assert.ok(Number.isFinite(expected.confidence) && expected.confidence>=0 && expected.confidence<=1);
   assert.equal(expected.action,expected.confidence>=.85?'block':expected.confidence>=.5?'alert':'record');
   assert.ok(expected.reason && !/[\r\n]/.test(expected.reason));
   counts[expected.action]++;
 });
 assert.deepEqual(counts,{block:8,alert:8,record:8});
 assert.deepEqual(result.counts,counts);
});

for(const [index,alert] of fixture.alerts.entries()){
 const expected=index<8?'block':index<16?'alert':'record';
 test('official alert '+alert.id+' classifies as '+expected,()=>{
   assert.equal(decide(alert).action,expected,JSON.stringify(decide(alert)));
 });
}

test('all listed patterns have one-line ATT&CK evidence and match pure judge constants',async()=>{
 const patterns=await json('xdr/persistence/patterns.json');
 const judge=await readFile(new URL('../xdr/persistence/decide.mjs',import.meta.url),'utf8');
 assert.ok(patterns.length>=3);
 for(const pattern of patterns){
   assert.ok(pattern.name && pattern.condition && pattern.evidence);
   assert.match(pattern.evidence,/T1543|T1053|T1547/);
   assert.doesNotMatch(pattern.evidence,/[\r\n]/);
   assert.ok(judge.includes(pattern.name),pattern.name);
 }
 assert.ok(patterns.some(x=>x.evidence.includes('T1543')));
 assert.ok(patterns.some(x=>x.evidence.includes('T1053')));
});

test('respond stored 8 evidence-ID isolation rules and 16 one-line notifications',async()=>{
 const saved=await json('xdr/temporary-deny.json');
 const lines=(await readFile(new URL('../xdr/alerts.log',import.meta.url),'utf8')).trim().split('\n').filter(Boolean);
 assert.equal(saved.length,8);
 assert.equal(lines.length,16);
 assert.equal(new Set(saved.map(x=>x.alertId)).size,8);
 for(const line of lines){
   const alert=JSON.parse(line);
   assert.ok(['block','alert'].includes(alert.action));
   assert.ok(alert.alertId && alert.reason && alert.at);
   assert.equal(Object.hasOwn(alert,'password'),false);
   assert.equal(Object.hasOwn(alert,'path'),false);
 }
 for(const rule of saved){
   assert.equal(rule.action,'deny');
   assert.ok(rule.alertId && rule.source && rule.reason && rule.createdAt && rule.expiresAt);
   assert.equal(Date.parse(rule.expiresAt)-Date.parse(rule.createdAt),15*60*1000);
   assert.equal((await evaluateAccess(rule.source,clock)).action,'deny');
   assert.equal((await evaluateAccess(rule.source,clock.getTime()+16*60000)).action,'allow');
 }
});

test('normal PC or ambiguous activity stays reachable in file-backed ZTNA',async()=>{
 for(const item of fixture.alerts){
   const verdict=decide(item);
   const response=await evaluateAccess(item.data.srcip,clock);
   if(verdict.action==='block')assert.equal(response.action,'deny',item.id);
   else assert.equal(response.action,'allow',item.id);
 }
 assert.equal(checkAccess('192.0.2.90',[],clock).action,'allow');
 assert.equal(checkAccess('192.0.2.90',[],clock,{deny:[{source:'192.0.2.90'}]}).action,'deny');
});

test('forged block decision cannot isolate harmless ordinary logon',async()=>{
 const normal=fixture.alerts.find(x=>x.id==='ps-17');
 const reply=await respond(normal,{action:'block',confidence:.99,reason:'fake'}, {now:clock,persist:false});
 assert.equal(reply.rules.length,0);
 assert.equal(reply.access.action,'allow');
});

test('untrustworthy Wazuh count or invalid clock is rejected',async()=>{
 const clear=fixture.alerts[0];
 await assert.rejects(()=>respond(clear,{action:'block',confidence:NaN,reason:'bad'},{now:clock,persist:false}),TypeError);
 await assert.rejects(()=>respond(clear,decide(clear),{now:new Date('invalid'),persist:false}),TypeError);
});

const cases=[
 ['new unsigned service pointing at Temp',example('서명 없는 새 서비스가 등록됐습니다.',12,['T1543'],{path:'C:\\Users\\user01\\AppData\\Local\\Temp\\mal.exe'}),'block'],
 ['new unsigned service without a specific path',example('서명 없는 새 서비스가 등록되었습니다.',12,['T1543']),'block'],
 ['replaced unsigned service executable',example('서비스 실행 파일이 바뀌었고 서명이 없습니다.',12,['T1543'],{path:'C:\\Windows\\Temp\\svc.exe'}),'block'],
 ['unknown scheduled task runs Temp',example('처음 보는 예약 작업이 임시 폴더 프로그램을 실행합니다.',11,['T1053'],{path:'C:\\Users\\user\\AppData\\Local\\Temp\\x.exe'}),'block'],
 ['suspicious random task name with Temp',example('예약 작업 이름이 임의 문자열이고 임시 폴더에서 실행됩니다.',10,['T1053'],{path:'C:\\Users\\user\\AppData\\Local\\Temp\\random.exe'}),'block'],
 ['unknown startup folder program',example('시작 폴더에 평소 목록에 없는 프로그램이 추가됐습니다.',11,['T1547.001'],{path:'C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\app.exe'}),'block'],
 ['service and task together',example('시작 프로그램과 예약 작업이 같은 임시 파일을 함께 가리킵니다.',11,['T1543','T1053'],{path:'C:\\Windows\\Temp\\stay.exe'}),'block'],
 ['repeated registration of unsigned services',example('서명 없는 새 서비스 등록이 연속으로 3건입니다.',12,['T1543'],{count:'3'}),'block'],
 ['new service but uncertainty at low Wazuh level',example('서명 없는 새 서비스가 등록됐습니다.',7,['T1543']),'alert'],
 ['a newly created temp file is NOT a registered service',example('임시 폴더에 실행 파일이 생겼지만 서비스 등록은 없습니다.',12,['T1543'],{path:'C:\\Windows\\Temp\\draft.exe'}),'alert'],
 ['classroom task added under observation',example('수업 중 예약 작업을 하나 만들었습니다.',6,['T1053'],{path:'C:\\lab\\copy-notes.cmd'}),'alert'],
 ['unchanged service binary, description edited',example('서비스 설명만 바뀌었습니다. 실행 파일은 그대로입니다.',6,['T1543']),'alert'],
 ['clear service but no source IP', {...example('서명 없는 새 서비스가 등록됐습니다.',12,['T1543']),data:{path:'C:\\Windows\\Temp\\x.exe'}},'alert'],
 ['clear service but impossible source IP',example('서명 없는 새 서비스가 등록됐습니다.',12,['T1543'],{srcip:'999.999.999.999'}),'alert'],
 ['untagged event cannot quarantine',example('서명 없는 새 서비스가 등록됐습니다.',12,[]),'alert'],
 ['already authorized signed service',example('기존 수업 도구 서비스가 정상 서명된 채로 실행 중입니다.',12,['T1543']),'record'],
 ['scheduled routine OS updates',example('운영체제 업데이트 예약이 평소 시각에 그대로입니다.',2,['T1053']),'record'],
 ['ordinary login event',example('로그인했습니다.',3,[]),'record'],
 ['read-only startup inventory',example('시작 프로그램 목록을 읽기만 했습니다.',3,[]),'record'],
 ['system definition update',example('정의 업데이트가 평소 저장소에서 끝났습니다.',3,[]),'record'],
 ['unrelated high-level security error',example('방화벽 드라이버 오류가 발생했습니다.',12,[]),'record']
];
for(const [name,item,expected] of cases){
 test(name,()=>assert.equal(decide(item).action,expected,JSON.stringify(decide(item))));
}

test('public report preserves judge actions without claiming live machine isolation',async()=>{
 const publicResult=await json('public/report.json');
 const samples=await json('public/samples.json');
 assert.deepEqual(publicResult.counts,result.counts);
 assert.equal(publicResult.normalBlocked,0);
 assert.equal(samples.alerts.length,24);
 assert.equal(publicResult.temporaryDenyRules.length,8);
 const ui=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const app=await readFile(new URL('../public/app.js',import.meta.url),'utf8');
 assert.match(ui,/ALEPH XDR-04/);
 assert.match(app,/import \{decide\} from '.\/decide.mjs'/);
 assert.doesNotMatch(ui,/ALEPH-XDR-03|kc-01|JNDI|Log4Shell/);
});
