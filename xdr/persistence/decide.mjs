// ALEPH XDR-04 | Persistence | MITRE ATT&CK T1543 / T1053 (+ T1547.001)
// Judge loads this file alone. It never imports, reads/writes a file, or contacts a server.
// Pattern identifiers below are mirrored verbatim from patterns.json.
const PATTERNS = Object.freeze({
  service: 'T1543-Unsigned-New-Service',
  task: 'T1053-Untrusted-Scheduled-Task',
  startup: 'T1547-Startup-Folder-Persistence',
  correlated: 'T1543-T1053-Correlated-Persistence',
  uncertain: 'T1543-T1053-Uncertain-Change',
  benign: 'T1543-T1053-Benign-Activity'
});

const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const str = value => typeof value === 'string' ? value : '';
const choose = (...values) => values.find(value => value !== undefined && value !== null && value !== '') ?? null;
const readCount = value => {
  if (typeof value === 'number') return Number.isFinite(value) && value >= 0 && value <= 1e6 ? value : null;
  if (typeof value === 'string' && /^\s*\d{1,6}\s*$/.test(value)) return Number(value);
  return null;
};
function hasSource(value) {
  if (typeof value !== 'string') return false;
  const ip=value.trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) return ip.split('.').every(s=>Number(s) <= 255);
  return ip.includes(':') && /^[0-9a-f:]{2,45}$/i.test(ip);
}
function signal(alert) {
  const a=obj(alert), d=obj(a.data), r=obj(a.rule), service=obj(choose(d.service,a.service)),
    task=obj(choose(d.task,d.scheduledTask,a.task)), process=obj(d.process), sys=obj(d.syscheck),
    event=obj(d.event), win=obj(d.win), eventData=obj(win.eventdata);
  const description=[
    r.description,a.description,d.description,d.message,d.action,d.event_type,
    event.action,event.description,service.action,task.action
  ].filter(v=>typeof v==='string').join(' ').toLowerCase();
  const path=[d.path,d.file,d.filepath,d.file_path,d.image,d.executable,d.target,
    service.path,service.imagePath,service.executable,task.path,task.command,
    process.path,sys.path,eventData.imagePath,eventData.command].filter(v=>typeof v==='string')
    .join(' ').replaceAll('\\','/').toLowerCase();
  const level=readCount(choose(r.level,a.level,d.level)) ?? 0;
  const count=readCount(choose(d.count,d.frequency,d.attemptCount,d.repetitions,r.frequency,a.count)) ?? 0;
  const techniques=Array.isArray(r.mitre)?r.mitre.map(x=>typeof x==='string'?x:str(obj(x).id)):[];
  const tagged=techniques.some(x=>x==='T1543'||x==='T1053'||x==='T1547'||x==='T1547.001');
  const svc=/서비스|service|daemon|systemd/.test(description) ||
    Object.keys(service).length>0;
  const scheduled=/예약\s*작업|작업\s*스케줄|scheduled\s*task|schedule[dr]|schtasks|cron|crontab/.test(description) ||
    Object.keys(task).length>0;
  const startup=/시작\s*(?:폴더|프로그램|항목)|startup|autorun|자동\s*시작|로그온\s*실행/.test(description) ||
    /\/startup\//.test(path);
  const newChange=/처음\s*보는|새로|새\s*서비스|생겼|등록|생성|설치|추가|바뀌|변경|교체|임의\s*문자열|modified|created|registered|new\s|install/.test(description) ||
    d.isNew===true || service.isNew===true || task.isNew===true;
  const missingSignature=/서명\s*없는|서명이\s*없|미서명|서명되지\s*않|unsigned|untrusted|invalid\s*sign|signature.*(?:missing|invalid)/.test(description) ||
    d.signed===false || service.signed===false || service.signatureValid===false ||
    str(choose(d.signature,d.signatureStatus,service.signature)).toLowerCase()==='unsigned';
  const unknown=/평소\s*목록에\s*없는|처음\s*보는|낯선|모르는|미확인|임의\s*문자열|허용\s*목록에\s*없|unknown|unrecognized|random|unapproved|unexpected/.test(description) ||
    d.allowlisted===false || service.allowlisted===false || task.allowlisted===false;
  const tmp=/\/(?:appdata\/local\/temp|windows\/temp|temp|tmp)\//.test(path);
  const fromStartup=/\/(?:start menu\/programs\/startup|startup)\//.test(path);
  const afterHours=/수업\s*시간\s*밖|근무\s*시간\s*밖|야간|outside\s*(?:working|school|office)\s*hours|off.hours/.test(description);
  const survive=/다시\s*켜도\s*남|재부팅.*남|영구\s*등록|부팅.*자동|persists?\s*after\s*reboot|survive\s*reboot/.test(description);
  const repeated=/연속|반복|같은\s*파일|함께|여러\s*건|consecutive|repeated|multiple\s*registrations?/.test(description) || count>=3;
  const passive=/읽기만|보기만|변경\s*없|그대로|완료|로그인했|로그아웃|화면이\s*열|상태\s*조회|status\s*check|read.only/.test(description);
  const signedSafe=/서명된\s*채|정상\s*서명|서명이\s*유효|valid\s*signature|signed\s*(?:binary|service)/.test(description) ||
    service.signatureValid===true;
  const authorized=/기존|평소\s*시각|운영체제\s*업데이트|정의\s*업데이트|수업\s*도구\s*서비스/.test(description);
  return {svc,scheduled,startup,newChange,missingSignature,unknown,tmp,fromStartup,
    afterHours,survive,repeated,passive,signedSafe,authorized,tagged,level,count,
    source:choose(d.srcip,d.src_ip,d.source_ip,d.client_ip,a.srcip,a.source_ip),
    description};
}
export function decide(alert) {
  const s=signal(alert);
  const result=(confidence,reason)=>({
    action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',
    confidence,reason
  });
  // Valid known-good activities must not become quarantine candidates.
  if(s.passive && !s.newChange && !s.missingSignature && !s.unknown)
    return result(.06,PATTERNS.benign);
  if(s.signedSafe && !s.missingSignature && !s.unknown)
    return result(.06,PATTERNS.benign);
  if(s.authorized && s.level<=3 && !s.unknown && !s.missingSignature)
    return result(.06,PATTERNS.benign);

  const serviceRisk=s.svc && s.newChange &&
    (s.missingSignature || s.unknown || s.survive || (s.tmp && !s.authorized));
  const taskRisk=s.scheduled && s.newChange &&
    (s.tmp || s.unknown || s.afterHours || s.missingSignature);
  const startupRisk=s.startup && s.newChange &&
    (s.unknown || s.fromStartup && s.level>=10 || s.missingSignature);
  const jointRisk=(s.scheduled && s.startup && s.tmp) ||
    (s.svc && s.scheduled && s.unknown) ||
    (s.svc && s.missingSignature && s.repeated && s.newChange);

  if(s.tagged && s.level>=10 && hasSource(s.source)) {
    if(jointRisk)return result(.98,PATTERNS.correlated);
    if(serviceRisk)return result(.96,PATTERNS.service);
    if(taskRisk)return result(.95,PATTERNS.task);
    if(startupRisk)return result(.94,PATTERNS.startup);
  }
  // Correlated Wazuh alerts at medium confidence need human review, never quarantine.
  const relevant=s.svc||s.scheduled||s.startup||s.tmp;
  if((s.tagged && s.level>=5 && relevant) ||
     (relevant && s.level>=5 && (s.newChange||s.unknown||s.missingSignature))) {
    return result(.64,PATTERNS.uncertain);
  }
  return result(.06,PATTERNS.benign);
}
