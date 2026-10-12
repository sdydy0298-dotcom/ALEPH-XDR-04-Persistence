import {readFile,writeFile,appendFile,mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {isIP} from 'node:net';
import {decide} from './decide.mjs';
import {checkAccess} from '../../ztna/check.mjs';

const temporary=new URL('../temporary-deny.json',import.meta.url);
const alertsFile=new URL('../alerts.log',import.meta.url);
const safeId=value=>/^[A-Za-z0-9_.:-]{1,96}$/.test(String(value??''))?String(value):null;
const safeIp=value=>typeof value==='string' && isIP(value.trim())?value.trim():null;
async function readActive() {
  try{
    const saved=JSON.parse(await readFile(temporary,'utf8'));
    if(!Array.isArray(saved))throw new Error('Invalid temporary deny list');
    return saved;
  }catch(error){if(error.code==='ENOENT')return [];throw error;}
}
export async function respond(alert,verdict,{now=new Date(),persist=true}={}) {
  if(!verdict || !['block','alert','record'].includes(verdict.action) ||
    typeof verdict.confidence!=='number' || !Number.isFinite(verdict.confidence) ||
    verdict.confidence<0 || verdict.confidence>1)
    throw new TypeError('Invalid persistence verdict');
  if(!(now instanceof Date)||Number.isNaN(now.getTime()))throw new TypeError('Invalid clock');
  const data=alert?.data??{};
  const id=safeId(alert?.id??alert?.alertId);
  const source=safeIp(data.srcip??data.src_ip??data.source_ip??data.client_ip??alert?.srcip??alert?.source_ip);
  const active=(persist?await readActive():[]).filter(rule=>
    rule?.action==='deny' && Number.isFinite(Date.parse(rule.expiresAt)) &&
    Date.parse(rule.expiresAt)>now.getTime());
  const checked=decide(alert);
  // Independent re-check: a forged external verdict must never quarantine a normal PC.
  if(verdict.action==='block' && verdict.confidence>=0.85 && checked.action==='block' &&
     id && source) {
    const rule={
      id:'xdr04-'+id,action:'deny',source,alertId:id,reason:checked.reason,
      createdAt:now.toISOString(),expiresAt:new Date(now.getTime()+15*60*1000).toISOString()
    };
    if(!active.some(other=>other.id===rule.id))active.push(rule);
  }
  const notification={
    alertId:id??'unknown',action:checked.action,confidence:checked.confidence,
    reason:checked.reason,at:now.toISOString()
  };
  if(persist){
    await mkdir(dirname(fileURLToPath(temporary)),{recursive:true});
    await writeFile(temporary,JSON.stringify(active,null,2)+'\n');
    if(checked.action!=='record')
      await appendFile(alertsFile,JSON.stringify(notification)+'\n');
  }
  return {
    notification:checked.action==='record'?null:notification,
    rules:active,
    access:source?checkAccess(source,active,now.getTime()):
      {action:'allow',reason:'유효한 출발 주소 없음'}
  };
}
