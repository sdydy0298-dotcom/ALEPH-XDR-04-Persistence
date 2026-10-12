// A local policy checker, not a production enforcement device.
export function checkAccess(source,dynamicRules=[],at=Date.now(),basePolicy={}) {
  const time=at instanceof Date?at.getTime():Number(at);
  if(!Number.isFinite(time))throw new TypeError('Invalid evaluation time');
  const matches=rule=>rule && (rule.source===source || rule.ip===source);
  const staticDeny=Array.isArray(basePolicy.deny)&&basePolicy.deny.some(rule=>
    matches(rule)&&(!rule.expiresAt||Date.parse(rule.expiresAt)>time));
  if(staticDeny)return {action:'deny',reason:'기존 ZTNA 거부 규칙'};
  const xdrDeny=Array.isArray(dynamicRules)&&dynamicRules.some(rule=>
    rule.action==='deny' && matches(rule) && Date.parse(rule.expiresAt)>time);
  if(xdrDeny)return {action:'deny',reason:'XDR-04 임시 격리 규칙'};
  return {action:'allow',reason:'활성 거부 규칙 없음'};
}
