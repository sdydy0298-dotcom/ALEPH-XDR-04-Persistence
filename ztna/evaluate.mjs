import {readFile} from 'node:fs/promises';
import {checkAccess} from './check.mjs';

// Preserve existing access controls and add XDR dynamic denies as a separate gate.
export async function evaluateAccess(source,at=Date.now()) {
  const [baseline,current]=await Promise.all([
    readFile(new URL('./rules.json',import.meta.url),'utf8'),
    readFile(new URL('../xdr/temporary-deny.json',import.meta.url),'utf8')
  ]);
  const policy=JSON.parse(baseline),dynamic=JSON.parse(current);
  if(!Array.isArray(dynamic))throw new Error('Invalid dynamic deny rules');
  return checkAccess(source,dynamic,at,policy);
}
