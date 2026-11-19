import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';

/** Fixed error only: never attach raw capture, child stderr, arguments or exception causes. */
export class PrivacyBlocked extends Error {
  constructor() { super('privacy-processing-blocked'); this.name='PrivacyBlocked'; }
}
/** Trusted host data plane. Config and key path must never come from agent/page arguments. No disable/approval tools. */
export function createCliSanitizer({executable, policyFile, privateKeyFile, scope, timeoutMs=5000}) {
  if([executable,policyFile,privateKeyFile].some(path=>typeof path!=='string'||!isAbsolute(path))||typeof scope!=='string'||scope.length<1||scope.length>128)throw new PrivacyBlocked();
  if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000)throw new PrivacyBlocked();
  return async function sanitize(raw) {
    let input;
    try { input=JSON.stringify(raw);if(Buffer.byteLength(input,'utf8')>262144)throw new PrivacyBlocked(); }
    catch { throw new PrivacyBlocked(); }
    try { return await new Promise((resolve,reject)=>{
      const child=spawn(executable,['sanitize','json',policyFile,privateKeyFile,scope],{stdio:['pipe','pipe','ignore']});
      const chunks=[];let size=0,failed=false;
      const fail=()=>{if(failed)return;failed=true;clearTimeout(timer);child.kill();reject(new PrivacyBlocked());};
      const timer=setTimeout(fail,timeoutMs);
      child.on('error',fail);child.stdin.on('error',fail);child.stdout.on('error',fail);
      child.stdout.on('data',chunk=>{size+=chunk.length;if(size>4194304){fail();return;}chunks.push(chunk);});
      child.on('close',code=>{
        clearTimeout(timer);if(failed)return;
        try {
          if(code!==0)throw new PrivacyBlocked();
          const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if(result.Allowed!==true||result.SafeForAgent!==true)throw new PrivacyBlocked();
          resolve(result);
        } catch { fail(); }
      });
      child.stdin.end(input+'\n');
    }); } catch { throw new PrivacyBlocked(); }
  };
}
/** Capture must execute entirely in trusted host, before raw output can be observed by any model/agent tool. */
export function createPrivateCaptureTool({captureInHost,sanitizeInHost}) {
  return async function readForAgent(request) {
    try {
      const raw=await captureInHost(request);
      const clean=await sanitizeInHost(raw);
      if(clean?.Allowed!==true || clean?.SafeForAgent!==true)throw new PrivacyBlocked();
      // Never return raw capture or a fallback, including on provider errors.
      const masked=clean.MustDiscloseMasking===true||clean.OriginalReplaced===true;
      const notice=masked?'Часть данных скрыта ag-privacy. Исходные значения агенту недоступны.':'ag-privacy включён.';
      return {data:clean.Data,notice,mustDiscloseMasking:masked};
    } catch { throw new PrivacyBlocked(); }
  };
}
/** Honest adapter qualification: Codex is optional, and no already-visible built-in browser result can be retroactively protected. */
export const providerContract=Object.freeze({
  codex:{status:'unqualified',required:'supported pre-model capture hook in trusted host'},
  direct:{status:'host-contract',required:'capture callback and sanitized-only tool response'},
  agentDependencies:[], consentControlExposed:false, rawFallback:false
});


/** Verified installer profile is fixed by trusted host, not per-request arguments. May intentionally authorize originals in minimal/off. */
export function createVerifiedCliSanitizer({executable,profileDirectory,pinnedPublicKeyFile,approvedConfigSha256,privateKeyFile,timeoutMs=5000}) {
  if([executable,profileDirectory,pinnedPublicKeyFile,privateKeyFile].some(path=>typeof path!=='string'||!isAbsolute(path))||
     typeof approvedConfigSha256!=='string'||!/^([a-fA-F0-9]{64})$/.test(approvedConfigSha256)||
     !Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000)throw new PrivacyBlocked();
  return async raw=>{
    try {
      const input=JSON.stringify(raw);if(Buffer.byteLength(input,'utf8')>262144)throw new PrivacyBlocked();
      return await new Promise((resolve,reject)=>{
        const child=spawn(executable,['sanitize-verified',profileDirectory,pinnedPublicKeyFile,approvedConfigSha256,privateKeyFile],{stdio:['pipe','pipe','ignore']});
        const chunks=[];let size=0,failed=false;
        const fail=()=>{if(failed)return;failed=true;clearTimeout(timer);child.kill();reject(new PrivacyBlocked());};
        const timer=setTimeout(fail,timeoutMs);
        child.on('error',fail);child.stdin.on('error',fail);child.stdout.on('error',fail);
        child.stdout.on('data',data=>{size+=data.length;if(size>4194304){fail();return;}chunks.push(data);});
        child.on('close',code=>{
          clearTimeout(timer);if(failed)return;
          try {
            if(code!==0)throw new PrivacyBlocked();
            const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if(result.Allowed!==true)throw new PrivacyBlocked();
            const strict=result.SafeForAgent===true&&result.ProtectionMode==='strict';
            const selected=result.SafeForAgent===false&&result.AuthorizedByHumanChoice===true&&['credentials-only','off'].includes(result.ProtectionMode);
            if(!strict&&!selected)throw new PrivacyBlocked();
            resolve(result);
          }catch{fail();}
        });
        child.stdin.end(input+'\n');
      });
    }catch{throw new PrivacyBlocked();}
  };
}


/** Capture adapter for a verified installation. All config comes from trusted host; user-selected originals are explicit in the response. */
export function createVerifiedCaptureTool({captureInHost,...configuration}) {
  const sanitize=createVerifiedCliSanitizer(configuration);
  return async request=>{
    try {
      const result=await sanitize(await captureInHost(request));
      const mode=result.ProtectionMode,masked=result.MustDiscloseMasking===true;
      let notice=masked?'Часть данных скрыта ag-privacy. Исходные значения агенту недоступны.':'ag-privacy включён.';
      if(mode==='off')notice='ag-privacy выключен пользователем при установке. Данные передаются в оригинале.';
      if(mode==='credentials-only')notice=(masked?'Часть данных скрыта ag-privacy. ':'')+'Минимальный режим выбран пользователем; остальные данные могут передаваться в оригинале.';
      return {data:result.Data,protectionMode:mode,notice,mustDiscloseMasking:masked,authorizedByHumanChoice:result.AuthorizedByHumanChoice===true};
    }catch{throw new PrivacyBlocked();}
  };
}
