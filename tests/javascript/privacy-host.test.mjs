import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateCaptureTool, PrivacyBlocked, providerContract } from '../../adapters/javascript/privacy-host.mjs';

test('provider-neutral tool returns only clean data and generic required notice',async()=>{
  const tool=createPrivateCaptureTool({captureInHost:async()=>({token:'RAW_CANARY'}),sanitizeInHost:async raw=>{
    assert.equal(raw.token,'RAW_CANARY');return {Allowed:true,SafeForAgent:true,Data:{token:'[REDACTED:v1:OPAQUE]'},AgentNotice:'Часть данных скрыта ag-privacy.',MustDiscloseMasking:true};
  }});
  const result=await tool({});assert.equal(result.mustDiscloseMasking,true);assert.ok(!JSON.stringify(result).includes('RAW_CANARY'));
});
test('heuristic, capture failures and sanitizer failures never return raw fallback',async()=>{
  for(const mode of ['unsafe','capture','sanitize']){
    const tool=createPrivateCaptureTool({captureInHost:async()=>{if(mode==='capture')throw new Error('RAW_CANARY');return 'RAW_CANARY';},sanitizeInHost:async()=>{if(mode==='sanitize')throw new Error('RAW_CANARY');return {Allowed:true,SafeForAgent:false,Data:'RAW_CANARY'};}});
    await assert.rejects(tool({}),e=>e instanceof PrivacyBlocked&&!e.message.includes('RAW_CANARY')&&!e.cause);
  }
  assert.equal(providerContract.codex.status,'unqualified');assert.equal(providerContract.consentControlExposed,false);
});

test('masking notice cannot echo sanitizer diagnostic samples or silently omit original-replaced flag',async()=>{
  const tool=createPrivateCaptureTool({captureInHost:async()=>({token:'RAW_CANARY'}),sanitizeInHost:async()=>({Allowed:true,SafeForAgent:true,Data:{token:'[REDACTED:v1:OPAQUE]'},OriginalReplaced:true,AgentNotice:'RAW_CANARY'})});
  const result=await tool({});assert.equal(result.mustDiscloseMasking,true);assert.ok(!JSON.stringify(result).includes('RAW_CANARY'));
});
