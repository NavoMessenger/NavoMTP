(()=>{
'use strict';
const maxChunks=4096;
function cancel(response){
 if(!response.body)return;
 try{const pending=response.body.cancel();if(pending&&typeof pending.catch==='function')pending.catch(()=>{})}catch(error){}
}
function declaredLength(response){
 const value=response.headers.get('Content-Length');
 if(value===null)return null;
 if(!/^(0|[1-9]\d*)$/.test(value))throw new Error('invalid response length');
 const parsed=Number(value);
 if(!Number.isSafeInteger(parsed))throw new Error('invalid response length');
 return parsed;
}
async function read(response,limit,exact,signal){
 let declared;
 try{declared=declaredLength(response)}catch(error){cancel(response);throw error}
 if(declared!==null&&(declared>limit||(exact&&declared!==limit))){cancel(response);throw new Error('response body overflow')}
 if(limit===0){cancel(response);return new ArrayBuffer(0)}
 if(!response.body){if(exact||declared){throw new Error('missing response body')}return new ArrayBuffer(0)}
 const reader=response.body.getReader(),chunks=[];let total=0,count=0,failed=false;
 try{
  for(;;){
   if(signal&&signal.aborted)throw new Error('response read aborted');
   const part=await reader.read();if(part.done)break;
   if(!(part.value instanceof Uint8Array))throw new Error('invalid response chunk');
   count++;total+=part.value.byteLength;
   if(count>maxChunks||total>limit||(declared!==null&&total>declared))throw new Error('response body overflow');
   chunks.push(part.value);
  }
  if((exact&&total!==limit)||(declared!==null&&total!==declared))throw new Error('invalid response length');
 }catch(error){failed=true;try{const pending=reader.cancel();if(pending&&typeof pending.catch==='function')pending.catch(()=>{})}catch(cancelError){}throw error}
 finally{try{reader.releaseLock()}catch(error){}if(failed&&signal&&signal.aborted)cancel(response)}
 const joined=new Uint8Array(total);let offset=0;
 for(const chunk of chunks){joined.set(chunk,offset);offset+=chunk.byteLength}
 return joined.buffer;
}
globalThis.TelemtBridgeResponse=Object.freeze({cancel,read});
})();
