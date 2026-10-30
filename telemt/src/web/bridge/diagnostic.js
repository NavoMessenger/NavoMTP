(()=>{'use strict';
let bootstrap="__BOOTSTRAP__",hello=false,emitted=0,boundaryTimer=null;
const relayOrigin='https://__HOST__',relayBase=relayOrigin+'__BASE_PREFIX__',requestMs=__BRIDGE_REQUEST_SECS__*1000;
function eventBit(event){
 if(event==='runtime_started')return 1;if(event==='status_posted')return 2;if(event==='hello_received')return 4;if(event==='boundary_timeout')return 8;
 if(event==='hello_timeout')return 16;if(event==='client_close_before_hello')return 32;if(event==='document_unloaded_before_hello')return 64;
 return event==='runtime_error_before_hello'?128:0;
}
function discard(response){try{if(response.body)response.body.cancel().catch(()=>{})}catch(error){}}
function report(event){
 if(hello&&event!=='hello_received')return;const bit=eventBit(event);if(!bit||(emitted&bit))return;emitted|=bit;
 let timer=null;
 try{
  const controller=new AbortController(),body=JSON.stringify({v:1,event});timer=setTimeout(()=>controller.abort(),requestMs);
  fetch(relayBase+'/api/v1/diagnostic',{method:'POST',body,signal:controller.signal,keepalive:true,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',headers:{Authorization:'Bearer '+bootstrap,'Content-Type':'application/json'}})
   .then(discard,()=>{}).then(()=>clearTimeout(timer),()=>clearTimeout(timer));
 }catch(error){if(timer)clearTimeout(timer)}
}
const boundaryWall=Date.now()+requestMs,boundaryMonotonic=performance.now()+requestMs;
function waitBoundary(){
 boundaryTimer=null;if(hello||(emitted&2))return;const remaining=Math.min(boundaryWall-Date.now(),boundaryMonotonic-performance.now());
 if(remaining>0){boundaryTimer=setTimeout(waitBoundary,remaining);return}report('boundary_timeout');
}
function clearBoundary(){try{if(boundaryTimer)clearTimeout(boundaryTimer)}catch(error){}boundaryTimer=null}
function runtimeStarted(){report('runtime_started');try{boundaryTimer=setTimeout(waitBoundary,Math.max(1,Math.min(boundaryWall-Date.now(),boundaryMonotonic-performance.now())))}catch(error){}}
function boundaryActivated(){clearBoundary()}
function statusPosted(){clearBoundary();report('status_posted')}
function helloReceived(){clearBoundary();hello=true;report('hello_received')}
function helloTimeout(){report('hello_timeout')}
function clientCloseBeforeHello(){report('client_close_before_hello')}
function documentUnloadedBeforeHello(){report('document_unloaded_before_hello')}
function setBootstrap(value){if(/^[A-Za-z0-9_-]{43}$/.test(value))bootstrap=value}
addEventListener('error',()=>report('runtime_error_before_hello'));
addEventListener('unhandledrejection',()=>report('runtime_error_before_hello'));
globalThis.TelemtBridgeDiagnostics=Object.freeze({runtimeStarted,boundaryActivated,statusPosted,helloReceived,helloTimeout,clientCloseBeforeHello,documentUnloadedBeforeHello,setBootstrap});
})();
