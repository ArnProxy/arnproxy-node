import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import {EventEmitter} from 'node:events';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
const root=process.argv[2],f=JSON.parse(fs.readFileSync(process.argv[3])),{Client,ArnproxyError,verifyWebhook}=await import(pathToFileURL(path.join(root,'node/arnproxy.mjs'))),resources=JSON.parse(fs.readFileSync(path.join(root,'resources.json'))).resources;let checks=0;
// Deliberately public synthetic bytes; never a production signing secret.
for(const vector of f.vectors){
 if(vector.secret_fixture!==undefined){
  assert(['repeat_X_32','repeat_Y_32'].includes(vector.secret_fixture));
  vector.secret='whsec_'+Buffer.alloc(32,vector.secret_fixture==='repeat_X_32'?88:89).toString('base64');
 }
}

const ck=v=>{assert(v);checks++;},error=async(call,code)=>{try{await call();assert.fail('Expected '+code);}catch(e){assert(e instanceof ArnproxyError);ck(e.code===code);ck(!e.message.includes(f.key));return e;}};
class Mock extends Client{calls=[];status=200;responseHeaders={};raw=Buffer.from(JSON.stringify(f.body));failure=false;async _send(...args){this.calls.push(args);if(this.failure)throw Error('sensitive '+f.key);return{status:this.status,headers:this.responseHeaders,body:this.raw};}}
const c=new Mock(f.key,{allow_writes:true,allow_provider_reads:true});
for(const[name,s]of Object.entries(resources)){
 const params=s.path.includes('{id}')?{id:123}:{};params.q='ü & = ? /';const operation_key=s.idempotency?f.operation_key:null,count=c.calls.length;
 if(s.disabled){await error(()=>c.request(name,params,{operation_key}),'DISABLED_RESOURCE');ck(c.calls.length===count);continue;}
 ck((await c.request(name,params,{operation_key})).data.id===2);const[method,p,headers,body]=c.calls.at(-1),url=new URL('https://www.arnproxy.com'+p);ck(method===s.method);ck(url.pathname==='/account/api/v1/'+s.path.replace('{id}','123'));ck(!p.includes(f.key));ck(headers.Authorization==='Bearer '+f.key);ck((headers['Idempotency-Key']??null)===operation_key);if(method==='GET'){ck(url.searchParams.get('q')===params.q);ck(body===null);}else ck(JSON.stringify(JSON.parse(body))===JSON.stringify(params));ck(c.calls.length===count+1);
 const guarded=new Mock(f.key);if(s.write||s.provider_read){await error(()=>guarded.request(name,params,{operation_key}),s.write?'WRITES_DISABLED':'PROVIDER_READS_DISABLED');ck(!guarded.calls.length);}if(s.idempotency){await error(()=>c.request(name,params),'OPERATION_KEY_REQUIRED');ck(c.calls.length===count+1);}
}
for(const key of ['',f.key+'\n',' '+f.key,'x'.repeat(31)])await error(()=>new Client(key),'INVALID_KEY_FORMAT');
await error(()=>c.request('account',{resource:'purchase'}),'INVALID_PARAMETERS');await error(()=>c.request('proxy',{id:'1/../../secret'}),'INVALID_ROUTE_ID');await error(()=>c.request('orders',{id:[1,2]}),'INVALID_QUERY_VALUE');await error(()=>c.request('quote',{bad:NaN}),'INVALID_JSON_BODY');await error(()=>c.request('quote',{x:'a'.repeat(2*1024*1024)}),'REQUEST_TOO_LARGE');
c.status=302;c.raw=Buffer.alloc(0);let n=c.calls.length;ck((await error(()=>c.account(),'REDIRECT_BLOCKED')).uncertain===false);ck(c.calls.length===n+1);
c.status=429;c.raw=Buffer.from(JSON.stringify({ok:false,error:{code:'RATE_LIMITED'},meta:{request_id:f.request_id}}));c.responseHeaders={'retry-after':'12'};let e=await error(()=>c.account(),'RATE_LIMITED');ck(e.http_status===429&&e.retry_after===12&&e.request_id===f.request_id);
c.status=500;c.raw=Buffer.from('<html>not json</html>');ck((await error(()=>c.request('purchase',{},{operation_key:f.operation_key}),'INVALID_API_RESPONSE')).uncertain===true);
c.failure=true;n=c.calls.length;ck((await error(()=>c.request('purchase',{},{operation_key:f.operation_key}),'TRANSPORT_ERROR')).uncertain===true);ck(c.calls.length===n+1);c.failure=false;c.status=200;c.raw=Buffer.from(JSON.stringify({ok:true,data:{state:'unknown'},meta:{request_id:f.request_id}}));ck((await c.request('purchase',{},{operation_key:f.operation_key})).data.state==='unknown');ck(!JSON.stringify(new Client(f.key)).includes(f.key));
for(const v of f.vectors){const call=()=>verifyWebhook(Buffer.from(v.body),v.headers,v.secret,{now:v.now});if(v.valid)ck(call().id.startsWith('evt_'));else await error(call,'WEBHOOK_VERIFICATION_FAILED');}
const native=https.request;let requests=0,options,lastBody;
try{https.request=(o,cb)=>{requests++;options=o;const q=new EventEmitter();q.destroy=()=>{};q.end=body=>{lastBody=body;queueMicrotask(()=>{const r=new EventEmitter();r.statusCode=200;r.headers={};r.destroy=()=>{};cb(r);r.emit('data',Buffer.from(JSON.stringify(f.body)));r.emit('end');});};return q;};ck((await new Client(f.key).account()).data.id===2);ck(requests===1);ck(options.hostname==='www.arnproxy.com'&&options.port===443&&options.path==='/account/api/v1/account');ck(options.rejectUnauthorized===true&&options.agent===false&&lastBody===null);}finally{https.request=native;}
console.log(JSON.stringify({status:'PASS',checks,resources:Object.keys(resources).length,webhook_vectors:f.vectors.length,external_requests:0}));
