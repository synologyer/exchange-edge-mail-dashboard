// Run with NODE_PATH pointing to a Playwright installation. Synthetic data only.
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.join(__dirname, '..', 'static');
const stamp = '2026-09-29T09:00:00Z';
const event = {time:stamp,node:'mx1',type:'收件',sender:'sender@example.org',recipients:'user@company.example',remoteIp:'192.0.2.20',subject:'报价确认',category:'外部来信已接收',source:'MessageTracking',status:'RECEIVE',rawIds:[1]};
const server = http.createServer((req,res)=>{
 const url=new URL(req.url,'http://localhost');
 if(url.pathname.startsWith('/api/')){
  res.setHeader('Content-Type','application/json');
  const days=Number(url.searchParams.get('days')||1);
  if(url.pathname==='/api/dashboard')return res.end(JSON.stringify({days,generatedAt:stamp,config:{domain:'company.example',trustedIps:['192.0.2.10'],nodes:['mx1','mx2']},counts:{inbound:3286,outbound:209,rejected:87,failed:43,spoofed:32,systemNdr:2},daily:Array.from({length:days},(_,i)=>({date:`2026-09-${String(i+1).padStart(2,'0')}`,inbound:20+i%6*13,outbound:10,rejected:2,spoofed:1})),hourly:Array.from({length:24},(_,i)=>({label:`${i}:00`,inbound:10+i%7*10,outbound:5,rejected:2,spoofed:0})),sync:{mode:'sftp',lastSuccess:stamp,newestRecord:stamp,intervalSeconds:60,nodes:[{name:'mx1',online:true,lastSuccess:stamp},{name:'mx2',online:false,lastError:'连接超时'}]},index:{files:690,lastSuccess:stamp},files:{tracking:120,agent:30,protocol:10},trustedMessages:200}));
  if(url.pathname==='/api/log-detail')return res.end(JSON.stringify({items:[{fields:{'event-id':'RECEIVE'}}]}));
  return setTimeout(()=>res.end(JSON.stringify({items:[{...event,subject:`${days}天的记录`}],page:1,pageSize:100,total:1,parseErrors:0})),days===30?150:10);
 }
 const file=path.join(root,url.pathname==='/'?'index.html':url.pathname.slice(1));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;return res.end()}
 res.setHeader('Content-Type',file.endsWith('.css')?'text/css':file.endsWith('.js')?'text/javascript':'text/html');res.end(fs.readFileSync(file));
});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true,channel:process.env.BROWSER_CHANNEL||'msedge'});try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(`http://127.0.0.1:${server.address().port}`);await page.getByText('采集运行状态',{exact:true}).waitFor();
 await page.screenshot({path:'/tmp/edge-console-overview.png',fullPage:true});
 await page.locator('[data-view="mail"]').click();await page.locator('#rows tr').waitFor();
 await page.selectOption('#days','30');await page.selectOption('#days','7');await page.getByText('7天的记录',{exact:true}).waitFor();
 await page.waitForTimeout(250);assert.equal(await page.locator('#rows tr').count(),1);assert.match(await page.locator('#rows').innerText(),/7天的记录/);
 await page.locator('#rows tr').click();await page.getByText('"event-id": "RECEIVE"',{exact:false}).waitFor();await page.locator('#closeDetail').click();
 await page.locator('[data-view="servers"]').click();await page.getByText('连接超时',{exact:true}).waitFor();
 await page.locator('[data-view="queue"]').click();await page.getByText('尚未连接实时队列',{exact:true}).waitFor();
 await page.setViewportSize({width:390,height:844});await page.locator('.mobile-menu').click();await page.locator('[data-view="overview"]').click();assert.equal(await page.locator('.sidebar').evaluate(e=>e.classList.contains('open')),false);
 await page.waitForTimeout(200);await page.screenshot({path:'/tmp/edge-console-mobile.png',fullPage:true});assert.deepEqual(errors,[]);console.log('Browser checks passed: navigation, date switch, lazy details, node errors, queue state, mobile.');
 }finally{await browser.close();server.close()}})().catch(e=>{console.error(e);server.close();process.exitCode=1});
