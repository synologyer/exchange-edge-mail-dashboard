// Queue snapshots are independent of historical mail/date-range queries.
let queueData=null, queueNode='', queuePage=1, queueSelection=null, queueBusy=false, queueError='';
const queueLabels={Ready:'等待投递',Active:'正在处理',Connecting:'正在连接',Retry:'等待重试',Suspended:'已暂停',PendingSuspend:'正在暂停'};
const snapshotLabels={ok:'采集正常',stale:'快照过期或时钟异常',error:'采集失败',unavailable:'尚无可用快照'};
const previousWorkspace=renderWorkspace;
renderWorkspace=function(){if(view==='queue')renderQueueWorkspace();else previousWorkspace()};
const previousRefresh=load;
load=async function(){if(view==='queue')return fetchQueues();return previousRefresh()};
$('#refresh').onclick=load;
async function fetchQueues(){
 if(queueBusy)return;
 queueBusy=true;
 try{
  const query=new URLSearchParams();
  const selection=queueSelection;
  if(selection){query.set('node',selection.node);query.set('queue',selection.identity);query.set('page',selection.page||1)}
  const r=await fetch('/api/queues?'+query,{cache:'no-store',signal:AbortSignal.timeout(15000)});
  if(!r.ok)throw Error(`读取队列失败 (${r.status})`);
  const payload=await r.json();
  if(selection!==queueSelection)return;
  queueData=payload;queueError='';
 }catch(e){queueError='队列状态读取失败：'+e.message}
 finally{queueBusy=false;if(view==='queue')renderQueueWorkspace()}
}
function renderQueueWorkspace(){
 const workspace=$('#workspace');
 if(!queueData){workspace.innerHTML=`<section class="panel"><h2>邮件队列</h2><p>${esc(queueError||'正在读取队列快照…')}</p></section>`;if(!queueBusy&&!queueError)fetchQueues();return}
 const nodes=queueData.nodes||[],filtered=nodes.filter(n=>!queueNode||n.name===queueNode);
 const entries=filtered.flatMap(n=>(n.queues||[]).map(q=>({node:n,...q})));
 const pages=Math.max(1,Math.ceil(entries.length/50));queuePage=Math.min(queuePage,pages);
 workspace.innerHTML=`<section class="panel"><h2 class="section-heading">邮件队列快照</h2><p class="page-note">定时读取 Edge 状态文件，非即时连接；不受上方历史天数影响。每 ${esc(queueData.intervalSeconds)} 秒读取，超过 ${esc(queueData.staleSeconds)} 秒标记过期。只读，不支持重试或删除。</p>${queueError?`<p class="warn">${esc(queueError)}（下方可能为旧数据）</p>`:''}<div class="node-grid">${filtered.map(n=>`<div class="node-card"><h3>${esc(n.name)}</h3><p class="${n.status==='ok'?'':'warn'}">${esc(snapshotLabels[n.status]||n.status)}</p><p>快照内邮件数：${n.messageCount===null?'未知':esc(n.messageCount)}${n.status!=='ok'?'（不可作为当前状态）':''}</p><p>采集时间：${n.collectedAt?esc(formatDate(n.collectedAt)):'暂无'}</p>${n.error?`<p class="warn">${esc(n.error)}</p>`:''}</div>`).join('')}</div><div class="queue-toolbar"><select id="queueNode" aria-label="队列 MX 节点"><option value="">全部 MX 节点</option>${nodes.map(n=>`<option value="${esc(n.name)}" ${n.name===queueNode?'selected':''}>${esc(n.name)}</option>`).join('')}</select><button id="queueReload">刷新快照</button><span>第 ${queuePage}/${pages} 页 · ${entries.length} 个队列</span><button id="queuePrev" ${queuePage<=1?'disabled':''}>上一页</button><button id="queueNext" ${queuePage>=pages?'disabled':''}>下一页</button>${queueSelection?'<button id="queueBack">返回全部队列</button>':''}</div><div class="table-wrap"><table><thead><tr><th>MX 节点</th><th>队列</th><th>目标域名</th><th>状态</th><th>邮件数</th><th>失败原因</th><th>概要</th></tr></thead><tbody>${entries.slice((queuePage-1)*50,queuePage*50).map((q,i)=>`<tr><td>${esc(q.node.name)}</td><td>${esc(q.identity)}</td><td>${esc(q.nextHopDomain||'—')}</td><td>${esc(queueLabels[q.status]||q.status)}</td><td>${esc(q.messageCount)}</td><td class="queue-reason">${esc(q.lastError||'—')}</td><td><button data-queue-index="${i+(queuePage-1)*50}">查看邮件</button></td></tr>`).join('')}</tbody></table></div>${!entries.length?'<p class="page-note">'+(filtered.length&&filtered.every(n=>n.status==='ok')?'采集成功，快照中没有队列。':'尚无可展示的队列；请检查上方采集状态。这不代表队列为空。')+'</p>':''}<div id="queueMessages"></div></section>`;
 $('#queueNode').onchange=e=>{queueNode=e.target.value;queuePage=1;renderQueueWorkspace()};
 $('#queueReload').onclick=fetchQueues;
 $('#queuePrev').onclick=()=>{queuePage--;renderQueueWorkspace()};$('#queueNext').onclick=()=>{queuePage++;renderQueueWorkspace()};
 if($('#queueBack'))$('#queueBack').onclick=()=>{queueSelection=null;queueNode='';fetchQueues()};
 workspace.querySelectorAll('[data-queue-index]').forEach(b=>b.onclick=()=>{const q=entries[Number(b.dataset.queueIndex)];queueSelection={node:q.node.name,identity:q.identity,page:1};fetchQueues()});
 if(queueSelection){const q=entries.find(q=>q.node.name===queueSelection.node&&q.identity===queueSelection.identity);if(q?.messages){$('#queueMessages').innerHTML=`<h3>${esc(q.identity)} · 邮件概要</h3><p class="page-note">已采集 ${q.capturedMessages} 条概要，队列计数 ${q.messageCount}。${q.messagesTruncated?'概要受采集上限限制或队列正在变化，不是完整清单。':''}${q.messageError?'采集概要失败：'+esc(q.messageError):''}</p><div class="table-wrap"><table><thead><tr><th>发件人</th><th>收件人</th><th>主题</th><th>状态</th><th>原始响应</th></tr></thead><tbody>${q.messages.map(m=>`<tr><td>${esc(m.sender||'空发件人（退信）')}</td><td>${esc((m.recipients||[]).join('、'))}</td><td>${esc(m.subject)}</td><td>${esc(queueLabels[m.status]||m.status)}</td><td class="queue-reason">${esc(m.lastError||'—')}</td></tr>`).join('')}</tbody></table></div><button id="msgPrev" ${q.page<=1?'disabled':''}>上一页概要</button><span> 第 ${q.page} 页 </span><button id="msgNext" ${q.page*50>=q.capturedMessages?'disabled':''}>下一页概要</button>`;$('#msgPrev').onclick=()=>{queueSelection={...queueSelection,page:q.page-1};fetchQueues()};$('#msgNext').onclick=()=>{queueSelection={...queueSelection,page:q.page+1};fetchQueues()}}}
}
setInterval(()=>{if(view==='queue'&&!document.hidden)fetchQueues()},30000);
