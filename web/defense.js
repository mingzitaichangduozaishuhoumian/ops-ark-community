/* Fixed-profile SSH transactions. API transport and authentication belong to app.js. */
(() => {
  'use strict';
  const idPattern = /^[0-9a-f]{32}$/;
  const hashPattern = /^[0-9a-f]{64}$/;
  const phases = {armed:'观察窗口已建立',attached:'已取得候选',consumed:'观察已使用',expired:'已到期',invalid:'证据不足',ready:'待精确确认',ready_expired:'准备已到期',active:'最近确认生效',revoked:'最近确认已撤销',unknown:'结果未知',created:'意图已保留',prepared_intent:'准备意图已保留',prepare_sendable:'准备已准入，待对账',apply_sendable:'执行已准入，待对账',revoke_sendable:'撤销已准入，待对账',arm_sendable:'观察已准入，待对账',mode_sendable:'模式已准入，待对账',replied:'已收到回执',unavailable:'回执不可用',synced:'模式已同步',not_found:'未查到',rejected:'已拒绝'};
  const modes = {manual:'手动',assisted:'半自动',automatic:'全自动'};
  const sessionPhases={declared:'会话已登记',observing:'等待本窗口候选',analyzing:'分析这一次候选',analysis_ready:'建议已核对',preparing:'准备固定清单',prepared:'清单已准备',applying:'执行结果待核',confirmed:'执行已确认',completed:'本次会话已结束',stopped:'会话已停止',expired:'原窗口已到期',reconciliation_only:'只读对账'};
  const sessionReasons={requested:'已明确停止',mode_changed:'模式已变化',registration_changed:'登记已变化',lease_lost:'会话租约已失效',owner_changed:'原进程已变化',deadline_elapsed:'原窗口已结束',result_unknown:'结果未确认',ai_unavailable:'分析未完成',proof_changed:'证据已变化',budget_insufficient:'剩余预算不足'};
  const sessionAIStates={not_required:'原策略不要求 AI，本次未调用',not_started:'本次尚未登记 AI 调用',unknown:'原分析结果未确认',completed:'原分析已完成',refused:'原分析未取得有效答复',failed:'原分析失败',stale:'原分析证据已失效'};
  const sessionAIDecisions={propose_defense:'建议固定处置',collect_more:'继续收集证据',review_access:'核对合法访问',no_action:'建议不处置'};
  const sessionAIUsage={reserved:'已预留',consumed:'已占用',unknown:'保留未知'};
  const verdicts={pending:'待验收',failed:'复验未通过',passed:'登记业务复验通过'};
  const checkStatuses={passed:'通过',failed:'未通过',inconclusive:'未取得完整证据',uncovered:'未覆盖'};
  const checkReasons={matched:'符合登记条件',status_mismatch:'响应状态不符',body_mismatch:'响应内容不符',incomplete:'检查超时或证据不完整',uncovered:'未覆盖',scope_changed:'检查范围已变化',time_unverified:'时间证据未核实'};
  const reportReasons={not_run:'尚未运行复验',in_progress:'复验尚未完成',result_unknown:'复验结果未知',root_unverified:'原任务查询未核实',authority_unproven:'原任务授权依据未核实',original_profile_missing:'原任务缺少业务检查快照',scope_changed:'目标范围已变化',profile_changed:'业务检查登记已变化',time_unverified:'时间证据未核实',incomplete:'证据不完整',legacy_incomplete:'历史记录证据不完整',current_unknown:'当前原任务结果未知',current_unverified:'当前对账证据待核实',evidence_changed:'绑定证据已变化',collector_unavailable:'只读采集不可用',business_failed:'存在明确业务检查失败',interrupted:'复验已明确中断，保留待验收',newer_recheck:'存在更新复验，请选择新记录核对当前状态'};
  const watchStates={active:'最近查询确认生效',expired:'原任务已自然到期',revoked:'原任务已撤销',ready:'尚无原执行生效确认',ready_expired:'原准备已到期',unknown:'结果未知，保留同一原任务',not_found:'原任务尚未查到',rejected:'原查询被拒绝',unavailable:'未取得可信查询回执',registration_changed:'登记或信任材料变化，停止远程跟进',daily_limit:'只读查询日预算已用完',attempt_limit:'该任务查询次数已达上限',capacity_limit:'跟进记录容量已达上限'};
  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined && value !== null) node.textContent = String(value);
    return node;
  }
  function list(pairs) {
    const result = element('dl','detail-list');
    for (const [key,value] of pairs) result.append(element('dt','',key),element('dd','',value ?? '未提供'));
    return result;
  }
  function timestamp(value) {
    if (value===null || value===undefined || value==='') return '未提供';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '未提供' : date.toLocaleString('zh-CN',{hour12:false,timeZone:'Asia/Shanghai'})+' UTC+08:00';
  }
  function create({root, api, getContext}) {
    if (!root || typeof api !== 'function' || typeof getContext !== 'function') return null;
    const $ = suffix => root.querySelector('[data-defense="'+suffix+'"]');
    const state = {host:'',status:null,rows:[],selected:null,cursor:null,cursorClock:null,candidate:'',preview:null,analysis:null,analysisFor:null,busy:'',error:'',message:'',ticket:0,modeKey:null,statusStale:true,uncertain:new Set(),attempted:new Set(),visible:false,dialog:null,rechecks:new Map(),historyTargets:new Map(),historyNext:null,historyLoaded:false};
    const hostSelect = $('host');
    const dialog = $('dialog');
    const watchSection=element('section','ssh-defense-task-watch'); watchSection.dataset.defense='task-watch'; watchSection.setAttribute('aria-label','原任务只读跟进');
    root.insertBefore(watchSection,$('history')?.closest('.ssh-defense-layout') || null);
    state.watch={status:null,events:[],error:false,after:0,next:null,pages:[0],pageIndex:0};
    let watchTimer=null;
    const sessionSection=element('section','ssh-defense-session'); sessionSection.dataset.defense='sessions'; sessionSection.setAttribute('aria-label','单次防护会话');
    root.insertBefore(sessionSection,watchSection);
    state.sessions={status:null,page:[],all:new Map(),selected:'',record:null,error:false,after:0,next:null,pages:[0],pageIndex:0,refs:new Map(),origins:new Map(),uncertain:new Set(),attempted:new Set(),receipts:new Map()};
    let sessionTimer=null;
    let sessionDeadlineTimer=null;
    function context() { return getContext() || {}; }
    function modeKey() {
      const value = context();
      return JSON.stringify([value.session,value.automation?.mode,value.automation?.revision,value.automation?.sync_generation,value.automation?.mode_sync_complete,value.modePending===true]);
    }
    function knownTransaction(value) { return value && idPattern.test(value.request_id || '') && ['mode','cursor','action'].includes(value.kind); }
    function target() { return state.status?.targets?.find(item => item.host_id === state.host); }
    function modeFresh() {
      const value=context(), automation=value.automation;
      return value.signedIn===true && value.modePending!==true && !state.statusStale && automation && modes[automation.mode] && automation.revision===state.status?.revision && automation.mode===state.status.mode && automation.sync_generation===state.status.sync_generation && automation.mode_sync_complete===true && state.status.mode_sync_complete===true;
    }
    function mutable() { return !state.busy && state.status?.enabled===true && modeFresh(); }
    function newAdmission() {
      return mutable() && target()?.reconciliation_required!==true && !state.rows.some(row=>row.query_required===true || row.current_result?.state==='unknown' || state.uncertain.has(row.request_id));
    }
    function selectedCandidate() { return state.cursor?.current_result?.candidates?.find(item => item.source_ref === state.candidate); }
    function eligible() {
      const candidate=selectedCandidate();
      return candidate && candidate.classification==='eligible' && idPattern.test(candidate.source_ref) && hashPattern.test(candidate.evidence_sha256 || '') && candidate.distinct_failure_ports>=5 && !state.cursor.query_required && !state.uncertain.has(state.cursor.request_id) && Date.parse(state.cursor.current_result?.deadline_at)>Date.now();
    }
    function exactAction() {
      const value=state.selected;
      return knownTransaction(value) && value.kind==='action' && hashPattern.test(value.manifest?.sha256 || '');
    }
    function rechecksSupported() { return context().capabilities?.ssh_defense_rechecks===true; }
    function readable() { return context().capabilities?.ssh_defense_transactions===true || context().capabilities?.ssh_defense_history===true || context().capabilities?.ssh_defense_task_watch===true || context().capabilities?.ssh_defense_sessions===true || rechecksSupported(); }
    function recheckKey() { return state.host+':'+state.selected?.request_id; }
    function recheckState() {
      if (!exactAction()) return null;
      const key=recheckKey();
      if (!state.rechecks.has(key)) state.rechecks.set(key,{history:null,page:[],all:new Map(),selected:'',report:null,after:0,next:null,pages:[0],pageIndex:0,unresolved:new Set(),readAt:null,fresh:false});
      return state.rechecks.get(key);
    }
    function recheckCanRun() {
      const value=recheckState();
      return context().signedIn===true && rechecksSupported() && !state.busy && value?.history?.can_run===true && hashPattern.test(value.history.current_profile_sha256 || '') && value.history.expected_manifest_sha256===state.selected?.manifest?.sha256 && value.unresolved.size===0;
    }
    function recheckCanInterrupt() {
      const value=recheckState(), report=value?.report;
      return context().signedIn===true && rechecksSupported() && !state.busy && report?.status==='claimed' && report.can_interrupt===true && value.selected===report.run_ref && hashPattern.test(report.declaration_sha256 || '');
    }
    function staleRecheck() { const value=recheckState(); if (value) value.fresh=false; }
    function legacyState() {
      const value=recheckState(); if (!value) return null;
      if (!value.legacy) value.legacy={page:[],all:new Map(),after:0,next:null,pages:[0],pageIndex:0,selected:'',report:null,loaded:false,open:false};
      return value.legacy;
    }
    function actionReady() {
      return newAdmission() && target()?.execution_available===true && context().automation.mode==='assisted' && exactAction() && state.selected.phase==='ready' && state.selected.current_result?.state==='ready' && !state.selected.query_required && !state.uncertain.has(state.selected.request_id) && state.selected.mode_revision===state.status.revision && Date.parse(state.selected.manifest.deadline_at)>Date.now();
    }
    function actionRevocable() {
      return mutable() && context().automation.mode!=='manual' && exactAction() && !state.selected.query_required && !state.uncertain.has(state.selected.request_id) && state.selected.current_result?.state==='active';
    }
    function sourceKey() { return state.host+':'+state.cursor?.request_id+':'+state.candidate; }
    function evidenceKey() { return sourceKey()+':'+selectedCandidate()?.evidence_sha256; }
    function aiReady() { return state.status?.ai_required!==true || (state.analysisFor===evidenceKey() && state.analysis?.status==='completed' && state.analysis.decision==='propose_defense' && hashPattern.test(state.analysis.proof_sha256 || '')); }
    function endpoint(suffix) { return '/api/hosts/'+encodeURIComponent(state.host)+'/ssh-defense/'+suffix; }
    function button(label, action, disabled=false, className='button') {
      const result=element('button',className,label); result.type='button'; result.disabled=disabled; result.addEventListener('click',action); return result;
    }
    function closeDialog() {
      state.dialog=null;
      if (dialog.open) dialog.close();
      $('confirm').checked=false; $('send').disabled=true; $('dialog-summary').replaceChildren();
    }
    function clearSelection() {
      if (sessionDeadlineTimer!==null) { clearTimeout(sessionDeadlineTimer); sessionDeadlineTimer=null; }
      closeDialog(); state.selected=null; state.cursor=null; state.cursorClock=null; state.candidate=''; state.preview=null; state.analysis=null; state.analysisFor=null;
    }
    function invalidate() {
      closeDialog(); state.preview=null; state.statusStale=true;
      if (state.visible) render();
    }
    function sessionChanged() {
      const next=modeKey();
      if (state.modeKey!==next) { state.modeKey=next; invalidate(); }
    }
    function reset() {
      if (watchTimer!==null) { clearInterval(watchTimer); watchTimer=null; }
      if (sessionTimer!==null) { clearInterval(sessionTimer); sessionTimer=null; }
      if (sessionDeadlineTimer!==null) { clearTimeout(sessionDeadlineTimer); sessionDeadlineTimer=null; }
      state.watch={status:null,events:[],error:false,after:0,next:null,pages:[0],pageIndex:0};
      state.sessions={status:null,page:[],all:new Map(),selected:'',record:null,error:false,after:0,next:null,pages:[0],pageIndex:0,refs:new Map(),origins:new Map(),uncertain:new Set(),attempted:new Set(),receipts:new Map()};
      state.ticket+=1; closeDialog(); state.host=''; state.status=null; state.rows=[]; state.selected=null; state.cursor=null; state.cursorClock=null; state.candidate=''; state.preview=null; state.analysis=null; state.analysisFor=null; state.busy=''; state.error=''; state.message=''; state.statusStale=true; state.visible=false; state.modeKey=null; state.uncertain.clear(); state.attempted.clear(); state.rechecks.clear(); state.historyTargets.clear(); state.historyNext=null; state.historyLoaded=false; hostSelect.replaceChildren(); root.hidden=true;
    }
    function configure() {
      const value=context();
      root.hidden=value.signedIn!==true;
      if (root.hidden) return;
      hostOptions();
      sessionChanged(); render();
    }
    function hostOptions() {
      const previous=state.host;
      hostSelect.replaceChildren();
      const hosts=new Map((context().hosts || []).map(host=>[host.id,host]));
      for (const id of state.historyTargets.keys()) if (!hosts.has(id)) hosts.set(id,{id,name:id});
      for (const host of hosts.values()) {
        const retired=state.historyTargets.has(host.id) && !state.status?.targets?.some(item=>item.host_id===host.id);
        const option=element('option','',(host.name || host.id)+(retired?' · 历史（未登记执行）':'')); option.value=host.id; hostSelect.append(option);
      }
      state.host=hosts.has(previous)?previous:(hosts.keys().next().value || '');
      hostSelect.value=state.host;
    }
    async function fetchHistoryTargets(after, current) {
      const params=new URLSearchParams({limit:'20'}); if (after) params.set('after',after);
      const value=await api('/api/ssh-defense/history-targets?'+params);
      if (!current()) return;
      const valid=id=>typeof id==='string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(id);
      if (!value || !Array.isArray(value.history_targets) || value.history_targets.length>20 || !value.history_targets.every(row=>row && valid(row.host_id)) || (value.next_after!==null && (!valid(value.next_after) || value.next_after===after))) throw new Error('Invalid history targets');
      for (const row of value.history_targets) state.historyTargets.set(row.host_id,true);
      state.historyNext=value.next_after; state.historyLoaded=true; hostOptions();
    }
    async function moreHistoryTargets() {
      if (context().capabilities?.ssh_defense_history!==true || !state.historyNext) return;
      await run('读取更多历史目标',current=>fetchHistoryTargets(state.historyNext,current));
    }
    function selectHost() {
      cancelSessionReceiptReads();
      state.sessions.page=[]; state.sessions.selected=''; state.sessions.record=null; state.sessions.after=0; state.sessions.next=null; state.sessions.pages=[0]; state.sessions.pageIndex=0;
      state.ticket+=1; clearSelection(); state.busy=''; state.host=hostSelect.value; state.rows=[]; state.status=null; state.error=''; state.message=''; state.statusStale=true; render();
      if (state.visible && state.host) refresh();
    }
    function setVisible(value) {
      state.visible=value===true;
      if (!state.visible) cancelSessionReceiptReads();
      if (watchTimer!==null) { clearInterval(watchTimer); watchTimer=null; }
      if (sessionTimer!==null) { clearInterval(sessionTimer); sessionTimer=null; }
      if (state.visible && context().capabilities?.ssh_defense_task_watch===true) watchTimer=setInterval(()=>{
        if (state.visible && !state.busy && !state.dialog && context().signedIn===true) refreshWatch(state.watch.after,state.watch.pageIndex);
      },30000);
      if (state.visible && context().capabilities?.ssh_defense_sessions===true) sessionTimer=setInterval(()=>{
        if (state.visible && !state.busy && !state.dialog && context().signedIn===true) refreshSessions();
      },5000);
      if (!state.visible) closeDialog();
      else { configure(); if (context().signedIn && readable() && !state.status && !state.busy) refresh(); }
    }
    async function run(label, operation, {rid=null,mutation=false}={}) {
      if (state.busy || !context().signedIn) return;
      const ticket=++state.ticket, session=context().session;
      state.busy=label; state.error=''; state.message=''; render();
      try {
        const value=await operation(()=>ticket===state.ticket && context().session===session);
        if (ticket!==state.ticket || context().session!==session) return;
        return value;
      } catch (cause) {
        if (ticket!==state.ticket || context().session!==session) return;
        if (mutation && rid) state.uncertain.add(rid);
        // Do not expose arbitrary upstream HTTP text, logs or error bodies.
        state.error='本次'+label+'未确认。'+(rid?'请查询同一个原任务；不要重复提交。':'请刷新已有记录核对结果；不会自动重试。');
      } finally {
        if (ticket===state.ticket && context().session===session) { state.busy=''; render(); }
      }
    }
    function accept(value, readStartedAt=performance.now()) {
      if (!knownTransaction(value)) throw new Error('Invalid transaction');
      state.selected=value;
      if (value.kind==='action' && rechecksSupported()) staleRecheck();
      const index=state.rows.findIndex(item=>item.request_id===value.request_id);
      if (index<0) state.rows.unshift(value); else state.rows[index]=value;
      if (value.kind==='cursor') {
        state.cursor=value;
        const observed=value.controller_observation;
        state.cursorClock=observed && typeof observed.owned_by_current_boot==='boolean' && Number.isSafeInteger(observed.remaining_ms) && observed.remaining_ms>=0 && observed.remaining_ms<=120000 && Number.isFinite(Date.parse(observed.deadline_at))?{rid:value.request_id,owned:observed.owned_by_current_boot,remaining:observed.remaining_ms,deadline:observed.deadline_at,readStartedAt}:null;
        if (sessionDeadlineTimer!==null) clearTimeout(sessionDeadlineTimer);
        const remaining=state.cursorClock?state.cursorClock.remaining-Math.max(0,performance.now()-readStartedAt):0;
        sessionDeadlineTimer=remaining>0?setTimeout(()=>{sessionDeadlineTimer=null;if (state.visible) render();},remaining+1):null;
        if (!value.current_result?.candidates?.some(item=>item.source_ref===state.candidate)) state.candidate='';
      }
      if (value.query_required!==true && value.current_result && value.current_result.state!=='unknown') state.uncertain.delete(value.request_id);
    }
    async function refresh() {
      if (!readable()) { render(); return; }
      await run('读取记录',async current=>{
        const ticket=state.ticket;
        const status=await api('/api/ssh-defense/status');
        if (!current()) return;
        if (!status || !modes[status.mode] || !Number.isSafeInteger(status.revision) || !Array.isArray(status.targets)) throw new Error('Invalid defense status');
        state.status=status; state.statusStale=false;
        await fetchWatch(0,0,current);
        if (context().capabilities?.ssh_defense_history===true && !state.historyLoaded) await fetchHistoryTargets(null,current);
        if (!current()) return;
        hostOptions(); const host=state.host;
        await fetchSessions(0,0,current);
        if (!host) { state.rows=[]; clearSelection(); state.message='尚无当前登记目标或本地防护历史。'; return; }
        if (!status.targets.some(item=>item.host_id===host) && !state.historyTargets.has(host)) {
          state.rows=[]; clearSelection(); state.message='所选目标未登记事务专用凭据。请选择已单独登记的防护目标。'; return;
        }
        const rowsStartedAt=performance.now(), rows=await api(endpoint('transactions'));
        if (!current() || host!==state.host || ticket!==state.ticket) return;
        if (!Array.isArray(rows.transactions)) throw new Error('Invalid defense status');
        state.status=status; state.rows=rows.transactions.filter(knownTransaction); state.statusStale=false;
        if (state.selected) {
          const selected=state.rows.find(item=>item.request_id===state.selected.request_id);
          if (selected) accept(selected,rowsStartedAt); else clearSelection();
        }
        state.message='已读取本地记录。读取历史不代表刚刚连接目标；请单独查询原任务。';
      });
      if (exactAction() && rechecksSupported()) await refreshSelectedRecheck();
    }
    function validSession(row) {
      return row && row.v===1 && row.host_id===state.host && idPattern.test(row.session_ref || '') && idPattern.test(row.cursor_request_id || '') && (row.action_request_id===null || idPattern.test(row.action_request_id || '')) && hashPattern.test(row.declaration_sha256 || '') && Object.hasOwn(sessionPhases,row.phase) && Object.hasOwn(sessionPhases,row.effective_phase) && row.business_verdict==='pending' && row.max_actions_per_session===1 && row.max_ai_intents===1 && typeof row.owned_by_current_boot==='boolean' && typeof row.can_stop==='boolean' && typeof row.requires_ai==='boolean' && Number.isSafeInteger(row.mode_revision) && Number.isFinite(Date.parse(row.created_at)) && Number.isFinite(Date.parse(row.updated_at)) && Number.isFinite(Date.parse(row.controller_deadline_at)) && (row.stop_reason===null || Object.hasOwn(sessionReasons,row.stop_reason));
    }
    function rememberSession(row) {
      if (!validSession(row)) throw new Error('Invalid single session');
      const value=state.sessions, origin=value.origins.get(row.session_ref);
      if (origin && (origin.host!==row.host_id || origin.cursor!==row.cursor_request_id)) throw new Error('Invalid original session binding');
      value.origins.set(row.session_ref,{host:row.host_id,cursor:row.cursor_request_id});
      value.refs.set(row.host_id+':'+row.cursor_request_id,row.session_ref); value.all.set(row.session_ref,row);
    }
    function acceptSession(row) {
      rememberSession(row);
      const value=state.sessions; value.selected=row.session_ref; value.record=row; value.uncertain.delete(row.session_ref);
    }
    async function fetchSessions(after,pageIndex,current) {
      if (context().capabilities?.ssh_defense_sessions!==true) return;
      const value=state.sessions;
      try {
        const status=await api('/api/ssh-defense/sessions/status');
        if (!current()) return;
        if (!status || status.session_only!==true || status.continuous_execution!==false || status.max_actions_per_session!==1 || typeof status.enabled!=='boolean' || typeof status.running!=='boolean') throw new Error('Invalid session status');
        value.status=status;
        if (!state.host) { value.page=[]; return; }
        const page=await api(endpoint('sessions')+'?after_sequence='+after+'&limit=20');
        if (!current()) return;
        if (!page || page.host_id!==state.host || !Array.isArray(page.sessions) || page.sessions.length>20 || !page.sessions.every(validSession) || (page.next_after_sequence!==null && (!Number.isSafeInteger(page.next_after_sequence) || page.next_after_sequence<=after))) throw new Error('Invalid session history');
        value.page=page.sessions; value.after=after; value.next=page.next_after_sequence; value.pageIndex=pageIndex; value.pages[pageIndex]=after; value.error=false;
        for (const row of page.sessions) rememberSession(row);
        if (value.selected && value.origins.get(value.selected)?.host!==state.host) {
          value.selected=''; value.record=null;
        }
        if (value.selected) {
          const row=await api(endpoint('sessions/'+value.selected));
          if (current()) acceptSession(row);
        }
      } catch (_) { if (current()) value.error=true; }
    }
    async function refreshSessions(after=state.sessions.after,pageIndex=state.sessions.pageIndex) {
      await run('读取单次会话',current=>fetchSessions(after,pageIndex,current));
    }
    function sessionChecks() {
      const cursor=state.cursor, value=state.sessions, clock=state.cursorClock;
      const knownCursor=cursor?.kind==='cursor' && cursor.host_id===state.host && idPattern.test(cursor.request_id || '');
      const remaining=knownCursor && clock?.rid===cursor.request_id?Math.max(0,clock.remaining-Math.max(0,performance.now()-clock.readStartedAt)):null;
      const windowOpen=knownCursor && clock?.owned===true && remaining>0 && ['armed','attached'].includes(cursor.current_result?.state) && cursor.query_required!==true && cursor.mode_revision===state.status?.revision;
      const unknown=target()?.reconciliation_required===true || state.rows.some(row=>row.query_required===true || row.current_result?.state==='unknown' || state.uncertain.has(row.request_id));
      const submitted=knownCursor && (value.attempted.has(state.host+':'+cursor.request_id) || value.all.has(value.refs.get(state.host+':'+cursor.request_id)));
      const deployed=value.status?.enabled===true && value.status.mutation_owner===true && value.status.running===true;
      return [
        ['部署开关与进程',deployed,deployed?'部署端已启用，本进程后台可用。':value.status?.enabled!==true?'由部署者启用单次会话；网页不能开启。':value.status?.mutation_owner!==true?'当前进程仅能读取原会话。':'单次会话后台未运行，保持关闭。'],
        ['全自动模式',context().automation?.mode==='automatic',context().automation?.mode==='automatic'?'已选择全自动；模式本身不创建许可。':'先保存全自动模式，再核对许可范围。'],
        ['当前模式 ACK',modeFresh() && state.status?.enabled===true,modeFresh() && state.status?.enabled===true?'本次读取已核对当前修订与同步确认。':'重新读取模式与事务状态；未确认时不启动。'],
        ['双侧许可的本地核对',target()?.observation_available===true && target()?.execution_available===true,!target()?'请选择已独立登记的防护目标。':target().observation_available!==true?'本地观察许可未就绪。':target().execution_available!==true?'本地执行许可未就绪。':'本地许可检查通过；Root 仍在实际请求时独立准入。'],
        ['同进程原观察窗口',Boolean(windowOpen),!knownCursor?'先明确建立并选择这一次原观察窗口。':!clock?'控制端窗口读数待核实，请只读查询原观察。':!clock.owned?'原观察不属于本进程，只能读取或对账。':remaining<=0?'原观察窗口已到期；不自动续窗。':!windowOpen?'原观察回执或模式版本待核实。':'控制端窗口读数剩余约 '+String(Math.floor(remaining/1000))+' 秒（本地保守计时）。'],
        ['原任务对账',Boolean(state.status) && !unknown,unknown?'存在未知原任务，先只读核对；不重发动作。':state.status?'本地记录未报告未知任务。':'尚未读取原任务状态。'],
        ['本次提交记录',Boolean(knownCursor && !submitted),submitted?'此原观察已提交会话；只查原会话，不重复提交。':knownCursor?'尚未提交这一次会话。':'选择原观察后核对是否已提交。'],
      ];
    }
    function canStartSession() {
      return !state.busy && sessionChecks().every(row=>row[1]);
    }
    function renderSessionChecks() {
      const panel=element('section','ssh-defense-session-checks'); panel.setAttribute('aria-label','本地启动条件');
      panel.append(element('h4','','启动前本地核对'),element('p','small muted','以下是本地条件快照，不代表 Root 最终准入。不会因此自动连接目标、续发许可或提交操作。'));
      const checks=element('ul','ssh-defense-session-check-list');
      for (const [label,ready,detail] of sessionChecks()) {
        const item=element('li'); item.dataset.ready=String(ready);
        const heading=element('div'); heading.append(element('strong','',label),element('span','small',ready?'已核对':'待处理'));
        item.append(heading,element('p','small',detail)); checks.append(item);
      }
      panel.append(checks); sessionSection.append(panel);
    }
    function confirmSession(stop=false) {
      const value=state.sessions, row=value.record;
      if (state.busy || (!stop && !canStartSession()) || (stop && row?.can_stop!==true)) return;
      const cursor=state.cursor?.request_id;
      const reference=stop?row.session_ref:(value.refs.get(state.host+':'+cursor) || crypto.randomUUID().replaceAll('-',''));
      const origin=value.origins.get(reference), originalCursor=stop?row.cursor_request_id:cursor;
      if ((stop && row.host_id!==state.host) || (origin && (origin.host!==state.host || origin.cursor!==originalCursor))) return;
      value.origins.set(reference,{host:state.host,cursor:originalCursor});
      if (!stop) value.refs.set(state.host+':'+cursor,reference);
      closeDialog();
      $('dialog-title').textContent=stop?'停止这个原会话':'启动这一次防护会话';
      $('dialog-summary').append(list([['目标',hostSelect.selectedOptions[0]?.textContent || state.host],['会话标识',reference],['原观察',stop?row.cursor_request_id:cursor],['模式版本',stop?row.mode_revision:state.status.revision]]));
      if (stop) $('dialog-summary').append(list([['声明 SHA256',row.declaration_sha256]]));
      $('dialog-summary').append(element('p','notice neutral',stop?'停止新的会话步骤，保留原费用、暂停和在途结果；不会自动撤销，后续只查询原任务。':'只使用已明确建立的原观察窗口，最多一次动作；需要 AI 时最多一次分析。到期、权限或证据变化即停止，未知不重发；业务复验另行确认。'));
      state.dialog={op:stop?'session_stop':'session_start',key:snapshot(stop?'session_stop':'session_start'),reference,cursor,host:state.host,declaration:stop?row.declaration_sha256:null};
      $('confirm-label').textContent=stop?'我已核对原会话与声明，明确停止。':'我已核对原窗口与目标，明确同意本次会话及策略内分析费用。';
      $('send').textContent=stop?'停止原会话':'启动这一次会话'; dialog.showModal(); $('cancel').focus();
    }
    async function submitSession(pending) {
      const stop=pending.op==='session_stop', value=state.sessions;
      if (pending.host!==state.host) { closeDialog(); return; }
      if (!stop && !canStartSession()) { closeDialog(); state.message='原窗口或本地条件已变化，请重新读取；未提交新会话。'; render(); return; }
      const reference=pending.reference, revision=state.status?.revision;
      const origin=value.origins.get(reference);
      if (!origin || origin.host!==pending.host || origin.cursor!==(stop?value.record?.cursor_request_id:pending.cursor)) return;
      if (!stop) value.attempted.add(pending.host+':'+pending.cursor);
      closeDialog(); value.selected=reference; value.uncertain.add(reference);
      await run(stop?'停止会话':'启动会话',async current=>{
        try {
          const row=await api(endpoint(stop?'sessions/'+reference+'/stop':'sessions'),{method:'POST',body:stop?{expected_declaration_sha256:pending.declaration,confirm_stop:true}:{cursor_request_id:pending.cursor,session_ref:reference,expected_mode_revision:revision,confirm_session:true}});
          if (current()) { acceptSession(row); state.message=stop?'原会话已停止；原任务及费用保留。':'这一次会话已登记；业务仍待独立复验。'; }
        } catch (_) { if (current()) state.message='未确认会话回执，只读取这个原会话标识；不会自动重试提交。'; }
      });
    }
    async function selectSession(reference) {
      if (!idPattern.test(reference || '')) return;
      if (state.sessions.origins.get(reference)?.host!==state.host) return;
      cancelSessionReceiptReads();
      state.sessions.selected=reference;
      await run('读取原会话',async current=>{
        const row=await api(endpoint('sessions/'+reference));
        if (current()) acceptSession(row);
      });
    }
    async function reconcileSession(row) {
      const host=state.host, rid=row.action_request_id || row.cursor_request_id;
      await selectTransaction(rid);
      if (state.host===host && state.selected?.request_id===rid) await query();
    }
    function cancelSessionReceiptReads() {
      for (const entry of state.sessions.receipts.values()) if (entry.phase==='loading') { entry.sequence+=1; entry.phase='idle'; entry.record=null; }
    }
    function sessionReceiptKey(row) { return row.host_id+':'+row.session_ref+':'+row.declaration_sha256; }
    function safeSessionReceipt(value, row) {
      const keys=['v','session_ref','analysis_id','status','decision','usage_state','input_digest','proof_sha256','actions_executable'];
      if (!value || Object.keys(value).length!==keys.length || !keys.every(key=>Object.hasOwn(value,key)) || value.v!==1 || value.session_ref!==row.session_ref || value.actions_executable!==false || !Object.hasOwn(sessionAIStates,value.status)) throw new Error('Invalid original analysis receipt');
      const noIntent=['not_required','not_started'].includes(value.status);
      if (noIntent) {
        if ([value.analysis_id,value.usage_state,value.input_digest,value.decision,value.proof_sha256].some(item=>item!==null) || (value.status==='not_required')===row.requires_ai) throw new Error('Invalid no-intent receipt');
      } else {
        if (row.requires_ai!==true || !idPattern.test(value.analysis_id || '') || !hashPattern.test(value.input_digest || '') || !Object.hasOwn(sessionAIUsage,value.usage_state)) throw new Error('Invalid original analysis identity');
        if (value.status==='completed') {
          if (!Object.hasOwn(sessionAIDecisions,value.decision) || (value.decision==='propose_defense'?!hashPattern.test(value.proof_sha256 || ''):value.proof_sha256!==null)) throw new Error('Invalid completed analysis receipt');
        } else if (value.decision!==null || value.proof_sha256!==null) throw new Error('Invalid unconfirmed analysis receipt');
      }
      return Object.fromEntries(keys.map(key=>[key,value[key]]));
    }
    async function readSessionReceipt(row) {
      const value=state.sessions, host=state.host, reference=row.session_ref, login=context().session;
      if (state.busy || row.host_id!==host || value.selected!==reference || value.record?.declaration_sha256!==row.declaration_sha256) return;
      const key=sessionReceiptKey(row), old=value.receipts.get(key);
      if (old?.phase==='loading') return;
      const entry={phase:'loading',record:null,sequence:(old?.sequence || 0)+1}; value.receipts.set(key,entry);
      const sequence=entry.sequence;
      const current=()=>context().signedIn===true && context().session===login && state.visible && state.host===host && state.sessions===value && value.selected===reference && value.record?.declaration_sha256===row.declaration_sha256 && entry.sequence===sequence;
      render();
      try {
        const receipt=await api('/api/hosts/'+encodeURIComponent(host)+'/ssh-defense/sessions/'+reference+'/ai-receipt');
        if (!current()) return;
        entry.record=safeSessionReceipt(receipt,row); entry.phase='ready';
      } catch (_) { if (current()) { entry.phase='error'; entry.record=null; } }
      finally { if (current()) render(); }
    }
    function renderSessionReceipt(row) {
      const entry=state.sessions.receipts.get(sessionReceiptKey(row));
      const section=element('section','ssh-defense-session-receipt'); section.setAttribute('aria-label','原 AI 安全回执');
      section.append(element('h4','','原 AI 安全回执'),element('p','small muted','只读取这个原会话已保存的安全回执，不重新调用模型。历史建议不作为新的执行依据。'));
      section.append(button('读取原 AI 安全回执',()=>readSessionReceipt(row),Boolean(state.busy) || entry?.phase==='loading'));
      if (entry?.phase==='loading') section.append(element('p','small muted','正在读取原回执；不会重新分析或提交动作。'));
      else if (entry?.phase==='error') section.append(element('p','notice neutral','原 AI 回执暂时无法核实，请只读取原回执；不会重试模型或显示部分结果。'));
      else if (entry?.phase==='ready') {
        const receipt=entry.record;
        section.append(list([['原分析状态',sessionAIStates[receipt.status]],['原建议',receipt.decision===null?'未形成已确认建议':sessionAIDecisions[receipt.decision]],['本地分析额度',receipt.usage_state===null?'未登记调用意图':sessionAIUsage[receipt.usage_state]],['原分析标识',receipt.analysis_id || '未登记'],['输入摘要 SHA256',receipt.input_digest || '尚无摘要'],['建议证明 SHA256',receipt.proof_sha256 || '尚无有效建议证明']]));
      }
      section.append(element('p','small muted','额度状态来自 OpsArk 本地意图账本，不是提供方账单回执。结果未知仍保留原意图，不自动重试。'));
      sessionSection.append(section);
    }
    function renderSessions() {
      sessionSection.replaceChildren(); sessionSection.hidden=context().capabilities?.ssh_defense_sessions!==true;
      if (sessionSection.hidden) return;
      const value=state.sessions;
      sessionSection.append(element('h3','','单次防护会话'),element('p','small muted','每次使用原观察窗口，最多一个动作。自动会话不代表业务恢复，也不补新许可。'));
      if (value.error) sessionSection.append(element('p','notice neutral','会话记录暂不可用，请读取原会话，不重新提交。'));
      if (value.status?.enabled!==true) sessionSection.append(element('p','notice neutral','此实例未由部署端启用单次会话；历史仍可读取。'));
      const actions=element('div','ssh-defense-actions'); actions.append(button('刷新单次会话',()=>refreshSessions(),Boolean(state.busy)));
      actions.append(button('启动这一次防护会话',()=>confirmSession(),!canStartSession(),'button primary'));
      if (value.pageIndex>0) actions.append(button('上一页单次会话',()=>refreshSessions(value.pages[value.pageIndex-1],value.pageIndex-1),Boolean(state.busy)));
      if (value.next!==null) actions.append(button('下一页单次会话',()=>refreshSessions(value.next,value.pageIndex+1),Boolean(state.busy)));
      sessionSection.append(actions);
      renderSessionChecks();
      for (const row of value.page) { const item=button(sessionPhases[row.effective_phase]+' · 待验收',()=>selectSession(row.session_ref),Boolean(state.busy),'ssh-defense-row'); item.append(element('span','mono small',row.session_ref)); sessionSection.append(item); }
      const row=value.record;
      if (row && row.host_id===state.host) {
        sessionSection.append(list([['会话状态',sessionPhases[row.effective_phase]],['业务验收','待验收 · 未进行独立业务复验'],['声明摘要',row.declaration_sha256],['记录时间',timestamp(row.updated_at)],['原窗口截止',timestamp(row.controller_deadline_at)],['停止原因',row.stop_reason?sessionReasons[row.stop_reason]:'未记录停止原因']]));
        const links=element('div','ssh-defense-actions');
        if (row.can_stop) links.append(button('核对并停止原会话',()=>confirmSession(true),Boolean(state.busy)));
        links.append(button('打开原观察任务',()=>selectTransaction(row.cursor_request_id),Boolean(state.busy)));
        if (row.action_request_id) links.append(button('打开原处置任务',()=>selectTransaction(row.action_request_id),Boolean(state.busy)));
        links.append(button('只读核对原任务',()=>reconcileSession(row),Boolean(state.busy) || !target()));
        sessionSection.append(links);
        renderSessionReceipt(row);
      }
      for (const reference of value.uncertain) if (value.origins.get(reference)?.host===state.host) sessionSection.append(element('p','notice neutral','这个会话回执尚未确认，保留原标识。'),button('只查询未确认的原会话',()=>selectSession(reference),Boolean(state.busy)));
    }
    function validWatchEvent(row) {
      return row && idPattern.test(row.event_ref || '') && idPattern.test(row.request_id || '') && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(row.host_id || '') && hashPattern.test(row.task_reference_sha256 || '') && Number.isSafeInteger(row.sequence) && row.sequence>0 && Object.hasOwn(watchStates,row.state) && Number.isFinite(Date.parse(row.observed_at)) && (row.acknowledged_at===null || Number.isFinite(Date.parse(row.acknowledged_at)));
    }
    async function fetchWatch(after,pageIndex,current) {
      if (context().capabilities?.ssh_defense_task_watch!==true) return;
      try {
        const status=await api('/api/ssh-defense/task-watch');
        if (!current()) return;
        if (!status || status.v!==1 || typeof status.enabled!=='boolean' || typeof status.running!=='boolean' || typeof status.capacity_limited!=='boolean' || typeof status.discovery_incomplete!=='boolean' || status.continuous_execution!==false || !Array.isArray(status.host_ids) || status.host_ids.length>10 || !status.host_ids.every(id=>typeof id==='string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(id)) || !Number.isInteger(status.interval_seconds) || status.interval_seconds<30 || status.interval_seconds>3600 || !['disabled','idle','running','stopped','store_unavailable','capacity_limit'].includes(status.reason_code) || (status.reason_code==='capacity_limit' && status.capacity_limited!==true) || !status.counts || !['tasks','pending','alerts','unread'].every(key=>Number.isSafeInteger(status.counts[key]) && status.counts[key]>=0)) throw new Error('Invalid original-task follow-up status');
        const page=await api('/api/ssh-defense/task-watch/events?after_sequence='+after+'&limit=20');
        if (!current()) return;
        if (!page || page.v!==1 || !Array.isArray(page.events) || page.events.length>20 || !page.events.every((row,index)=>validWatchEvent(row) && row.sequence>(index?page.events[index-1].sequence:after)) || (page.next_after_sequence!==null && (!Number.isSafeInteger(page.next_after_sequence) || page.next_after_sequence<=after))) throw new Error('Invalid original-task follow-up events');
        state.watch.status=status; state.watch.events=page.events; state.watch.error=false; state.watch.after=after; state.watch.next=page.next_after_sequence; state.watch.pages[pageIndex]=after; state.watch.pageIndex=pageIndex;
      } catch {
        if (current()) state.watch.error=true;
      }
    }
    async function refreshWatch(after=0,pageIndex=0) {
      await run('读取跟进告警',current=>fetchWatch(after,pageIndex,current));
    }
    async function acknowledgeWatch(row) {
      await run('标记跟进告警已阅',async current=>{
        const updated=await api('/api/ssh-defense/task-watch/events/'+row.event_ref+'/ack',{method:'POST',body:{confirm_ack:true}});
        if (!current()) return;
        if (!validWatchEvent(updated) || updated.event_ref!==row.event_ref || updated.task_reference_sha256!==row.task_reference_sha256 || updated.request_id!==row.request_id || updated.host_id!==row.host_id || !updated.acknowledged_at) throw new Error('Invalid follow-up acknowledgement');
        await fetchWatch(state.watch.after,state.watch.pageIndex,current);
        if (current()) state.message='仅标记告警已阅；原任务、执行暂停、配额和授权保持。';
      });
    }
    async function openWatchTask(row) {
      if (state.busy) return;
      state.historyTargets.set(row.host_id,true); state.host=row.host_id; state.rows=[]; clearSelection(); hostOptions();
      await selectTransaction(row.request_id);
    }
    function renderWatch() {
      watchSection.replaceChildren(); watchSection.hidden=context().capabilities?.ssh_defense_task_watch!==true;
      if (watchSection.hidden) return;
      watchSection.append(element('h3','','原任务只读跟进'),element('p','small muted','后台仅查询已存在的原任务并记录状态变化，不建立观察、不执行或撤销、不续期封禁、不调用 AI。已阅仅确认告警，不解除执行暂停。'));
      const value=state.watch, status=value.status;
      if (value.error) watchSection.append(element('p','notice neutral','跟进记录暂未核实；保留已有历史，不据此判断目标健康。'));
      if (!status) watchSection.append(element('p','small muted','尚未读取跟进状态。后台仅由部署端配置启用。'));
      else {
        watchSection.append(list([['后台状态',status.enabled?(status.running?(status.capacity_limited===true?'后台运行，新增跟进已暂停':'正在按登记范围只读跟进'):'已配置，当前未运行'):'部署未启用；已有告警仅供核对'],['查询间隔',String(status.interval_seconds)+' 秒'],['待跟进任务',status.counts.pending],['未阅告警',status.counts.unread],['持续自动执行','未启用']]));
        if (status.capacity_limited===true) watchSection.append(element('p','notice neutral','跟进容量已达上限，保留历史并停止新增跟进。标为已阅不解除容量限制或执行门禁。'));
        if (status.discovery_incomplete===true) watchSection.append(element('p','notice neutral','历史仍在分批登记；暂无事件不代表已完成跟进。'));
      }
      const actions=element('div','ssh-defense-actions'); actions.append(button('刷新跟进告警',()=>refreshWatch(),Boolean(state.busy)));
      if (value.pageIndex>0) actions.append(button('上一页跟进告警',()=>refreshWatch(value.pages[value.pageIndex-1],value.pageIndex-1),Boolean(state.busy)));
      if (value.next!==null) actions.append(button('下一页跟进告警',()=>refreshWatch(value.next,value.pageIndex+1),Boolean(state.busy)));
      watchSection.append(actions);
      if (status && !value.events.length) watchSection.append(element('p','empty-note','本页没有已保存的跟进告警。'));
      for (const row of value.events) {
        const item=element('article','ssh-defense-row'); item.append(element('strong','',watchStates[row.state]),element('span','mono small','任务摘要 '+row.task_reference_sha256),element('span','small',timestamp(row.observed_at)+' · '+(row.acknowledged_at?'已阅':'未阅')));
        const buttons=element('div','ssh-defense-actions'); buttons.append(button('打开对应原任务',()=>openWatchTask(row),Boolean(state.busy)));
        if (!row.acknowledged_at) buttons.append(button('仅标记已阅',()=>acknowledgeWatch(row),Boolean(state.busy)));
        item.append(buttons); watchSection.append(item);
      }
    }
    async function selectTransaction(rid) {
      if (!idPattern.test(rid)) return;
      closeDialog(); state.preview=null; state.analysis=null; state.analysisFor=null;
      await run('读取原任务',async current=>{
        const readStartedAt=performance.now(), value=await api(endpoint('transactions/'+rid));
        if (!current()) return;
        if (value.kind!=='cursor') { state.cursor=null; state.candidate=''; }
        accept(value,readStartedAt);
      });
      if (state.selected?.request_id===rid && exactAction() && rechecksSupported()) await loadRechecks(0);
    }
    async function query() {
      const rid=state.selected?.request_id;
      if (!idPattern.test(rid || '')) return;
      closeDialog(); state.preview=null;
      staleRecheck();
      await run('查询原任务',async current=>{
        const readStartedAt=performance.now(), value=await api(endpoint('transactions/'+rid+'/query'),{method:'POST',body:{}});
        if (!current()) return;
        accept(value,readStartedAt);
        state.message='本次仅查回原任务；没有重建观察窗口、重新执行或续期。';
      },{rid,mutation:true});
      if (state.selected?.request_id===rid && exactAction() && rechecksSupported()) await refreshSelectedRecheck();
    }
    async function previewAI() {
      if (!eligible() || state.busy) return;
      closeDialog(); state.preview=null;
      const key=sourceKey();
      await run('预览 AI 摘要',async current=>{
        const value=await api(endpoint('ai/preview')+'?cursor_request_id='+encodeURIComponent(state.cursor.request_id)+'&source_ref='+encodeURIComponent(state.candidate));
        if (!current()) return;
        if (key!==sourceKey() || !hashPattern.test(value.input_digest || '') || value.actions_executable!==false) throw new Error('Invalid AI preview');
        state.preview=value;
      });
    }
    async function queryAI() {
      const analysis=state.analysis;
      if (!idPattern.test(analysis?.analysis_id || '')) return;
      await run('查询原分析',async current=>{ const value=await api(endpoint('ai/analyses/'+analysis.analysis_id)); if (current()) state.analysis=value; });
    }
    function recheckRow(value, rid=state.selected?.request_id) {
      const projection=value?.projection;
      if (!value || value.v!==2 || value.host_id!==state.host || value.request_id!==rid || !idPattern.test(value.run_ref || '') || !Number.isSafeInteger(value.sequence) || value.sequence<1 || !['pending','claimed','completed','interrupted'].includes(value.status) || !hashPattern.test(value.expected_manifest_sha256 || '') || !hashPattern.test(value.expected_profile_sha256 || '') || !Object.hasOwn(verdicts,value.historical_verdict) || !Object.hasOwn(verdicts,value.current_verdict) || !projection || projection.v!==2 || projection.historical_verdict!==value.historical_verdict || projection.current_verdict!==value.current_verdict || !Object.hasOwn(verdicts,projection.business_verdict) || !Array.isArray(projection.checks) || projection.checks.length>3 || !projection.checks.every((check,index)=>check.number===index+1 && Object.hasOwn(checkStatuses,check.status) && Object.hasOwn(checkReasons,check.reason_code)) || !Array.isArray(projection.reasons) || projection.reasons.length>20 || !projection.reasons.every(reason=>Object.hasOwn(reportReasons,reason)) || !['human_approval','preauthorization','unproven'].includes(projection.authority_kind) || !['unchanged','ttl_elapsed','changed','unknown'].includes(projection.transition)) throw new Error('Invalid recheck projection');
      if ((value.declaration_sha256!==undefined && !hashPattern.test(value.declaration_sha256)) || (value.can_interrupt!==undefined && typeof value.can_interrupt!=='boolean')) throw new Error('Invalid interruption declaration');
      if (value.expected_manifest_sha256!==state.selected?.manifest?.sha256 || !Number.isFinite(Date.parse(value.created_at)) || (value.current_verdict==='passed' && value.historical_verdict!=='passed')) throw new Error('Changed recheck binding');
      return value;
    }
    function adoptRecheck(row, {select=false}={}) {
      row=recheckRow(row);
      const value=recheckState(); value.all.set(row.run_ref,row);
      if (row.status==='completed' || row.status==='interrupted') value.unresolved.delete(row.run_ref); else value.unresolved.add(row.run_ref);
      if (select) value.selected=row.run_ref;
      if (value.selected===row.run_ref) { value.report=row; value.fresh=true; value.readAt=new Date().toISOString(); }
      return row;
    }
    async function loadRechecks(after=0, {pageIndex=0,selectRef=null}={}) {
      if (!exactAction() || !rechecksSupported()) return;
      const taskKey=recheckKey(), rid=state.selected.request_id;
      recheckState().fresh=false;
      await run('读取业务复验历史',async current=>{
        const data=await api(endpoint('transactions/'+rid+'/rechecks')+'?'+new URLSearchParams({after_sequence:String(after),limit:'20'}));
        if (!current() || taskKey!==recheckKey()) return;
        if (!data || data.v!==2 || data.host_id!==state.host || data.request_id!==rid || data.expected_manifest_sha256!==state.selected.manifest.sha256 || (data.current_profile_sha256!==null && !hashPattern.test(data.current_profile_sha256 || '')) || !Number.isInteger(data.configured_checks) || data.configured_checks<0 || data.configured_checks>3 || typeof data.can_run!=='boolean' || !Array.isArray(data.runs) || data.runs.length>20 || (data.next_after_sequence!==null && (!Number.isSafeInteger(data.next_after_sequence) || data.next_after_sequence<=after))) throw new Error('Invalid recheck history');
        if ((data.active_run_ref!=null || data.active_request_id!=null) && (!idPattern.test(data.active_run_ref || '') || !idPattern.test(data.active_request_id || '') || data.can_run!==false)) throw new Error('Invalid active recheck');
        const rows=data.runs.map(row=>recheckRow(row,rid));
        if (new Set(rows.map(row=>row.run_ref)).size!==rows.length || rows.some((row,index)=>row.sequence<=(index?rows[index-1].sequence:after))) throw new Error('Invalid recheck order');
        const value=recheckState(); value.history=data; value.page=rows; value.after=after; value.next=data.next_after_sequence; value.pageIndex=pageIndex; value.pages[pageIndex]=after;
        if (data.active_run_ref && data.active_request_id===rid) value.unresolved.add(data.active_run_ref);
        for (const row of rows) adoptRecheck(row);
        if (selectRef && value.all.has(selectRef)) { value.selected=selectRef; value.report=value.all.get(selectRef); value.fresh=true; value.readAt=new Date().toISOString(); }
        if (value.selected && !rows.some(row=>row.run_ref===value.selected)) {
          const selected=await api(endpoint('transactions/'+rid+'/rechecks/'+value.selected));
          if (!current() || taskKey!==recheckKey()) return;
          adoptRecheck(selected,{select:true});
        }
        state.message='已读取同一个原任务的复验记录；未运行新的检查。';
      });
    }
    async function selectRecheck(runRef) {
      if (!exactAction() || !rechecksSupported()) return;
      closeDialog();
      const value=recheckState(); value.selected=runRef; value.report=null; value.fresh=false;
      if (!runRef) { render(); return; }
      await readRecheck(runRef);
    }
    async function readRecheck(runRef) {
      if (!idPattern.test(runRef || '') || !exactAction()) return;
      const taskKey=recheckKey(), rid=state.selected.request_id;
      await run('查询原复验',async current=>{
        const row=await api(endpoint('transactions/'+rid+'/rechecks/'+runRef));
        if (!current() || taskKey!==recheckKey()) return;
        adoptRecheck(row,{select:true});
        state.message='只查回这个复验标识；没有重新采集、执行或调用 AI。';
      });
    }
    async function refreshSelectedRecheck() {
      const value=recheckState();
      if (value?.selected) await readRecheck(value.selected);
      else if (value) await loadRechecks(value.after,{pageIndex:value.pageIndex});
    }
    function confirmRecheck() {
      if (!recheckCanRun()) return;
      closeDialog();
      const value=recheckState(), bytes=new Uint8Array(16);
      window.crypto.getRandomValues(bytes);
      const runRef=Array.from(bytes,byte=>byte.toString(16).padStart(2,'0')).join('');
      $('dialog-title').textContent='运行同一个原任务的只读复验';
      $('dialog-summary').append(list([['目标',hostSelect.selectedOptions[0]?.textContent || state.host],['原任务',state.selected.request_id],['本次复验标识',runRef],['原清单 SHA256',state.selected.manifest.sha256],['检查配置 SHA256',value.history.current_profile_sha256],['登记检查数',value.history.configured_checks]]),element('p','notice neutral','通过已登记的只读采集检查业务，并新增一份复验记录。不会重跑补丁或防护动作、续期封禁或调用 AI。超时和证据缺口保留待验收。'));
      state.dialog={op:'recheck',key:snapshot('recheck'),runRef,taskKey:recheckKey(),manifest:state.selected.manifest.sha256,profile:value.history.current_profile_sha256};
      $('confirm-label').textContent='我已核对原任务和登记检查，确认运行这一次只读复验。';
      $('send').textContent='运行这次只读复验'; dialog.showModal(); $('cancel').focus();
    }
    async function submitRecheck(pending) {
      if (!recheckCanRun() || pending.taskKey!==recheckKey() || pending.profile!==recheckState().history.current_profile_sha256 || pending.manifest!==state.selected.manifest.sha256) { closeDialog(); return; }
      const value=recheckState(), rid=state.selected.request_id, taskKey=recheckKey();
      // Reserve the stable client reference before the single POST. An error never resets it.
      value.unresolved.add(pending.runRef); value.selected=pending.runRef; value.report=null; value.fresh=false;
      closeDialog();
      await run('只读业务复验',async current=>{
        const row=await api(endpoint('transactions/'+rid+'/rechecks'),{method:'POST',body:{run_ref:pending.runRef,expected_manifest_sha256:pending.manifest,expected_profile_sha256:pending.profile,confirm_recheck:true}});
        if (!current() || taskKey!==recheckKey()) return;
        adoptRecheck(row,{select:true});
        state.message='本次复验已返回；请分别核对业务结果、历史验收和读取时的当前验收。';
      });
      if (taskKey===recheckKey() && context().signedIn) await loadRechecks(value.after,{pageIndex:value.pageIndex,selectRef:pending.runRef});
    }
    function confirmInterrupt() {
      if (!recheckCanInterrupt()) return;
      closeDialog();
      const report=recheckState().report;
      $('dialog-title').textContent='结束这份未完成只读复验';
      $('dialog-summary').append(list([['原任务',state.selected.request_id],['原复验标识',report.run_ref],['声明 SHA256',report.declaration_sha256]]),element('p','notice neutral','服务端已开放本地中断入口，提交时还会重新核对时限。结束后原记录仍待验收；不重新采集，不改变 Root 动作、授权用量或未知状态门禁。新复验必须另行明确确认。'));
      state.dialog={op:'interrupt',key:snapshot('interrupt'),runRef:report.run_ref,declaration:report.declaration_sha256,taskKey:recheckKey()};
      $('confirm-label').textContent='我已核对原复验，确认结束这份未完成的只读复验并保留待验收记录。';
      $('send').textContent='结束这份未完成复验'; dialog.showModal(); $('cancel').focus();
    }
    async function submitInterrupt(pending) {
      if (!recheckCanInterrupt() || pending.taskKey!==recheckKey() || recheckState().report.declaration_sha256!==pending.declaration) { closeDialog(); return; }
      const rid=state.selected.request_id, taskKey=recheckKey(), value=recheckState(); closeDialog();
      await run('结束未完成只读复验',async current=>{
        const row=await api(endpoint('transactions/'+rid+'/rechecks/'+pending.runRef+'/interrupt'),{method:'POST',body:{expected_declaration_sha256:pending.declaration,confirm_interrupt:true}});
        if (!current() || taskKey!==recheckKey()) return;
        adoptRecheck(row,{select:true});
      });
      if (taskKey===recheckKey() && context().signedIn) await loadRechecks(value.after,{pageIndex:value.pageIndex,selectRef:pending.runRef});
    }
    async function exportRecheck() {
      if (!exactAction() || !rechecksSupported() || state.busy) return;
      const taskKey=recheckKey(), rid=state.selected.request_id, runRef=recheckState().selected;
      if (runRef && !idPattern.test(runRef)) return;
      const suffix=runRef?'?'+new URLSearchParams({run_ref:runRef}):'';
      await run('导出安全交接摘要',async current=>{
        const blob=await api(endpoint('transactions/'+rid+'/handoff')+suffix,{blob:true});
        if (!current() || taskKey!==recheckKey() || recheckState().selected!==runRef || !state.visible) return;
        if (!/^text\/markdown(?:;|$)/i.test(blob.type) || blob.size>65536) throw new Error('Invalid handoff file');
        const url=URL.createObjectURL(blob), link=element('a');
        link.href=url; link.download='opsark-defense-handoff.md'; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
        state.message='已下载服务端白名单摘要，覆盖所选原任务及这份复验；未附复验时标待验收。';
      });
    }
    function legacyRow(row) {
      if (!row || row.v!==1 || row.host_id!==state.host || row.request_id!==state.selected?.request_id || !idPattern.test(row.legacy_id || '') || !Number.isSafeInteger(row.sequence) || row.sequence<1 || row.historical_verdict!=='pending' || row.current_verdict!=='pending' || row.projection?.historical_verdict!=='pending' || row.projection.current_verdict!=='pending' || row.projection.business_verdict!=='pending' || !Array.isArray(row.projection.checks) || row.projection.checks.length!==0 || !Array.isArray(row.projection.reasons) || !row.projection.reasons.includes('legacy_incomplete')) throw new Error('Invalid legacy recheck');
      return row;
    }
    async function loadLegacy(after=0, pageIndex=0) {
      if (!rechecksSupported() || !exactAction()) return;
      const key=recheckKey(), rid=state.selected.request_id; legacyState().open=true;
      await run('读取早期复验历史',async current=>{
        const data=await api(endpoint('transactions/'+rid+'/legacy-rechecks')+'?'+new URLSearchParams({after_sequence:String(after),limit:'20'}));
        if (!current() || key!==recheckKey()) return;
        if (!data || data.v!==1 || data.host_id!==state.host || data.request_id!==rid || !Array.isArray(data.legacy_rechecks) || data.legacy_rechecks.length>20 || (data.next_after_sequence!==null && (!Number.isSafeInteger(data.next_after_sequence) || data.next_after_sequence<=after))) throw new Error('Invalid legacy history');
        const rows=data.legacy_rechecks.map(legacyRow);
        if (rows.some((row,index)=>row.sequence<=(index?rows[index-1].sequence:after)) || new Set(rows.map(row=>row.legacy_id)).size!==rows.length) throw new Error('Invalid legacy order');
        const value=legacyState(); value.page=rows; value.after=after; value.next=data.next_after_sequence; value.pages[pageIndex]=after; value.pageIndex=pageIndex; value.loaded=true;
        for (const row of rows) value.all.set(row.legacy_id,row);
      });
    }
    async function selectLegacy(id) {
      if (!rechecksSupported() || !exactAction()) return;
      const key=recheckKey(), rid=state.selected.request_id, value=legacyState(); value.selected=id; value.report=null; value.open=true;
      if (!id) { render(); return; }
      if (!idPattern.test(id)) return;
      await run('读取原早期记录',async current=>{
        const row=await api(endpoint('transactions/'+rid+'/legacy-rechecks/'+id));
        if (!current() || key!==recheckKey()) return;
        value.report=legacyRow(row); value.all.set(id,row);
      });
    }
    async function exportLegacy() {
      if (!rechecksSupported() || !exactAction() || state.busy) return;
      const key=recheckKey(), rid=state.selected.request_id, id=legacyState().selected;
      if (!idPattern.test(id) || !legacyState().report) return;
      await run('导出早期记录安全摘要',async current=>{
        const blob=await api(endpoint('transactions/'+rid+'/legacy-rechecks/'+id+'/handoff'),{blob:true});
        if (!current() || key!==recheckKey() || legacyState().selected!==id || !state.visible) return;
        if (!/^text\/markdown(?:;|$)/i.test(blob.type) || blob.size>65536) throw new Error('Invalid legacy summary');
        const url=URL.createObjectURL(blob), link=element('a'); link.href=url; link.download='opsark-defense-legacy-handoff.md'; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
        state.message='已按原早期记录导出待验收摘要；未转换为新的完整复验记录。';
      });
    }
    function renderLegacy(section) {
      const value=legacyState(), details=element('details','ssh-defense-legacy'); details.open=value.open;
      details.addEventListener('toggle',()=>{if (details.isConnected) value.open=details.open;});
      details.append(element('summary','','早期工程复验记录 · 仅供历史查阅'));
      details.append(element('p','small muted','早期记录缺少完整业务证据，固定保留待验收，不依据旧的成功或失败标记重算业务结论。'));
      details.append(button('读取早期历史记录',()=>loadLegacy(value.after,value.pageIndex),Boolean(state.busy)));
      if (value.loaded) {
        const label=element('label','field','早期原记录'), select=element('select'); select.dataset.defenseLegacy='selection'; select.disabled=Boolean(state.busy);
        const none=element('option','','选择早期原记录'); none.value=''; select.append(none);
        const rows=new Map(value.page.map(row=>[row.legacy_id,row]));
        if (value.selected && value.all.has(value.selected)) rows.set(value.selected,value.all.get(value.selected));
        for (const row of rows.values()) { const option=element('option','','#'+String(row.sequence)+' · 待验收 · '+timestamp(row.started_at)); option.value=row.legacy_id; select.append(option); }
        select.value=value.selected; select.addEventListener('change',()=>selectLegacy(select.value)); label.append(select); details.append(label);
        const pages=element('div','ssh-defense-pagination');
        pages.append(button('早期记录上一页',()=>loadLegacy(value.pages[value.pageIndex-1],value.pageIndex-1),Boolean(state.busy) || value.pageIndex===0,'text-button'),element('span','small muted','早期历史第 '+String(value.pageIndex+1)+' 页'),button('早期记录下一页',()=>loadLegacy(value.next,value.pageIndex+1),Boolean(state.busy) || value.next===null,'text-button')); details.append(pages);
        if (value.report) details.append(element('strong','badge neutral','待验收 · 早期证据不完整'),list([['早期原记录',value.report.legacy_id],['原任务',value.report.request_id],['记录时间',timestamp(value.report.started_at)+' → '+timestamp(value.report.finished_at)]]),button('导出早期原记录摘要（待验收）',exportLegacy,Boolean(state.busy)));
        if (!value.page.length) details.append(element('p','small muted','这一页没有早期记录。'));
      }
      section.append(details);
    }
    function snapshot(op) {
      return JSON.stringify({op,host:state.host,mode:modeKey(),revision:state.status?.revision,generation:state.status?.sync_generation,rid:state.selected?.request_id,manifest:state.selected?.manifest?.sha256,cursor:state.cursor?.request_id,source:state.candidate,input:state.preview?.input_digest,profile:op==='recheck'?recheckState()?.history?.current_profile_sha256:null,run:op==='interrupt'?recheckState()?.report?.run_ref:null,declaration:op==='interrupt'?recheckState()?.report?.declaration_sha256:null});
    }
    function confirm(op) {
      if (state.busy) return;
      if (op==='arm' && !(newAdmission() && target()?.observation_available===true)) return;
      if (op==='apply' && !actionReady()) return;
      if (op==='revoke' && !actionRevocable()) return;
      if (op==='ai' && !(eligible() && state.preview && !state.attempted.has('ai:'+sourceKey()))) return;
      closeDialog();
      const title={arm:'建立这一次观察窗口',apply:'批准这一个封禁动作',revoke:'批准撤销这一个动作',ai:'只发送这一份白名单摘要'};
      $('dialog-title').textContent=title[op];
      const summary=$('dialog-summary');
      summary.append(list([['目标',hostSelect.selectedOptions[0]?.textContent || state.host],['全局模式',modes[context().automation?.mode] || '未取得'],['模式版本',state.status?.revision ?? state.preview?.mode_revision]]));
      if (op==='arm') summary.append(element('p','notice neutral','只建立固定 120 秒观察窗口，需要独立观察许可。本次不封禁；到期后不自动续期。'));
      if (op==='apply' || op==='revoke') {
        summary.append(list([['原任务',state.selected.request_id],['候选来源',state.selected.manifest.source_alias || '已登记候选'],['清单 SHA256',state.selected.manifest.sha256],['原动作 TTL','60 秒，不续期'],['准备截止',timestamp(state.selected.manifest.deadline_at)]]));
        summary.append(element('p','notice neutral',op==='revoke'?'撤销前由服务重新查询同一个原任务并核对当前许可。旧回执不代表当前仍生效。':'只批准这份清单；目标、模式、证据、截止时间及许可变化都会阻止执行。结果未知时只查询原任务。'));
      }
      if (op==='ai') {
        summary.append(element('p','notice neutral','只向已登记提供方发送下方白名单摘要。独立费用许可仍由服务核对；分析结果不授予执行权限。'));
        summary.append(element('pre','ssh-defense-input',JSON.stringify(state.preview.input,null,2)));
        summary.append(list([['输入摘要 SHA256',state.preview.input_digest],['提供方指纹',state.preview.provider_fingerprint]]));
      }
      state.dialog={op,key:snapshot(op)};
      $('confirm-label').textContent=op==='ai'?'我已检查白名单摘要，明确同意本次发送和费用。':'我已核对目标、模式和本次操作，明确批准。';
      $('send').textContent=op==='ai'?'发送这份摘要':op==='arm'?'建立观察窗口':op==='apply'?'执行这份清单':'撤销这个动作';
      dialog.showModal(); $('cancel').focus();
    }
    async function submitConfirmation() {
      const pending=state.dialog;
      if (!pending || !$('confirm').checked || pending.key!==snapshot(pending.op)) { closeDialog(); return; }
      if (pending.op==='recheck') { await submitRecheck(pending); return; }
      if (pending.op==='interrupt') { await submitInterrupt(pending); return; }
      if (pending.op==='session_start' || pending.op==='session_stop') { await submitSession(pending); return; }
      const op=pending.op, revision=state.status?.revision, selected=state.selected;
      if ((op==='apply' && !actionReady()) || (op==='revoke' && !actionRevocable()) || (op==='arm' && !(newAdmission() && target()?.observation_available===true)) || (op==='ai' && !eligible())) { closeDialog(); return; }
      const body=op==='arm'?{expected_mode_revision:revision,confirm_arm:true}:op==='ai'?{cursor_request_id:state.cursor.request_id,source_ref:state.candidate,expected_input_digest:state.preview.input_digest,expected_mode_revision:state.preview.mode_revision,confirm_send:true}:{expected_manifest_sha256:selected.manifest.sha256,expected_mode_revision:revision,[op==='apply'?'confirm_execute':'confirm_revoke']:true};
      const path=op==='arm'?'arm':op==='ai'?'ai/analyses':'transactions/'+selected.request_id+'/'+op;
      const analysisFor=evidenceKey();
      if (op==='ai') state.attempted.add('ai:'+sourceKey());
      closeDialog();
      await run(op==='ai'?'AI 分析':op==='arm'?'建立观察':op==='apply'?'执行':'撤销',async current=>{
        const readStartedAt=performance.now(), value=await api(endpoint(path),{method:'POST',body});
        if (!current()) return;
        if (op==='ai') { state.analysis=value; state.analysisFor=analysisFor; state.preview=null; }
        else accept(value,readStartedAt);
      },{rid:op==='apply' || op==='revoke'?selected.request_id:null,mutation:true});
      if (exactAction() && rechecksSupported()) { staleRecheck(); await loadRechecks(recheckState().after,{pageIndex:recheckState().pageIndex}); }
    }
    async function prepare() {
      if (!(newAdmission() && target()?.execution_available===true && eligible() && aiReady() && context().automation.mode==='assisted') || state.attempted.has('prepare:'+sourceKey())) return;
      const candidate=selectedCandidate(), cursor=state.cursor, key=sourceKey();
      state.attempted.add('prepare:'+key); closeDialog();
      await run('准备处置清单',async current=>{
        const value=await api(endpoint('prepare'),{method:'POST',body:{cursor_request_id:cursor.request_id,source_ref:candidate.source_ref,expected_evidence_sha256:candidate.evidence_sha256,expected_mode_revision:state.status.revision}});
        if (!current()) return;
        accept(value);
        state.message='清单已准备，尚未执行。请核对精确清单并单独批准。';
      },{mutation:true});
      if (exactAction() && rechecksSupported()) await loadRechecks(0);
    }
    function renderRechecks(detail) {
      if (!rechecksSupported() || !exactAction()) return;
      const value=recheckState(), section=element('section','ssh-defense-rechecks'); section.setAttribute('aria-label','业务复验与客户交接');
      section.append(element('p','eyebrow','Business acceptance / Independent evidence'),element('h3','','业务复验与交接'));
      section.append(element('p','small muted','处置回执与业务验收分别记录。准备、生效、自然到期或撤销，均不代表业务检查已经通过。'));
      const actions=element('div','ssh-defense-actions');
      actions.append(button('刷新只读复验历史',()=>loadRechecks(value.after,{pageIndex:value.pageIndex}),Boolean(state.busy)),button('运行只读复验',confirmRecheck,!recheckCanRun(),'button primary')); section.append(actions);
      if (!value.history) section.append(element('p','small muted','尚未核对只读检查配置；可导出未复验的待验收摘要。'));
      else section.append(element('p','small muted','登记检查 '+String(value.history.configured_checks)+' 项。'+(value.history.can_run?'只读入口可用，提交时仍由服务核实目标及原任务绑定。':'当前没有可运行的只读复验；已保存历史仍可核对和导出。')));
      if (value.history?.active_request_id && value.history.active_request_id!==state.selected.request_id) section.append(element('p','notice neutral','这个目标的另一个原任务仍有未确认复验，请先核对该原任务。不会重复采集。'));
      const selectLabel=element('label','field','所选历史复验'), select=element('select'); select.dataset.defenseRecheck='selection'; select.disabled=Boolean(state.busy);
      const none=element('option','','未附复验 · 待验收'); none.value=''; select.append(none);
      const options=new Map(value.page.map(row=>[row.run_ref,row]));
      if (value.selected && !options.has(value.selected) && value.all.has(value.selected)) options.set(value.selected,value.all.get(value.selected));
      for (const row of options.values()) {
        const option=element('option','','#'+String(row.sequence)+' · '+verdicts[row.historical_verdict]+' · '+timestamp(row.created_at)); option.value=row.run_ref; select.append(option);
      }
      if (value.selected && !options.has(value.selected)) { const unknown=element('option','','原复验 '+value.selected+' · 结果待查回'); unknown.value=value.selected; select.append(unknown); }
      select.value=value.selected; select.addEventListener('change',()=>selectRecheck(select.value)); selectLabel.append(select); section.append(selectLabel);
      const pages=element('div','ssh-defense-pagination');
      pages.append(button('上一页',()=>loadRechecks(value.pages[value.pageIndex-1],{pageIndex:value.pageIndex-1}),Boolean(state.busy) || value.pageIndex===0,'text-button'),element('span','small muted','历史第 '+String(value.pageIndex+1)+' 页 · 按原顺序保留'),button('下一页',()=>loadRechecks(value.next,{pageIndex:value.pageIndex+1}),Boolean(state.busy) || value.next===null,'text-button')); section.append(pages);
      const report=value.report;
      const current=value.fresh && report?report.current_verdict:'pending';
      const labels=element('div','ssh-defense-verdicts');
      for (const [label,verdict] of [['所选历史验收',report?.historical_verdict || 'pending'],['本页读取时的当前验收',current],['业务检查结果',report?.projection.business_verdict || 'pending']]) {
        const card=element('div','ssh-defense-verdict'); card.append(element('span','small muted',label),element('strong','badge '+(verdict==='passed'?'green':verdict==='failed'?'amber':'neutral'),verdicts[verdict] || verdicts.pending)); labels.append(card);
      }
      section.append(labels);
      if (report) {
        const projection=report.projection;
        section.append(list([['复验标识',report.run_ref],['原任务',report.request_id],['授权依据',({human_approval:'原任务精确确认声明',preauthorization:'原任务预授权依据',unproven:'尚未核实'}[projection.authority_kind])],['复验前 / 后', (phases[projection.root_before] || '未取得可信查询')+' / '+(phases[projection.root_after] || '未取得可信查询')],['当前本地对账',phases[projection.current_root] || '未取得可信查询'],['复验时间',timestamp(projection.started_at)+' → '+timestamp(projection.finished_at)],['本页读取时间',timestamp(value.readAt)]]));
        const checks=element('ol','ssh-defense-checks');
        for (const check of projection.checks) {
          const item=element('li'); item.dataset.checkStatus=check.status;
          item.append(element('strong','','检查 '+String(check.number)+' · '+checkStatuses[check.status]),element('p','small muted',checkReasons[check.reason_code])); checks.append(item);
        }
        section.append(checks);
        if (projection.reasons.length) section.append(element('p','notice neutral',projection.reasons.map(reason=>reportReasons[reason]).join('；')+'。'));
        if (projection.transition==='ttl_elapsed') section.append(element('p','small muted','两次原任务查询确认本轮自然到期；到期本身不改变业务检查结论。'));
      } else section.append(element('p','notice neutral',value.selected?'这次复验的结果尚未查回；只能查询原复验标识，不自动重新运行。':'未选择复验记录，摘要保留待验收。'));
      if (value.unresolved.size) {
        const unknown=element('div','ssh-defense-unresolved'); unknown.append(element('p','notice neutral','存在结果未确认的只读复验，保留原标识；不会重新提交。'));
        for (const ref of value.unresolved) unknown.append(button('查询原复验 '+ref.slice(0,8),()=>readRecheck(ref),Boolean(state.busy)));
        section.append(unknown);
      }
      const exportActions=element('div','ssh-defense-actions');
      if (value.selected) exportActions.append(button('查询当前选定复验',()=>readRecheck(value.selected),Boolean(state.busy)));
      if (report?.can_interrupt===true) exportActions.append(button('结束未完成只读复验',confirmInterrupt,!recheckCanInterrupt()));
      exportActions.append(button(value.selected?'导出所选复验的安全摘要':'导出未复验摘要（待验收）',exportRecheck,Boolean(state.busy)));
      section.append(exportActions,element('p','small muted','只下载服务端白名单 Markdown，串起原任务授权、执行、断线对账和所选复验；不带原始日志或敏感信息。当前验收是读取时的快照，不代表持续业务健康。'));
      renderLegacy(section);
      detail.append(section);
    }
    function render() {
      if (context().signedIn!==true) { root.hidden=true; return; }
      root.hidden=false;
      renderSessions();
      const supported=readable();
      $('status').replaceChildren(); $('history').replaceChildren(); $('detail').replaceChildren(); $('sources').replaceChildren(); $('ai').replaceChildren();
      hostSelect.disabled=Boolean(state.busy) || !hostSelect.options.length;
      $('refresh').disabled=Boolean(state.busy) || !supported;
      $('arm').disabled=context().capabilities?.ssh_defense_transactions!==true || !(newAdmission() && target()?.observation_available===true);
      $('history-targets').hidden=context().capabilities?.ssh_defense_history!==true;
      $('history-targets').disabled=Boolean(state.busy) || !state.historyNext;
      $('progress').textContent=state.busy?'正在'+state.busy+'…':state.message;
      $('error').textContent=state.error; $('error').hidden=!state.error;
      const status=$('status');
      renderWatch();
      if (!supported) { status.append(element('p','notice neutral','当前实例未登记事务专用凭据，防护执行默认关闭。登记只读采集凭据不会开放防护权限。')); return; }
      if (!state.status) status.append(element('p','empty-note','尚未读取防护事务状态；不会据模式选择推断执行权限。'));
      else {
        const mode=context().automation;
        status.append(list([['全局模式',modes[mode?.mode] || '未取得'],['模式同步',modeFresh()?'本次读取已确认':'待重新读取或同步，禁止新动作'],['观察许可',target()?.observation_available===true?'本次读取可用':'未就绪'],['执行许可',target()?.execution_available===true?'本次读取可用，仍需每次校验':'未就绪'],['AI 分析',state.status.ai_required===true?'执行前必须有有效 AI 建议；费用单独授权':'可选建议；费用单独授权'],['防护状态',state.status.enabled===true?'固定隔离范围已启用':'已关闭'],['原任务对账',target()?.reconciliation_required===true?'有未知记录，保留保护门禁':'未报告锁存']]));
      }
      const history=$('history');
      if (!state.rows.length) history.append(element('p','empty-note','尚无本地事务记录。'));
      for (const row of state.rows.slice(0,100)) {
        const item=button((row.kind==='cursor'?'观察':row.kind==='action'?'处置':'模式')+' · '+(phases[row.phase] || '待核对'),()=>selectTransaction(row.request_id),Boolean(state.busy),'ssh-defense-row');
        item.setAttribute('aria-pressed',String(state.selected?.request_id===row.request_id));
        item.append(element('span','mono small',row.request_id)); history.append(item);
      }
      const detail=$('detail'), value=state.selected;
      if (!value) detail.append(element('p','empty-note','选择原任务，核对当前结果和历史回执。'));
      else {
        const unknown=value.query_required===true || state.uncertain.has(value.request_id) || value.current_result?.state==='unknown';
        detail.append(element('h3','',unknown?'结果未确认，只查询原任务':phases[value.current_result?.state] || phases[value.phase] || '待核对'));
        detail.append(list([['原任务',value.request_id],['当前回执',unknown?'未知；旧成功记录不能替代本次结果':phases[value.current_result?.state] || '未取得'],['任务模式版本',value.mode_revision],['最近确认',value.last_confirmed?(phases[value.last_confirmed.state] || '待核对')+' · '+timestamp(value.last_confirmed.observed_at):'无'],['最近确认剩余 TTL',value.last_confirmed?.remaining_ms?String(value.last_confirmed.remaining_ms)+' ms（历史观测值，不是当前计时）':'无']]));
        detail.append(button('查询同一个原任务',query,Boolean(state.busy) || !target()));
        if (exactAction()) {
          detail.append(list([['清单 SHA256',value.manifest.sha256],['来源别名',value.manifest.source_alias],['动作 TTL','60 秒'],['准备截止',timestamp(value.manifest.deadline_at)]]));
          const actions=element('div','ssh-defense-actions');
          actions.append(button('核对并执行这份清单',()=>confirm('apply'),!actionReady(),'button primary'),button('核对并撤销原动作',()=>confirm('revoke'),!actionRevocable())); detail.append(actions);
        }
        const records=element('details','ssh-defense-history-detail'), summary=element('summary','', '历史回执 · '+String(value.history?.length || 0)+' 条'); records.append(summary);
        const items=element('ol','ssh-defense-receipts');
        for (const record of value.history || []) items.append(element('li','small',timestamp(record.observed_at)+' · '+String(record.op)+' · '+(phases[record.state] || '待核对')+' · '+(record.accepted===true?'已接受':'未接受')+' · '+String(record.reason)));
        records.append(items); detail.append(records);
        renderRechecks(detail);
      }
      const sources=$('sources');
      if (state.cursor?.current_result && !state.cursor.query_required && !state.uncertain.has(state.cursor.request_id)) {
        sources.append(element('h3','','观察候选 · 明确选择后再分析'));
        for (const candidate of state.cursor.current_result.candidates || []) {
          const line=element('label','ssh-defense-candidate');
          const radio=element('input'); radio.type='radio'; radio.name='ssh-defense-source'; radio.value=candidate.source_ref; radio.checked=state.candidate===candidate.source_ref; radio.disabled=Boolean(state.busy) || candidate.classification!=='eligible';
          radio.addEventListener('change',()=>{closeDialog(); state.candidate=candidate.source_ref; state.preview=null; state.analysis=null; state.analysisFor=null; render();});
          line.append(radio,element('span','',candidate.source_alias+' · '+String(candidate.distinct_failure_ports)+' 个不同失败源端口 · '+({eligible:'符合固定候选条件',insufficient:'证据不足',success_seen:'出现成功，禁止处置',gap:'证据缺口'}[candidate.classification] || '待核对'))); sources.append(line);
        }
        const actions=element('div','ssh-defense-actions');
        actions.append(button('预览 AI 白名单摘要',previewAI,!eligible() || Boolean(state.busy)),button('准备处置清单（不执行）',prepare,!(newAdmission() && target()?.execution_available===true && eligible() && aiReady() && context().automation.mode==='assisted') || state.attempted.has('prepare:'+sourceKey()))); sources.append(actions);
        if (state.status?.ai_required===true && !aiReady()) sources.append(element('p','small muted','此范围要求先取得同一候选及证据的完整 AI 处置建议；未知、失败或仅建议继续观察不能准备执行。'));
        if (context().automation?.mode!=='assisted') sources.append(element('p','small muted','界面手动准备和精确批准使用半自动模式。手动模式只建议；本版本尚未启用此通道的持续自动执行。'));
      }
      const ai=$('ai');
      if (state.preview) {
        ai.append(element('h3','','拟发送的完整白名单摘要'),element('pre','ssh-defense-input',JSON.stringify(state.preview.input,null,2)));
        ai.append(button('核对白名单并批准这次发送',()=>confirm('ai'),Boolean(state.busy) || state.attempted.has('ai:'+sourceKey())));
      }
      if (state.analysis) {
        ai.append(element('h3','','原 AI 分析'),list([['分析标识',state.analysis.analysis_id],['分析状态',state.analysis.status],['建议',({propose_defense:'建议固定处置',collect_more:'继续收集证据',review_access:'核对合法访问',no_action:'建议不处置'}[state.analysis.decision] || '无可执行建议')],['执行权限','建议本身不授予权限']]));
        ai.append(button('查询原分析，不重新发送',queryAI,Boolean(state.busy)));
      } else if (state.attempted.has('ai:'+sourceKey())) ai.append(element('p','notice neutral','这份摘要已提交过。未收到分析标识时保留未知状态，不从本页再次发送；请核对服务端原记录。'));
    }
    $('refresh').addEventListener('click',refresh);
    $('history-targets').addEventListener('click',moreHistoryTargets);
    $('arm').addEventListener('click',()=>confirm('arm'));
    hostSelect.addEventListener('change',selectHost);
    $('cancel').addEventListener('click',closeDialog);
    $('confirm').addEventListener('change',()=>{$('send').disabled=!$('confirm').checked || !state.dialog || state.dialog.key!==snapshot(state.dialog.op);});
    $('send').addEventListener('click',submitConfirmation);
    dialog.addEventListener('cancel',closeDialog);
    return Object.freeze({configure,reset,setVisible,sessionChanged,invalidate});
  }
  window.OpsArkDefense=Object.freeze({create});
})();
