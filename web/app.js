(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const scenarios = {web_502:'网站 502',disk:'磁盘空间异常',container_restart:'容器反复重启',ssh_security:'SSH 安全观察'};
  const reportStatuses = {needs_attention:'需要关注',inconclusive:'证据不足',no_issue_detected:'本次未发现明确异常'};
  const checkStatuses = {ok:'已取得',error:'检查失败',timeout:'采集超时',permission_denied:'权限不足',unavailable:'未取得'};
  const comparisonStatuses = {no_baseline:'无可用基线',compared:'已完成字段对照',incomplete:'对照不完整',scope_changed:'目标范围已变化'};
  const verificationStatuses = {passed:'即时检查符合',failed:'条件不符',error:'检查未完成',not_run:'未执行',uncovered:'未覆盖'};
  const compatibilityStatuses = {compatible:'符合当前适配条件',unsupported:'目标环境不支持',unknown:'环境预检未知'};
  const state = {token:'',session:0,requests:new Set(),samples:[],hosts:[],reports:[],capabilities:null,report:null,tab:'diagnosis',busy:false,aiBusy:false,aiTarget:null,baselineBusy:false,baselineTarget:null,loadingReport:false,reportRequest:0,view:'workspace',securityStatus:null,securityAlerts:[],securityAlert:null,securitySelected:null,securitySupported:null,securityBusy:false,securityAckBusy:null,securityTimer:null,securityRequest:0,securityDetailRequest:0,securityRefreshedAt:null,securityAITarget:null,securityAIBusy:false,securityAIRequest:0,securityAIResult:null,automation:null,automationDraft:'manual',automationBusy:false,automationRequest:0,automationNeedsReload:false,automationError:''};
  Object.assign(state,{remediation:null,remediationHost:'',remediationScan:null,remediationPlan:null,remediationBusy:'',remediationError:'',remediationRequest:0,remediationSelection:0,remediationSubmission:null,remediationJob:null,remediationJobRef:null,remediationDialogTarget:null,remediationPoll:null,remediationExpiry:null});
  Object.assign(state,{vulnerabilityWatchStatus:null,vulnerabilityWatchAlerts:[],vulnerabilityWatchSelected:null,vulnerabilityWatchDetail:null,vulnerabilityWatchBusy:false,vulnerabilityWatchDetailBusy:false,vulnerabilityWatchAckBusy:null,vulnerabilityWatchError:'',vulnerabilityWatchRequest:0,vulnerabilityWatchDetailRequest:0,vulnerabilityWatchTimer:null,vulnerabilityWatchReadAt:null});
  Object.assign(state,{automaticStatus:null,automaticBusy:false,automaticError:'',automaticRequest:0,automaticTimer:null,automaticReadAt:null});
  Object.assign(state,{automaticRecoveryBusy:'',automaticRecoveryError:'',automaticRecoveryRequest:0,automaticRecoveryPlan:null,automaticRecoveryRef:null,automaticRecoveryRecord:null,automaticRecoveryRecords:null,automaticRecoveryDialogTarget:null,automaticRecoveryExpiry:null,automaticRecoveryNeedsRefresh:false});
  Object.assign(state,{vulnerabilityAIBusy:'',vulnerabilityAIError:'',vulnerabilityAIRequest:0,vulnerabilityAIProvider:null,vulnerabilityAIRecords:[],vulnerabilityAIRecord:null,vulnerabilityAIRefs:{},vulnerabilityAITarget:null,vulnerabilityAIReadAt:null,vulnerabilityAIPlanRef:null});
  Object.assign(state,{serviceActivationData:null,serviceActivationRecord:null,serviceActivationPlan:null,serviceActivationBusy:'',serviceActivationError:'',serviceActivationRequest:0,serviceActivationRef:null,serviceActivationDialogTarget:null,serviceActivationExpiry:null,serviceActivationTimer:null});
  Object.assign(state,{activationRecoveryData:null,activationRecoveryRecord:null,activationRecoveryPlan:null,activationRecoveryBusy:'',activationRecoveryError:'',activationRecoveryRequest:0,activationRecoveryRef:null,activationRecoveryDialogTarget:null,activationRecoveryExpiry:null,activationRecoveryTimer:null});
  let hostOnboardingRequest=0,hostOnboardingMaterials=null;
  const hostComposeStates=new Map();
  let handoffTarget=null;
  let accessState=null;
  let containerReportRecheck=null;
  const pendingContainerRechecks=new Map();
  let changeState=null;
  const pendingChanges=new Map();
  let nginxActions=null, nginxActionsLoading=false;
  let containerRestarts=null, containerRestartsLoading=false;
  const defenseWorkspace=window.OpsArkDefense?.create({root:$('ssh-defense-workspace'),api,getContext:()=>({signedIn:Boolean(state.token),session:state.session,hosts:state.hosts,capabilities:state.capabilities,automation:state.automation,modePending:Boolean(state.automationBusy || state.automationNeedsReload)})});

  class SessionEnded extends Error {}

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }

  function clear(element) { element.replaceChildren(); }
  function announce(text) { $('announcement').textContent = text; }
  function dateLabel(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value || '未知时间') : new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',dateStyle:'medium',timeStyle:'medium',hour12:false}).format(date) + ' UTC+08:00';
  }
  function sourceLabel(source) { return source === 'replay' ? '样本回放（合成数据）' : source === 'ssh' ? 'SSH 采集' : '来源未确认'; }
  function reportStatusClass(status) { return status === 'needs_attention' || status === 'inconclusive' ? 'amber' : 'neutral'; }
  function message(text) { $('app-message').textContent=text; $('app-message').hidden=!text; }
  function error(text) { $('app-error').textContent=text; $('app-error').hidden=!text; }
  function errorMessage(cause) { return cause instanceof Error ? cause.message : '请求失败，请稍后重新操作。'; }

  async function api(path, options={}) {
    if (!state.token) throw new SessionEnded('需要控制台令牌。');
    const session=state.session;
    const controller=new AbortController();
    state.requests.add(controller);
    try {
      const headers = new Headers(options.headers || {});
      headers.set('Authorization','Bearer '+state.token);
      if(options.body !== undefined) headers.set('Content-Type','application/json');
      const response=await fetch(path,{method:options.method || 'GET',headers,body:options.body === undefined ? undefined : JSON.stringify(options.body),signal:controller.signal,credentials:'omit',cache:'no-store'});
      if(session !== state.session) throw new SessionEnded('会话已结束。');
      if(response.status===401) { lockConsole('令牌无效或已失效，请重新输入。'); throw new SessionEnded('认证失败。'); }
      if(!response.ok) {
        let detail='请求失败（HTTP '+response.status+'）。';
        try {
          const payload=await response.json();
          if(typeof payload.detail==='string') detail=payload.detail;
          else if(response.status===422) detail='请求信息不符合要求，请检查所选目标和调查场景。';
        } catch { /* Keep the bounded HTTP error, without rendering a response body. */ }
        const cause=new Error(detail); cause.status=response.status; throw cause;
      }
      return options.blob ? await response.blob() : await response.json();
    } catch(cause) {
      if(session !== state.session || cause instanceof SessionEnded || cause.name==='AbortError') throw new SessionEnded('会话已结束。');
      if(cause instanceof TypeError) throw new Error('无法连接本地服务。请确认 OpsArk 仍在运行，再重新操作。');
      throw cause;
    } finally { state.requests.delete(controller); }
  }

  function lockConsole(reason='') {
    accessState=null;
    containerReportRecheck=null; pendingContainerRechecks.clear();
    changeState=null; pendingChanges.clear();
    defenseWorkspace?.reset();
    nginxActions?.reset();
    containerRestarts?.reset();
    $('nginx-actions-section').hidden=true;
    $('container-restarts-section').hidden=true;
    stopActivationRecoveryPolling();dismissActivationRecoveryDialog();state.activationRecoveryRequest+=1;state.activationRecoveryData=null;state.activationRecoveryRecord=null;state.activationRecoveryPlan=null;state.activationRecoveryBusy='';state.activationRecoveryError='';state.activationRecoveryRef=null;['activation-recovery-summary','activation-recovery-progress','activation-recovery-candidates','activation-recovery-records','activation-recovery-detail','activation-recovery-dialog-summary'].forEach(id=>clear($(id)));$('activation-recovery-dialog-evidence').textContent='';$('activation-recovery-section').hidden=true;
    stopServiceActivationPolling();dismissServiceActivationDialog();state.serviceActivationRequest+=1;state.serviceActivationData=null;state.serviceActivationRecord=null;state.serviceActivationPlan=null;state.serviceActivationBusy='';state.serviceActivationError='';state.serviceActivationRef=null;['service-activation-summary','service-activation-progress','service-activation-pending','service-activation-records','service-activation-detail','service-activation-dialog-summary'].forEach(id=>clear($(id)));$('service-activation-dialog-evidence').textContent='';$('service-activation-section').hidden=true;
    ['automatic-ai-summary','automatic-ai-requests','automatic-ai-alerts'].forEach(id=>clear($(id))); $('automatic-ai-section').hidden=true;
    dismissVulnerabilityAIDialog(); state.vulnerabilityAIRequest+=1; state.vulnerabilityAIBusy=''; state.vulnerabilityAIError=''; state.vulnerabilityAIProvider=null; state.vulnerabilityAIRecords=[]; state.vulnerabilityAIRecord=null; state.vulnerabilityAIRefs={}; state.vulnerabilityAIReadAt=null; state.vulnerabilityAIPlanRef=null; renderVulnerabilityAI();
    ['vulnerability-ai-provider','vulnerability-ai-history','vulnerability-ai-detail','vulnerability-ai-progress'].forEach(id=>clear($(id))); $('vulnerability-ai-section').hidden=true;
    stopSecurityPolling();
    stopVulnerabilityWatchPolling();
    stopAutomaticPolling();
    dismissAutomaticRecoveryDialog();
    clear($('automatic-recovery-dialog-summary'));
    stopRemediationPolling(); dismissRemediationDialog();
    state.session += 1;
    for(const controller of state.requests) controller.abort();
    state.requests.clear();
    state.token=''; state.samples=[]; state.hosts=[]; state.reports=[]; state.capabilities=null; state.report=null; state.busy=false; state.aiBusy=false; state.baselineBusy=false; state.loadingReport=false; state.reportRequest += 1;
    hostComposeStates.clear();
    $('open-host-onboarding').hidden=true;
    $('host-onboarding-form').reset(); $('host-onboarding').open=false; $('host-onboarding').hidden=true; resetHostOnboardingResult();
    state.securityRequest+=1; state.securityDetailRequest+=1; state.securityStatus=null; state.securityAlerts=[]; state.securityAlert=null; state.securitySelected=null; state.securitySupported=null; state.securityBusy=false; state.securityAckBusy=null; state.securityRefreshedAt=null;
    state.securityAIRequest+=1; state.securityAIBusy=false; state.securityAIResult=null; dismissSecurityAIDialog();
    state.automationRequest+=1; state.automation=null; state.automationDraft='manual'; state.automationBusy=false; state.automationNeedsReload=false; state.automationError=''; renderAutomation();
    state.remediationRequest+=1; state.remediationSelection+=1; state.remediation=null; state.remediationHost=''; state.remediationScan=null; state.remediationPlan=null; state.remediationBusy=''; state.remediationError=''; state.remediationSubmission=null; state.remediationJob=null; state.remediationJobRef=null; renderRemediation();
    state.vulnerabilityWatchRequest+=1; state.vulnerabilityWatchDetailRequest+=1; state.vulnerabilityWatchStatus=null; state.vulnerabilityWatchAlerts=[]; state.vulnerabilityWatchSelected=null; state.vulnerabilityWatchDetail=null; state.vulnerabilityWatchBusy=false; state.vulnerabilityWatchDetailBusy=false; state.vulnerabilityWatchAckBusy=null; state.vulnerabilityWatchError=''; state.vulnerabilityWatchReadAt=null; renderVulnerabilityWatch();
    state.automaticRequest+=1; state.automaticStatus=null; state.automaticBusy=false; state.automaticError=''; state.automaticReadAt=null; renderAutomatic();
    state.automaticRecoveryRequest+=1; state.automaticRecoveryBusy=''; state.automaticRecoveryError=''; state.automaticRecoveryPlan=null; state.automaticRecoveryRef=null; state.automaticRecoveryRecord=null; state.automaticRecoveryRecords=null; state.automaticRecoveryNeedsRefresh=false; renderAutomaticRecovery();
    ['security-monitor-summary','security-host-list','security-alert-list','security-alert-detail'].forEach(id=>clear($(id)));
    $('security-alert-count').hidden=true; $('security-alert-count').textContent=''; $('security-last-refresh').textContent=''; $('security-list-count').textContent=''; $('security-error').hidden=true; $('security-error').textContent=''; $('refresh-security').disabled=false; $('refresh-security').textContent='刷新观察';
    $('token-input').value='';
    clear($('report-list')); clear($('report-panel')); clear($('host-list')); clear($('capability-details')); clear($('sample-select')); clear($('host-select'));
    ['report-id','report-title','report-context','report-time','report-source','report-status','ai-dialog-model'].forEach(id=>$(id).textContent='');
    $('report-content').hidden=true; $('report-empty').hidden=false; $('investigation-progress').hidden=true;
    $('export-report').disabled=false; $('export-handoff').disabled=false;
    $('app-shell').hidden=true; $('login-screen').hidden=false; $('login-button').disabled=false; $('login-button').textContent='进入控制台 →';
    $('login-error').textContent=reason; $('login-error').hidden=!reason;
    dismissAIDialog();
    dismissBaselineDialog();
    dismissHandoffDialog();
    $('run-investigation').textContent='运行只读调查 →'; $('investigation-form').removeAttribute('aria-busy');
    message(''); error(''); announce(reason || '已退出控制台，页面内存中的令牌和报告已清除。');
  }

  async function checkService() {
    $('service-status').textContent='正在检查本地服务…'; $('retry-status').hidden=true;
    try {
      const response=await fetch('/api/status',{credentials:'omit',cache:'no-store'});
      if(!response.ok) throw new Error();
      const status=await response.json();
      $('service-status').textContent='服务已就绪 · 版本 '+String(status.version || '未知');
    } catch {
      $('service-status').textContent='服务未就绪，请从启动的 OpsArk 服务打开控制台。'; $('retry-status').hidden=false;
    }
  }

  function showView(view) {
    defenseWorkspace?.setVisible(view==='security');
    if(view!=='remediation') dismissActivationRecoveryDialog();
    if(view!=='remediation') dismissServiceActivationDialog();
    if(view!=='remediation') dismissVulnerabilityAIDialog();
    if(view!=='security') dismissSecurityAIDialog();
    if(view!=='workspace') { dismissHandoffDialog(); accessState=null; containerReportRecheck=null; changeState=null; }
    if(view==='remediation' && !remediationViewSupported()) view='workspace';
    if(view!=='remediation') dismissRemediationDialog();
    state.view=view;
    const labels={workspace:'调查工作台',hosts:'已登记主机',security:'安全观察',remediation:remediationViewLabel(),capabilities:'能力与边界'};
    Object.keys(labels).forEach(key=>$('view-'+key).hidden=key!==view);
    document.querySelectorAll('[data-view]').forEach(button=>{
      if(button.dataset.view===view) button.setAttribute('aria-current','page'); else button.removeAttribute('aria-current');
    });
    $('view-label').textContent=labels[view];
    announce('已打开'+labels[view]+'。');
    stopSecurityPolling();
    stopRemediationPolling();
    stopVulnerabilityWatchPolling();
    stopAutomaticPolling();
    stopServiceActivationPolling();
    stopActivationRecoveryPolling();
    if(view==='security') refreshSecurity();
    if(view==='workspace' && state.tab==='verification') renderPanel();
    if(view==='workspace' && state.tab==='diagnosis' && changeEnabled(state.report) && !changeState) renderPanel();
    if(view==='remediation') { renderRemediation(); refreshRemediation(); refreshVulnerabilityWatch({quiet:true}); refreshAutomatic({quiet:true}); refreshServiceActivations(); refreshActivationRecoveries(); }
    else { nginxActions?.configure(); containerRestarts?.configure(); }
  }

  function option(value,label) { const item=node('option','',label); item.value=value; return item; }
  function fillSelections() {
    clear($('sample-select')); clear($('host-select'));
    if(!state.samples.length) $('sample-select').append(option('','没有可用样本'));
    for(const sample of state.samples) $('sample-select').append(option(sample.id,sample.title+' · '+(scenarios[sample.scenario] || sample.scenario)));
    if(!state.hosts.length) $('host-select').append(option('','尚未登记 SSH 主机'));
    for(const host of state.hosts) $('host-select').append(option(host.id,host.name+' · '+host.address));
    updateSelection();
  }

  function canOpenHostOnboarding() {
    return Boolean(state.token && $('source-select').value==='ssh' && state.hosts.length===0 && state.capabilities?.host_onboarding===true);
  }

  function updateSelection() {
    const replay=$('source-select').value==='replay';
    const canOnboard=canOpenHostOnboarding();
    $('open-host-onboarding').hidden=!canOnboard;
    $('sample-field').hidden=!replay; $('host-field').hidden=replay; $('scenario-field').hidden=replay;
    $('selection-source').textContent=replay?'样本回放 · 合成数据':'SSH 只读采集';
    $('selection-source').className='badge '+(replay?'amber':'green');
    $('run-investigation').disabled=state.busy || (replay?!state.samples.length:!state.hosts.length);
    if(replay) {
      const selected=state.samples.find(sample=>sample.id===$('sample-select').value);
      $('selection-note').textContent=selected?'读取本地合成样本，运行实际诊断规则；场景：'+(scenarios[selected.scenario] || selected.scenario)+'。不是实际服务器检查。':'没有可用回放样本。';
    } else {
      const host=state.hosts.find(item=>item.id===$('host-select').value);
      $('selection-note').textContent=host?'将对已登记目标 '+host.name+' 执行预定义只读检查；未知主机密钥、权限不足或采集失败会记录为证据缺口。':canOnboard?'尚未登记 SSH 主机。接入向导可以核对主机指纹并生成登记材料。':'尚未登记 SSH 主机。请由部署者在服务端 TOML 配置中登记目标、凭据引用和可信主机记录。';
    }
  }

  function reportList() {
    const list=$('report-list');
    const focused=list.contains(document.activeElement)?document.activeElement.dataset.reportId:null;
    clear(list);
    if(!state.reports.length) { list.append(node('p','empty-note','还没有保存的报告。运行一次调查后，结果会保留在此处。')); return; }
    for(const report of state.reports) {
      const button=node('button','report-list-button'); button.type='button'; button.dataset.reportId=report.id; button.setAttribute('aria-pressed',String(state.report?.id===report.id));
      const meta=node('div','report-list-meta'); meta.append(node('span','badge '+(report.source==='replay'?'amber':'green'),report.source==='replay'?'合成样本':sourceLabel(report.source)));
      meta.append(node('span','small',scenarios[report.scenario] || report.scenario)); button.append(meta,node('strong','',report.title),node('p','small',report.host_name || report.host_id),node('p','small',dateLabel(report.created_at)));
      button.addEventListener('click',()=>selectReport(report.id)); list.append(button);
      if(focused===report.id) button.focus({preventScroll:true});
    }
  }

  async function refreshReports() {
    const session=state.session;
    const reports=await api('/api/reports');
    if(session!==state.session) return;
    state.reports=Array.isArray(reports)?reports:[]; reportList();
  }

  async function selectReport(id) {
    const request=++state.reportRequest;
    const session=state.session;
    accessState=null;
    containerReportRecheck=null;
    changeState=null;
    dismissAIDialog(); dismissBaselineDialog(); dismissHandoffDialog(); state.loadingReport=true; updateBaselineButton();
    if(state.tab==='verification') renderPanel();
    if(state.tab==='diagnosis' && changeEnabled(state.report)) renderPanel();
    error(''); message('正在读取报告…');
    try {
      const report=await api('/api/reports/'+encodeURIComponent(id));
      if(session!==state.session || request!==state.reportRequest) return;
      state.report=report; state.tab='diagnosis'; renderReport(); reportList(); message('');
      announce('已读取报告：'+report.title+'。来源：'+sourceLabel(report.source)+'。');
    } catch(cause) {
      if(cause instanceof SessionEnded || request!==state.reportRequest) return;
      message(''); error(errorMessage(cause));
    } finally {
      if(session===state.session && request===state.reportRequest) {
        state.loadingReport=false; updateBaselineButton();
        if(state.tab==='verification') renderPanel();
        if(state.tab==='diagnosis' && changeEnabled(state.report) && !changeState) renderPanel();
      }
    }
  }

  function setTab(tab,focus=false) {
    if(tab!=='verification') { accessState=null; containerReportRecheck=null; }
    if(tab!=='diagnosis') changeState=null;
    state.tab=tab; renderPanel();
    document.querySelectorAll('[data-tab]').forEach(button=>{
      const active=button.dataset.tab===tab; button.setAttribute('aria-selected',String(active)); button.tabIndex=active?0:-1;
    });
    $('report-panel').setAttribute('aria-labelledby','tab-'+tab);
    if(focus) $('tab-'+tab).focus();
  }

  function renderReport() {
    const report=state.report;
    if(!report) return;
    $('report-empty').hidden=true; $('report-content').hidden=false;
    $('report-id').textContent=report.id;
    $('report-source').textContent=sourceLabel(report.source); $('report-source').className='badge '+(report.source==='replay'?'amber':'green');
    $('report-title').textContent=report.title;
    $('report-status').textContent=reportStatuses[report.status] || '状态待核对'; $('report-status').className='badge '+reportStatusClass(report.status);
    $('report-context').textContent=(report.host_name || report.host_id)+' · '+(scenarios[report.scenario] || report.scenario)+' · '+sourceLabel(report.source);
    $('report-time').textContent='报告生成：'+dateLabel(report.created_at)+' · 调查耗时 '+((report.duration_ms || 0)/1000).toFixed(2)+' 秒';
    setTab(state.tab);
  }

  function sectionHeading(title,count) {
    const heading=node('div','section-heading'); heading.append(node('h3','',title));
    if(count!==undefined) heading.append(node('span','small mono',String(count).padStart(2,'0')+' ITEMS'));
    return heading;
  }

  function evidenceReference(id) {
    const button=node('button','evidence-link',id+' ↗'); button.type='button';
    button.addEventListener('click',()=>{
      setTab('evidence');
      const details=[...$('report-panel').querySelectorAll('details')].find(item=>item.dataset.evidenceId===id);
      if(details) { details.open=true; details.querySelector('summary').focus(); }
      else announce('对应证据未包含在该报告中。');
    });
    return button;
  }

  function findingList(findings,empty) {
    if(!findings?.length) return node('p','empty-note',empty);
    const list=node('ul','finding-list');
    for(const finding of findings) {
      const item=node('li'); item.append(node('p','',finding.text));
      if(finding.evidence_ids?.length) { const references=node('div','finding-references'); finding.evidence_ids.forEach(id=>references.append(evidenceReference(id))); item.append(references); }
      list.append(item);
    }
    return list;
  }

  function plainList(items,empty) {
    if(!items?.length) return node('p','empty-note',empty);
    const list=node('ul','plain-list'); items.forEach(item=>list.append(node('li','',item))); return list;
  }

  function baselineEligibility() {
    const report=state.report;
    if(state.capabilities?.baselines!==true) return {allowed:false,reason:'当前实例尚未开放观测基线接口。'};
    if(!report || typeof report.scope_hash!=='string' || !report.scope_hash.trim()) return {allowed:false,reason:'旧报告缺少目标范围信息，请重新运行调查后再保存观测基线。'};
    if(!report.target || report.target.id!==report.host_id || report.target.source!==report.source) return {allowed:false,reason:'报告缺少一致的登记目标，请重新运行调查。'};
    if(state.loadingReport || state.busy) return {allowed:false,reason:'请等待当前调查或报告读取完成，再确认保存目标。'};
    if(state.baselineBusy) return {allowed:false,reason:'正在保存已确认报告的观测字段。'};
    return {allowed:true,reason:'仅用于后续新调查的字段对照，不改变当前报告的事实或验收状态。'};
  }

  function updateBaselineButton() {
    const button=$('save-baseline'),note=$('baseline-save-note');
    if(!button || !note) return;
    const eligibility=baselineEligibility();
    button.disabled=!eligibility.allowed;
    button.textContent=state.baselineBusy?'正在保存观测基线…':'保存为观测基线';
    note.textContent=eligibility.reason;
  }

  function diskAllocationLabel(field) {
    if(field==='disk_scope.total.allocated_bytes') return '登记范围全部对象 · 已分配字节（inode 去重）';
    const category=/^disk_scope\.category\.(log|business)\.allocated_bytes$/.exec(field || '');
    if(category) return (category[1]==='log'?'日志':'业务数据（排除清理）')+' · 已分配字节';
    const group=/^disk_scope\.group\.(log|business)\.(directory-[1-8](?:\+directory-[1-8]){0,7})\.allocated_bytes$/.exec(field || '');
    if(!group) return null;
    const directories=group[2].split('+'); if([...new Set(directories)].sort().join('+')!==group[2]) return null;
    return (group[1]==='log'?'日志':'业务数据（排除清理）')+' · 登记目录组合 '+directories.join(' + ')+' · 已分配字节（组合只计一次）';
  }

  function renderBaseline(panel) {
    const report=state.report,comparison=report.comparison || {status:'no_baseline'};
    const section=node('section','baseline-section'); section.id='baseline-section';
    const heading=sectionHeading('观测基线与变化');
    heading.append(node('span','badge '+(comparison.status==='incomplete' || comparison.status==='scope_changed'?'amber':'neutral'),comparisonStatuses[comparison.status] || '对照状态未知'));
    section.append(heading,node('p','small muted','观测基线只保存已取得的字段，不证明健康，也不是配置备份或回退点。'));
    if(report.source==='replay') section.append(node('p','notice neutral','此处是合成样本之间的模拟差异，不代表真实服务器变化、增长速度或变更时间。'));
    const meta=node('div','baseline-meta');
    if(comparison.baseline_report_id) {
      const link=node('button','text-button','查看基线报告 ↗'); link.type='button'; link.id='baseline-report-link';
      link.addEventListener('click',()=>selectReport(comparison.baseline_report_id));
      meta.append(link,node('span','small mono',comparison.baseline_report_id));
    }
    if(comparison.baseline_created_at) meta.append(node('span','small muted','基线保存：'+dateLabel(comparison.baseline_created_at)));
    if(meta.childNodes.length) section.append(meta);
    if(comparison.status==='scope_changed') section.append(node('div','notice','登记目标范围与基线不同，本次停止字段比较。旧范围不能沿用到当前目标。'));
    else if(comparison.status==='no_baseline') section.append(node('p','empty-note','本次调查没有可用的观测基线，无法追溯这之前的字段变化。'));
    else if(comparison.status==='compared' || comparison.status==='incomplete') {
      let changes=Array.isArray(comparison.changes)?comparison.changes:[];
      const allocationNumber=value=>typeof value==='string' && /^(0|[1-9][0-9]{0,18})$/.test(value) && BigInt(value)<=9223372036854775807n && BigInt(value)%512n===0n;
      const allocationRejected=changes.some(change=>typeof change.field==='string' && change.field.startsWith('disk_scope') && (!diskAllocationLabel(change.field) || !allocationNumber(change.before) || !allocationNumber(change.after)));
      if(allocationRejected) {
        section.append(node('p','notice','磁盘聚合指标未通过完整白名单核验，整份对照未展示。')); changes=[];
      }
      if(!allocationRejected && changes.some(change=>diskAllocationLabel(change.field))) section.append(node('p','small muted','全局、类别和目录组合是同一占用的不同汇总层次，不能再相加；只比较同一指标的前后值。'));
      if(!changes.length && !allocationRejected) section.append(node('p','empty-note','参与比较的已知字段未显示差异；缺失或未覆盖的字段不能据此视为相同或正常。'));
      for(const change of changes) {
        const allocation=diskAllocationLabel(change.field);
        const item=node('div','baseline-change'); item.append(node('h3','mono',allocation || change.field || '未标明字段'));
        const values=node('dl','change-values');
        const observation=value=>typeof value==='string'?(value===''?'空文本（按记录）':value):'未取得';
        values.append(node('dt','','基线值'),node('dd','mono',observation(change.before)),node('dt','','本次值'),node('dd','mono',observation(change.after))); item.append(values);
        if(allocation && /^(0|[1-9][0-9]{0,18})$/.test(change.before) && /^(0|[1-9][0-9]{0,18})$/.test(change.after)) {
          const delta=BigInt(change.after)-BigInt(change.before);
          item.append(node('p','small',delta>0n?'已分配字节增加 '+delta.toString()+'；仅为聚合观察，不证明单文件原因或可清理量。':'已分配字节变化 '+delta.toString()+'；不证明物理释放或业务恢复。'));
        }
        if(change.evidence_ids?.length) { const references=node('div','finding-references'); change.evidence_ids.forEach(id=>references.append(evidenceReference(id))); item.append(references); }
        section.append(item);
      }
    } else section.append(node('p','empty-note','没有可解释的对照状态，不能推断目标正常或字段未变化。'));
    if(comparison.missing?.length) section.append(plainList(comparison.missing,''));
    section.append(node('p','small muted','两次观测不相同，不直接证明修改者、发生时间或故障因果。磁盘配置摘要也不等于 Nginx 已加载配置。'));
    if(state.capabilities?.compose_generation===true && report.source==='ssh' && report.scenario==='container_restart' && comparison.baseline_report_id && comparison.status!=='scope_changed') {
      renderComposeGeneration(section,report);
    }
    const actions=node('div','baseline-actions'),button=node('button','button','保存为观测基线'); button.type='button'; button.id='save-baseline'; button.addEventListener('click',openBaselineDialog);
    const note=node('p','small muted'); note.id='baseline-save-note'; actions.append(button,note); section.append(actions); panel.append(section); updateBaselineButton();
  }

  function renderComposeGeneration(section,report) {
    const block=node('div','baseline-change');
    const button=node('button','text-button','查看容器与 Compose 配置变化');
    const result=node('div','small'); result.setAttribute('role','status');
    const fields=[['container','容器实例'],['image','镜像'],['compose_configuration','Compose 配置']];
    const labels={changed:'有变化',unchanged:'未观察到变化',unavailable:'证据不足'};
    button.type='button';
    button.addEventListener('click',async()=>{
      const current=()=>block.isConnected && state.report===report;
      button.disabled=true; result.textContent='正在读取基线与本次报告的观测记录…';
      try {
        const value=await api('/api/reports/'+encodeURIComponent(report.id)+'/compose-generation');
        if(!current()) return;
        const keys=['status','container','image','compose_configuration','source','deployment_source','changed_at','actor'];
        if(!closedHandoffObject(value,keys) || value.source!=='docker_engine_metadata_and_compose_labels' ||
          value.deployment_source!=='unknown' || value.changed_at!=='unknown' || value.actor!=='unknown' ||
          fields.some(([key])=>typeof value[key]!=='string' || !Object.hasOwn(labels,value[key]))) throw new Error();
        if(value?.status==='unavailable') {
          if(fields.some(([key])=>value[key]!=='unavailable')) throw new Error();
          result.textContent='缺少同一登记范围内可比较的两次观测。';
          return;
        }
        if(value.status!=='observed' || value.container==='unavailable' || value.image==='unavailable') throw new Error();
        const rows=node('dl','change-values');
        for(const [key,label] of fields) rows.append(node('dt','',label),node('dd','',labels[value[key]]));
        clear(result); result.append(rows,node('p','small muted','部署来源、变更时间和操作者未知。'));
      } catch(cause) {
        if(!(cause instanceof SessionEnded) && current()) result.textContent='暂时无法读取容器变化记录。';
      } finally { if(current()) button.disabled=false; }
    });
    block.append(button,result); section.append(block);
  }

  const changeKinds={
    unknown:'不确定',nginx_configuration:'Nginx 配置',compose_configuration:'Compose 配置',
    image_update:'镜像更新',application_configuration:'应用配置',service_restart:'服务重启',
  };
  const changeFields={container:'容器实例',image:'镜像',compose_configuration:'Compose 配置'};
  const changeBaselines={
    no_baseline:'没有可比基线',compared:'已对照登记范围内的观测',
    incomplete:'部分字段缺少可比证据',scope_changed:'登记范围已变化，旧基线不可比',
  };
  const changeId=/^cr-[a-f0-9]{32}$/;
  const changeDate=/^\d{4}-\d\d-\d\d$/;
  const changeUtc=(value,secondsOnly=false)=>accessTime(value) && /(?:Z|\+00:00)$/.test(value) &&
    new Date(value).toISOString().slice(0,19)===value.slice(0,19) && (!secondsOnly || !value.includes('.'));
  const changeTimeKey=value=>{
    const [seconds,fraction='']=value.replace(/(?:Z|\+00:00)$/,'').split('.');
    return seconds+'.'+fraction.padEnd(6,'0');
  };
  const changeClaimValid=claim=>closedHandoffObject(claim,['precision','value']) &&
    (claim.precision==='unknown' && claim.value===null ||
      claim.precision==='date' && typeof claim.value==='string' && changeDate.test(claim.value) &&
      Number.isFinite(Date.parse(claim.value)) && new Date(claim.value).toISOString().slice(0,10)===claim.value ||
      claim.precision==='instant' && changeUtc(claim.value,true));
  const changeLabel=(labels,value)=>typeof value==='string' && Object.hasOwn(labels,value);

  function changeEnabled(report) {
    return state.capabilities?.change_records===true && report?.source==='ssh' &&
      typeof report.id==='string' && /^[A-Za-z0-9_-]{1,80}$/.test(report.id);
  }

  function checkedChangeRecord(row,id) {
    if(!closedHandoffObject(row,['id','report_id','kind','claimed_at','recorded_at','source']) ||
      typeof row.id!=='string' || !changeId.test(row.id) || row.report_id!==id ||
      row.source!=='operator_statement' || !changeLabel(changeKinds,row.kind) ||
      !changeClaimValid(row.claimed_at) || !changeUtc(row.recorded_at)) throw new Error();
    return row;
  }

  function checkedChanges(data,id) {
    if(!closedHandoffObject(data,['report_id','can_record','records','observation']) ||
      data.report_id!==id || typeof data.can_record!=='boolean' ||
      !Array.isArray(data.records) || data.records.length>20) throw new Error();
    const observation=data.observation;
    if(!closedHandoffObject(observation,['current_at','baseline_status','changes']) ||
      (observation.current_at!==null && !changeUtc(observation.current_at)) ||
      !changeLabel(changeBaselines,observation.baseline_status) ||
      !Array.isArray(observation.changes) || observation.changes.length>3 ||
      observation.changes.some(row=>!closedHandoffObject(row,['field','from_at','to_at']) ||
        !changeLabel(changeFields,row.field) || !changeUtc(row.from_at) || !changeUtc(row.to_at) ||
        changeTimeKey(row.from_at)>=changeTimeKey(row.to_at) || observation.current_at===null ||
        changeTimeKey(row.to_at)!==changeTimeKey(observation.current_at) ||
        ['scope_changed','no_baseline'].includes(observation.baseline_status)) ||
      new Set(observation.changes.map(row=>row.field)).size!==observation.changes.length ||
      new Set(observation.changes.map(row=>changeTimeKey(row.from_at))).size>1) throw new Error();
    const records=data.records.map(row=>checkedChangeRecord(row,id));
    if(new Set(records.map(row=>row.id)).size!==records.length) throw new Error();
    return {...data,records};
  }

  const changePath=target=>'/api/reports/'+encodeURIComponent(target.id)+'/change-records';
  const currentChange=target=>changeState===target && Boolean(state.token) && state.view==='workspace' &&
    state.tab==='diagnosis' && !state.loadingReport && changeEnabled(state.report) && sameReportTarget(target);

  async function readChangeHistory(target) {
    if(!currentChange(target) || target.busy) return;
    target.busy='正在读取变更记录…'; target.error='';
    redrawChanges(target);
    try {
      const data=checkedChanges(await api(changePath(target)),target.id);
      if(!currentChange(target)) return;
      target.data=data;
      if(!data.records.some(row=>row.id===target.selected)) target.selected=data.records[0]?.id || '';
    } catch(cause) {
      if(currentChange(target) && !(cause instanceof SessionEnded)) {
        target.data=null;
        target.error='暂时无法核实变更记录。';
      }
    } finally { finishChangeRequest(target); }
  }

  function finishChangeRequest(target) {
    target.busy='';
    redrawChanges(target);
  }

  function claimedInstant(value) {
    if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?$/.test(value)) return null;
    return (value.length===16 ? value+':00' : value)+'Z';
  }

  function newReportRequestId() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)),byte=>byte.toString(16).padStart(2,'0')).join('');
  }

  function newChangeSubmission(target) {
    const draft=target.draft;
    const value=draft.precision==='date' ? draft.date : draft.precision==='instant' ? claimedInstant(draft.instant) : null;
    const claimed_at={precision:draft.precision,value};
    if(!changeLabel(changeKinds,draft.kind) || !changeClaimValid(claimed_at)) return null;
    if(claimed_at.precision==='instant' &&
      (!draft.confirmed || Date.parse(value)>Date.now())) return null;
    return {request_id:newReportRequestId(),kind:draft.kind,claimed_at};
  }

  function sameClaim(left,right) {
    if(left.precision!==right.precision) return false;
    return left.precision==='instant' ? Date.parse(left.value)===Date.parse(right.value) : left.value===right.value;
  }

  async function submitChange(target) {
    if(!currentChange(target) || target.busy || state.busy || target.data?.can_record!==true) return;
    const previous=pendingChanges.get(target.id);
    if(!previous && target.data.records.length>=20) return;
    if(previous && previous.scope!==target.scope) return;
    if(previous?.submitting) return;
    const payload=previous?.payload || newChangeSubmission(target);
    if(!payload) {
      target.error='请填写有效的日期或 UTC 时间，并确认所填写的时刻。';
      redrawChanges(target);
      return;
    }
    const pending=previous || {scope:target.scope,payload};
    pending.submitting=true;
    pendingChanges.set(target.id,pending);
    target.busy='正在提交维护者陈述…'; target.error='';
    redrawChanges(target);
    try {
      const row=checkedChangeRecord(await api(changePath(target),{method:'POST',body:payload}),target.id);
      if(row.kind!==payload.kind || !sameClaim(row.claimed_at,payload.claimed_at)) throw new Error();
      if(pendingChanges.get(target.id)!==pending || !currentChange(target)) return;
      const recorded=target.data.records.find(item=>item.id===row.id);
      if(recorded && (recorded.kind!==row.kind || !sameClaim(recorded.claimed_at,row.claimed_at) ||
        changeTimeKey(recorded.recorded_at)!==changeTimeKey(row.recorded_at))) throw new Error();
      pendingChanges.delete(target.id);
      if(!recorded) {
        const order=item=>changeTimeKey(item.recorded_at)+item.id;
        target.data.records=[row,...target.data.records].sort((left,right)=>order(right).localeCompare(order(left))).slice(0,20);
      }
      target.selected=row.id;
      target.draft={kind:'unknown',precision:'unknown',date:'',instant:'',confirmed:false};
    } catch(cause) {
      if(currentChange(target) && !(cause instanceof SessionEnded)) {
        target.error='尚未确认原提交结果。刷新记录可查看已保存历史，重试会使用原请求编号。';
      }
    } finally {
      pending.submitting=false;
      finishChangeRequest(target);
      if(changeState && changeState!==target && changeState.id===target.id) redrawChanges(changeState);
    }
  }

  async function downloadChange(target,id) {
    if(!currentChange(target) || target.busy || target.selected!==id ||
      !target.data?.records.some(row=>row.id===id)) return;
    target.busy='正在下载所选变更记录…'; target.error='';
    redrawChanges(target);
    try {
      const blob=await api(changePath(target)+'/'+id+'/handoff',{blob:true});
      if(!currentChange(target) || target.selected!==id) return;
      if(!/^text\/markdown(?:;|$)/i.test(blob.type)) throw new Error();
      saveReportFile(blob,'opsark-change-record.md');
    } catch(cause) {
      if(currentChange(target) && !(cause instanceof SessionEnded)) target.error='未能下载所选变更记录。';
    } finally { finishChangeRequest(target); }
  }

  function changeClaimLabel(claim) {
    if(claim.precision==='unknown') return '时间未知';
    if(claim.precision==='date') return claim.value+'（仅日期）';
    return claim.value.replace('+00:00','Z')+'（UTC）';
  }

  const recordedChangeTime=value=>value.replace('+00:00','Z')+'（UTC）';

  function changeField(label,input) {
    const field=node('label','field',label);
    field.append(input);
    return field;
  }

  function renderChangeDraft(section,target,busy) {
    const pending=pendingChanges.get(target.id);
    if(pending) {
      const {kind,claimed_at}=pending.payload;
      section.append(node('p','small','待确认的原陈述：'+changeKinds[kind]+' · '+changeClaimLabel(claimed_at)));
      if(pending.scope===target.scope) section.append(accessButton('重试原陈述',()=>{ void submitChange(target); },busy || pending.submitting));
      return;
    }
    const draft=target.draft;
    const kinds=node('select'),time=node('select');
    for(const [code,label] of Object.entries(changeKinds)) kinds.append(option(code,label));
    time.append(option('unknown','时间未知'),option('date','仅知道日期'),option('instant','知道 UTC 时刻'));
    kinds.value=draft.kind; time.value=draft.precision; kinds.disabled=time.disabled=busy;
    kinds.addEventListener('change',()=>{ if(currentChange(target)) draft.kind=kinds.value; });
    time.addEventListener('change',()=>{
      if(!currentChange(target)) return;
      draft.precision=time.value; draft.confirmed=false;
      redrawChanges(target);
      target.mount.querySelector('[data-change-time-precision]')?.focus();
    });
    time.dataset.changeTimePrecision='';
    section.append(changeField('变更类型',kinds),changeField('声明时间精度',time));
    if(draft.precision!=='unknown') {
      const instant=draft.precision==='instant',timeInput=node('input');
      const key=instant?'instant':'date';
      timeInput.type=instant?'datetime-local':'date'; timeInput.disabled=busy; timeInput.value=draft[key];
      if(instant) timeInput.step='1';
      timeInput.addEventListener('input',()=>{
        if(!currentChange(target)) return;
        draft[key]=timeInput.value;
        if(instant) { draft.confirmed=false; confirm.checked=false; confirm.disabled=!claimedInstant(timeInput.value); }
      });
      const confirm=node('input');
      if(instant) {
        confirm.type='checkbox'; confirm.checked=draft.confirmed; confirm.disabled=busy || !claimedInstant(draft.instant);
        confirm.addEventListener('change',()=>{ if(currentChange(target)) draft.confirmed=confirm.checked; });
        section.append(changeField('声明时刻（UTC）',timeInput),changeField('我确认填写的是 UTC 时刻',confirm));
      } else section.append(changeField('声明日期',timeInput));
    }
    section.append(accessButton('保存维护者陈述',()=>{ void submitChange(target); },busy));
  }

  function renderChangeRecords(panel,report) {
    if(!changeEnabled(report) || state.loadingReport || state.view!=='workspace') return;
    if(!sameReportTarget(changeState)) {
      const target={id:report.id,scope:report.scope_hash || null,hostId:report.host_id,source:report.source,
        session:state.session,selection:state.reportRequest,data:null,selected:'',busy:'',error:'',
        draft:{kind:'unknown',precision:'unknown',date:'',instant:'',confirmed:false}};
      changeState=target;
      queueMicrotask(()=>{ void readChangeHistory(target); });
    }
    const target=changeState;
    target.mount=node('div');
    panel.append(target.mount);
    redrawChanges(target);
  }

  function redrawChanges(target) {
    if(!currentChange(target) || !target.mount?.isConnected) return;
    const data=target.data,busy=Boolean(target.busy || state.busy);
    const section=node('section','baseline-section');
    section.setAttribute('aria-label','近期变更记录');
    section.append(sectionHeading('近期变更记录'));
    const status=node('p','small muted',target.busy); status.setAttribute('role','status');
    section.append(status,accessButton('刷新变更记录',()=>{ void readChangeHistory(target); },Boolean(target.busy)));
    if(target.error) {
      const alert=node('p','error',target.error); alert.setAttribute('role','alert'); section.append(alert);
    }
    if(data) {
      const operator=node('div','baseline-change');
      operator.append(node('h4','','维护者陈述'),node('p','small muted','此处记录维护者提供的线索，内容尚未核实。'));
      const selected=data.records.find(row=>row.id===target.selected);
      if(selected) {
        const picker=node('select'); picker.disabled=busy;
        for(const row of data.records) picker.append(option(row.id,changeKinds[row.kind]+' · '+recordedChangeTime(row.recorded_at)));
        picker.value=selected.id;
        picker.addEventListener('change',()=>{
          if(!currentChange(target)) return;
          target.selected=picker.value; redrawChanges(target);
          target.mount.querySelector('[data-change-record-picker]')?.focus();
        });
        picker.dataset.changeRecordPicker='';
        operator.append(changeField('所选陈述',picker),
          node('p','small','声明时间：'+changeClaimLabel(selected.claimed_at)),
          node('p','small muted','记录时间：'+recordedChangeTime(selected.recorded_at)),
          accessButton('下载所选变更记录',()=>{ void downloadChange(target,selected.id); },busy));
      } else operator.append(node('p','empty-note','还没有维护者陈述。'));
      if(data.can_record && (data.records.length<20 || pendingChanges.has(target.id))) renderChangeDraft(operator,target,busy);
      else if(data.can_record) operator.append(node('p','small muted','此报告已保存 20 条陈述。'));
      else operator.append(node('p','small muted','当前条件不支持新增陈述。'));
      const observation=node('div','baseline-change');
      observation.append(node('h4','','可核实观测'),node('p','small',changeBaselines[data.observation.baseline_status]));
      const {current_at,changes}=data.observation;
      observation.append(node('p','small',current_at ?
        '本报告最近可核实观测：'+recordedChangeTime(current_at) : '本报告没有可核实的观测时点。'));
      if(changes.length) {
        const intervals=node('ul','small');
        for(const item of changes) intervals.append(node('li','',changeFields[item.field]+'发生变化：('+recordedChangeTime(item.from_at)+'，'+recordedChangeTime(item.to_at)+']'));
        observation.append(intervals);
      } else observation.append(node('p','small muted','没有可核实的变更区间，此前变更无法从本报告追溯。'));
      observation.append(node('p','small muted','实际变更时刻、部署来源和操作者均未知。'));
      section.append(operator,observation);
    }
    target.mount.replaceChildren(section);
  }

  function renderAI(panel) {
    const report=state.report;
    const explanation=report.ai || {status:'not_requested'};
    const section=node('section','ai-section'); section.append(sectionHeading('AI 补充解释'));
    if(explanation.status==='completed') {
      section.append(node('p','small muted','模型：'+(explanation.model || '未记录')+' · 补充解释，不覆盖上方诊断事实'));
      section.append(node('p','ai-copy',explanation.text));
      if(explanation.evidence_ids?.length) { const references=node('div','finding-references'); explanation.evidence_ids.forEach(id=>references.append(evidenceReference(id))); section.append(references); }
    } else if(explanation.status==='failed') {
      section.append(node('p','small error',explanation.text || '上一次模型解释未完成，诊断报告仍然保留。'));
    } else if(!state.capabilities?.model_configured || explanation.status==='disabled') {
      section.append(node('p','muted','AI 解释未配置。当前报告来自诊断规则与采集证据，没有调用模型。'));
    } else {
      section.append(node('p','muted','尚未请求模型解释。只有主动确认后，才会发送脱敏摘要。'));
    }
    if(state.capabilities?.model_configured) {
      const button=node('button','button',state.aiBusy?'模型正在解释…':explanation.status==='completed'?'重新请求 AI 解释':'请求 AI 解释'); button.type='button'; button.disabled=state.aiBusy; button.id='request-ai'; button.addEventListener('click',openAIDialog); section.append(button);
    }
    panel.append(section);
  }

  function renderCompatibility(panel) {
    const report=state.report,assessment=report.compatibility || {};
    const status=Object.hasOwn(compatibilityStatuses,assessment.status)?assessment.status:'unknown';
    const section=node('section','compatibility-section'); section.id='compatibility-section';
    const heading=sectionHeading('目标环境与适配条件');
    heading.append(node('span','badge '+(status==='unsupported'?'red':status==='unknown'?'amber':'neutral'),compatibilityStatuses[status]));
    section.append(heading,node('p','boundary-detail',assessment.detail || '旧报告未包含环境预检，请重新调查后查看。'));
    section.append(detailList([['系统标识',assessment.os_id || '未取得'],['系统版本',assessment.version_id || '未取得'],['处理器架构',assessment.architecture || '未取得'],['采集适配器',assessment.adapter || '未确定']]));
    const available=Array.isArray(assessment.available_tools)?assessment.available_tools:[];
    const missing=Array.isArray(assessment.missing_tools)?assessment.missing_tools:[];
    if(available.length) section.append(node('p','small muted','已发现工具：'+available.join('、')));
    if(missing.length) section.append(node('p','notice','工具缺口：'+missing.join('、')+'。相关检查不能据此视为完成。'));
    else if(status==='unknown') section.append(node('p','small muted','尚未取得完整工具探测结果，工具可用性未知。'));
    if(Array.isArray(assessment.evidence_ids) && assessment.evidence_ids.length) {
      const references=node('div','finding-references'); assessment.evidence_ids.forEach(id=>references.append(evidenceReference(id))); section.append(references);
    }
    section.append(node('p','small muted',report.source==='replay'?'此预检来自合成样本，不代表实际服务器的平台验证。':'预检只判断本次采集的适配条件，不代表该系统版本已完成故障实验或所有组件均受支持。'));
    panel.append(section);
  }

  function renderDiskLocalLocator(details,evidence,report) {
    if(report.source!=='ssh' || evidence.check_id!=='disk_reclaim' || evidence.status!=='ok' || evidence.exit_code!==0 || evidence.truncated || report.ai_egress_block_reason) return;
    let value; try { value=JSON.parse(evidence.output); } catch { return; }
    const hash=item=>typeof item==='string' && /^[0-9a-f]{64}$/.test(item);
    const keys=['schema','scope_digest','snapshot_atomic','holder_coverage','filesystem_coverage','physical_reclaim_verified','immediate_reclaimable_bytes','conditional_lower_bytes','conditional_log_upper_bytes','objects','actions_enabled','snapshot_digest'];
    if(!value || Object.keys(value).sort().join(',')!==keys.sort().join(',') || value.schema!=='opsark-disk-reclaim/v1' || value.actions_enabled!==false || !hash(value.scope_digest) || !hash(value.snapshot_digest) || value.scope_digest!==report.target?.disk_reclaim_scope_digest || !Array.isArray(value.objects) || value.objects.length>32 || value.objects.some(item=>!item || !hash(item.object_ref)) || new Set(value.objects.map(item=>item.object_ref)).size!==value.objects.length) return;
    const section=node('section','next-steps'); section.dataset.diskLocalLocator='';
    section.append(node('h3','','在目标机本地定位证据对象'),node('p','small muted','仅目标机 root 管理员在本地终端运行。命令重新核对范围与整份快照，只返回本地路径/PID；不要上传定位结果。页面不会执行命令，业务数据仍排除清理。快照已变时重新调查，不能删去核验参数。'));
    for(const item of value.objects) {
      const label=node('label','field'); label.append(node('span','mono',item.object_ref));
      const input=node('input','mono'); input.type='text'; input.readOnly=true; input.dataset.diskLocateCommand=''; input.setAttribute('aria-label','仅供目标机管理员本地定位的只读命令');
      input.value='/usr/local/libexec/opsark-disk-reclaim --locate-ref '+item.object_ref+' --expected-scope-sha256 '+value.scope_digest+' --expected-snapshot-sha256 '+value.snapshot_digest;
      const select=node('button','text-button','选中本地定位命令'); select.type='button'; select.addEventListener('click',()=>{input.focus();input.select();});
      label.append(input,select); section.append(label);
    }
    if(value.objects.length) details.append(section);
  }

  function renderNginxErrorWindow(panel,value) {
    const summary=node('section','baseline-section');
    summary.setAttribute('aria-label','Nginx 错误日志窗口');
    summary.append(sectionHeading('Nginx 错误日志窗口'));
    const labels={observed:'已取得窗口摘要',permission_denied:'权限不足',source_missing:'日志文件缺失',inconclusive:'证据不足'};
    const reasons={
      coverage_unconfirmed:'无法确认取样覆盖最近 15 分钟，未取得完整窗口摘要。',
      source_untrusted:'无法核实登记日志来源。',
      source_changed:'采集期间日志来源发生变化。',
      clock_unconfirmed:'无法核对日志时间窗口。',
      read_unconfirmed:'未能完整读取本次窗口。',
    };
    const keys=['status','reason','observed_at','window_seconds','matching_refused','matching_timeout'];
    const count=number=>Number.isSafeInteger(number) && number>=0;
    const valid=value && typeof value==='object' && !Array.isArray(value) &&
      Object.keys(value).length===keys.length && keys.every(key=>Object.hasOwn(value,key)) &&
      typeof value.status==='string' && Object.hasOwn(labels,value.status) && value.window_seconds===900 &&
      typeof value.observed_at==='string' &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(value.observed_at) &&
      Number.isFinite(Date.parse(value.observed_at)) &&
      (value.status==='observed' ? value.reason===null && count(value.matching_refused) && count(value.matching_timeout) &&
        value.matching_refused+value.matching_timeout<=512 :
        value.matching_refused===null && value.matching_timeout===null &&
        (value.status==='inconclusive' ? typeof value.reason==='string' && Object.hasOwn(reasons,value.reason) : value.reason===null));
    if(!valid) {
      summary.append(node('p','notice neutral','日志窗口摘要无法核实。'));
      panel.append(summary);
      return;
    }
    const time=node('time','small muted','采集时点：'+dateLabel(value.observed_at));
    time.dateTime=value.observed_at;
    summary.append(node('p','badge '+(value.status==='observed'?'neutral':'amber'),labels[value.status]),time);
    if(value.status==='observed') {
      const result=value.matching_refused || value.matching_timeout ?
        '最近 15 分钟识别到的登记站点上游事件：拒绝连接 '+value.matching_refused+' 次，超时 '+value.matching_timeout+' 次。' :
        '最近 15 分钟未观察到可识别的登记站点上游拒绝连接或超时事件。';
      summary.append(node('p','small',result));
    } else if(value.status==='inconclusive') {
      summary.append(node('p','small',reasons[value.reason]));
    }
    summary.append(node('p','small muted','网站健康需要单独核验。'));
    panel.append(summary);
  }

  function renderPanel() {
    const report=state.report, panel=$('report-panel'); clear(panel);
    if(!report) return;
    if(state.tab==='diagnosis') {
      const summary=node('div','summary-block'); summary.append(node('p','eyebrow','RULE-BASED FINDINGS / 可复核诊断'),node('h3','',report.summary)); panel.append(summary);
      if(report.source==='replay') panel.append(node('p','notice neutral','本报告由合成样本经实际诊断规则生成。证据的读取时间不是目标服务器的真实采集时间。'));
      panel.append(sectionHeading('已记录的事实',report.facts?.length || 0),findingList(report.facts,'目前没有足够的可引用事实。'));
      panel.append(sectionHeading('候选原因',report.candidates?.length || 0),findingList(report.candidates,'本次没有形成可支持的候选原因。'));
      renderBaseline(panel);
      renderChangeRecords(panel,report);
      panel.append(sectionHeading('缺失信息与判断边界'),plainList(report.missing,'本报告没有列出额外缺口；这不代表完整业务或系统已通过验收。'));
      const next=node('div','next-steps'); next.append(sectionHeading('下一步检查建议'),plainList(report.next_steps,'当前没有额外建议。')); panel.append(next);
      renderAI(panel);
    } else if(state.tab==='evidence') {
      panel.append(node('p','notice neutral',report.source==='replay'?'来源：样本回放（合成数据）。以下内容来自预置检查样本，不是当前真实服务器日志。':'来源：SSH 采集。失败、截断与权限缺口会分别标记；未取得内容不表示目标健康。'));
      const nginxWindow=report.nginx_error_window;
      const hasNginxWindow=nginxWindow!==undefined && nginxWindow!==null;
      const evidenceRows=report.evidence || [];
      if(hasNginxWindow && !evidenceRows.some(row=>row.check_id==='nginx_errors')) renderNginxErrorWindow(panel,nginxWindow);
      panel.append(sectionHeading('证据记录',evidenceRows.length));
      if(!evidenceRows.length && !hasNginxWindow) panel.append(node('p','empty-note','没有可展示的证据记录。'));
      for(const evidence of evidenceRows) {
        const details=node('details','evidence-entry'); details.dataset.evidenceId=evidence.id;
        const summary=node('summary'); summary.append(node('span','mono',evidence.id),node('span','',evidence.check_id));
        const meta=node('div','evidence-meta'); meta.append(node('span','badge '+(evidence.status==='ok'?'neutral':'amber'),checkStatuses[evidence.status] || evidence.status));
        meta.append(node('span','',evidence.target),node('span','',sourceLabel(evidence.source)),node('span','',(evidence.source==='replay'?'读取时间：':'采集时间：')+dateLabel(evidence.collected_at)));
        if(evidence.exit_code!==null && evidence.exit_code!==undefined) meta.append(node('span','mono','exit '+evidence.exit_code));
        if(evidence.truncated) meta.append(node('span','badge amber','输出已截断'));
        details.append(summary,meta);
        if(hasNginxWindow && evidence.check_id==='nginx_errors') {
          details.open=true;
          renderNginxErrorWindow(details,nginxWindow);
        } else {
          details.append(node('pre','evidence-output',evidence.output || '（没有返回输出，请结合检查状态判断。）'));
          renderDiskLocalLocator(details,evidence,report);
        }
        panel.append(details);
      }
    } else if(state.tab==='boundary') {
      const heading=node('div','boundary-title'); heading.append(node('h3','','此调查仅采集与记录'),node('span','badge neutral','调查不执行修改')); panel.append(heading);
      panel.append(node('div','notice',report.action?.reason || '当前版本不提供修复或封禁执行接口。'));
      panel.append(node('p','boundary-detail','本次调查不会修改配置、重启或停止容器，也不会新增封禁。安全事件仅观察并记录；既有外部防护的动作需要独立标明执行归属。'));
      renderCompatibility(panel);
      panel.append(sectionHeading('建议与执行分别处理'),plainList(report.next_steps,'没有额外建议。'));
      panel.append(node('p','small muted','后续版本的动作需要目标、当前配置、依赖影响、授权和回退条件共同满足。模型解释不会扩大权限。'));
    } else {
      const immediate=(report.verification || []).some(check=>['passed','failed','error'].includes(check.status));
      panel.append(node('div','notice neutral',immediate?'本次包含已登记站点的即时检查结果。即时检查符合不等于服务恢复；修复、防御处置与完整恢复验收仍未执行。':'尚未取得已登记站点的即时检查结果。诊断完成不等于服务恢复，未配置或未覆盖项目仍保留原状态。'));
      if(report.source==='replay') panel.append(node('p','small muted','以下即时检查结果来自合成样本，不是真实网站探测。'));
      panel.append(sectionHeading('即时站点结果与恢复验收覆盖'));
      if(!report.verification?.length) panel.append(node('p','empty-note','尚未配置或运行本次业务验收；恢复状态未知。'));
      for(const check of report.verification || []) {
        const row=node('div','check-row'),description=node('div'); description.append(node('strong','',check.name),node('p','',check.detail));
        if(check.evidence_ids?.length) { const references=node('div','finding-references'); check.evidence_ids.forEach(id=>references.append(evidenceReference(id))); description.append(references); }
        const color=check.status==='passed'?'green':check.status==='failed'?'red':check.status==='error'?'amber':'neutral';
        row.append(description,node('span','badge '+color,verificationStatuses[check.status] || '状态未知')); panel.append(row);
      }
      panel.append(node('p','small muted','无业务写入的检查、正常访问影响与持续观察需要各自记录证据。未验证的登录、下单、支付和回调不能被报告为恢复。'));
      renderAccessRechecks(panel, report);
      renderContainerReportRechecks(panel, report);
    }
  }

  function detailList(pairs) {
    const list=node('dl','detail-list'); pairs.forEach(([label,value])=>list.append(node('dt','',label),node('dd','',value))); return list;
  }

  const hostPreflightStatuses={ready:'预检通过',needs_attention:'需要核对',unreachable:'SSH 连接未建立',unsupported:'平台超出适配范围'};
  const hostPreflightConnections={ok:'连接成功',error:'连接失败',permission_denied:'认证或权限未通过',timeout:'连接超时'};
  const hostPreflightChecks={os_release:'系统识别',platform_tools:'架构与工具',nginx_status:'Nginx 服务',container_state:'登记容器状态',disk_bytes:'根分区容量读取',disk_inodes:'根分区 inode 读取',compose_version:'Compose v2 插件',docker_rootful:'本地 rootful Docker 引擎'};
  const hostPreflightReasons={plugin_unavailable:'当前 CLI 未识别 Compose 子命令',unsupported_version:'插件版本不在 Compose v2 范围',rootless_unsupported:'检测到 rootless，引擎超出首版范围',engine_unsupported:'引擎不是支持的 Linux 模式',invalid_output:'未取得完整可信的固定格式输出',output_truncated:'输出已截断，不能据此确认能力',permission_denied:'账号或固定策略权限不足',timeout:'检查超时，能力未确认',probe_unavailable:'工具或固定探针未就绪',probe_failed:'固定能力探针未通过，原因未确认',policy_refused:'受限入口拒绝固定命令，请核对策略和权限',registration_unconfirmed:'容器登记尚未确认，未读取容器状态或日志'};
  const hostPreflightCheckStatuses={...checkStatuses,inactive:'未处于运行状态'};
  const hostPreflightFamilies={ubuntu:'Ubuntu',debian:'Debian'};

  function renderHostPreflight(result, hostId, payload) {
    if(!payload || payload.host_id!==hostId || !Object.hasOwn(hostPreflightStatuses,payload.status) ||
      !Object.hasOwn(hostPreflightConnections,payload.connection) || !Object.hasOwn(compatibilityStatuses,payload.platform) ||
      (payload.os_family!==null && !Object.hasOwn(hostPreflightFamilies,payload.os_family)) ||
      ![null,'x86_64','aarch64'].includes(payload.architecture) ||
      !Array.isArray(payload.missing_tools) || !payload.missing_tools.every(tool=>typeof tool==='string' && /^[a-z0-9_-]{1,32}$/.test(tool)) ||
      !Array.isArray(payload.checks) || !payload.checks.every(check=>check && Object.hasOwn(hostPreflightChecks,check.id) && Object.hasOwn(hostPreflightCheckStatuses,check.status) && (check.reason===undefined || check.reason===null || Object.hasOwn(hostPreflightReasons,check.reason))) ||
      new Set(payload.checks.map(check=>check.id)).size!==payload.checks.length ||
      typeof payload.checked_at!=='string' || !Number.isFinite(Date.parse(payload.checked_at)) ||
      !Number.isSafeInteger(payload.duration_ms) || payload.duration_ms<0) throw new Error();
    if(payload.status==='ready' && (payload.connection!=='ok' || payload.platform!=='compatible' || !payload.os_family || !payload.architecture ||
      payload.missing_tools.length || payload.checks.length!==Object.keys(hostPreflightChecks).length || payload.checks.some(check=>check.status!=='ok' || (check.reason!==undefined && check.reason!==null)))) throw new Error();

    const advice={
      ready:'可发起只读调查，继续核对具体故障或服务表现。',
      needs_attention:'请按检查结果核对工具、组件或采集账号权限，再运行预检。',
      unreachable:payload.connection==='permission_denied'?'请核对登记账号和密钥授权，再运行预检。':'请核对 SSH 地址、端口、网络可达性和可信主机记录，再运行预检。',
      unsupported:'当前适配 Ubuntu / Debian 和 x86_64 / aarch64，请核对登记目标的平台。'
    };
    const missing=payload.missing_tools.length?payload.missing_tools.join('、'):payload.platform==='compatible'?'本次未发现缺失':'未取得完整信息';
    const details=detailList([
      ['SSH',hostPreflightConnections[payload.connection]], ['平台',compatibilityStatuses[payload.platform]],
      ['系统与架构',(hostPreflightFamilies[payload.os_family] || '未确认')+' / '+(payload.architecture || '未确认')], ['缺少工具',missing]
    ]);
    const content=[node('strong','badge '+(payload.status==='ready'?'green':'amber'),hostPreflightStatuses[payload.status]),details];
    if(payload.checks.length) {
      const checks=node('ul','host-preflight-checks');
      for(const check of payload.checks) {
        const item=node('li','check-row'); item.dataset.checkId=check.id;
        const running=check.status==='ok' && (check.id==='nginx_status' || check.id==='container_state');
        const copy=node('div'); copy.append(node('strong','',hostPreflightChecks[check.id]));
        if(check.reason) copy.append(node('p','small muted',hostPreflightReasons[check.reason]));
        item.append(copy,node('span','badge '+(check.status==='ok'?'neutral':'amber'),running?'运行中':hostPreflightCheckStatuses[check.status])); checks.append(item);
      }
      content.push(checks);
    }
    content.push(node('p','small muted',dateLabel(payload.checked_at)+' · 耗时 '+(payload.duration_ms/1000).toFixed(2)+' 秒'),node('p','small',advice[payload.status]));
    result.replaceChildren(...content); result.dataset.status=payload.status;
  }

  async function runHostPreflight(hostId, button, result) {
    if(!state.token || state.capabilities?.host_preflight!==true || button.disabled || !button.isConnected) return;
    const session=state.session;
    const isCurrent=()=>session===state.session && result.isConnected;
    button.disabled=true; button.textContent='正在预检…';
    delete result.dataset.status;
    result.replaceChildren(node('p','small muted','正在检查登记目标的 SSH、平台和组件。'));
    try {
      const payload=await api('/api/hosts/'+encodeURIComponent(hostId)+'/preflight',{method:'POST',body:{}});
      if(isCurrent()) renderHostPreflight(result,hostId,payload);
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && isCurrent()) {
        const detail=cause.status===409?'已有只读检查正在运行，请稍后重试。':'未能取得此主机的预检结果，请稍后重试。';
        result.replaceChildren(node('p','error',detail));
      }
    } finally {
      if(isCurrent()) { button.disabled=false; button.textContent='运行接入预检'; }
    }
  }

  const businessReadinessStatuses={
    passed:{label:'业务检查通过',color:'green'},
    failed:{label:'业务检查未通过',color:'red'},
    inconclusive:{label:'证据不足',color:'amber'},
    uncovered:{label:'未覆盖',color:'neutral'}
  };

  const accessExternal={unavailable:'未取得机外证据',matched:'机外观察符合预期',unreachable:'机外无法访问'};
  const accessVerdicts={accepted:'复验通过',failed:'复验未通过',pending:'待验收'};
  const accessManagement={verified:'已取得认证只读响应',unavailable:'未取得认证只读响应'};
  const accessChecks={passed:'通过',failed:'未通过',inconclusive:'证据不足',uncovered:'未覆盖'};
  const accessId=/^ar-[a-f0-9]{32}$/;
  const accessTime=value=>typeof value==='string' &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value));
  const accessObject=(row,keys)=>row && typeof row==='object' && !Array.isArray(row) &&
    Object.keys(row).length===keys.length && keys.every(key=>Object.hasOwn(row,key));
  function accessEligible(report) {
    const evidence=report?.evidence;
    return state.capabilities?.access_rechecks===true && state.view==='workspace' && state.tab==='verification' &&
      !state.loadingReport && report?.source==='ssh' && report.scenario==='web_502' && report.status==='inconclusive' &&
      typeof report.id==='string' && /^[A-Za-z0-9_-]{1,80}$/.test(report.id) &&
      Array.isArray(evidence) && evidence.length===1 && evidence[0]?.source==='ssh' &&
      evidence[0].check_id==='connection' && evidence[0].exit_code===null &&
      ['error','timeout','permission_denied'].includes(evidence[0].status);
  }

  function checkedAccessRow(row,reportId) {
    if(!accessObject(row,['id','report_id','finished_at','management','external','checks','status']) ||
      typeof row.id!=='string' || !accessId.test(row.id) || row.report_id!==reportId || !accessTime(row.finished_at) ||
      typeof row.management!=='string' || !Object.hasOwn(accessManagement,row.management) ||
      typeof row.external!=='string' || !Object.hasOwn(accessExternal,row.external) ||
      !Array.isArray(row.checks) || row.checks.length<1 || row.checks.length>3 ||
      row.checks.some(check=>!accessObject(check,['id','status']) || typeof check.id!=='string' ||
        !/^[a-z][a-z0-9_]{0,39}$/.test(check.id) || typeof check.status!=='string' ||
        !Object.hasOwn(accessChecks,check.status)) || new Set(row.checks.map(check=>check.id)).size!==row.checks.length ||
      (row.management==='unavailable' && row.checks.some(check=>['passed','failed'].includes(check.status)))) throw new Error();
    const status=row.external==='unreachable' || row.checks.some(check=>check.status==='failed') ? 'failed' :
      row.management==='verified' && row.external==='matched' && row.checks.every(check=>check.status==='passed') ? 'accepted' : 'pending';
    if(row.status!==status) throw new Error();
    return row;
  }

  function accessPath(target) {
    return '/api/reports/'+encodeURIComponent(target.id)+'/access-rechecks';
  }

  function currentAccess(target) {
    return accessState===target && Boolean(state.token) && sameReportTarget(target) && accessEligible(state.report);
  }

  async function fetchAccessHistory(target) {
    if(!currentAccess(target) || target.busy) return;
    target.busy='history'; target.error='';
    renderPanel();
    try {
      const data=await api(accessPath(target));
      if(!currentAccess(target)) return;
      if(!accessObject(data,['report_id','can_run','last_evidence_at','rechecks']) ||
        data.report_id!==target.id || typeof data.can_run!=='boolean' ||
        (data.last_evidence_at!==null && !accessTime(data.last_evidence_at)) ||
        !Array.isArray(data.rechecks) || data.rechecks.length>20) throw new Error();
      const rows=data.rechecks.map(row=>checkedAccessRow(row,target.id));
      if(new Set(rows.map(row=>row.id)).size!==rows.length) throw new Error();
      target.rows=rows;
      target.lastEvidenceAt=data.last_evidence_at;
      if(!rows.some(row=>row.id===target.selected)) target.selected=rows[0]?.id || '';
      target.canRun=data.can_run;
    } catch(cause) {
      if(currentAccess(target) && !(cause instanceof SessionEnded)) {
        target.canRun=null;
        target.error='未能核实复验历史，请刷新后重试。';
      }
    } finally {
      if(accessState===target) {
        target.busy='';
        if(currentAccess(target)) renderPanel();
      }
    }
  }

  async function submitAccessRecheck(target) {
    if(!currentAccess(target) || target.canRun!==true || target.busy || state.busy ||
      !Object.hasOwn(accessExternal,target.external)) return;
    const external=target.external;
    target.busy='recheck'; target.error='';
    renderPanel();
    try {
      const row=checkedAccessRow(await api(accessPath(target),{method:'POST',body:{external}}),target.id);
      if(!currentAccess(target)) return;
      if(row.external!==external || target.rows.some(previous=>previous.id===row.id)) throw new Error();
      target.rows=[row,...target.rows].slice(0,20);
      target.selected=row.id;
      target.external='unavailable';
    } catch(cause) {
      if(currentAccess(target) && !(cause instanceof SessionEnded)) {
        target.canRun=null;
        target.error='未能确认本次复验。请先刷新历史，确认是否已记录。';
      }
    } finally {
      if(accessState===target) {
        if(!currentAccess(target)) target.canRun=null;
        target.busy='';
        if(currentAccess(target)) renderPanel();
      }
    }
  }

  async function downloadAccessRecheck(target,id) {
    if(!currentAccess(target) || target.busy || target.selected!==id ||
      !target.rows.some(row=>row.id===id)) return;
    target.busy='download'; target.error='';
    renderPanel();
    try {
      const blob=await api(accessPath(target)+'/'+id+'/handoff',{blob:true});
      if(!currentAccess(target) || target.selected!==id) return;
      if(!/^text\/markdown(?:;|$)/i.test(blob.type)) throw new Error();
      saveReportFile(blob,'opsark-access-recheck.md');
      announce('所选失联复验摘要已下载。');
    } catch(cause) {
      if(currentAccess(target) && !(cause instanceof SessionEnded)) target.error='未能下载所选复验摘要。';
    } finally {
      if(accessState===target) {
        target.busy='';
        if(currentAccess(target)) renderPanel();
      }
    }
  }

  function accessButton(label,callback,disabled=false) {
    const button=node('button','button',label);
    button.type='button'; button.disabled=disabled;
    button.addEventListener('click',callback);
    return button;
  }

  function renderAccessRechecks(panel,report) {
    if(!accessEligible(report)) return;
    if(!sameReportTarget(accessState)) {
      accessState={id:report.id,scope:report.scope_hash || null,hostId:report.host_id,source:report.source,
        session:state.session,selection:state.reportRequest,rows:[],selected:'',lastEvidenceAt:null,
        canRun:null,external:'unavailable',busy:'',error:''};
      const target=accessState;
      queueMicrotask(()=>{ void fetchAccessHistory(target); });
    }
    const target=accessState,busy=Boolean(target.busy);
    const section=node('section','baseline-section');
    section.setAttribute('aria-label','SSH 失联复验');
    const status=node('p','small muted',({history:'正在读取复验历史…',recheck:'正在运行只读复验…',
      download:'正在下载所选复验摘要…'})[target.busy] || '');
    status.setAttribute('role','status');
    section.append(sectionHeading('SSH 失联复验'),status);
    if(target.lastEvidenceAt) section.append(node('p','small muted','失联前最近可比证据：'+dateLabel(target.lastEvidenceAt)+'（历史记录）'));
    else if(target.canRun!==null) section.append(node('p','small muted','未找到失联前的可比证据。'));
    const refresh=accessButton('刷新复验历史',()=>{ void fetchAccessHistory(target); },busy);
    section.append(refresh);
    if(target.canRun===true) {
      const external=node('select');
      external.disabled=busy;
      for(const [value,label] of Object.entries(accessExternal)) external.append(option(value,label));
      external.value=target.external;
      external.addEventListener('change',()=>{ if(currentAccess(target)) target.external=external.value; });
      const field=node('label','field','机外观察（人工记录）');
      field.append(external);
      section.append(field,accessButton('运行只读失联复验',()=>{ void submitAccessRecheck(target); },busy || state.busy));
    } else if(target.canRun===false) {
      section.append(node('p','small muted','当前登记条件不支持重新复验，仍可查看已有记录。'));
    }
    if(target.error) {
      const alert=node('p','error',target.error); alert.setAttribute('role','alert'); section.append(alert);
    }
    const selected=target.rows.find(row=>row.id===target.selected);
    if(selected) {
      const picker=node('select'); picker.disabled=busy;
      for(const row of target.rows) picker.append(option(row.id,dateLabel(row.finished_at)+' · '+accessVerdicts[row.status]));
      picker.value=selected.id;
      picker.addEventListener('change',()=>{
        if(!currentAccess(target)) return;
        target.selected=picker.value;
        renderPanel();
        panel.querySelector('[data-access-history-picker]')?.focus();
      });
      picker.dataset.accessHistoryPicker='';
      const field=node('label','field','复验快照'); field.append(picker);
      const details=node('div','check-row');
      const summary=node('div');
      summary.append(node('strong','',accessVerdicts[selected.status]),
        node('p','small muted','观测时间：'+dateLabel(selected.finished_at)),
        node('p','small','管理连接：'+accessManagement[selected.management]),
        node('p','small','机外观察（人工记录）：'+accessExternal[selected.external]));
      const checks=node('ul','small');
      for(const check of selected.checks) checks.append(node('li','',check.id+' · '+accessChecks[check.status]));
      details.append(summary,checks);
      section.append(field,details,accessButton('下载所选复验摘要',()=>{ void downloadAccessRecheck(target,selected.id); },busy));
    } else if(target.canRun!==null) {
      section.append(node('p','empty-note','还没有失联复验记录。'));
    }
    panel.append(section);
  }

  const containerReportRecheckId=/^rr-[a-f0-9]{32}$/;
  const containerReportRecheckLabels={passed:'复验通过',failed:'复验未通过',pending:'待验收'};
  const containerReportRecheckPath=target=>'/api/reports/'+encodeURIComponent(target.id)+'/container-rechecks';
  const containerReportRecheckEligible=report=>state.capabilities?.container_report_rechecks===true &&
    state.view==='workspace' && state.tab==='verification' && !state.loadingReport &&
    report?.source==='ssh' && report.scenario==='container_restart' &&
    typeof report.id==='string' && /^[A-Za-z0-9_-]{1,80}$/.test(report.id);
  const containerReportRecheckCurrent=target=>containerReportRecheck===target && Boolean(state.token) &&
    sameReportTarget(target) && containerReportRecheckEligible(state.report);

  function checkedContainerReportRecheck(row,reportId) {
    if(!accessObject(row,['id','report_id','finished_at','management','checks','status']) ||
      typeof row.id!=='string' || !containerReportRecheckId.test(row.id) || row.report_id!==reportId ||
      !changeUtc(row.finished_at) || !['verified','unavailable'].includes(row.management) ||
      !Array.isArray(row.checks) || row.checks.length<1 || row.checks.length>3 ||
      row.checks.some(value=>!changeLabel(accessChecks,value))) throw new Error();
    const status=row.checks.includes('failed') ? 'failed' :
      row.management==='verified' && row.checks.every(check=>check==='passed') ? 'passed' : 'pending';
    if(row.status!==status || (row.management==='unavailable' &&
      row.checks.some(check=>check==='passed' || check==='failed'))) throw new Error();
    return row;
  }

  function finishContainerReportRecheck(target) {
    target.busy='';
    redrawContainerReportRecheck(target);
  }

  async function readContainerReportRechecks(target) {
    if(!containerReportRecheckCurrent(target) || target.busy) return;
    target.busy='正在读取容器调查复验历史…'; target.error='';
    redrawContainerReportRecheck(target);
    try {
      const data=await api(containerReportRecheckPath(target));
      if(!containerReportRecheckCurrent(target)) return;
      if(!accessObject(data,['report_id','can_run','rechecks']) || data.report_id!==target.id ||
        typeof data.can_run!=='boolean' || !Array.isArray(data.rechecks) || data.rechecks.length>20) throw new Error();
      const rows=data.rechecks.map(row=>checkedContainerReportRecheck(row,target.id));
      if(new Set(rows.map(row=>row.id)).size!==rows.length) throw new Error();
      target.rows=rows; target.canRun=data.can_run;
      if(!rows.some(row=>row.id===target.selected)) target.selected=rows[0]?.id || '';
    } catch(cause) {
      if(containerReportRecheckCurrent(target) && !(cause instanceof SessionEnded)) {
        target.canRun=null;
        target.error='未能核实复验历史，请刷新后重试。';
      }
    } finally { finishContainerReportRecheck(target); }
  }

  async function submitContainerReportRecheck(target) {
    if(!containerReportRecheckCurrent(target) || target.canRun===null || target.busy || state.busy) return;
    const previous=pendingContainerRechecks.get(target.id);
    if((!previous && (!target.canRun || target.rows.length>=20)) ||
      (previous && (previous.scope!==target.scope || previous.submitting))) return;
    const pending=previous || {scope:target.scope,requestId:newReportRequestId()};
    pending.submitting=true;
    pendingContainerRechecks.set(target.id,pending);
    target.busy='正在运行容器调查只读复验…'; target.error='';
    redrawContainerReportRecheck(target);
    try {
      const row=checkedContainerReportRecheck(await api(containerReportRecheckPath(target),
        {method:'POST',body:{request_id:pending.requestId}}),target.id);
      if(pendingContainerRechecks.get(target.id)!==pending || !containerReportRecheckCurrent(target)) return;
      const recorded=target.rows.find(item=>item.id===row.id);
      if(recorded && (recorded.status!==row.status || recorded.management!==row.management ||
        recorded.checks.join()!==row.checks.join() ||
        changeTimeKey(recorded.finished_at)!==changeTimeKey(row.finished_at))) throw new Error();
      pendingContainerRechecks.delete(target.id);
      if(!recorded) {
        const order=item=>changeTimeKey(item.finished_at)+item.id;
        target.rows=[row,...target.rows].sort((left,right)=>order(right).localeCompare(order(left))).slice(0,20);
      }
      target.selected=row.id;
    } catch(cause) {
      if(containerReportRecheckCurrent(target) && !(cause instanceof SessionEnded)) {
        target.error='尚未确认原复验结果。请刷新历史，重试会使用原请求编号。';
      }
    } finally {
      pending.submitting=false;
      finishContainerReportRecheck(target);
      if(containerReportRecheck!==target && containerReportRecheck?.id===target.id) {
        redrawContainerReportRecheck(containerReportRecheck);
      }
    }
  }

  async function downloadContainerReportRecheck(target,id) {
    if(!containerReportRecheckCurrent(target) || target.busy || target.selected!==id ||
      !target.rows.some(row=>row.id===id)) return;
    target.busy='正在下载所选复验摘要…'; target.error='';
    redrawContainerReportRecheck(target);
    try {
      const blob=await api(containerReportRecheckPath(target)+'/'+id+'/handoff',{blob:true});
      if(!containerReportRecheckCurrent(target) || target.selected!==id) return;
      if(!/^text\/markdown(?:;|$)/i.test(blob.type)) throw new Error();
      saveReportFile(blob,'opsark-container-recheck.md');
    } catch(cause) {
      if(containerReportRecheckCurrent(target) && !(cause instanceof SessionEnded)) {
        target.error='未能下载所选复验摘要。';
      }
    } finally { finishContainerReportRecheck(target); }
  }

  function renderContainerReportRechecks(panel,report) {
    if(!containerReportRecheckEligible(report)) return;
    if(!sameReportTarget(containerReportRecheck)) {
      const target={id:report.id,scope:report.scope_hash || null,hostId:report.host_id,source:report.source,
        session:state.session,selection:state.reportRequest,rows:[],selected:'',canRun:null,busy:'',error:''};
      containerReportRecheck=target;
      queueMicrotask(()=>{ void readContainerReportRechecks(target); });
    }
    const target=containerReportRecheck;
    target.mount=node('div');
    panel.append(target.mount);
    redrawContainerReportRecheck(target);
  }

  function redrawContainerReportRecheck(target) {
    if(!containerReportRecheckCurrent(target) || !target.mount?.isConnected) return;
    const section=node('section','baseline-section');
    section.setAttribute('aria-label','容器调查业务复验');
    const status=node('p','small muted',target.busy);
    status.setAttribute('role','status');
    const busy=Boolean(target.busy),pending=pendingContainerRechecks.get(target.id);
    section.append(sectionHeading('容器调查业务复验'),
      node('p','small muted','按原调查登记的范围运行只读业务检查。'),status,
      accessButton('刷新容器复验历史',()=>{ void readContainerReportRechecks(target); },busy));
    if(target.canRun!==null) {
      if(pending?.scope===target.scope) {
        section.append(accessButton('重试原容器复验',()=>{ void submitContainerReportRecheck(target); },
          busy || state.busy || pending.submitting));
      } else if(pending) section.append(node('p','small muted','原复验的报告范围已变化。请核对原报告和历史。'));
      else if(target.canRun && target.rows.length<20) {
        section.append(accessButton('运行容器调查只读复验',()=>{ void submitContainerReportRecheck(target); },busy || state.busy));
      }
      if(target.rows.length===20) section.append(node('p','small muted','此报告已保存 20 条复验。'));
      else if(!target.canRun) section.append(node('p','small muted','当前登记条件不支持新复验，仍可查看已有记录。'));
    }
    if(target.error) {
      const alert=node('p','error',target.error); alert.setAttribute('role','alert'); section.append(alert);
    }
    const selected=target.rows.find(row=>row.id===target.selected);
    if(selected) {
      const picker=node('select'); picker.disabled=busy;
      for(const row of target.rows) picker.append(option(row.id,dateLabel(row.finished_at)+' · '+containerReportRecheckLabels[row.status]));
      picker.value=selected.id;
      picker.dataset.containerReportRecheckPicker='';
      picker.addEventListener('change',()=>{
        if(!containerReportRecheckCurrent(target)) return;
        target.selected=picker.value;
        redrawContainerReportRecheck(target);
        target.mount.querySelector('[data-container-report-recheck-picker]')?.focus();
      });
      const summary=node('div','check-row');
      const detail=node('div');
      detail.append(node('strong','',containerReportRecheckLabels[selected.status]),
        node('p','small muted','观测时间：'+dateLabel(selected.finished_at)),
        node('p','small','管理连接：'+accessManagement[selected.management]));
      const checks=node('ol','small');
      for(const result of selected.checks) checks.append(node('li','',accessChecks[result]));
      summary.append(detail,checks);
      section.append(changeField('容器复验快照',picker),summary,
        accessButton('下载所选容器复验摘要',()=>{ void downloadContainerReportRecheck(target,selected.id); },busy));
    } else if(target.canRun!==null) section.append(node('p','empty-note','还没有容器调查复验记录。'));
    target.mount.replaceChildren(section);
  }

  function validBusinessCheck(check) {
    if(!check || typeof check.id!=='string' || !/^[a-z][a-z0-9_]{0,39}$/.test(check.id)) return false;
    const {status,http_status,status_matches,body_matches}=check;
    if(status==='uncovered' || status==='inconclusive') return http_status===null && status_matches===null && body_matches===null;
    if(!Number.isSafeInteger(http_status) || http_status<200 || http_status>599) return false;
    if(status==='passed') return status_matches===true && body_matches===true;
    return status==='failed' && ((status_matches===false && body_matches===null) || (status_matches===true && body_matches===false));
  }

  function renderBusinessReadiness(result, hostId, payload) {
    if(!payload || payload.host_id!==hostId || !Object.hasOwn(businessReadinessStatuses,payload.status) ||
      !Array.isArray(payload.checks) || payload.checks.length>3 || !payload.checks.every(validBusinessCheck) ||
      new Set(payload.checks.map(check=>check.id)).size!==payload.checks.length) throw new Error();

    const outcomes=new Set(payload.checks.map(check=>check.status));
    const status=['failed','inconclusive','uncovered'].find(value=>outcomes.has(value)) || (outcomes.has('passed')?'passed':'uncovered');
    if(status!==payload.status) throw new Error();

    const summary=businessReadinessStatuses[status];
    const content=[node('strong','badge '+summary.color,summary.label)];
    const checks=node('ul','host-preflight-checks');
    const matchLabel=value=>value===true?'匹配':value===false?'不匹配':'未确认';
    for(const check of payload.checks) {
      const {label,color}=businessReadinessStatuses[check.status];
      const row=node('li','check-row'); row.dataset.checkId=check.id;
      const detail=node('div');
      detail.append(node('strong','',check.id),node('p','small muted',
        'HTTP '+(check.http_status ?? '未取得')+' · 状态 '+matchLabel(check.status_matches)+' · 正文 '+matchLabel(check.body_matches)));
      row.append(detail,node('span','badge '+color,label)); checks.append(row);
    }
    if(payload.checks.length) content.push(checks);
    else content.push(node('p','small muted','当前主机没有登记业务检查。'));
    result.replaceChildren(...content); result.dataset.status=status;
  }

  async function runBusinessReadiness(hostId, button, result) {
    if(!state.token || state.capabilities?.business_readiness!==true || button.disabled || !button.isConnected) return;
    const session=state.session;
    const isCurrent=()=>session===state.session && result.isConnected;
    button.disabled=true; button.textContent='正在检查…';
    delete result.dataset.status;
    result.replaceChildren(node('p','small muted','正在运行登记的只读业务检查。'));
    try {
      const payload=await api('/api/hosts/'+encodeURIComponent(hostId)+'/business-readiness',{method:'POST',body:{}});
      if(isCurrent()) renderBusinessReadiness(result,hostId,payload);
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && isCurrent()) {
        const detail=cause.status===409?'已有只读检查正在运行，请稍后重试。':'未能取得此主机的业务检查结果，请稍后重试。';
        result.replaceChildren(node('p','error',detail));
      }
    } finally {
      if(isCurrent()) { button.disabled=false; button.textContent='运行只读业务检查'; }
    }
  }

  const sshDefenseStates={
    active:{label:'规则生效',color:'green'},expired:{label:'规则已到期',color:'neutral'},
    revoked:{label:'规则已撤销',color:'neutral'},unknown:{label:'状态未知',color:'amber'},
    unavailable:{label:'目标暂不可查询',color:'amber'}
  };

  function defenseActionId(value) {
    return typeof value==='string' && value.length===32 && /^[0-9a-f]+$/.test(value);
  }

  function defenseTime(value) {
    return typeof value==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
  }

  function defenseRemaining(status, value) {
    return status==='active'?Number.isSafeInteger(value) && value>=1 && value<=60000:value===null;
  }

  function validDefenseObservation(value) {
    return value===null || Boolean(value && ['active','expired','revoked'].includes(value.status) &&
      defenseRemaining(value.status,value.remaining_ms) && defenseTime(value.observed_at));
  }

  function defenseHistory(history, value) {
    history.textContent=value===null?'历史观察 · 尚无已确认记录':
      '历史观察 · '+dateLabel(value.observed_at)+' · 当时'+sshDefenseStates[value.status].label+
      (value.status==='active'?' · 当时剩余 '+value.remaining_ms+' 毫秒':'');
  }

  async function readDefenseStatus(hostId, actionId, button, result, history) {
    if(!state.token || state.capabilities?.ssh_defense_status!==true || button.disabled || !button.isConnected) return;
    const session=state.session;
    const isCurrent=()=>session===state.session && result.isConnected;
    button.disabled=true;
    delete result.dataset.status;
    result.replaceChildren(node('p','small muted','正在查询原动作状态…'));
    try {
      const path='/api/hosts/'+encodeURIComponent(hostId)+'/ssh-defense/actions/'+actionId+'/status';
      const payload=await api(path,{method:'POST',body:{}});
      if(!isCurrent()) return;
      if(!payload || payload.host_id!==hostId || payload.action_id!==actionId ||
        typeof payload.status!=='string' || !Object.hasOwn(sshDefenseStates,payload.status) || !defenseRemaining(payload.status,payload.remaining_ms) ||
        !defenseTime(payload.checked_at) || !validDefenseObservation(payload.last_observed)) throw new Error();
      const {label,color}=sshDefenseStates[payload.status];
      result.replaceChildren(node('strong','badge '+color,'本次查询 · '+label),
        node('p','small muted',dateLabel(payload.checked_at)+(payload.status==='active'?' · 查询时剩余 '+payload.remaining_ms+' 毫秒':'')));
      result.dataset.status=payload.status;
      defenseHistory(history,payload.last_observed);
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && isCurrent()) result.replaceChildren(node('p','error','本次查询结果未能核实。先前观察仅供查阅。'));
    } finally {
      if(isCurrent()) button.disabled=false;
    }
  }

  function renderDefenseActions(result, hostId, payload) {
    if(!payload || payload.host_id!==hostId || !Array.isArray(payload.actions) || payload.actions.length>8 ||
      !payload.actions.every(action=>action && defenseActionId(action.action_id) && validDefenseObservation(action.last_observed)) ||
      new Set(payload.actions.map(action=>action.action_id)).size!==payload.actions.length) throw new Error();
    if(!payload.actions.length) {
      result.replaceChildren(node('p','small muted','没有可查询的 SSH 防护动作。'));
      return;
    }
    const list=node('ul','host-checks');
    for(const action of payload.actions) {
      const actionId=action.action_id;
      const row=node('li'); row.dataset.sshDefenseActionId=actionId;
      const history=node('p','small muted'); defenseHistory(history,action.last_observed);
      const button=node('button','text-button','查询此动作状态'); button.type='button'; button.dataset.sshDefenseActionStatus='';
      button.setAttribute('aria-label','查询动作 '+actionId+' 的状态');
      const status=node('div'); status.dataset.sshDefenseActionResult=''; status.setAttribute('aria-live','polite');
      button.addEventListener('click',()=>readDefenseStatus(hostId,actionId,button,status,history));
      row.append(node('strong','mono',actionId),history,button,status); list.append(row);
    }
    result.replaceChildren(list);
  }

  function hostDefenseSection(hostId) {
    const section=node('section','host-preflight'); section.setAttribute('aria-label','SSH 防护动作查询');
    const button=node('button','button','读取 SSH 防护动作'); button.type='button'; button.dataset.hostSshDefenseActions='';
    const result=node('div','host-preflight-result'); result.dataset.hostSshDefenseResult=''; result.setAttribute('aria-live','polite');
    button.addEventListener('click',async()=>{
      if(!state.token || state.capabilities?.ssh_defense_status!==true || button.disabled || !button.isConnected) return;
      const session=state.session;
      const isCurrent=()=>session===state.session && result.isConnected;
      button.disabled=true;
      result.replaceChildren(node('p','small muted','正在读取已记录的动作…'));
      try {
        const payload=await api('/api/hosts/'+encodeURIComponent(hostId)+'/ssh-defense/actions');
        if(isCurrent()) renderDefenseActions(result,hostId,payload);
      } catch(cause) {
        if(!(cause instanceof SessionEnded) && isCurrent()) result.replaceChildren(node('p','error','未能核实此主机的 SSH 防护动作列表。'));
      } finally {
        if(isCurrent()) button.disabled=false;
      }
    });
    section.append(button,node('p','small muted','隔离环境 · 只读查询已记录的动作及最近观察。'),result);
    return section;
  }

  function hostOnboardingError(text='') {
    const error=$('host-onboarding-error'); error.textContent=text; error.hidden=!text;
  }

  function resetHostOnboardingResult() {
    hostOnboardingRequest+=1; hostOnboardingMaterials=null;
    $('host-onboarding-prepare').disabled=false;
    $('host-onboarding-result').hidden=true; $('host-onboarding-preflight').hidden=true;
    $('host-onboarding-inventory').value=''; $('host-onboarding-known-hosts').value='';
    ['status','copy-status','result-fingerprint','key-file','known-hosts-file','next'].forEach(part=>$('host-onboarding-'+part).textContent='');
    hostOnboardingError();
  }

  function onboardingAddressMatches(address, requested) {
    if(address===requested) return true;
    const ipv6=value=>typeof value==='string' && value.includes(':') && /^[0-9a-f:.]+$/i.test(value);
    if(!ipv6(address) || !ipv6(requested)) return false;
    try { return new URL('http://['+address+']').hostname===new URL('http://['+requested+']').hostname; }
    catch { return false; }
  }

  function hostOnboardingPreflight(materials) {
    if(!materials || state.capabilities?.host_preflight!==true) return null;
    const host=state.hosts.find(item=>item.id===materials.host_id && item.address===materials.address && item.port===materials.port &&
      Object.values(materials.known_hosts_digests).includes(item.trusted_hosts_digest));
    if(!host) return null;
    const card=[...$('host-list').querySelectorAll('[data-host-id]')].find(item=>item.dataset.hostId===host.id);
    return card?.querySelector('[data-host-preflight]') || null;
  }

  function renderHostOnboarding(materials, draft) {
    const boundedText=(value,limit)=>typeof value==='string' && value.trim().length>0 && value.length<=limit;
    const digests=materials?.known_hosts_digests;
    if(!materials || materials.host_id!==draft.host_id || !onboardingAddressMatches(materials.address,draft.address) ||
      materials.port!==draft.port || materials.fingerprint!==draft.expected_fingerprint ||
      !boundedText(materials.inventory,32768) || !boundedText(materials.known_hosts,8192) ||
      !boundedText(materials.key_file,1024) || !boundedText(materials.known_hosts_file,1024) ||
      !digests || Object.keys(digests).length!==3 || !['lf','crlf','no_final_newline'].every(key=>typeof digests[key]==='string' && /^[a-f0-9]{64}$/.test(digests[key]))) throw new Error();
    hostOnboardingMaterials=materials;
    $('host-onboarding-inventory').value=materials.inventory;
    $('host-onboarding-known-hosts').value=materials.known_hosts;
    $('host-onboarding-result-fingerprint').textContent=materials.fingerprint;
    $('host-onboarding-key-file').textContent=materials.key_file;
    $('host-onboarding-known-hosts-file').textContent=materials.known_hosts_file;
    const target=hostOnboardingPreflight(materials);
    $('host-onboarding-preflight').hidden=!target;
    $('host-onboarding-next').textContent=target?'当前控制台已加载匹配的主机地址和可信主机记录，可前往主机卡片运行预检。':
      '部署者应用文件并重新加载 OpsArk 服务后，刷新控制台，从已登记主机的卡片运行接入预检。';
    $('host-onboarding-result').hidden=false;
  }

  async function prepareHostOnboarding(event) {
    event.preventDefault();
    const button=$('host-onboarding-prepare');
    if(!state.token || state.capabilities?.host_onboarding!==true || button.disabled || !$('host-onboarding-confirm').checked) return;
    resetHostOnboardingResult();
    const form=new FormData(event.currentTarget);
    const draft={};
    for(const key of ['host_id','name','address','username','site_domain','container_name','host_key','expected_fingerprint']) draft[key]=String(form.get(key) || '').trim();
    for(const key of ['port','expected_upstream_port']) draft[key]=Number(form.get(key));
    const composeProject=String(form.get('compose_project') || '').trim();
    if(composeProject) {
      if(!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(composeProject)) { hostOnboardingError('Compose 项目名只接受 1–63 位小写字母、数字、连字符或下划线，首位须为字母或数字。'); return; }
      draft.compose_project=composeProject;
    }
    if(!draft.container_name) {
      delete draft.container_name;
      if(!composeProject) { hostOnboardingError('请填写已确认的容器名，或填写授权 Compose 项目后只读发现；两项不能同时为空。'); return; }
    }
    if(Object.values(draft).some(value=>typeof value==='string' && /-----BEGIN\b/i.test(value)) ||
      !/^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))[ \t]+[A-Za-z0-9+/]+={0,2}(?:[ \t]+[^\r\n]*)?$/.test(draft.host_key)) {
      hostOnboardingError('请填写一行 OpenSSH 主机公钥（类型和 Base64 内容）。主机私钥、登录私钥和密码请留在部署端。'); return;
    }
    if(!/^SHA256:[A-Za-z0-9+/]{43}$/.test(draft.expected_fingerprint)) {
      hostOnboardingError('请填写已独立核验的 OpenSSH SHA256 指纹。'); return;
    }
    const session=state.session,request=hostOnboardingRequest;
    const isCurrent=()=>session===state.session && request===hostOnboardingRequest;
    button.disabled=true; $('host-onboarding-status').textContent='正在核对主机公钥并生成接入材料…';
    try {
      const materials=await api('/api/host-onboarding/prepare',{method:'POST',body:draft});
      if(!isCurrent()) return;
      renderHostOnboarding(materials,draft);
      $('host-onboarding-status').textContent='接入材料已生成。请按部署步骤应用。';
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && isCurrent()) {
        $('host-onboarding-status').textContent='';
        hostOnboardingError(cause.status===422?'请核对登记字段、公钥格式及独立取得的 SHA256 指纹。':'本次未能生成有效的接入材料，请重新核对后重试。');
      }
    } finally { if(isCurrent()) button.disabled=false; }
  }

  async function copyHostOnboarding(kind) {
    const materials=hostOnboardingMaterials;
    if(!materials || $('host-onboarding-result').hidden) return;
    const box=$('host-onboarding-'+kind), status=$('host-onboarding-copy-status');
    const text=kind==='inventory'?materials.inventory:materials.known_hosts;
    try {
      await navigator.clipboard.writeText(text);
      if(hostOnboardingMaterials===materials) status.textContent='已复制。';
    } catch {
      if(hostOnboardingMaterials!==materials) return;
      box.focus(); box.select();
      status.textContent='已选中文本。请使用系统复制快捷键或复制菜单。';
    }
  }

  const composeReasons={connection_failed:'SSH 连接或可信身份未核实',platform_unavailable:'平台或所需工具未就绪',compose_unavailable:'Compose v2 能力未确认',engine_unavailable:'本地 rootful Docker 能力未确认',inventory_unavailable:'未取得完整项目元数据',inventory_truncated:'项目元数据已截断，候选不可采用',inventory_invalid:'项目元数据格式无法核实',inventory_limit:'项目元数据超过固定预算',no_label_candidates:'本次未发现授权项目的标签候选'};
  const composeStates={created:'已创建',running:'运行中',paused:'已暂停',restarting:'重启中',removing:'移除中',exited:'已退出',dead:'已终止'};
  const composeHash=value=>typeof value==='string' && /^[a-f0-9]{64}$/.test(value);
  const composeIdentifier=value=>typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(value);
  function composeExact(value,keys) { return value && typeof value==='object' && !Array.isArray(value) && Object.keys(value).length===keys.length && keys.every(key=>Object.hasOwn(value,key)); }
  function composeIP(value) {
    if(typeof value!=='string' || value.length>45) return false;
    if(/^[0-9.]+$/.test(value)) { const parts=value.split('.'); return parts.length===4 && parts.every(part=>/^(?:0|[1-9][0-9]{0,2})$/.test(part) && Number(part)<=255); }
    if(!/^[a-f0-9:]+$/i.test(value) || !value.includes(':')) return false;
    try { return new URL('http://['+value+']').hostname.startsWith('['); } catch { return false; }
  }
  function checkedCompose(value,hostId) {
    const keys=['host_id','project','status','reason','candidates','snapshot_digest','collected_at','duration_ms','scope','evidence_kind','nginx_dependency','actions_enabled'];
    if(!composeExact(value,keys) || value.host_id!==hostId || typeof value.project!=='string' || !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(value.project) || !['candidates','empty','unavailable'].includes(value.status) || value.scope!=='one_authorized_compose_project' || value.evidence_kind!=='observed_compose_labels_and_published_ports' || value.nginx_dependency!=='unverified' || value.actions_enabled!==false || typeof value.collected_at!=='string' || !Number.isFinite(Date.parse(value.collected_at)) || !Number.isSafeInteger(value.duration_ms) || value.duration_ms<0 || !Array.isArray(value.candidates) || value.candidates.length>64 || new TextEncoder().encode(JSON.stringify(value)).length>65536) throw new Error('Invalid Compose discovery');
    if(value.status==='unavailable') { if(value.candidates.length || value.snapshot_digest!==null || !Object.hasOwn(composeReasons,value.reason) || value.reason==='no_label_candidates') throw new Error('Invalid unavailable discovery'); }
    else if(!composeHash(value.snapshot_digest) || (value.status==='empty'?(value.candidates.length!==0 || value.reason!=='no_label_candidates'):(value.candidates.length===0 || value.reason!==null))) throw new Error('Invalid discovery state');
    const ids=new Set(),names=new Set(),instances=new Map(); let total=0;
    for(const candidate of value.candidates) {
      if(!composeExact(candidate,['candidate_id','container_name','service_name','state','published_ports','service_instances','registration_supported']) || !composeHash(candidate.candidate_id) || ids.has(candidate.candidate_id) || typeof candidate.container_name!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/.test(candidate.container_name) || names.has(candidate.container_name) || !composeIdentifier(candidate.service_name) || !Object.hasOwn(composeStates,candidate.state) || !Number.isSafeInteger(candidate.service_instances) || candidate.service_instances<1 || candidate.service_instances>64 || typeof candidate.registration_supported!=='boolean' || !Array.isArray(candidate.published_ports) || candidate.published_ports.length>128) throw new Error('Invalid Compose candidate');
      const ports=new Set(); total+=candidate.published_ports.length; if(total>256) throw new Error('Too many observed ports');
      for(const port of candidate.published_ports) {
        if(!composeExact(port,['host_ip','host_port','container_port','protocol']) || !composeIP(port.host_ip) || !Number.isSafeInteger(port.host_port) || port.host_port<1 || port.host_port>65535 || !Number.isSafeInteger(port.container_port) || port.container_port<1 || port.container_port>65535 || !['tcp','udp','sctp'].includes(port.protocol)) throw new Error('Invalid observed port');
        const key=JSON.stringify([port.host_ip,port.host_port,port.container_port,port.protocol]); if(ports.has(key)) throw new Error('Duplicate observed port'); ports.add(key);
      }
      if(candidate.registration_supported!==(composeIdentifier(candidate.container_name) && candidate.published_ports.some(port=>port.protocol==='tcp'))) throw new Error('Invalid registration capability');
      ids.add(candidate.candidate_id); names.add(candidate.container_name); instances.set(candidate.service_name,(instances.get(candidate.service_name)||0)+1);
    }
    if(value.candidates.some(candidate=>candidate.service_instances!==instances.get(candidate.service_name))) throw new Error('Unclosed service instance count');
    return value;
  }
  function composeHostAnchor(host) { return JSON.stringify([host.id,host.address,host.port,host.username,host.trusted_hosts_digest,host.compose_discovery_configured,host.container_binding_confirmed]); }
  function hostComposeSection(host) {
    const section=node('section','host-preflight'); section.setAttribute('aria-label','只读 Compose 发现'); section.dataset.composeHost=host.id;
    const entry={sequence:0,busy:'',data:null,candidate:'',port:'',preview:null,message:''}; hostComposeStates.set(host.id,entry);
    const login=state.session,anchor=composeHostAnchor(host);
    const current=sequence=>Boolean(state.token) && state.session===login && section.isConnected && hostComposeStates.get(host.id)===entry && entry.sequence===sequence && composeHostAnchor(state.hosts.find(item=>item.id===host.id)||{})===anchor;
    const endpoint='/api/hosts/'+encodeURIComponent(host.id)+'/compose-discovery';
    async function discover() {
      if(entry.busy || host.compose_discovery_configured!==true) return;
      const sequence=++entry.sequence; entry.busy='discovery'; entry.data=null; entry.preview=null; entry.candidate=''; entry.port=''; entry.message=''; render();
      try { const value=await api(endpoint,{method:'POST',body:{}}); if(current(sequence)) entry.data=checkedCompose(value,host.id); }
      catch(cause) { if(current(sequence) && !(cause instanceof SessionEnded)) entry.message=cause.status===409?'发现范围未就绪或存在只读检查冲突，请核对授权后重新发现。':cause.status===404?'目标登记已变化，请重新读取主机清单。':'本次发现结果无法核实；没有采用部分候选，请明确重新发现。'; }
      finally { if(current(sequence)) { entry.busy=''; render(); } }
    }
    async function preview() {
      const data=entry.data,candidate=data?.candidates.find(item=>item.candidate_id===entry.candidate),port=Number(entry.port);
      if(entry.busy || !candidate?.registration_supported || !entry.port || !candidate.published_ports.some(item=>item.protocol==='tcp' && item.host_port===port)) return;
      const sequence=++entry.sequence; entry.busy='preview'; entry.preview=null; entry.message=''; render();
      try {
        const value=await api(endpoint+'/preview',{method:'POST',body:{candidate_id:candidate.candidate_id,snapshot_digest:data.snapshot_digest,host_port:port}});
        if(!current(sequence)) return;
        const expected='compose_project = '+JSON.stringify(data.project)+'\ncontainer_name = '+JSON.stringify(candidate.container_name)+'\ncontainer_binding_confirmed = true\nexpected_upstream_port = '+String(port)+'\n';
        if(!composeExact(value,['host_id','candidate_id','snapshot_digest','inventory_fragment','nginx_dependency','actions_enabled']) || value.host_id!==host.id || value.candidate_id!==candidate.candidate_id || value.snapshot_digest!==data.snapshot_digest || value.nginx_dependency!=='unverified' || value.actions_enabled!==false || value.inventory_fragment!==expected) throw new Error('Invalid registration fragment');
        entry.preview=value.inventory_fragment;
      } catch(cause) { if(current(sequence) && !(cause instanceof SessionEnded)) { entry.data=null; entry.candidate=''; entry.port=''; entry.message=cause.status===409?'旧候选已失效，请重新发现；没有保存登记或执行任何动作。':'预览结果无法核实，请重新发现；没有显示部分片段。'; } }
      finally { if(current(sequence)) { entry.busy=''; render(); } }
    }
    async function copy() {
      if(!entry.preview || entry.busy) return;
      try { await navigator.clipboard.writeText(entry.preview); entry.message='候选片段已复制，请人工核对并合并到原主机登记；未写入配置。'; }
      catch { entry.message='无法自动复制，请从下方手动复制候选片段。'; }
      render();
    }
    function render() {
      clear(section); section.append(node('h3','','只读 Compose 发现'),node('p','small muted','仅观察管理员授权的一个项目。Nginx 关系未确认；候选与登记预览均无执行权限，不调用模型。'));
      const button=node('button','button',entry.busy==='discovery'?'正在发现…':'发现授权 Compose 项目'); button.type='button'; button.dataset.composeDiscover=''; button.disabled=Boolean(entry.busy) || host.compose_discovery_configured!==true; button.addEventListener('click',discover); section.append(button);
      if(host.compose_discovery_configured!==true) section.append(node('p','small muted','此主机尚未配置授权 Compose 项目。请由部署者登记范围并更新精确只读策略；网页不会自行授权。'));
      if(entry.message) section.append(node('p','notice neutral',entry.message));
      const data=entry.data; if(!data) return;
      section.append(detailList([['授权项目',data.project],['采集时间',dateLabel(data.collected_at)],['Nginx 依赖','未确认'],['执行权限','无']]));
      if(data.status!=='candidates') { section.append(node('p','small muted',composeReasons[data.reason])); return; }
      const candidateLabel=node('label','field','选择已观察的容器候选'),selection=node('select'); selection.dataset.composeCandidate=''; selection.disabled=Boolean(entry.busy); const none=node('option','','请选择候选，不自动登记'); none.value=''; selection.append(none);
      for(const candidate of data.candidates) { const option=node('option','',candidate.service_name+' / '+candidate.container_name+' · '+composeStates[candidate.state]); option.value=candidate.candidate_id; selection.append(option); }
      selection.value=entry.candidate; selection.addEventListener('change',()=>{entry.candidate=selection.value;entry.port='';entry.preview=null;entry.message='';render();}); candidateLabel.append(selection); section.append(candidateLabel);
      const candidate=data.candidates.find(item=>item.candidate_id===entry.candidate); if(!candidate) return;
      section.append(detailList([['服务',candidate.service_name],['容器',candidate.container_name],['运行状态',composeStates[candidate.state]],['同服务实例数',candidate.service_instances]]));
      const list=node('ul','host-checks'); for(const port of candidate.published_ports) list.append(node('li','mono small',port.host_ip+':'+port.host_port+' → '+port.container_port+'/'+port.protocol)); section.append(list);
      if(!candidate.registration_supported) { section.append(node('p','small muted','此候选没有可登记的 TCP 宿主发布端口，或容器名超出登记范围；不生成预览。')); return; }
      const portLabel=node('label','field','明确选择 TCP 宿主发布端口'),ports=node('select'); ports.dataset.composePort=''; ports.disabled=Boolean(entry.busy); const placeholder=node('option','','请选择已观察端口'); placeholder.value=''; ports.append(placeholder);
      for(const port of [...new Set(candidate.published_ports.filter(item=>item.protocol==='tcp').map(item=>item.host_port))].sort((a,b)=>a-b)) { const option=node('option','',String(port)); option.value=String(port); ports.append(option); }
      ports.value=entry.port; ports.addEventListener('change',()=>{entry.port=ports.value;entry.preview=null;entry.message='';render();}); portLabel.append(ports); section.append(portLabel);
      const prepare=node('button','button',entry.busy==='preview'?'正在重新核对…':'核对并生成候选登记片段'); prepare.type='button'; prepare.dataset.composePreview=''; prepare.disabled=Boolean(entry.busy) || !entry.port; prepare.addEventListener('click',preview); section.append(prepare);
      if(entry.preview) { const pre=node('pre','evidence-output',entry.preview); pre.dataset.composeFragment=''; const button=node('button','text-button','复制候选登记片段'); button.type='button'; button.addEventListener('click',copy); section.append(pre,button,node('p','small muted','服务端已重新采集并核对旧摘要；这里只生成片段，没有保存、重载、安装、补丁或业务复验。')); }
    }
    render(); return section;
  }

  function renderHosts() {
    $('host-onboarding').hidden=state.capabilities?.host_onboarding!==true;
    const list=$('host-list'); clear(list);
    if(!state.hosts.length) {
      const empty=node('div','host-empty'); empty.append(node('h2','','尚未登记 SSH 主机'),node('p','','可以先使用本地合成样本验证调查流程。真实采集需要部署者登记主机、专用账号、凭据引用和可信主机记录；当前没有成功连接的主机。')); list.append(empty); return;
    }
    for(const host of state.hosts) {
      const card=node('article','host-card'); card.dataset.hostId=host.id;
      card.append(node('h2','',host.name),node('span','badge neutral','已登记'));
      card.append(detailList([['目标标识',host.id],['地址',host.address+':'+host.port],['专用账号',host.username],['网站',host.site_domain],['容器',host.container_binding_confirmed===false?'容器待确认':host.container_name],['预期上游',host.expected_upstream_port]]));
      if(host.container_binding_confirmed===false) card.append(node('p','small muted','容器登记待确认，当前不会读取容器状态或日志。发现并复制候选片段后，仍须部署者核对、应用登记并重新导出受限权限。'));
      const checks=Array.isArray(host.health_checks)?host.health_checks:[];
      if(checks.length) {
        card.append(sectionHeading('登记的站点检查'));
        const list=node('ul','host-checks');
        for(const check of checks) {
          const item=node('li'); item.append(node('strong','',check.id+' · '+check.domain),node('p','mono','目标机 loopback:'+check.port+check.path),node('p','small muted','预期 HTTP '+String(check.expected_status ?? '未登记')+' · '+(check.expected_body?'已设置正文条件':'未要求正文匹配')),node('span','badge '+(check.read_only_confirmed===true?'neutral':'amber'),check.read_only_confirmed===true?'部署者已确认只读':'未确认 · 不会探测')); list.append(item);
        }
        card.append(list);
      } else card.append(node('p','small muted','尚未登记站点即时检查。'));
      if(host.nginx_config_path) card.append(node('p','host-config-path small muted','配置摘要路径：'+host.nginx_config_path+'；只读取磁盘文件摘要，不证明已加载或可回退。'));
      if(state.capabilities?.host_preflight===true) {
        const section=node('section','host-preflight'); section.setAttribute('aria-label','接入预检');
        const preflight=node('button','button','运行接入预检'); preflight.type='button'; preflight.dataset.hostPreflight='';
        const result=node('div','host-preflight-result'); result.dataset.hostPreflightResult=''; result.setAttribute('aria-live','polite');
        preflight.addEventListener('click',()=>runHostPreflight(host.id,preflight,result));
        section.append(preflight,node('p','small muted','只读核对 SSH、系统与工具、Nginx、登记容器及根分区。日志检查和网站验收属于后续调查。'),result); card.append(section);
      }
      if(state.capabilities?.business_readiness===true) {
        const section=node('section','host-preflight'); section.setAttribute('aria-label','业务就绪检查');
        const check=node('button','button','运行只读业务检查'); check.type='button'; check.dataset.hostBusinessReadiness='';
        const result=node('div','host-preflight-result'); result.dataset.hostBusinessReadinessResult=''; result.setAttribute('aria-live','polite');
        check.addEventListener('click',()=>runBusinessReadiness(host.id,check,result));
        section.append(check,node('p','small muted','仅探测登记并确认只读的业务入口。结果反映本次探测，业务恢复验收请查看对应任务。'),result); card.append(section);
      }
      if(state.capabilities?.ssh_defense_status===true) card.append(hostDefenseSection(host.id));
      if(state.capabilities?.host_compose_discovery===true && host.source==='ssh') card.append(hostComposeSection(host));
      if(state.capabilities?.host_nginx_dependencies===true && host.source==='ssh' && window.OpsArkNginxDependencies) card.append(window.OpsArkNginxDependencies.create({host,api,getContext:()=>({signedIn:Boolean(state.token),session:state.session,hosts:state.hosts})}));
      if(host.source==='ssh' && host.compose_volume_binding_digest) {
        const mount=node('div',''); card.append(mount);
        const getContext=()=>({signedIn:Boolean(state.token),session:state.session,hosts:state.hosts});
        const session=state.session;
        import('/compose-volumes.js').then(()=>{
          if(mount.isConnected && state.token && state.session===session) mount.replaceChildren(window.OpsArkComposeVolumes.create({host,api,getContext}));
        }).catch(()=>{
          if(mount.isConnected && state.token && state.session===session) mount.replaceChildren(node('p','notice neutral','卷观察界面暂时不可用。'));
        });
      }
      const button=node('button','text-button','对此主机发起只读调查 →'); button.type='button'; button.addEventListener('click',()=>{showView('workspace');$('source-select').value='ssh';$('host-select').value=host.id;updateSelection();$('scenario-select').focus();}); card.append(button); list.append(card);
    }
  }

  const automationModes={manual:{name:'手动',description:'只分析、生成建议，始终不进入执行。'},assisted:{name:'半自动',description:'先给出具体建议，经过批准且条件仍然匹配后才可执行。'},automatic:{name:'全自动',description:'仅在已启用策略和明确目标、动作、包范围内自主处理，并验证结果；未知风险需要停止或升级复核。'}};

  function automationMode(value) { return Object.hasOwn(automationModes,value)?value:null; }
  function automationSpec(value) { const modes=Array.isArray(state.automation?.modes)?state.automation.modes:[]; return modes.find(item=>item && item.id===value) || automationModes[value]; }
  function automationPayload(value) {
    if(!value || !automationMode(value.mode) || !Number.isSafeInteger(value.revision) || value.revision<0) throw new Error('模式响应缺少有效状态或版本，未允许保存。');
    return value;
  }

  function automationSaveAllowed(mode,settings) {
    return Boolean(mode && settings && !state.automationBusy && !state.automaticRecoveryBusy &&
      !state.automationNeedsReload && (mode!==settings.mode || settings.mode_sync_complete===false));
  }

  function renderAutomation() {
    defenseWorkspace?.sessionChanged();
    nginxActions?.configure();
    containerRestarts?.configure();
    const section=$('automation-mode-section');
    const supported=state.capabilities?.automation_modes===true;
    section.hidden=!supported;
    if(!supported) {
      $('automation-mode-select').value='manual'; $('automation-mode-select').disabled=true;
      $('save-automation-mode').disabled=true; $('automation-current').textContent=''; $('automation-mode-description').textContent='';
      clear($('automation-execution-boundary')); clear($('automation-policy-details')); $('automation-error').textContent=''; $('automation-error').hidden=true;
      return;
    }
    const settings=state.automation,valid=Boolean(settings && automationMode(settings.mode));
    const select=$('automation-mode-select');
    select.value=automationMode(state.automationDraft) || 'manual';
    select.disabled=state.automationBusy || Boolean(state.automaticRecoveryBusy) || !valid || state.automationNeedsReload;
    $('refresh-automation').disabled=state.automationBusy;
    const resync=select.value===settings?.mode && settings.mode_sync_complete===false;
    $('save-automation-mode').disabled=!valid || !automationSaveAllowed(select.value,settings);
    $('save-automation-mode').textContent=state.automationBusy?'正在读取或保存…':resync?'重新同步':'保存模式';
    const spec=automationSpec(select.value);
    $('automation-mode-description').textContent=typeof spec?.description==='string'?spec.description:automationModes[select.value].description;
    $('automation-current').textContent=valid?'当前保存：'+String(automationSpec(settings.mode)?.name || automationModes[settings.mode].name)+' · 版本 '+String(settings.revision)+(state.automationNeedsReload?' · 待重新核对':''):'尚未取得当前模式；不会以默认选项推断服务器执行状态。';
    const boundary=$('automation-execution-boundary'); clear(boundary);
    const defenseChannel=Array.isArray(settings?.sync_channels) && settings.sync_channels.includes('ssh-defense');
    if(state.automationNeedsReload) boundary.append(node('strong','','设置可能已经变化，请重新读取后再选择。'));
    if(!valid) boundary.append(node('p','','尚未取得有效的执行能力信息，保存暂不可用。'));
    else if(settings.execution_available!==true) boundary.append(node('strong','',defenseChannel?'补丁执行能力尚未就绪；防护许可请在“安全观察”单独核对。保存模式不会新增授权。':automaticSupported()?'当前执行能力或模式同步尚未就绪；切换仅保存选择，仍需核对自动处置状态。':'执行器未配置。切换仅保存模式选择，不表示已经接管、扫描、升级或修复服务器。'));
    else boundary.append(node('strong','',defenseChannel?'部署声明补丁执行器可用；防护许可请在“安全观察”单独核对。实际任务仍需满足各自授权与验证条件。':'部署声明执行器可用；实际任务仍需满足授权范围、状态校验及验证条件，保存模式不等于已执行。'));
    if(resync && !state.automationNeedsReload) boundary.append(node('p','small','重新同步会向已登记的执行通道确认当前模式。若已有有效预授权，同步后后台可继续按当前模式运行。'));
    if(automaticSupported()) boundary.append(node('p','small','全自动仅使用部署端明确预授权；目标、UTC 维护窗口、配额及持续暂停状态见“漏洞与修复”。保存模式不会新增授权或恢复暂停任务。'));
    if(typeof settings?.detail==='string') boundary.append(node('p','small',settings.detail));
    const policy=settings?.policy;
    const details=$('automation-policy-details'); clear(details);
    if(policy && typeof policy==='object') {
      const list=value=>Array.isArray(value) && value.length?value.slice(0,20).join('、'):'尚未授权';
      details.append(detailList([['授权策略',policy.enabled===true?'已启用':'未启用'],['目标 ID',list(policy.host_ids)],['动作',list(policy.allowed_actions)],['包范围',list(policy.allowed_packages)],['单任务包数',Number.isSafeInteger(policy.max_packages_per_job)?String(policy.max_packages_per_job):'未提供'],['允许重启主机',policy.allow_reboot===true?'是':'否'],['允许服务重启',policy.allow_service_restart===true?'是':'否']]));
    } else details.append(node('p','small muted','尚未取得授权策略；选择全自动也不能补足缺失的授权。'));
    $('automation-error').textContent=state.automationError; $('automation-error').hidden=!state.automationError;
  }

  async function refreshAutomation() {
    if(!state.token || state.capabilities?.automation_modes!==true || state.automationBusy) return;
    const session=state.session,request=++state.automationRequest;
    state.automationBusy=true; state.automationError=''; renderAutomation();
    try {
      const value=automationPayload(await api('/api/automation'));
      if(session!==state.session || request!==state.automationRequest) return;
      if(state.automation && (value.revision!==state.automation.revision || value.mode!==state.automation.mode)) {invalidateVulnerabilityAIPreview();dismissServiceActivationDialog();state.serviceActivationPlan=null;dismissActivationRecoveryDialog();state.activationRecoveryPlan=null;}
      if(state.remediationPlan && (value.revision!==state.remediationPlan.mode_revision || value.mode!=='assisted')) invalidateRemediationPlan('操作模式或版本已变化，请重新生成修复方案。');
      state.automation=value; state.automationDraft=value.mode; state.automationNeedsReload=false;
    } catch(cause) {
      if(cause instanceof SessionEnded || session!==state.session || request!==state.automationRequest) return;
      state.automationNeedsReload=true; state.automationError='模式读取未完成：'+errorMessage(cause)+' 历史信息不能表示当前执行状态。';
    } finally {
      if(session===state.session && request===state.automationRequest) { state.automationBusy=false; renderAutomation(); renderRemediation(); if(state.view==='remediation') refreshAutomatic({quiet:true}); }
    }
  }

  async function saveAutomation(event) {
    event.preventDefault();
    const mode=automationMode($('automation-mode-select').value),settings=state.automation;
    if(!state.token || state.capabilities?.automation_modes!==true || !automationSaveAllowed(mode,settings)) return;
    const resync=mode===settings.mode;
    const session=state.session,request=++state.automationRequest;
    invalidateAutomaticRecoveryPlan('模式选择发生变化，旧恢复确认已取消。');
    invalidateRemediationPlan('模式选择发生变化，旧修复方案已取消。');
    dismissServiceActivationDialog();state.serviceActivationPlan=null;
    dismissActivationRecoveryDialog();state.activationRecoveryPlan=null;
    state.automationDraft=mode; state.automationBusy=true; state.automationError=''; renderAutomation();
    try {
      const value=automationPayload(await api('/api/automation',{method:'PUT',body:{mode,expected_revision:settings.revision}}));
      if(session!==state.session || request!==state.automationRequest) return;
      if(resync && (value.mode!==mode || value.revision!==settings.revision || value.mode_sync_complete!==true)) throw new Error('当前模式未获得同步确认。');
      state.automation=value; state.automationDraft=value.mode; state.automationNeedsReload=false;
      announce((resync?'已同步当前模式：':'已保存模式：')+String(automationSpec(value.mode)?.name || automationModes[value.mode].name)+'。'+(value.execution_available===true?'实际任务仍受授权策略约束。':'执行器未配置，当前没有执行服务器动作。'));
    } catch(cause) {
      if(cause instanceof SessionEnded || session!==state.session || request!==state.automationRequest) return;
      state.automationNeedsReload=true;
      state.automationError=cause.status===409?'模式已被其他会话更新，请重新读取后再选择。':'保存结果未确认：'+errorMessage(cause)+' 请重新读取，不要重复提交旧版本。';
    } finally {
      if(session===state.session && request===state.automationRequest) { state.automationBusy=false; renderAutomation(); renderRemediation(); if(state.view==='remediation') refreshAutomatic({quiet:true}); }
    }
  }

  function renderCapabilities() {
    const details=$('capability-details'); clear(details);
    const capabilities=state.capabilities || {};
    $('console-mode-badge').textContent=capabilities.vulnerability_remediation===true?'调查 / 受控修复':'只读 / 安全观察';
    const pairs=[['运行模式','只读诊断 / 安全观察'],['站点检查',capabilities.site_checks===true?'登记目标的即时只读检查':'未开放'],['观测基线',capabilities.baselines===true?'字段快照与变化对照；非配置备份':'未开放'],['AI 解释',capabilities.model_configured?'已配置，发送前逐次确认':'未配置'],['模型',capabilities.model_configured?(capabilities.model_name || '已配置模型'):'未调用'],['SSH 目标',state.hosts.length+' 台已登记'],['本地样本',state.samples.length+' 份合成样本'],['权限范围','单管理员实例']];
    pairs.push(['业务就绪检查',capabilities.business_readiness===true?'已登记并确认只读的业务入口，展示即时匹配结果':'当前实例未开放']);
    pairs.push(['持续安全观察',capabilities.security_observation===true?'登记目标的 SSH 事件与控制台告警；不执行封禁':'当前实例未开放']);
    pairs.push(['漏洞与补丁修复',capabilities.vulnerability_remediation===true?'登记目标的扫描、具体计划和受限修复；以实际执行能力和任务验证为准':'当前实例未开放']);
    pairs.push(['预授权自动处置',capabilities.automatic_repair===true?'按目标、包、公告、UTC 窗口与配额执行；暂停原因及任务结果单独核对':'当前实例未开放']);
    $('capability-execution-boundary').textContent=capabilities.automatic_repair===true?'人工批准的计划仅在半自动模式执行；自动处置另受部署端预授权、UTC 窗口与配额限制。未知结果、失败或重启待办不会因切换模式而解除暂停。':capabilities.vulnerability_remediation===true?'补丁安装须符合当前执行能力、半自动模式及具体计划授权；安装成功、重启待办和验证失败分别记录。':'本版本不执行修复、重启或封禁；即时站点结果不等于完整恢复验收。';
    const controller=capabilities.platforms?.controller,managed=capabilities.platforms?.managed;
    const platformText=value=>typeof value==='string' && value.trim()?value:'未取得';
    pairs.push(['控制台平台',controller?platformText(controller.system)+' / '+platformText(controller.architecture):'旧实例未提供平台信息'],['Python 环境',controller?platformText(controller.python):'未取得']);
    const families=Array.isArray(managed?.families)?managed.families:[];
    const architectures=Array.isArray(managed?.architectures)?managed.architectures:[];
    pairs.push(['远端适配范围',families.length?families.join(' / ')+'（版本及组件以目标预检和验证记录为准）':'旧实例未提供适配范围，不能据此确认目标兼容'],['远端架构',architectures.length?architectures.join(' / ')+'（需逐项实测）':'未提供'],['环境预检',managed?.preflight===true?'采集前检查系统与工具条件':'未声明支持'],['平台边界','控制台运行平台与被管理服务器的适配范围分别验证。']);
    pairs.forEach(([label,value])=>details.append(node('dt','',label),node('dd','',value)));
  }

  const vulnerabilityGapLabels={pro_cve_collection_failed:'Ubuntu Pro 漏洞数据读取未完成。',pro_cve_coverage_unavailable:'Ubuntu Pro 的完整 CVE 覆盖不可用。',usn_recent_or_requested_window_only:'仅核实最近或指定的 Ubuntu 安全公告。',usn_collection_failed:'Ubuntu 安全公告读取失败。',vendor_evidence_unavailable:'尚未取得供应商漏洞证据。',vendor_metadata_stale:'供应商漏洞数据已过期，需要重新读取。',usn_evidence_freshness_unproven:'Ubuntu 公告的新鲜度尚未核实。',apt_metadata_freshness_unproven:'APT 更新索引的新鲜度尚未核实。',apt_state_fingerprint_unavailable:'无法核实完整包管理状态摘要。',apt_insecure_configuration:'APT 信任配置未通过检查。',inventory_changed_during_scan:'扫描期间软件清单发生变化，需要重新核实。',vendor_affected_status_unconfirmed:'供应商受影响状态仍需评估，不能作为确认漏洞。',scan_output_truncated:'扫描记录因大小预算裁剪，未展示部分不代表安全。',controller_evidence_budget:'控制端仅保留有界证据摘要，未展示部分不代表安全。',finding_evidence_invalid:'部分漏洞记录的证据格式未能核实。',explicit_package_filter:'本次只检查明确选择的软件包。'};
  const automaticHostStates={disabled:'目标自动处置未启用',manual:'当前模式不执行自动处置',mode_unsynced:'等待模式同步',outside_window:'等待 UTC 维护窗口',expired:'预授权已到期',quota_exhausted:'配额已用尽',latched:'已持续暂停 · 待核实',waiting_scan:'等待有效扫描',planning:'正在核对预授权计划',tracking:'正在追踪原任务',idle:'等待下一次后台检查',error:'后台条件未能核实',remote_unavailable:'远端 root 安全状态未核实',remote_mismatch:'远端 root 授权范围不符'};
  function automaticSupported() { return state.capabilities?.automatic_repair===true; }
  function automaticUTC(value) {
    if(typeof value!=='string' || !value) return '未提供';
    const date=new Date(value);
    return Number.isNaN(date.getTime())?'时间格式未确认':date.toISOString().replace('T',' ').replace(/\.\d{3}Z$/,' UTC');
  }
  function automaticCount(value) { return Number.isSafeInteger(value) && value>=0?String(value):'未知'; }
  function automaticQuota(quota,period) { return automaticCount(quota?.[period+'_used'])+' / '+automaticCount(quota?.[period+'_limit']); }
  function automaticPauseReason(reason) {
    const value=typeof reason==='string'?reason:'暂停原因尚未提供';
    const key=value.startsWith('automatic_job_')?value.slice('automatic_job_'.length):value;
    return Object.hasOwn(remediationJobStates,key)?remediationJobLabel(key)+'（'+value+'）':value;
  }
  function automaticList(value) { return Array.isArray(value) && value.length?value.slice(0,30).map(item=>String(item)).join('、')+(value.length>30?'（此处仅展示前 30 项，共 '+String(value.length)+' 项）':''):'未授权'; }
  function automaticWindow(value) {
    const days=['周一','周二','周三','周四','周五','周六','周日'];
    if(!value || !Array.isArray(value.weekdays) || !value.weekdays.length || !value.weekdays.every(day=>Number.isInteger(day) && day>=0 && day<=6) || !Number.isInteger(value.start_minute) || value.start_minute<0 || value.start_minute>1439 || !Number.isInteger(value.end_minute) || value.end_minute<0 || value.end_minute>1440) return '窗口格式未确认';
    const time=minute=>String(Math.floor(minute/60)).padStart(2,'0')+':'+String(minute%60).padStart(2,'0');
    return value.weekdays.map(day=>days[day]).join('、')+' '+time(value.start_minute)+' → '+time(value.end_minute)+' UTC'+(value.end_minute<value.start_minute?'（次日结束，按开始日）':'')+'；开始含、结束不含';
  }
  function automaticPayload(value) {
    if(!value || typeof value.enabled!=='boolean' || typeof value.running!=='boolean' || !automationMode(value.mode) || !Number.isSafeInteger(value.mode_revision) || value.mode_revision<0 || typeof value.mode_sync_complete!=='boolean' || !Array.isArray(value.grants) || !value.grants.every(grant=>grant && typeof grant==='object' && !Array.isArray(grant)) || !Array.isArray(value.hosts) || !value.hosts.every(host=>host && remediationToken(host.host_id)) || new Set(value.hosts.map(host=>host.host_id)).size!==value.hosts.length || !Array.isArray(value.latched_hosts) || !Array.isArray(value.jobs)) throw new Error('自动处置响应缺少有效模式、目标或授权清单，当前状态未确认。');
    if(value.ai!==undefined && value.ai!==null && (typeof value.ai.enabled!=='boolean' || !Array.isArray(value.ai.requests) || value.ai.requests.length>100 || !Array.isArray(value.ai.alerts) || value.ai.alerts.length>100)) throw new Error('自动 AI 许可或告警状态未能核实。');
    return value;
  }
  function stopAutomaticPolling() { if(state.automaticTimer!==null) window.clearTimeout(state.automaticTimer); state.automaticTimer=null; }
  function scheduleAutomaticPolling() {
    stopAutomaticPolling();
    if(state.token && automaticSupported() && state.view==='remediation' && !document.hidden && !state.automaticBusy) state.automaticTimer=window.setTimeout(()=>refreshAutomatic({quiet:true}),30000);
  }
  function renderAutomatic() {
    renderActivationRecoveries();
    const supported=automaticSupported(); $('automatic-repair-section').hidden=!supported;
    const summary=$('automatic-repair-summary'),hosts=$('automatic-repair-hosts'),grants=$('automatic-repair-grant-list'),jobs=$('automatic-repair-jobs');
    [summary,hosts,grants,jobs].forEach(clear);
    $('refresh-automatic-repair').disabled=state.automaticBusy;
    $('refresh-automatic-repair').textContent=state.automaticBusy?'正在读取…':'刷新自动状态';
    $('automatic-repair-error').textContent=state.automaticError; $('automatic-repair-error').hidden=!state.automaticError;
    if(!supported) { renderAutomaticRecovery(); return; }
    const status=state.automaticStatus,stale=Boolean(state.automaticError || state.automaticBusy);
    if(!status) { summary.append(node('p','empty-note',state.automaticBusy?'正在读取部署端自动处置状态…':'尚未取得自动处置状态；不能据此认定目标已授权或正在执行。')); renderAutomaticRecovery(); return; }
    const title=stale?'当前状态待核实 · 以下为上次读取快照':status.enabled!==true?'自动处置后台未启用':status.running!==true?'自动处置后台未运行':status.mode!=='automatic'?'后台已运行 · 当前模式不执行自动处置':!status.grants.some(grant=>grant.enabled===true)?'已选择全自动 · 尚无预授权':status.mode_sync_complete!==true?'已选择全自动 · 等待模式同步':'预授权自动处置后台已运行';
    summary.append(node('strong','',title));
    summary.append(detailList([['后台读取的模式',automationModes[status.mode].name+' · 版本 '+String(status.mode_revision)],['模式同步',status.mode_sync_complete===true?'已完成':'尚未完成'],['AI 提供方',status.ai?.enabled===true?'已登记自动分析许可；实际调用还需核对提供方、预算和当前证据':state.capabilities?.model_configured===true?'已配置；自动分析许可单独核对':'未配置；此自动流程不调用模型'],['本页读取时间',state.automaticReadAt?dateLabel(state.automaticReadAt):'未记录'],['告警渠道',status.notification_channel==='console'?'控制台记录':'未确认']]));
    summary.append(node('p','small muted','后台运行只说明调度器状态。每个目标仍需核对下方授权、UTC 窗口、配额与暂停记录；选择全自动不会扩大允许范围。'));
    if(typeof status.last_error==='string' && status.last_error) summary.append(node('p','notice',status.last_error));
    if(state.automation && (status.mode!==state.automation.mode || status.mode_revision!==state.automation.revision)) summary.append(node('p','notice','模式读数与已保存选择尚未一致。以上后台读数不能证明新选择已经同步生效。'));
    for(const host of status.hosts.slice(0,100)) {
      const card=node('article','automatic-repair-host'); card.dataset.automaticHost=host.host_id;
      const authorized=status.grants.filter(grant=>grant.enabled===true && Array.isArray(grant.host_ids) && grant.host_ids.includes(host.host_id));
      const remoteCache=host.remote_status,remote=remoteCache?.remote,rootSafety=remote?.safety;
      const remoteIdentity=remoteCache && remoteCache.host_id===host.host_id && remoteCache.scope_hash===host.scope_hash;
      const latch=host.latch || status.latched_hosts.find(item=>item && item.host_id===host.host_id) || (rootSafety?.paused===true?{reason:rootSafety.reason,job_id:rootSafety.job_id,latched_at:rootSafety.updated_at,source:'remote_root',remote_safety:rootSafety}:null);
      const label=latch?automaticHostStates.latched:!authorized.length?'未获自动处置授权':host.state==='idle' && (!remoteIdentity || remoteCache.status!=='available')?automaticHostStates.remote_unavailable:automaticHostStates[host.state] || '后台状态未确认';
      const heading=node('div','automatic-repair-host-heading'); heading.append(node('h3','',host.name || host.host_id),node('span','badge '+(latch || ['error','expired','quota_exhausted'].includes(host.state)?'amber':'neutral'),(stale?'历史快照 · ':'')+label)); card.append(heading,node('p','mono small',host.host_id));
      card.append(detailList([['自动授权',authorized.length?authorized.map(grant=>String(grant.grant_id || 'ID 未提供')).join('、'):'未授权；此目标不自动安装'],['UTC 窗口',host.maintenance_open===true?'后台报告：窗口内':host.maintenance_open===false?'后台报告：窗口外':'未核实'],['授权到期',automaticUTC(host.grant_expires_at)],['今日已用 / 上限',automaticQuota(host.quota,'daily')],['总计已用 / 上限',automaticQuota(host.quota,'total')],['最近后台检查',automaticUTC(host.last_checked)],['下次后台检查',automaticUTC(host.next_check)]]));
      if(typeof host.detail==='string' && host.detail) card.append(node('p','small muted',host.detail));
      const remoteLabel=!remoteCache?'尚未读取 root 状态':!remoteIdentity?'root 快照作用域不符':remoteCache.status==='available'?'root 状态快照已缓存':remoteCache.status==='unavailable'?'root 状态未能核实 · 保留历史快照':'root 缓存状态未确认';
      card.append(detailList([['root 状态缓存',remoteLabel],['root 检查时间',automaticUTC(remoteCache?.checked_at)],['root 今日 / 总使用',automaticCount(remote?.usage?.daily_used)+' / '+automaticCount(remote?.usage?.total_used)],['root UTC 窗口',remote?.maintenance_open===true?'快照报告：窗口内':remote?.maintenance_open===false?'快照报告：窗口外':'未核实'],['root 暂停记录',rootSafety?.paused===true?'已持久暂停':rootSafety?.paused===false?'此快照未报告暂停':'未核实']]));
      card.append(node('p','small muted','root 状态由后台每 30 秒读取；新提交只接受不超过 60 秒且范围一致的可信缓存。缓存可见不代表当前可执行，读取失败时历史值只供核对。'));
      if(latch) {
        const pause=node('div','notice automatic-repair-pause'); pause.append(node('strong','','持续暂停，保留原任务'),node('p','small',automaticPauseReason(latch.reason)),node('p','mono small','原任务：'+String(latch.job_id || host.current_job_id || '未提供')),node('p','small muted','暂停来源：'+(latch.source==='remote_root'?'远端 root 持续记录':'控制端持续记录')+'；暂停时间：'+automaticUTC(latch.latched_at)));
        if(latch.remote_safety) pause.append(detailList([['root 暂停原因',automaticPauseReason(latch.remote_safety.reason)],['root 原任务',latch.remote_safety.job_id || '未提供'],['root 记录时间',automaticUTC(latch.remote_safety.updated_at)]]));
        pause.append(node('p','small','切换模式、刷新或新扫描不会解除暂停。需核实原任务与服务状态，再明确批准恢复。'));
        if(automaticRecoverySupported()) {
          const button=node('button','button automatic-recovery-prepare','核对恢复条件'); button.type='button'; button.dataset.recoveryHost=host.host_id;
          button.disabled=!automaticRecoveryCanPrepare(host,latch); button.addEventListener('click',()=>prepareAutomaticRecovery(host,latch)); pause.append(button);
          if(!automaticRecoveryPolicy(host.host_id)) pause.append(node('p','small muted','当前部署未授权此目标的恢复入口；策略变更须单独审核。'));
          else if(status.mode!=='manual' || status.mode_sync_complete!==true) pause.append(node('p','small muted','恢复核验仅在手动模式并完成同步后开放。'));
          else if(automaticRecoveryPending(host.host_id)) pause.append(node('p','small muted','已有恢复结果待核实，只查询原恢复记录。'));
        }
        card.append(pause);
      } else if(host.current_job_id) card.append(node('p','mono small','正在追踪原任务：'+String(host.current_job_id)));
      hosts.append(card);
    }
    if(!status.hosts.length) hosts.append(node('p','empty-note','后台尚未登记自动处置目标。'));
    if(status.hosts.length>100) hosts.append(node('p','small muted','此处仅展示前 100 个目标，共 '+String(status.hosts.length)+' 个。未展示的目标需另行核对。'));
    const orphanLatches=status.latched_hosts.filter(latch=>latch && !status.hosts.some(host=>host.host_id===latch.host_id));
    for(const latch of orphanLatches.slice(0,100)) {
      const card=node('article','automatic-repair-host'); card.append(node('h3','','历史目标仍有持续暂停'),node('p','mono small',latch.host_id || '目标未确认'),node('p','notice',automaticPauseReason(latch.reason)),node('p','mono small','原任务：'+String(latch.job_id || '未提供')),node('p','small muted','暂停时间：'+automaticUTC(latch.latched_at)+'。此目标不在当前清单内；暂停记录仍须部署端核实。')); hosts.append(card);
    }
    if(orphanLatches.length>100) hosts.append(node('p','small muted','另有未展示的历史目标暂停记录；共 '+String(orphanLatches.length)+' 条。'));
    for(const grant of status.grants.slice(0,30)) {
      const item=node('article','automatic-repair-grant'); item.append(node('h3','','预授权 '+String(grant.grant_id || 'ID 未提供')));
      const risks=Array.isArray(grant.allowed_risk_levels)?grant.allowed_risk_levels.map(risk=>({low:'低风险',medium:'中风险（可能影响服务）'}[risk] || String(risk))).join('、'):'未提供';
      item.append(detailList([['部署端开关',grant.enabled===true?'已启用':'未启用'],['目标 ID',automaticList(grant.host_ids)],['软件包允许名单',automaticList(grant.allowed_packages)],['安全公告允许名单',automaticList(grant.allowed_advisories)],['签发时间',automaticUTC(grant.issued_at)],['到期时间',automaticUTC(grant.expires_at)],['每日任务上限',automaticCount(grant.max_jobs_per_day)],['累计任务上限',automaticCount(grant.max_total_jobs)],['允许风险',risks || '未授权'],['允许服务重启',grant.allow_service_restart===true?'明确允许（仍须符合计划）':'未授权'],['系统重启','不自动执行'],['授权摘要',grant.grant_digest || '未提供']]));
      const windows=node('ul','plain-list'); for(const window of (Array.isArray(grant.maintenance_windows)?grant.maintenance_windows:[]).slice(0,30)) windows.append(node('li','',automaticWindow(window)));
      if(windows.childElementCount) { item.append(node('h4','','UTC 维护窗口'),windows); } else item.append(node('p','small muted','未提供 UTC 维护窗口，不能认定当前可执行。'));
      grants.append(item);
    }
    if(!status.grants.length) grants.append(node('p','empty-note','没有部署端预授权。保存全自动模式也不会授权任何目标或软件包。'));
    if(status.grants.length>30) grants.append(node('p','small muted','此处仅展示前 30 份预授权，共 '+String(status.grants.length)+' 份。'));
    if(status.jobs.length) {
      jobs.append(node('h3','','自动处置任务记录'));
      for(const job of status.jobs.slice(0,30)) {
        if(!job || typeof job!=='object') continue;
        const item=node('article','automatic-repair-job'); item.append(node('strong','',remediationJobLabel(job.status || job.state)),node('p','mono small',String(job.host_id || '目标未确认')+' · 原任务 '+String(job.job_id || '尚未分配')));
        item.append(node('p','small',String(job.package || '软件包未确认')+'：'+String(job.current_version || '未取得')+' → '+String(job.candidate_version || '未取得')));
        if(typeof job.detail==='string') item.append(node('p','small muted',job.detail));
        item.append(node('p','small muted','更新于 '+automaticUTC(job.updated_at)+'；具体复扫与服务验证请核对同一任务记录。')); jobs.append(item);
      }
      if(status.jobs.length>30) jobs.append(node('p','small muted','此处仅展示前 30 条自动任务，共 '+String(status.jobs.length)+' 条。'));
    }
    renderAutomaticAI();
    renderAutomaticRecovery();
  }
  const automaticAIKinds={analysis_started:'自动分析已登记',analysis_completed:'AI提案已核验',analysis_failed:'模型分析被阻断',no_proposal:'没有可执行提案',plan_ready:'原生计划已核验',repair_verified:'修复覆盖项验证通过',repair_failed:'修复结果需核实',blocked:'自动 AI 处置被阻断',analysis_unknown:'模型结果未知'};
  function renderAutomaticAI() {
    const section=$('automatic-ai-section'); if(!section) return;
    const value=state.automaticStatus?.ai;
    section.hidden=!automaticSupported() || state.capabilities?.automatic_ai!==true || !value;
    const summary=$('automatic-ai-summary'),requests=$('automatic-ai-requests'),alerts=$('automatic-ai-alerts');
    [summary,requests,alerts].forEach(clear); if(section.hidden) return;
    const stale=Boolean(state.automaticError || state.automaticBusy);
    summary.append(node('strong','',stale?'读取中或状态待核实':value.enabled===true?'已配置自动 AI 分析许可':'自动 AI 分析未启用'));
    summary.append(node('p','small muted','模型分析每日上限 '+automaticCount(value.policy?.max_analyses_per_day)+'，本次授权上限 '+automaticCount(value.policy?.max_total_analyses)+'。执行另需当前 Root 授权、窗口和配额。'));
    for(const [host,quota] of Object.entries(value.quotas || {})) summary.append(node('p','small muted',host+'：当日分析 '+automaticCount(quota?.daily_used)+' / '+automaticCount(value.policy?.max_analyses_per_day)+'，本次授权分析 '+automaticCount(quota?.total_used)+' / '+automaticCount(value.policy?.max_total_analyses)));
    if(value.last_error) summary.append(node('p','notice',String(value.last_error)));
    if(Array.isArray(value.requests)) for(const request of value.requests.slice(0,30)) {
      const item=node('article','automatic-repair-job');
      item.append(node('strong','',vulnerabilityAIStates[request.status] || '分析状态待核实'),node('p','mono small',String(request.host_id || '')+' · '+String(request.analysis_id || '')));
      item.append(node('p','small muted','更新于 '+automaticUTC(request.updated_at)+'；同一候选不因新扫描重复请求模型。')); requests.append(item);
    }
    if(Array.isArray(value.alerts)) for(const alert of value.alerts.slice(0,30)) {
      const item=node('article','automatic-repair-job');
      item.append(node('strong','',automaticAIKinds[alert.kind] || '需核对的自动事件'),node('p','small',String(alert.detail || '')),
        node('p','mono small',String(alert.host_id || '')+(alert.job_id?' · '+String(alert.job_id):'')));
      if(alert.acknowledged) item.append(node('span','small muted','已阅'));
      else {
        const ack=node('button','button','标记已阅'); ack.type='button';ack.disabled=stale;
        ack.addEventListener('click',async()=>{
          const session=state.session;ack.disabled=true;
          try { await api('/api/automatic/ai/alerts/'+encodeURIComponent(alert.id)+'/ack',{method:'POST'});if(session===state.session) await refreshAutomatic({quiet:true}); }
          catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session) { state.automaticError='告警已阅状态未能保存：'+errorMessage(cause);renderAutomatic(); } }
        });item.append(ack);
      }
      alerts.append(item);
    }
    if(!value.alerts?.length) alerts.append(node('p','small muted','尚无自动 AI 告警。'));
  }
  async function refreshAutomatic({quiet=false}={}) {
    if(!state.token || !automaticSupported() || state.automaticBusy) return;
    const session=state.session,request=++state.automaticRequest; state.automaticBusy=true; state.automaticError=''; stopAutomaticPolling(); renderAutomatic();
    try {
      const value=automaticPayload(await api('/api/automatic/status'));
      if(session!==state.session || request!==state.automaticRequest) return;
      state.automaticStatus=value; state.automaticReadAt=new Date().toISOString();
      if(automaticRecoverySupported()) {
        try {
          const records=Array.isArray(value.recoveries)?value.recoveries:await api('/api/automatic/recoveries');
          if(session!==state.session || request!==state.automaticRequest) return;
          state.automaticRecoveryRecords=checkedAutomaticRecoveries(records); state.automaticRecoveryNeedsRefresh=false;
          const ref=state.automaticRecoveryRef,updated=ref?state.automaticRecoveryRecords.find(item=>item.host_id===ref.host_id && item.recovery_id===ref.recovery_id):null;
          if(updated) acceptAutomaticRecovery(updated,ref);
          if(state.automaticRecoveryPlan && !automaticRecoveryContext(state.automaticRecoveryPlan)) invalidateAutomaticRecoveryPlan('模式或暂停上下文已变化，旧恢复确认已取消。');
        } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.automaticRequest) { state.automaticRecoveryRecords=null; state.automaticRecoveryError='恢复审计读取未完成：'+errorMessage(cause)+' 未核实前不创建新恢复。'; } }
      }
      if(!quiet) announce('已读取自动处置状态，未创建或重试任何任务。');
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && session===state.session && request===state.automaticRequest) state.automaticError='自动状态读取未完成：'+errorMessage(cause)+' 历史快照不能证明当前授权、窗口或任务状态。';
    } finally { if(session===state.session && request===state.automaticRequest) { state.automaticBusy=false; renderAutomatic(); scheduleAutomaticPolling(); } }
  }

  const automaticRecoveryStates={prepared:'已生成核验预览 · 尚未批准',submission_intent:'已登记恢复意图 · 结果待核实',unknown:'恢复结果未知 · 只查询原记录',verified:'恢复核验通过',rejected:'恢复被拒绝 · 暂停保留',superseded:'上下文已变化，原恢复未解除当前暂停'};
  const automaticRecoveryChecks={original_job_verified:['原补丁任务已验收','原自动任务须已完成明确验证，不能以安装返回成功代替。'],ledger_settled:['其它事务均已对账','不能有进行中、未知或等待验收的其它事务。'],original_plan_intact:['原方案与包身份完整','原任务、方案、软件包及当前允许范围须相互匹配。'],exact_package_version:['当前软件版本匹配','实际安装版本须等于原方案明确批准的候选版本。'],apt_configuration_safe:['软件来源与包管理配置可信','重新检查归档来源和当前有效的包管理配置。'],package_inventory:['当前软件清单可核实','未能取得当前清单时不能恢复。'],registered_health:['登记服务与站点检查通过','包状态、登记服务和只读 HTTP 检查须全部符合。'],no_reboot_pending:['没有重启待办','存在重启待办时保留暂停。'],runtime_complete:['运行时检查完整','须有安装前文件清单并完成旧文件及当前文件的进程映射检查。'],vendor_rescan:['同一漏洞记录复扫通过','需要新鲜且完整的逐条供应商证据明确确认本条不受影响。'],root_pause_job:['远端暂停关联原任务','另一个原任务触发的暂停必须先完成对应对账。'],original_job_unchanged:['原任务状态保持一致','批准时原任务修订与摘要必须仍匹配此预览。'],fresh_ssh:['新的 SSH 管理连接','批准时重新确认预览检查之后建立的管理连接。']};
  function automaticRecoverySupported() { return automaticSupported() && state.capabilities?.automatic_recovery===true; }
  Object.assign(automaticRecoveryChecks,{final_package_state:['核验末尾的软件状态仍一致','慢检查结束后再次核对实际版本、软件来源和包管理摘要。'],final_ledger_settled:['核验末尾没有新增未决事务','完成核验时再次确认原任务及其它事务均已对账。'],policy_unchanged:['当前部署策略保持一致','最后核对策略与受信任执行器源码仍匹配这份预览。']});
  function recoveryIdentifier(value) { return typeof value==='string' && /^[0-9a-f]{32}$/.test(value); }
  function recoveryDigest(value) { return typeof value==='string' && /^[0-9a-f]{64}$/.test(value); }
  function recoveryTimestamp(value) { return typeof value==='string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value)); }
  function checkedAutomaticRecovery(value,ref=null) {
    if(!value || !remediationToken(value.host_id) || !recoveryIdentifier(value.recovery_id) || !Object.hasOwn(automaticRecoveryStates,value.status) || !recoveryDigest(value.recovery_digest) || (ref && (value.host_id!==ref.host_id || value.recovery_id!==ref.recovery_id || ref.recovery_digest && value.recovery_digest!==ref.recovery_digest))) throw new Error('恢复记录与原目标、恢复 ID 或摘要不一致。');
    return value;
  }
  function checkedAutomaticRecoveries(value) {
    if(!Array.isArray(value) || value.length>100 || !value.every(record=>{try { checkedAutomaticRecovery(record); return true; } catch { return false; }}) || new Set(value.map(record=>record.host_id+'\n'+record.recovery_id)).size!==value.length) throw new Error('恢复审计缺少有效的原记录。');
    return value;
  }
  function automaticRecoveryPending(host) {
    const local=state.automaticRecoveryRef;
    return Boolean(local?.host_id===host && local.uncertain) || (state.automaticRecoveryRecords || []).some(record=>record.host_id===host && (['submission_intent','unknown'].includes(record.status) || record.status==='verified' && record.local_released!==true));
  }
  function automaticRecoveryMode() {
    const current=state.automaticStatus,mode=state.automation;
    return Boolean(automaticRecoverySupported() && current && mode && current.mode==='manual' && current.mode_sync_complete===true && mode.mode==='manual' && mode.mode_sync_complete===true && current.mode_revision===mode.revision && state.automationDraft==='manual' && !state.automationNeedsReload && !state.automationBusy);
  }
  function automaticRecoveryPolicy(host) {
    const policy=state.automation?.policy;
    return Boolean(policy?.enabled===true && Array.isArray(policy.allowed_actions) && policy.allowed_actions.includes('os_security_upgrade') && Array.isArray(policy.host_ids) && policy.host_ids.includes(host));
  }
  function automaticRecoveryCanPrepare(host,latch) {
    const saved=host.latch || state.automaticStatus?.latched_hosts.find(item=>item.host_id===host.host_id);
    return Boolean(state.token && automaticRecoveryMode() && automaticRecoveryPolicy(host.host_id) && !state.automaticBusy && !state.automaticError && !state.automaticRecoveryBusy && !state.automaticRecoveryNeedsRefresh && Array.isArray(state.automaticRecoveryRecords) && recoveryIdentifier(latch?.job_id) && saved?.job_id===latch.job_id && !automaticRecoveryPending(host.host_id));
  }
  function automaticRecoveryContext(plan) {
    if(!plan || !automaticRecoveryMode() || !automaticRecoveryPolicy(plan.host_id) || plan.mode_revision!==state.automation.revision) return false;
    const host=state.automaticStatus.hosts.find(item=>item.host_id===plan.host_id);
    const latch=host?.latch || state.automaticStatus.latched_hosts.find(item=>item.host_id===plan.host_id);
    return Boolean(host && latch && latch.job_id===plan.job_id && !automaticRecoveryPending(plan.host_id));
  }
  function automaticRecoveryCanApprove(plan) {
    return Boolean(plan && automaticRecoveryContext(plan) && !state.automaticRecoveryBusy && !state.automaticBusy && !state.automaticError && !state.automaticRecoveryNeedsRefresh && plan.eligible===true && Array.isArray(plan.blockers) && !plan.blockers.length && Array.isArray(plan.checks) && plan.checks.length && plan.checks.every(check=>check?.status==='passed') && Date.parse(plan.expires_at)>Date.now());
  }
  function checkedAutomaticRecoveryPlan(value,host,job,revision) {
    const start=Date.parse(value?.created_at),expiry=Date.parse(value?.expires_at);
    if(!value || value.schema_version!==1 || value.host_id!==host || value.job_id!==job || !recoveryIdentifier(value.recovery_id) || !recoveryDigest(value.recovery_digest) || !recoveryDigest(value.policy_digest) || !recoveryDigest(value.driver_source_digest) || !recoveryDigest(value.job_digest) || !recoveryDigest(value.context_digest) || !Number.isSafeInteger(value.job_revision) || value.job_revision<0 || value.mode_revision!==revision || typeof value.eligible!=='boolean' || !Array.isArray(value.checks) || !value.checks.every(check=>check && typeof check.id==='string' && ['passed','failed','unavailable'].includes(check.status) && typeof check.detail==='string') || !Array.isArray(value.blockers) || !value.blockers.every(item=>typeof item==='string') || !recoveryTimestamp(value.created_at) || !recoveryTimestamp(value.expires_at) || !Number.isFinite(start) || !Number.isFinite(expiry) || start>Date.now()+5000 || expiry<=Date.now() || expiry-start<=0 || expiry-start>300000) throw new Error('恢复方案的目标、证据、模式版本或有效期未能核实。');
    return value;
  }
  function dismissAutomaticRecoveryDialog() {
    if(state.automaticRecoveryExpiry!==null) window.clearTimeout(state.automaticRecoveryExpiry);
    state.automaticRecoveryExpiry=null; state.automaticRecoveryDialogTarget=null;
    $('automatic-recovery-confirm').checked=false; $('automatic-recovery-execute').disabled=true; $('automatic-recovery-dialog-error').hidden=true; $('automatic-recovery-dialog-error').textContent='';
    if($('automatic-recovery-dialog').open) $('automatic-recovery-dialog').close();
  }
  function invalidateAutomaticRecoveryPlan(reason='') {
    dismissAutomaticRecoveryDialog(); state.automaticRecoveryPlan=null;
    if(reason) state.automaticRecoveryError=reason;
  }
  function automaticRecoveryPlanContent(container,plan) {
    clear(container); const host=state.automaticStatus?.hosts.find(item=>item.host_id===plan.host_id);
    container.append(node('h3','',host?.name || plan.host_id),detailList([['登记目标',plan.host_id],['原补丁任务',plan.job_id],['原任务修订',String(plan.job_revision)],['当前模式修订',String(plan.mode_revision)],['核验结果',plan.eligible?'符合当前恢复条件':'未符合恢复条件，暂停保留'],['核验时间',automaticUTC(plan.created_at)],['方案到期',automaticUTC(plan.expires_at)],['当前每日 / 累计用量',automaticCount(host?.quota?.daily_used)+' / '+automaticCount(host?.quota?.total_used)],['用量与授权','保持既有计数和授权，不切换自动模式']]));
    const evidence=plan.verification;
    if(evidence && typeof evidence==='object') {
      const pairs=[];
      if(evidence.exact_package_version) pairs.push(['批准的候选版本',evidence.exact_package_version.expected || '未取得'],['当前实际版本',evidence.exact_package_version.observed || '未取得']);
      if(evidence.runtime) pairs.push(['运行时覆盖',evidence.runtime.status==='complete'?'本次检查完整':'未完整核实'],['旧映射进程',automaticCount(evidence.runtime.outdated_process_count)]);
      if(Array.isArray(evidence.health?.services)) for(const service of evidence.health.services.slice(0,10)) pairs.push(['登记服务 '+String(service.service || '未提供'),service.active===true?'当前 active':'未确认 active']);
      if(Array.isArray(evidence.health?.http)) for(const http of evidence.health.http.slice(0,10)) pairs.push(['站点检查 '+String(http.id || '未提供'),(http.passed===true?'符合':'未通过')+' · HTTP '+String(http.status ?? '未取得')]);
      if(pairs.length) container.append(detailList(pairs));
    }
    const checks=node('ul','automatic-recovery-checks');
    for(const check of plan.checks.slice(0,40)) { const item=node('li',''),copy=automaticRecoveryChecks[check.id]; item.append(node('strong','',({passed:'通过',failed:'未通过',unavailable:'未核实'}[check.status])+' · '+(copy?.[0] || check.id)),node('p','small muted',copy?.[1] || check.detail)); const raw=node('details','automatic-recovery-check-source'); raw.append(node('summary','','查看服务端核验记录'),node('p','mono small',check.id),node('p','small muted',check.detail)); item.append(raw); checks.append(item); }
    container.append(checks);
    if(plan.blockers.length) { const blockers=node('ul','plain-list'); for(const entry of plan.blockers.slice(0,40)) blockers.append(node('li','',automaticRecoveryChecks[entry]?.[0] || entry)); const note=node('div','notice'); note.append(node('strong','','当前不能恢复'),blockers); container.append(note); }
    const binding=node('details','automatic-recovery-binding'); binding.append(node('summary','','核对这份恢复方案的绑定'),detailList([['恢复 ID',plan.recovery_id],['恢复摘要',plan.recovery_digest],['策略摘要',plan.policy_digest],['原任务摘要',plan.job_digest],['上下文摘要',plan.context_digest]])); container.append(binding);
  }
  function acceptAutomaticRecovery(value,ref) {
    const record=checkedAutomaticRecovery(value,ref); state.automaticRecoveryRecord=record;
    state.automaticRecoveryRef={host_id:record.host_id,recovery_id:record.recovery_id,recovery_digest:record.recovery_digest,uncertain:['submission_intent','unknown'].includes(record.status) || ref?.uncertain && record.status==='prepared'};
    if(['verified','rejected','superseded'].includes(record.status)) state.automaticRecoveryError='';
    const records=state.automaticRecoveryRecords || []; state.automaticRecoveryRecords=[record,...records.filter(item=>item.host_id!==record.host_id || item.recovery_id!==record.recovery_id)];
    return record;
  }
  function renderAutomaticRecovery() {
    const supported=automaticRecoverySupported(),section=$('automatic-recovery-section'),records=$('automatic-recovery-records'); section.hidden=!supported; clear(records);
    $('automatic-recovery-error').textContent=state.automaticRecoveryError; $('automatic-recovery-error').hidden=!state.automaticRecoveryError;
    $('automatic-recovery-progress').textContent={prepare:'正在核对原任务、包状态与登记服务；不安装或重启。',submit:'恢复意图已固定，正在核验；不会重复提交。',query:'只查询原恢复 ID，不重新批准。'}[state.automaticRecoveryBusy] || '';
    if(!supported) return;
    const rows=[...(state.automaticRecoveryRecords || [])],ref=state.automaticRecoveryRef;
    if(ref && !rows.some(row=>row.host_id===ref.host_id && row.recovery_id===ref.recovery_id)) rows.unshift({...ref,status:'unknown',detail:'提交结果尚未确认；原恢复 ID 已保留，只能查询。'});
    if(!rows.length) records.append(node('p','empty-note',state.automaticRecoveryRecords===null?'尚未取得恢复审计；不能据此发起恢复。':'尚无恢复记录。暂停不会因刷新或模式选择而解除。'));
    for(const record of rows.slice(0,30)) {
      const item=node('article','automatic-recovery-record'); item.dataset.recoveryId=record.recovery_id;
      const uncertain=ref?.host_id===record.host_id && ref.recovery_id===record.recovery_id && ref.uncertain;
      const released=record.status==='verified' && record.local_released===true,label=uncertain?'恢复结果未知 · 只查询原记录':released?'已完成核验并解除这次暂停':record.status==='verified'?'核验通过 · 本地恢复状态仍待核实':automaticRecoveryStates[record.status] || '恢复状态未确认';
      item.append(node('strong','',label),node('p','mono small',String(record.host_id)+' · 恢复 '+String(record.recovery_id)),node('p','mono small','原任务：'+String(record.job_id || record.plan?.job_id || '未提供')));
      if(record.latch_before) item.append(node('p','small','原暂停：'+automaticPauseReason(record.latch_before.reason)),node('p','small muted','原暂停时间：'+automaticUTC(record.latch_before.latched_at)));
      if(record.detail) item.append(node('p','small muted',record.detail));
      item.append(node('p','small muted','确认时间：'+automaticUTC(record.confirmed_at)+'；更新于 '+automaticUTC(record.updated_at)),node('p','small muted','原任务与已用配额继续保留；恢复记录不启用自动模式。'));
      const query=node('button','button','查询原恢复记录'); query.type='button'; query.dataset.queryRecovery=record.recovery_id; query.disabled=Boolean(state.automaticRecoveryBusy); query.addEventListener('click',()=>queryAutomaticRecovery({host_id:record.host_id,recovery_id:record.recovery_id,recovery_digest:record.recovery_digest,uncertain:ref?.recovery_id===record.recovery_id && ref.uncertain})); item.append(query);
      if(record.receipt) remediationDetails(item,'查看本次恢复回执',record.receipt);
      records.append(item);
    }
    if(rows.length>30) records.append(node('p','small muted','此处展示最近 30 条恢复审计。'));
    if(state.automaticRecoveryDialogTarget) $('automatic-recovery-execute').disabled=!$('automatic-recovery-confirm').checked || !automaticRecoveryCanApprove(state.automaticRecoveryDialogTarget.plan);
  }
  async function prepareAutomaticRecovery(host,latch) {
    if(!automaticRecoveryCanPrepare(host,latch)) return;
    invalidateAutomaticRecoveryPlan(); const session=state.session,request=++state.automaticRecoveryRequest,revision=state.automaticStatus.mode_revision;
    state.automaticRecoveryBusy='prepare'; state.automaticRecoveryError=''; stopAutomaticPolling(); renderAutomation(); renderAutomatic();
    try {
      const value=await api('/api/automatic/recovery-plans',{method:'POST',body:{host_id:host.host_id,job_id:latch.job_id,expected_mode_revision:revision}});
      if(session!==state.session || request!==state.automaticRecoveryRequest || state.view!=='remediation') return;
      const plan=checkedAutomaticRecoveryPlan(value,host.host_id,latch.job_id,revision);
      if(!automaticRecoveryContext(plan)) throw new Error('核验期间模式或原暂停已变化，请重新读取。');
      state.automaticRecoveryPlan=plan; state.automaticRecoveryDialogTarget={plan,session}; automaticRecoveryPlanContent($('automatic-recovery-dialog-summary'),plan);
      $('automatic-recovery-confirm').checked=false; $('automatic-recovery-confirm').disabled=plan.eligible!==true || plan.blockers.length>0 || !plan.checks.every(check=>check.status==='passed');
      $('automatic-recovery-dialog').showModal(); $('automatic-recovery-dialog-title').tabIndex=-1; $('automatic-recovery-dialog-title').focus();
      state.automaticRecoveryExpiry=window.setTimeout(()=>{if(state.automaticRecoveryDialogTarget?.plan===plan) { invalidateAutomaticRecoveryPlan('恢复方案已过期，确认已取消。请重新核对。'); renderAutomatic(); }},Math.max(0,Date.parse(plan.expires_at)-Date.now()));
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.automaticRecoveryRequest) state.automaticRecoveryError='恢复条件未能核实：'+errorMessage(cause)+' 暂停继续保留。'; }
    finally { if(session===state.session && request===state.automaticRecoveryRequest) { state.automaticRecoveryBusy=''; renderAutomation(); renderAutomatic(); scheduleAutomaticPolling(); } }
  }
  async function executeAutomaticRecovery() {
    const target=state.automaticRecoveryDialogTarget,plan=target?.plan;
    if(!target || target.session!==state.session || !$('automatic-recovery-confirm').checked || !automaticRecoveryCanApprove(plan)) return;
    const session=state.session,request=++state.automaticRecoveryRequest,ref={host_id:plan.host_id,recovery_id:plan.recovery_id,recovery_digest:plan.recovery_digest,uncertain:true};
    state.automaticRecoveryRef=ref; state.automaticRecoveryRecord=null; state.automaticRecoveryBusy='submit'; state.automaticRecoveryError=''; state.automaticRecoveryNeedsRefresh=true;
    dismissAutomaticRecoveryDialog(); state.automaticRecoveryPlan=null; stopAutomaticPolling(); renderAutomation(); renderAutomatic();
    try {
      const value=await api('/api/automatic/recoveries',{method:'POST',body:{host_id:ref.host_id,recovery_id:ref.recovery_id,expected_recovery_digest:ref.recovery_digest,expected_mode_revision:plan.mode_revision,confirm_recover:true}});
      if(session!==state.session || request!==state.automaticRecoveryRequest) return;
      const record=acceptAutomaticRecovery(value,ref);
      announce(record.status==='verified' && record.local_released===true?'恢复核验已完成，原任务与配额保留；没有启用自动模式。':'恢复结果已记录；继续核对原恢复 ID，暂停不会自动清除。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.automaticRecoveryRequest) state.automaticRecoveryError='恢复提交结果未确认：'+errorMessage(cause)+' 已保留原恢复 ID，只查询该记录，不重复批准。'; }
    finally { if(session===state.session && request===state.automaticRecoveryRequest) { state.automaticRecoveryBusy=''; renderAutomation(); renderAutomatic(); refreshAutomatic({quiet:true}); } }
  }
  async function queryAutomaticRecovery(ref) {
    if(!state.token || !automaticRecoverySupported() || state.automaticRecoveryBusy || !remediationToken(ref.host_id) || !recoveryIdentifier(ref.recovery_id)) return;
    const session=state.session,request=++state.automaticRecoveryRequest; state.automaticRecoveryBusy='query'; state.automaticRecoveryError=''; renderAutomation(); renderAutomatic();
    try {
      const value=await api('/api/automatic/recoveries/'+encodeURIComponent(ref.host_id)+'/'+encodeURIComponent(ref.recovery_id));
      if(session!==state.session || request!==state.automaticRecoveryRequest) return;
      acceptAutomaticRecovery(value,ref);
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.automaticRecoveryRequest) state.automaticRecoveryError='原恢复记录读取未完成：'+errorMessage(cause)+' 不能据此判断未恢复，请保留原 ID 继续核对。'; }
    finally { if(session===state.session && request===state.automaticRecoveryRequest) { state.automaticRecoveryBusy=''; renderAutomation(); renderAutomatic(); refreshAutomatic({quiet:true}); } }
  }
  function vulnerabilityGapLabel(value) { return vulnerabilityGapLabels[value] || (/^[a-z][a-z0-9_]*$/.test(value)?'尚未识别的覆盖提示：'+value:value); }
  function vulnerabilityWatchSupported() { return state.capabilities?.vulnerability_watch===true; }
  function vulnerabilityWatchTime(value) { return typeof value==='string' && value?dateLabel(value):'未记录'; }
  function vulnerabilityWatchName(id) { return remediationList(state.vulnerabilityWatchStatus?.hosts).find(host=>host.host_id===id)?.name || state.hosts.find(host=>host.id===id)?.name || id || '目标未确认'; }
  function vulnerabilityWatchCoverage(value) { const key=typeof value==='string'?value:value?.status; return {complete:'本轮数据完整',partial:'本轮仅覆盖部分',unavailable:'本轮数据不可用'}[key] || '覆盖范围未确认'; }
  function vulnerabilityWatchEventValid(value) { return Boolean(value && typeof value.id==='string' && /^[0-9a-f]{64}$/.test(value.id) && remediationToken(value.host_id) && typeof value.scope_hash==='string' && /^[0-9a-f]{64}$/.test(value.scope_hash)); }
  function vulnerabilityWatchCondition(event) {
    const finding=event.evidence?.finding,confirmed=finding?.affected===true && finding.vendor_evidence_fresh===true && finding.finding_evidence_complete===true;
    if(event.kind==='vulnerability_confirmed') {
      if(event.condition==='not_affected_on_rescan') return finding?.affected===false && finding.vendor_evidence_fresh===true && finding.finding_evidence_complete===true?'本条复扫不再受影响':'复扫结论仍待核实';
      if(event.condition==='patch_available') return confirmed?(finding.candidate_fixable===true?'确认受影响 · 有修复候选':'确认受影响 · 修复条件待满足'):'受影响依据仍待核实';
      if(event.condition==='patch_unavailable') return confirmed?'确认受影响 · 修复条件待满足':'受影响依据仍待核实';
      if(event.condition==='no_patch') return confirmed?'确认受影响 · 暂无可用补丁':'受影响依据仍待核实';
      return '漏洞条件仍待核实';
    }
    if(event.kind==='scan_coverage') return {partial:'扫描覆盖存在缺口',unavailable:'扫描证据暂不可用',complete:'扫描读取已恢复'}[event.condition] || '扫描覆盖仍待核实';
    return '观察通知类型待核实';
  }
  function stopVulnerabilityWatchPolling() { if(state.vulnerabilityWatchTimer!==null) window.clearTimeout(state.vulnerabilityWatchTimer); state.vulnerabilityWatchTimer=null; }
  function scheduleVulnerabilityWatchPolling() {
    stopVulnerabilityWatchPolling();
    if(state.token && state.view==='remediation' && vulnerabilityWatchSupported() && !document.hidden && !state.vulnerabilityWatchBusy && state.vulnerabilityWatchAckBusy===null) state.vulnerabilityWatchTimer=window.setTimeout(()=>refreshVulnerabilityWatch({quiet:true}),30000);
  }
  function vulnerabilityWatchGaps(parent,gaps) {
    if(!Array.isArray(gaps) || !gaps.length) return;
    const list=node('ul','plain-list vulnerability-watch-gaps');
    for(const gap of gaps.slice(0,20)) list.append(node('li','',typeof gap==='string'?vulnerabilityGapLabel(gap):remediationJSON(gap)));
    if(gaps.length>20) list.append(node('li','','还有 '+String(gaps.length-20)+' 条覆盖提示未展开。'));
    parent.append(list);
  }
  function vulnerabilityWatchVendorLinks(parent,values) {
    if(!Array.isArray(values) || !values.length) return;
    const list=node('ul','plain-list vulnerability-watch-links');
    for(const raw of values.slice(0,10)) {
      const item=node('li');
      let accepted=false;
      try { const url=new URL(raw); accepted=url.protocol==='https:' && !url.username && !url.password && (!url.port || url.port==='443') && ((url.hostname==='ubuntu.com' && url.pathname.startsWith('/security/')) || (url.hostname==='security-metadata.canonical.com' && url.pathname.startsWith('/'))); } catch { /* Unrecognized evidence remains text only. */ }
      if(accepted) { const link=node('a','',raw); link.href=raw; link.target='_blank'; link.rel='noopener noreferrer'; item.append(link); }
      else item.append(node('span','','未识别的证据链接：'+String(raw)));
      list.append(item);
    }
    parent.append(list);
  }
  function renderVulnerabilityWatchSummary() {
    const summary=$('vulnerability-watch-summary'),hosts=$('vulnerability-watch-hosts'); clear(summary); clear(hosts);
    const value=state.vulnerabilityWatchStatus;
    if(!value) { summary.append(node('p','empty-note',state.vulnerabilityWatchBusy?'正在读取后台定期观察状态…':'尚未取得定期观察记录，不能据此确认服务器安全。')); return; }
    const label=!value.enabled?'定期扫描未启用':value.running?'后台定期扫描运行中':'已启用 · 当前运行状态待核对';
    summary.append(node('strong','',label),node('p','small muted',!value.enabled?'当前没有定期扫描安排；按需扫描仍需主动发起。':'按部署端登记范围只读扫描，每 '+String(value.interval_seconds)+' 秒一轮；通知保存在本控制台。'));
    summary.append(node('p','small muted','最近读取：'+vulnerabilityWatchTime(state.vulnerabilityWatchReadAt)+'。完整、部分和不可用分别记录；没有告警不等于整机没有漏洞。'));
    if(value.webhook?.configured===true) {
      const counts=value.webhook.counts;
      const count=key=>Number.isSafeInteger(counts?.[key]) && counts[key]>=0?String(counts[key]):'未知';
      const retired=Number.isSafeInteger(counts?.retired) && counts.retired>=0?' · 已清理旧目标待发 '+count('retired'):'';
      summary.append(node('p','small muted',(value.webhook.running===true?'签名 Webhook 运行中':'签名 Webhook 已配置，运行状态待核对')+'。待发送 '+count('pending')+' · 发送中 '+count('sending')+' · 已送达 '+count('delivered')+' · 失败 '+count('rejected')+' · 队列满未登记 '+count('dropped')+retired));
    }
    if(typeof value.last_error==='string' && value.last_error) summary.append(node('p','notice','最近一次后台读取未完成：'+value.last_error+' 最近成功时间只供追溯。'));
    if(!value.hosts.length) hosts.append(node('p','empty-note','尚无定期扫描目标；这里只展示部署端明确登记的范围。'));
    for(const host of value.hosts) {
      const labels={starting:'等待首次扫描',stopped:'扫描已停止',complete:'本轮数据完整',partial:'本轮仅覆盖部分',unavailable:'证据不可用',busy:'正在扫描或等待入口',scanning:'正在扫描'};
      const card=node('article','vulnerability-watch-host'),head=node('div','vulnerability-watch-host-heading'); card.dataset.vulnerabilityWatchHost=host.host_id;
      head.append(node('h3','',host.name || host.host_id),node('span','badge '+(host.status==='complete'?'neutral':'amber'),labels[host.status] || '扫描状态待核实')); card.append(head);
      card.append(detailList([['最近尝试',vulnerabilityWatchTime(host.last_attempt)],['最近成功读取',vulnerabilityWatchTime(host.last_success)],['下次计划',value.enabled?vulnerabilityWatchTime(host.next_scan):'未安排'],['本轮覆盖',vulnerabilityWatchCoverage(host.coverage || host.status)]]));
      if(host.detail) card.append(node('p','small muted',host.detail));
      const totals=host.summary;
      if(totals && typeof totals==='object') {
        const count=key=>Number.isSafeInteger(totals[key]) && totals[key]>=0?String(totals[key]):'未知';
        card.append(node('p','small muted','确认受影响记录 '+count('confirmed_affected')+' · 修复候选 '+count('patch_available')+' · 条件待满足 '+count('patch_blocked')+' · 暂无补丁 '+count('no_patch')+' · 待评估 '+count('needs_vendor_review')));
      }
      card.append(node('p','mono small','范围 '+host.scope_hash)); hosts.append(card);
    }
  }
  function renderVulnerabilityWatchAlerts() {
    const list=$('vulnerability-watch-alert-list'); clear(list);
    const alerts=state.vulnerabilityWatchAlerts,unread=alerts.filter(value=>value.status==='open').length;
    $('vulnerability-watch-count').textContent=String(alerts.length)+' 条记录 · '+String(unread)+' 条待阅';
    if(!alerts.length) { list.append(node('p','empty-note','当前没有已保存的观察通知；仍需结合覆盖范围、时间与未评估项核对。')); return; }
    for(const alert of alerts.slice(0,100)) {
      const button=node('button','vulnerability-watch-alert'); button.type='button'; button.dataset.vulnerabilityWatchAlert=alert.id; button.disabled=state.vulnerabilityWatchBusy || state.vulnerabilityWatchAckBusy!==null;
      if(alert.id===state.vulnerabilityWatchSelected) button.setAttribute('aria-pressed','true');
      const meta=node('div','vulnerability-watch-alert-meta'); meta.append(node('span','badge '+(alert.status==='acknowledged'?'neutral':'amber'),alert.status==='acknowledged'?'已阅':alert.status==='open'?'待阅':'已阅状态待核对'),node('span','small muted',vulnerabilityWatchName(alert.host_id)));
      button.append(meta,node('strong','',alert.title || vulnerabilityWatchCondition(alert)),node('p','small',vulnerabilityWatchCondition(alert)),node('p','small muted',vulnerabilityWatchTime(alert.last_seen)));
      button.addEventListener('click',()=>selectVulnerabilityWatchAlert(alert.id)); list.append(button);
    }
    if(alerts.length>100) list.append(node('p','small muted','仅展示前 100 条，共 '+String(alerts.length)+' 条；展示范围不能当作完整扫描范围。'));
  }
  function renderVulnerabilityWatchDetail() {
    const parent=$('vulnerability-watch-detail'); clear(parent); const value=state.vulnerabilityWatchDetail;
    if(state.vulnerabilityWatchDetailBusy) { parent.append(node('p','empty-note','正在读取这条观察通知的证据…')); return; }
    if(!value) { parent.append(node('p','empty-note','选择一条通知，核对具体扫描时间、供应商依据和覆盖范围。')); return; }
    const evidence=value.evidence && typeof value.evidence==='object'?value.evidence:{},finding=evidence.finding;
    parent.append(node('p','eyebrow','Evidence and follow-up'),node('h3','',value.title || '漏洞观察通知'),node('p','vulnerability-watch-condition',vulnerabilityWatchCondition(value)),node('p','small muted',value.detail || '请结合本次证据核对，不能只凭通知标题判断。'));
    parent.append(detailList([['目标',vulnerabilityWatchName(value.host_id)],['首次记录',vulnerabilityWatchTime(value.first_seen)],['最近记录',vulnerabilityWatchTime(value.last_seen)],['已阅状态',value.status==='acknowledged'?'已阅 · 不代表风险解除':'待阅'],['通知次数',Number.isSafeInteger(value.notification_count)?value.notification_count:'未提供']]));
    const action=node('div','vulnerability-watch-actions'),ack=node('button','button','标记已阅'); ack.type='button'; ack.id='ack-vulnerability-watch'; ack.disabled=value.status!=='open' || state.vulnerabilityWatchAckBusy!==null || state.vulnerabilityWatchBusy; ack.textContent=state.vulnerabilityWatchAckBusy===value.id?'正在记录…':value.status==='acknowledged'?'已记录已阅':'标记已阅'; ack.addEventListener('click',()=>acknowledgeVulnerabilityWatch(value.id)); action.append(ack,node('p','small muted','已阅只记录核对进度；不会安装补丁、关闭漏洞或清除其他通知。')); parent.append(action);
    parent.append(node('h3','vulnerability-watch-evidence-heading','本次扫描依据'),detailList([['采集时间',vulnerabilityWatchTime(evidence.collected_at)],['覆盖状态',vulnerabilityWatchCoverage(evidence.coverage)],['扫描标识',evidence.scan_id || '未提供'],['观察标识',evidence.observation_id || '未提供']]));
    if(evidence.evidence_origin==='controlled_lab') parent.append(node('p','notice neutral','受控漏洞实验记录：只代表实验环境，不能作为物理宿主漏洞已清除的结论。'));
    vulnerabilityWatchGaps(parent,evidence.gaps);
    if(finding && typeof finding==='object') {
      parent.append(detailList([['软件包',finding.package || '未提供'],['公告',finding.advisory || '未提供'],['CVE',Array.isArray(finding.cve)?finding.cve.join('、'):finding.cve || '未提供'],['当前版本',finding.current_version || '未提供'],['供应商修复版',finding.fixed_binary_version || '未提供'],['具体证据',finding.finding_evidence_complete===true && finding.vendor_evidence_fresh===true?'本条依据完整且新鲜':'本条依据仍需补齐或更新'],['供应商摘要',finding.vendor_record_digest || '未提供']]));
      vulnerabilityWatchVendorLinks(parent,finding.evidence_urls);
    }
    if(value.condition==='not_affected_on_rescan') parent.append(node('p','notice neutral','本条复扫结论只适用于当前软件包及供应商记录；不代表整机、其他漏洞或未覆盖业务均已安全。'));
    parent.append(node('p','mono small','记录 '+value.id+' · 范围 '+value.scope_hash));
  }
  function renderVulnerabilityWatch() {
    const supported=vulnerabilityWatchSupported(); $('vulnerability-watch-section').hidden=!supported;
    $('vulnerability-watch-boundary-copy').textContent=automaticSupported()?'此观察器按登记范围只读扫描，本页只读取记录。独立的自动处置后台另行核对预授权条件，以前述各目标状态为准。':'后台按登记范围只读扫描，本页只读取记录；发现漏洞不会自动安装补丁。';
    if(!supported) {
      ['vulnerability-watch-summary','vulnerability-watch-hosts','vulnerability-watch-alert-list','vulnerability-watch-detail'].forEach(id=>clear($(id)));
      $('vulnerability-watch-count').textContent=''; $('vulnerability-watch-error').textContent=''; $('vulnerability-watch-error').hidden=true; $('refresh-vulnerability-watch').disabled=true; return;
    }
    $('refresh-vulnerability-watch').disabled=state.vulnerabilityWatchBusy || state.vulnerabilityWatchAckBusy!==null;
    $('refresh-vulnerability-watch').textContent=state.vulnerabilityWatchBusy?'正在读取观察…':'刷新定期观察';
    $('vulnerability-watch-error').textContent=state.vulnerabilityWatchError; $('vulnerability-watch-error').hidden=!state.vulnerabilityWatchError;
    renderVulnerabilityWatchSummary(); renderVulnerabilityWatchAlerts(); renderVulnerabilityWatchDetail();
  }
  function vulnerabilityWatchStatusPayload(value) {
    if(!value || typeof value.enabled!=='boolean' || typeof value.running!=='boolean' || value.read_only!==true || !Number.isSafeInteger(value.interval_seconds) || value.interval_seconds<300 || !Array.isArray(value.hosts) || !value.hosts.every(host=>host && remediationToken(host.host_id) && typeof host.scope_hash==='string' && /^[0-9a-f]{64}$/.test(host.scope_hash)) || new Set(value.hosts.map(host=>host.host_id)).size!==value.hosts.length) throw new Error('定期观察响应缺少有效的范围、权限或运行状态。');
    return value;
  }
  function vulnerabilityWatchAlertPayload(value) {
    if(!Array.isArray(value) || !value.every(vulnerabilityWatchEventValid) || new Set(value.map(alert=>alert.id)).size!==value.length) throw new Error('观察通知清单缺少有效标识或范围。');
    return value;
  }
  async function refreshVulnerabilityWatch({quiet=false}={}) {
    if(!state.token || !vulnerabilityWatchSupported() || state.vulnerabilityWatchBusy || state.vulnerabilityWatchAckBusy!==null) return;
    const session=state.session,request=++state.vulnerabilityWatchRequest; state.vulnerabilityWatchBusy=true; state.vulnerabilityWatchError=''; stopVulnerabilityWatchPolling(); renderVulnerabilityWatch();
    try {
      const [status,alerts]=await Promise.all([api('/api/vulnerability-watch/status'),api('/api/vulnerability-watch/alerts')]);
      if(session!==state.session || request!==state.vulnerabilityWatchRequest) return;
      const checkedStatus=vulnerabilityWatchStatusPayload(status),checkedAlerts=vulnerabilityWatchAlertPayload(alerts);
      state.vulnerabilityWatchStatus=checkedStatus; state.vulnerabilityWatchAlerts=checkedAlerts; state.vulnerabilityWatchReadAt=new Date().toISOString();
      if(state.vulnerabilityWatchSelected && alerts.some(alert=>alert.id===state.vulnerabilityWatchSelected)) selectVulnerabilityWatchAlert(state.vulnerabilityWatchSelected);
      else { state.vulnerabilityWatchSelected=null; state.vulnerabilityWatchDetail=null; state.vulnerabilityWatchDetailRequest+=1; state.vulnerabilityWatchDetailBusy=false; }
      if(!quiet) announce('定期漏洞观察记录已刷新；覆盖缺口和待评估项仍需核对。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.vulnerabilityWatchRequest) state.vulnerabilityWatchError='定期观察读取未完成：'+errorMessage(cause)+' 下面保留的历史信息不能表示当前扫描状态。'; }
    finally { if(session===state.session && request===state.vulnerabilityWatchRequest) { state.vulnerabilityWatchBusy=false; renderVulnerabilityWatch(); scheduleVulnerabilityWatchPolling(); } }
  }
  async function selectVulnerabilityWatchAlert(id) {
    const listed=state.vulnerabilityWatchAlerts.find(alert=>alert.id===id);
    if(!state.token || !listed || state.vulnerabilityWatchAckBusy!==null) return;
    const session=state.session,request=++state.vulnerabilityWatchDetailRequest; state.vulnerabilityWatchSelected=id; state.vulnerabilityWatchDetail=null; state.vulnerabilityWatchDetailBusy=true; state.vulnerabilityWatchError=''; renderVulnerabilityWatch();
    try {
      const value=await api('/api/vulnerability-watch/alerts/'+encodeURIComponent(id));
      if(session!==state.session || request!==state.vulnerabilityWatchDetailRequest || state.vulnerabilityWatchSelected!==id) return;
      if(!vulnerabilityWatchEventValid(value) || value.id!==id || value.host_id!==listed.host_id || value.scope_hash!==listed.scope_hash) throw new Error('通知详情与所选目标或范围不一致。');
      state.vulnerabilityWatchDetail=value; state.vulnerabilityWatchAlerts=state.vulnerabilityWatchAlerts.map(alert=>alert.id===id?value:alert);
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.vulnerabilityWatchDetailRequest) state.vulnerabilityWatchError='观察证据读取未完成：'+errorMessage(cause); }
    finally { if(session===state.session && request===state.vulnerabilityWatchDetailRequest) { state.vulnerabilityWatchDetailBusy=false; renderVulnerabilityWatch(); } }
  }
  async function acknowledgeVulnerabilityWatch(id) {
    const selected=state.vulnerabilityWatchDetail;
    if(!state.token || !selected || selected.id!==id || selected.status!=='open' || state.vulnerabilityWatchBusy || state.vulnerabilityWatchAckBusy!==null) return;
    const session=state.session; state.vulnerabilityWatchAckBusy=id; state.vulnerabilityWatchError=''; stopVulnerabilityWatchPolling(); renderVulnerabilityWatch();
    try {
      const value=await api('/api/vulnerability-watch/alerts/'+encodeURIComponent(id)+'/ack',{method:'POST',body:{acknowledge:true}});
      if(session!==state.session || state.vulnerabilityWatchSelected!==id) return;
      if(!vulnerabilityWatchEventValid(value) || value.id!==id || value.scope_hash!==selected.scope_hash || value.host_id!==selected.host_id || value.status!=='acknowledged') throw new Error('已阅结果未能确认，请刷新记录核对，不要据此判断风险解除。');
      state.vulnerabilityWatchDetail=value; state.vulnerabilityWatchAlerts=state.vulnerabilityWatchAlerts.map(alert=>alert.id===id?value:alert); announce('已记录通知已阅；风险和复扫结论保持独立。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session) state.vulnerabilityWatchError='未能确认已阅：'+errorMessage(cause)+' 请只刷新记录核对结果。'; }
    finally { if(session===state.session) { state.vulnerabilityWatchAckBusy=null; renderVulnerabilityWatch(); scheduleVulnerabilityWatchPolling(); } }
  }

  const remediationJobStates={queued:'任务已登记',preflight:'执行前核验',downloading:'下载已核验软件包',applying:'正在安装软件包',verifying:'正在复扫与验证',awaiting_transport_verification:'待验证新的管理连接',running_overdue:'执行超时待核查',verified:'本任务覆盖项验证通过',installed_restart_pending:'补丁已安装 · 服务重启待处理',reboot_pending:'补丁已安装 · 系统重启待处理',verification_failed:'修复后验证未通过',failed:'任务失败',rejected:'任务已拒绝',unknown:'执行结果未知'};
  const remediationActiveStates=new Set(['queued','preflight','downloading','applying','verifying','awaiting_transport_verification','running_overdue']);
  function remediationList(value) { return Array.isArray(value)?value:[]; }
  function remediationName(id) { return remediationList(state.remediation?.hosts).find(host=>host.host_id===id)?.name || id || '目标未确认'; }
  function remediationJobLabel(value) { return remediationJobStates[value] || '状态未确认'; }
  function remediationToken(value) { return typeof value==='string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value); }
  function remediationJobReference(job) { return job && remediationToken(job.host_id) && typeof job.job_id==='string' && /^[0-9a-f]{32}$/.test(job.job_id)?{host_id:job.host_id,job_id:job.job_id}:null; }
  function remediationHasPendingTask() { return state.remediationSubmission?.uncertain===true || remediationList(state.remediation?.jobs).some(job=>!Object.hasOwn(remediationJobStates,job.status) || remediationActiveStates.has(job.status) || ['unknown','installed_restart_pending','reboot_pending'].includes(job.status)); }
  function remediationJSON(value) { const text=JSON.stringify(value,null,2) || '尚无记录'; return text.length>8192?text.slice(0,8192)+'\n… 此处仅展示前 8192 字符，不能当作完整证据。':text; }
  const vulnerabilityAIStates={submission_intent:'请求已登记 · 结果待核实',running:'模型分析中',unknown:'模型结果未知 · 只查原记录',completed:'模型分析已返回',stale:'证据已变化 · 保留历史分析',failed:'模型分析未完成',disabled:'模型尚未配置',refused:'模型拒绝本次分析'};
  function vulnerabilityAISupported() { return state.capabilities?.vulnerability_ai===true; }
  function vulnerabilityAIHex(value,length=64) { return typeof value==='string' && new RegExp('^[0-9a-f]{'+length+'}$').test(value); }
  function vulnerabilityAIUncertain(record) { return record && ['submission_intent','running','unknown'].includes(record.status); }
  function vulnerabilityAIHostRecords() { return state.vulnerabilityAIRecords.filter(record=>record.host_id===state.remediationHost); }
  function vulnerabilityAIPending(host=state.remediationHost) { return Object.values(state.vulnerabilityAIRefs).some(ref=>ref.host_id===host && ref.uncertain) || state.vulnerabilityAIRecords.some(record=>record.host_id===host && vulnerabilityAIUncertain(record)); }
  function dismissVulnerabilityAIDialog() {
    state.vulnerabilityAITarget=null;
    if(state.vulnerabilityAIBusy==='preview') { state.vulnerabilityAIBusy=''; state.vulnerabilityAIRequest+=1; }
    const dialog=$('vulnerability-ai-dialog'); if(dialog?.open) dialog.close();
    if($('vulnerability-ai-confirm')) { $('vulnerability-ai-confirm').checked=false; $('vulnerability-ai-confirm').disabled=true; }
    if($('vulnerability-ai-send')) { $('vulnerability-ai-send').disabled=true; $('vulnerability-ai-send').textContent='发送证据并分析'; }
    if($('vulnerability-ai-cancel')) $('vulnerability-ai-cancel').disabled=false;
    if($('vulnerability-ai-input')) $('vulnerability-ai-input').textContent='';
    if($('vulnerability-ai-selection')) { clear($('vulnerability-ai-selection')); $('vulnerability-ai-selection').disabled=true; }
    if($('vulnerability-ai-selection-wrap')) $('vulnerability-ai-selection-wrap').hidden=true;
    if($('vulnerability-ai-dialog-target')) $('vulnerability-ai-dialog-target').textContent='';
    if($('vulnerability-ai-dialog-error')) { $('vulnerability-ai-dialog-error').textContent=''; $('vulnerability-ai-dialog-error').hidden=true; }
    renderVulnerabilityAI();
  }
  function invalidateVulnerabilityAIPreview() { dismissVulnerabilityAIDialog(); state.vulnerabilityAIPlanRef=null; }
  function vulnerabilityAIContext() { return {session:state.session,host:state.remediationHost,scan:remediationScanStamp(state.remediationScan),mode:state.automation?.mode,revision:state.automation?.revision}; }
  function sameVulnerabilityAIContext(context,{mode=false}={}) { return Boolean(context && state.token && context.session===state.session && context.host===state.remediationHost && context.scan===remediationScanStamp(state.remediationScan) && (!mode || context.mode===state.automation?.mode && context.revision===state.automation?.revision)); }
  function checkedVulnerabilityAIRecord(value,host=null,id=null) {
    if(!value || typeof value!=='object' || !vulnerabilityAIHex(value.analysis_id,32) || !remediationToken(value.host_id) || (host && value.host_id!==host) || (id && value.analysis_id!==id) || !Object.hasOwn(vulnerabilityAIStates,value.status) || !vulnerabilityAIHex(value.input_digest) || !Array.isArray(value.proposals) || value.proposals.length>30 || !value.proposals.every(proposal=>proposal && typeof proposal==='object' && vulnerabilityAIHex(proposal.proposal_id,32) && remediationToken(proposal.candidate_id) && proposal.candidate && typeof proposal.candidate==='object' && Array.isArray(proposal.evidence_refs))) throw new Error('分析记录缺少有效目标、原请求或状态绑定。');
    if(value.result?.status==='completed' && value.result.actions_executable!==false) throw new Error('模型分析没有保持非执行建议边界。');
    if(Object.hasOwn(value,'selection') && !validVulnerabilityAIFocus(value)) throw new Error('单候选分析缺少对应范围和证据。');
    return value;
  }
  function mergeVulnerabilityAIRecord(value) {
    const record=checkedVulnerabilityAIRecord(value); state.vulnerabilityAIRecords=[record,...state.vulnerabilityAIRecords.filter(item=>item.analysis_id!==record.analysis_id)].slice(0,100);
    const ref=state.vulnerabilityAIRefs[record.analysis_id]; if(ref && !vulnerabilityAIUncertain(record)) delete state.vulnerabilityAIRefs[record.analysis_id];
    if(record.host_id===state.remediationHost) state.vulnerabilityAIRecord=record;
    return record;
  }
  function vulnerabilityAICanPlan(record,proposal) {
    const policy=state.automation?.policy;
    return Boolean(record && proposal && (!record.selection || record.selection.candidate_id===proposal.candidate_id) && state.token && state.view==='remediation' && record.host_id===state.remediationHost && record.status==='completed' && record.stale===false && record.applicable===true && !state.vulnerabilityAIRefs[record.analysis_id]?.uncertain && vulnerabilityAIHex(record.analysis_digest) && vulnerabilityAIHex(proposal.proposal_id,32) && proposal.candidate?.eligible===true && proposal.candidate.action==='os_security_upgrade' && proposal.candidate.requires_reboot===false && record.result?.actions_executable===false && state.remediationScan?.scan_id===record.scan_id && ['manual','assisted'].includes(state.automation?.mode) && Number.isSafeInteger(state.automation?.revision) && !state.automationBusy && !state.automationNeedsReload && policy?.enabled===true && Array.isArray(policy.host_ids) && policy.host_ids.includes(record.host_id) && Array.isArray(policy.allowed_actions) && policy.allowed_actions.includes('os_security_upgrade') && Array.isArray(policy.allowed_packages) && policy.allowed_packages.includes(proposal.candidate.package) && !state.vulnerabilityAIBusy && !state.remediationBusy && !remediationHasPendingTask());
  }
  function vulnerabilityAIReferences(parent,refs,input) {
    if(!Array.isArray(refs) || !refs.length) return;
    const wrap=node('div','vulnerability-ai-refs'); wrap.append(node('span','small muted','依据：'));
    for(const ref of refs.slice(0,32)) {
      const fact=remediationList(input?.findings).find(item=>item?.evidence_ref===ref);
      wrap.append(node('span','vulnerability-ai-ref',fact?String(ref)+' · '+String(fact.package || fact.finding_ref):String(ref)));
    }
    parent.append(wrap);
  }
  function vulnerabilityAIFacts(parent,record) {
    const input=record.input || {},findings=remediationList(input.findings); const section=node('section','vulnerability-ai-facts');
    section.append(node('h3','','服务端扫描事实'),node('p','small muted','下列身份、版本和受影响状态来自绑定的扫描证据，模型不能改写。'));
    if(input.evidence_origin==='controlled_lab') section.append(node('p','notice neutral','受控实验环境；该结果不能用于证明物理宿主已修复。'));
    if(validVulnerabilityAIFocus(record)) section.append(node('p','notice neutral','本次仅分析 '+record.selection.candidate_id+'；原扫描共有 '+String(input.analysis_scope.total_finding_count)+' 条发现，其他条目未纳入这次模型判断。'));
    const coverage=input.coverage?.status || input.coverage_status;
    section.append(node('p','small muted','覆盖：'+({partial:'部分覆盖',complete:'本次覆盖完整',unavailable:'未取得'}[coverage] || '以输入证据为准')+'。未发现条目不能推断整机没有漏洞。'));
    for(const finding of findings.slice(0,30)) {
      if(!finding || typeof finding!=='object') continue;
      const item=node('article','vulnerability-ai-fact');
      item.append(node('h4','mono',String(finding.package || finding.finding_ref || '软件包未确认')));
      const affected=finding.affected===true?'供应商证据确认受影响':finding.affected===false?'本次证据不受影响':'仍需核实';
      item.append(detailList([['证据编号',finding.evidence_ref || finding.finding_ref || '未提供'],['公告 / CVE',[finding.advisory,finding.cve].filter(Boolean).join(' / ') || '未提供'],['当前版本',finding.current_version || '未知'],['官方修复版本',finding.fixed_version || '未知'],['候选版本',finding.candidate_version || '未知'],['受影响状态',affected]])); section.append(item);
    }
    if(!findings.length) section.append(node('p','empty-note','这份输入没有保留逐条 finding；请核对覆盖和缺口，不能推断全机安全。'));
    parent.append(section);
  }
  function renderVulnerabilityAIDetail() {
    const parent=$('vulnerability-ai-detail'); if(!parent) return; clear(parent);
    const record=state.vulnerabilityAIRecord;
    if(!record || record.host_id!==state.remediationHost) { parent.append(node('p','empty-note','先查看当前扫描的发送预览，或选择一条既有分析。AI 不会因打开页面自动调用。')); return; }
    parent.append(node('p','eyebrow','Model analysis record'),node('h3','',vulnerabilityAIStates[record.status] || '分析状态未知'),node('p','mono small',record.analysis_id));
    parent.append(node('p','small muted','目标：'+remediationName(record.host_id)+'；模型：'+String(record.result?.model || record.model_name || '记录未提供')+'；生成时间：'+(record.updated_at?dateLabel(record.updated_at):'未知')));
    const query=node('button','button','查询这条分析记录'); query.type='button'; query.dataset.vulnerabilityAIQuery=record.analysis_id; query.disabled=Boolean(state.vulnerabilityAIBusy); query.addEventListener('click',()=>queryVulnerabilityAI(record.host_id,record.analysis_id)); parent.append(query);
    if(state.capabilities?.vulnerability_evidence===true) {
      const archive=record.evidence_archive || {status:'not_retained'};
      parent.append(node('p','small muted',archive.status==='retained'?'原始扫描已归档；可导出用于离线核对。':archive.status==='invalid'?'原始归档未能核验；不能据此准备修复。':'历史原始扫描未留存；导出会明确标记证据缺失。'));
      const download=node('button','button','导出证据包（含主机清单）');download.type='button';download.id='export-vulnerability-evidence';download.disabled=archive.status==='invalid';
      download.addEventListener('click',()=>downloadVulnerabilityEvidence(record,download));parent.append(download);
    }
    if(vulnerabilityAIUncertain(record)) { parent.append(node('p','notice','模型请求可能已被处理。只查询同一个分析 ID；页面不会重新发送或据此认定未计费。')); return; }
    if(record.stale===true || record.applicable!==true || record.scan_id!==state.remediationScan?.scan_id || state.vulnerabilityAIRefs[record.analysis_id]?.uncertain) parent.append(node('p','notice','当前证据或配置与这份记录不一致，或结果不满足应用条件。仅作为历史分析，不开放生成真实方案。'));
    vulnerabilityAIFacts(parent,record);
    const result=record.result;
    renderVulnerabilityAIFailure(parent,result);
    if(!result || result.status!=='completed' || result.actions_executable!==false) { parent.append(node('p','empty-note',record.detail || result?.summary || '尚无通过校验的模型分析；扫描事实和原有处置状态保留。')); return; }
    const reasoning=node('section','vulnerability-ai-reasoning'); reasoning.append(node('h3','','AI 判断 · 需要结合证据复核'),node('p','vulnerability-ai-summary',String(result.summary || '模型未提供摘要')));
    vulnerabilityAIReferences(reasoning,result.evidence_refs,record.input);
    for(const finding of remediationList(result.finding_analyses).slice(0,30)) {
      const actual=remediationList(record.input?.findings).find(item=>item?.finding_ref===finding.finding_ref);
      const item=node('article','vulnerability-ai-judgment');
      item.append(node('strong','',String(actual?.package || finding.finding_ref || '条目未确认')),node('p','small muted','模型建议优先级：'+({urgent:'优先核对',planned:'计划处理',review:'需要进一步核实'}[finding.priority] || '未确认')+'；这不是供应商严重度。'),node('p','small',String(finding.rationale || '未提供判断依据')));
      vulnerabilityAIReferences(item,finding.evidence_refs,record.input); reasoning.append(item);
    }
    const unknown=remediationList(result.uncertainty); reasoning.append(node('h4','','不确定与缺失证据'));
    if(unknown.length) { const list=node('ul','plain-list'); for(const item of unknown.slice(0,20)) list.append(node('li','',String(item))); reasoning.append(list); }
    else reasoning.append(node('p','small muted','模型没有额外列出不确定项；这不表示扫描覆盖完整。'));
    parent.append(reasoning);
    const proposals=node('section','vulnerability-ai-proposals'); proposals.append(node('h3','','修复提案 · 先生成受控计划'));
    for(const proposal of record.proposals.slice(0,20)) {
      const candidate=proposal.candidate || {},item=node('article','vulnerability-ai-proposal');
      item.append(node('h4','mono',String(candidate.package || proposal.candidate_id || '候选未确认')),node('p','small',String(proposal.rationale || '模型未提供提案理由')));
      item.append(detailList([['目录动作',candidate.action==='os_security_upgrade'?'官方系统单包升级':'未支持'],['当前 → 候选',[candidate.current_version,candidate.candidate_version].filter(Boolean).join(' → ') || '未确认'],['官方修复版本',candidate.fixed_version || '未确认'],['公告',[candidate.advisory,candidate.cve].filter(Boolean).join(' / ') || '未提供'],['目录风险',candidate.risk_level==='medium'?'中风险（需核对服务影响）':String(candidate.risk_level || '未知')]]));
      vulnerabilityAIReferences(item,proposal.evidence_refs,record.input);
      const button=node('button','button','按提案核验真实修复方案'); button.type='button'; button.dataset.vulnerabilityAIProposal=proposal.proposal_id; button.disabled=!vulnerabilityAICanPlan(record,proposal); button.addEventListener('click',()=>prepareVulnerabilityAIPlan(record,proposal)); item.append(button,node('p','small muted','只从服务端已验证目录选择动作。生成计划会重查版本、依赖、风险与权限，不会提交安装。'));
      if(!vulnerabilityAICanPlan(record,proposal)) item.append(node('p','small muted','当前记录、扫描、模式或授权不满足生成计划条件；请重新核对。'));
      proposals.append(item);
    }
    if(!record.proposals.length) proposals.append(node('p','empty-note','没有通过目录校验的修复提案；保留分析与不确定项，不补造执行动作。'));
    parent.append(proposals);
  }
  const vulnerabilityAIFailureCodes={
    response_shape_invalid:['response_envelope','模型响应结构不符合要求。'],
    response_incomplete:['response_envelope','模型没有完整结束这次回答。'],
    response_message_invalid:['response_envelope','模型返回了不支持的消息、工具调用或内容类型。'],
    json_invalid:['json','模型回答不是有效 JSON。'],
    json_duplicate_member:['json','模型 JSON 包含重复字段。'],
    json_non_finite:['json','模型 JSON 包含不支持的数值。'],
    execution_authority_forbidden:['schema','模型试图声明执行权限，已拒绝。'],
    schema_contract_invalid:['schema','模型回答的字段、类型或长度不符合约定。'],
    uncertainty_missing:['evidence','证据覆盖不完整，模型没有保留所需的不确定说明。'],
    evidence_reference_invalid:['evidence','模型引用了不存在或重复的证据。'],
    finding_reference_invalid:['evidence','模型引用了不存在或重复的漏洞条目。'],
    finding_support_invalid:['evidence','漏洞判断没有正确引用自身证据。'],
    factual_classification_invalid:['evidence','模型判断与供应商证据或候选事实不一致。'],
    candidate_selection_invalid:['selection','模型选择了不存在、重复或已阻止的候选。'],
    proposal_support_invalid:['selection','修复建议没有正确引用自身证据。'],
    text_empty_or_secret:['text','模型文本为空或触及凭据保护规则。'],
    text_control_characters:['text','模型文本包含不允许的控制字符。'],
    text_unsafe_instruction_or_claim:['text','模型文本包含命令、地址或未经验证的完成声明。'],
    text_url_forbidden:['text','模型文本包含不允许的 URL。'],
    text_command_or_code_forbidden:['text','模型文本包含不允许的命令或代码。'],
    text_file_path_forbidden:['text','模型文本包含不允许的文件路径。'],
    text_completion_claim_forbidden:['text','模型文本包含未经验证的完成声明。'],
    text_unknown_advisory:['text','模型提到了输入证据之外的漏洞或公告编号。'],
    text_unknown_reference:['text','模型文本包含未知的证据或候选编号。'],
    text_unknown_version_or_address:['text','模型文本包含未获证据支持的版本或网络标识。'],
    text_network_identity:['text','模型文本包含不允许的网络标识。'],
    provider_json_invalid:['provider_response','模型服务返回的外层响应不是有效 JSON。'],
    provider_response_too_large:['provider_response','模型服务响应超出大小限制。'],
    provider_object_invalid:['provider_response','模型服务返回的外层响应不是对象。']
  };
  function renderVulnerabilityAIFailure(parent,result) {
    if(result?.status!=='failed') return;
    const diagnostic=result.validation_failure;
    const known=!Object.hasOwn(result,'failure_stage') && ['model_response_not_usable','output_truncated'].includes(result.failure_kind) && (result.failure_kind!=='output_truncated' || diagnostic?.code==='response_incomplete') && diagnostic && typeof diagnostic==='object' && !Array.isArray(diagnostic) && Object.keys(diagnostic).length===3 && diagnostic.schema_version===1 && typeof diagnostic.code==='string' && Object.hasOwn(vulnerabilityAIFailureCodes,diagnostic.code)?vulnerabilityAIFailureCodes[diagnostic.code]:null;
    let message=known && diagnostic.stage===known[0]?known[1]:null;
    if(!message && result.failure_kind==='model_response_not_usable') message='这条记录未保留可识别的具体拒绝原因，不能据此推断触犯了哪项规则。';
    if(!message && result.failure_kind==='local_analysis_not_ready' && result.failure_stage==='local_input') message='本地证据或配置未准备好，尚未发送模型请求。';
    if(!message && result.failure_kind==='provider_request_failed' && result.failure_stage==='provider_request') message='模型服务请求未能完成；没有自动重发。';
    if(!message && result.failure_kind==='analysis_processing_failed' && result.failure_stage==='response_processing') message='本地响应处理未能完成，未生成修复提案。';
    if(!message) return;
    const section=node('section','notice neutral');section.dataset.vulnerabilityAIFailure='true';section.append(node('strong','','本次停止原因'),node('p','',message));
    if(known && diagnostic.stage===known[0]) section.append(node('p','mono small',diagnostic.code));
    section.append(node('p','small muted','已保留原分析记录；不会自动重试模型或据此提交安装。'));parent.append(section);
  }
  function renderVulnerabilityAI() {
    const section=$('vulnerability-ai-section'); if(!section) return;
    section.hidden=!vulnerabilityAISupported(); if(section.hidden) return;
    const provider=$('vulnerability-ai-provider'); clear(provider); const settings=state.vulnerabilityAIProvider;
    provider.append(node('strong','',settings?.configured===true?'OpenAI 兼容 API 已配置':'AI 尚未就绪'),node('p','small muted',settings?.configured===true?'接收方：'+String(settings.provider_host || '由服务器配置')+' · 模型：'+String(settings.model_name || '未提供')+'。配置已登记，实际调用及校验结果见每条分析。':'由部署者在服务器配置模型地址、模型名及密钥文件。不要在聊天、地址栏或日志中填写凭据。'));
    $('refresh-vulnerability-ai').disabled=Boolean(state.vulnerabilityAIBusy || !state.token);
    $('preview-vulnerability-ai').disabled=Boolean(!state.token || !state.remediationHost || !state.remediationScan || !Number.isSafeInteger(state.automation?.revision) || state.automationBusy || state.automationNeedsReload || state.remediationBusy || state.vulnerabilityAIBusy || vulnerabilityAIPending());
    $('vulnerability-ai-progress').textContent={refresh:'正在读取配置状态和既有分析，不调用模型。',preview:'正在取得这次发送的证据和输入指纹。',analyze:'原分析 ID 已固定，模型正在处理；不会自动重复发送。',query:'只读取原分析 ID，不重新请求模型。',plan:'正在重新核验真实软件包计划；未提交安装。'}[state.vulnerabilityAIBusy] || (vulnerabilityAIPending()?'已有模型结果待核实，请查询原分析记录。':'');
    $('vulnerability-ai-error').textContent=state.vulnerabilityAIError; $('vulnerability-ai-error').hidden=!state.vulnerabilityAIError;
    const history=$('vulnerability-ai-history'); clear(history); history.append(node('h3','','此目标的分析记录'));
    const records=vulnerabilityAIHostRecords();
    for(const record of records.slice(0,30)) { const button=node('button','vulnerability-ai-history-item'); button.type='button'; button.dataset.vulnerabilityAIAnalysis=record.analysis_id; button.disabled=Boolean(state.vulnerabilityAIBusy); button.append(node('strong','',vulnerabilityAIStates[record.status]),node('p','mono small',record.analysis_id),node('p','small muted',record.updated_at?dateLabel(record.updated_at):'时间未提供')); if(record.analysis_id===state.vulnerabilityAIRecord?.analysis_id) button.setAttribute('aria-pressed','true'); button.addEventListener('click',()=>queryVulnerabilityAI(record.host_id,record.analysis_id)); history.append(button); }
    const unresolved=Object.values(state.vulnerabilityAIRefs).filter(ref=>ref.host_id===state.remediationHost && ref.uncertain && !records.some(item=>item.analysis_id===ref.analysis_id));
    for(const ref of unresolved) { const button=node('button','vulnerability-ai-history-item'); button.type='button'; button.textContent='结果未取得 · 查询原分析 '+ref.analysis_id; button.disabled=Boolean(state.vulnerabilityAIBusy); button.dataset.vulnerabilityAIQuery=ref.analysis_id; button.addEventListener('click',()=>queryVulnerabilityAI(ref.host_id,ref.analysis_id)); history.append(button); }
    if(!records.length && !unresolved.length) history.append(node('p','empty-note','尚无此目标的分析记录。'));
    renderVulnerabilityAIDetail();
  }
  async function downloadVulnerabilityEvidence(record,button) {
    const session=state.session;button.disabled=true;
    try {
      const blob=await api('/api/vulnerability-ai/analyses/'+encodeURIComponent(record.host_id)+'/'+encodeURIComponent(record.analysis_id)+'/evidence',{blob:true});
      if(session!==state.session || !state.token) return;
      if(blob.size>4194304) throw new Error('证据包超过本地读取预算。');
      const url=URL.createObjectURL(blob),link=node('a');link.href=url;link.download='opsark-evidence-'+record.analysis_id+'.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
      announce('原分析证据包已导出；未请求模型或目标，离线校验不会授予执行权限。');
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && session===state.session && state.vulnerabilityAIRecord?.analysis_id===record.analysis_id) { state.vulnerabilityAIError='证据导出未完成：'+errorMessage(cause);renderVulnerabilityAI(); }
    } finally { if(session===state.session && button.isConnected) button.disabled=record.evidence_archive?.status==='invalid'; }
  }
  async function refreshVulnerabilityAI({quiet=false}={}) {
    if(!vulnerabilityAISupported() || !state.token || state.vulnerabilityAIBusy) return;
    const context=vulnerabilityAIContext(),request=++state.vulnerabilityAIRequest; state.vulnerabilityAIBusy='refresh'; if(!quiet) state.vulnerabilityAIError=''; renderVulnerabilityAI();
    try {
      const [provider,value]=await Promise.all([api('/api/ai/status'),api('/api/vulnerability-ai/analyses')]);
      if(context.session!==state.session || request!==state.vulnerabilityAIRequest) return;
      if(!provider || typeof provider.configured!=='boolean') throw new Error('模型配置状态未能核实。');
      const records=Array.isArray(value)?value:value?.analyses; if(!Array.isArray(records) || records.length>100) throw new Error('模型分析清单未能核实。');
      state.vulnerabilityAIProvider=provider; state.vulnerabilityAIRecords=records.map(record=>checkedVulnerabilityAIRecord(record)); state.vulnerabilityAIReadAt=new Date().toISOString();
      for(const record of state.vulnerabilityAIRecords) { const ref=state.vulnerabilityAIRefs[record.analysis_id]; if(ref && ref.host_id===record.host_id && ref.input_digest===record.input_digest && !vulnerabilityAIUncertain(record)) delete state.vulnerabilityAIRefs[record.analysis_id]; }
      const current=state.vulnerabilityAIRecord; state.vulnerabilityAIRecord=state.vulnerabilityAIRecords.find(item=>item.analysis_id===current?.analysis_id && item.host_id===state.remediationHost) || vulnerabilityAIHostRecords()[0] || null;
    } catch(cause) { if(!(cause instanceof SessionEnded) && context.session===state.session && request===state.vulnerabilityAIRequest) { state.vulnerabilityAIError='读取未完成：'+errorMessage(cause)+' 保留的分析仅为历史快照，不能因此生成新计划。'; if(state.vulnerabilityAIRecord) state.vulnerabilityAIRecord={...state.vulnerabilityAIRecord,applicable:false}; } }
    finally { if(context.session===state.session && request===state.vulnerabilityAIRequest) { state.vulnerabilityAIBusy=''; renderVulnerabilityAI(); } }
  }
  function validVulnerabilityAIFocus(value) {
    const selected=value?.selection,input=value?.input,scope=input?.analysis_scope,candidates=input?.candidate_catalog,findings=input?.findings;
    return Boolean(selected && typeof selected==='object' && !Array.isArray(selected) && Object.keys(selected).length===2 && selected.kind==='single_candidate' && typeof selected.candidate_id==='string' && /^[a-z][a-z0-9-]{0,79}$/.test(selected.candidate_id) && scope?.schema_version===2 && scope.binding_algorithm==='vulnerability-ai/v2' && scope.kind==='single_candidate' && scope.candidate_id===selected.candidate_id && Number.isSafeInteger(scope.total_finding_count) && scope.total_finding_count>=1 && Array.isArray(candidates) && candidates.length===1 && candidates[0]?.candidate_id===selected.candidate_id && Array.isArray(findings) && findings.length===1 && findings[0]?.finding_ref===scope.finding_ref && candidates[0]?.finding_ref===scope.finding_ref && findings[0]?.evidence_ref===scope.evidence_ref);
  }
  function applyVulnerabilityAIPreview(target,preview,selected='') {
    if(!preview || preview.host_id!==target.host || preview.scan_id!==state.remediationScan?.scan_id || !vulnerabilityAIHex(preview.input_digest) || !preview.input || typeof preview.input!=='object' || Array.isArray(preview.input) || typeof preview.configured!=='boolean') throw new Error('预览缺少当前目标、扫描或完整输入绑定。');
    if(selected && (!validVulnerabilityAIFocus(preview) || preview.selection.candidate_id!==selected)) throw new Error('模型预览没有对应所选候选。');
    if(target.previewContext && (Object.keys(target.previewContext).some(key=>preview[key]!==target.previewContext[key]) || preview.source_mode!==target.mode || preview.source_mode_revision!==target.revision)) throw new Error('读取预览期间证据、配置或模式已变化，请重新打开预览。');
    if(!selected && Object.hasOwn(preview,'selection')) throw new Error('预览返回了未选择的分析范围。');
    const summary=preview.model_input??preview.input;
    if(!summary || typeof summary!=='object' || Array.isArray(summary)) throw new Error('预览缺少模型白名单摘要。');
    const text=JSON.stringify(summary,null,2); if(text.length>131072) throw new Error('发送预览超过页面可完整核对的预算。');
    target.preview=preview; target.invalid=false;
    state.vulnerabilityAIProvider={...state.vulnerabilityAIProvider,configured:preview.configured,provider_host:preview.provider_host,model_name:preview.model_name};
    $('vulnerability-ai-input').textContent=text; $('vulnerability-ai-dialog-target').textContent='目标：'+remediationName(target.host)+' · 模型：'+String(preview.model_name || '未配置')+' · 接收方：'+String(preview.provider_host || '未配置')+(selected?' · 仅分析 '+selected:'');
    $('vulnerability-ai-confirm').checked=false; $('vulnerability-ai-confirm').disabled=!preview.configured; $('vulnerability-ai-send').disabled=true;
    $('vulnerability-ai-dialog-error').hidden=preview.configured;
    if(!preview.configured) $('vulnerability-ai-dialog-error').textContent='模型尚未配置。可核对这份预览，但不能发送；请由部署者在服务器配置凭据。';
  }
  function installVulnerabilityAIChoices(target,preview) {
    const select=$('vulnerability-ai-selection');clear(select);
    const all=node('option','','全部发现（原格式）');all.value='';select.append(all);
    const catalog=remediationList(preview.catalog);
    if(!vulnerabilityAIHex(preview.context_scope) || !vulnerabilityAIHex(preview.provider_binding)) throw new Error('候选清单缺少当前证据与提供方绑定。');
    target.previewContext={context_scope:preview.context_scope,provider_binding:preview.provider_binding,source_mode:preview.source_mode,source_mode_revision:preview.source_mode_revision};
    if(catalog.length>20 || catalog.some(c=>!c || typeof c.candidate_id!=='string' || !/^[a-z][a-z0-9-]{0,79}$/.test(c.candidate_id)) || new Set(catalog.map(c=>c.candidate_id)).size!==catalog.length) throw new Error('候选清单身份未能核实。');
    target.choices=catalog.map(c=>c.candidate_id);
    for(const candidate of catalog) { const option=node('option','',candidate.candidate_id+' · '+String(candidate.package || '包未确认')+' · '+String(candidate.cve || candidate.advisory || '证据待核对'));option.value=candidate.candidate_id;select.append(option); }
    const preferred=catalog.find(c=>c.eligible===true)?.candidate_id || '';select.value=preferred;$('vulnerability-ai-selection-wrap').hidden=false;return preferred;
  }
  async function changeVulnerabilityAISelection() {
    const target=state.vulnerabilityAITarget,select=$('vulnerability-ai-selection');
    if(!target || state.vulnerabilityAIBusy || !sameVulnerabilityAIContext(target,{mode:true})) return;
    const selected=select.value;if(selected && !target.choices?.includes(selected)) return;
    target.preview=null;target.invalid=true;target.request=++state.vulnerabilityAIRequest;const request=target.request;
    state.vulnerabilityAIBusy='preview';select.disabled=true;$('vulnerability-ai-confirm').checked=false;$('vulnerability-ai-confirm').disabled=true;$('vulnerability-ai-send').disabled=true;$('vulnerability-ai-input').textContent='正在读取所选范围的证据…';renderVulnerabilityAI();
    try {
      const preview=await api('/api/vulnerability-ai/hosts/'+encodeURIComponent(target.host)+'/preview'+(selected?'?candidate_id='+encodeURIComponent(selected):''));
      if(state.vulnerabilityAITarget!==target || !sameVulnerabilityAIContext(target,{mode:true}) || target.request!==request || request!==state.vulnerabilityAIRequest) return;
      applyVulnerabilityAIPreview(target,preview,selected);
    } catch(cause) { if(!(cause instanceof SessionEnded) && state.vulnerabilityAITarget===target && target.session===state.session) { $('vulnerability-ai-dialog-error').textContent='无法取得所选候选预览：'+errorMessage(cause);$('vulnerability-ai-dialog-error').hidden=false; } }
    finally { if(state.vulnerabilityAITarget===target && target.session===state.session && request===state.vulnerabilityAIRequest) {state.vulnerabilityAIBusy='';select.disabled=false;renderVulnerabilityAI();} }
  }
  async function openVulnerabilityAIDialog() {
    if(!vulnerabilityAISupported() || !state.token || !state.remediationHost || !state.remediationScan || !Number.isSafeInteger(state.automation?.revision) || state.automationBusy || state.automationNeedsReload || state.vulnerabilityAIBusy || state.remediationBusy || vulnerabilityAIPending()) return;
    dismissVulnerabilityAIDialog(); const target={...vulnerabilityAIContext(),request:++state.vulnerabilityAIRequest,preview:null,invalid:false}; state.vulnerabilityAITarget=target; state.vulnerabilityAIBusy='preview'; renderVulnerabilityAI();
    $('vulnerability-ai-dialog-target').textContent='目标：'+remediationName(target.host)+' · 正在读取发送预览'; $('vulnerability-ai-input').textContent='正在读取受限结构化证据…'; $('vulnerability-ai-dialog').showModal(); $('vulnerability-ai-dialog-title').focus();
    try {
      let preview=await api('/api/vulnerability-ai/hosts/'+encodeURIComponent(target.host)+'/preview');
      if(state.vulnerabilityAITarget!==target || !sameVulnerabilityAIContext(target,{mode:true}) || target.request!==state.vulnerabilityAIRequest) return;
      let selected='';
      if(state.capabilities?.vulnerability_ai_focus===true) {
        selected=installVulnerabilityAIChoices(target,preview);
        if(selected) preview=await api('/api/vulnerability-ai/hosts/'+encodeURIComponent(target.host)+'/preview?candidate_id='+encodeURIComponent(selected));
        if(state.vulnerabilityAITarget!==target || !sameVulnerabilityAIContext(target,{mode:true}) || target.request!==state.vulnerabilityAIRequest) return;
        $('vulnerability-ai-selection').disabled=false;
      }
      applyVulnerabilityAIPreview(target,preview,selected);
    } catch(cause) { if(!(cause instanceof SessionEnded) && state.vulnerabilityAITarget===target && target.session===state.session) { target.invalid=true; $('vulnerability-ai-dialog-error').textContent='无法取得可信发送预览：'+errorMessage(cause); $('vulnerability-ai-dialog-error').hidden=false; } }
    finally { if(target.session===state.session && state.vulnerabilityAITarget===target) { state.vulnerabilityAIBusy=''; renderVulnerabilityAI(); } }
  }
  async function sendVulnerabilityAI() {
    const target=state.vulnerabilityAITarget;
    if(!target || target.invalid || !target.preview?.configured || !$('vulnerability-ai-confirm').checked || state.vulnerabilityAIBusy || !sameVulnerabilityAIContext(target,{mode:true}) || vulnerabilityAIPending(target.host)) return;
    if(typeof crypto.randomUUID!=='function') return;
    const id=crypto.randomUUID().replaceAll('-',''); if(!vulnerabilityAIHex(id,32)) return;
    const ref={host_id:target.host,analysis_id:id,input_digest:target.preview.input_digest,uncertain:true}; state.vulnerabilityAIRefs[id]=ref;
    const request=++state.vulnerabilityAIRequest; state.vulnerabilityAIBusy='analyze'; state.vulnerabilityAIError=''; $('vulnerability-ai-confirm').disabled=true; $('vulnerability-ai-send').disabled=true; $('vulnerability-ai-cancel').disabled=true; $('vulnerability-ai-selection').disabled=true; renderVulnerabilityAI();
    try {
      const body={host_id:target.host,analysis_id:id,expected_input_digest:target.preview.input_digest,confirm_send:true};if(target.preview.selection) body.selection=target.preview.selection;
      const value=await api('/api/vulnerability-ai/analyses',{method:'POST',body});
      if(target.session!==state.session || request!==state.vulnerabilityAIRequest) return;
      const record=checkedVulnerabilityAIRecord(value,target.host,id); if(record.input_digest!==target.preview.input_digest || record.scan_id!==target.preview.scan_id || record.selection?.kind!==target.preview.selection?.kind || record.selection?.candidate_id!==target.preview.selection?.candidate_id) throw new Error('模型记录与已确认发送的输入、范围或扫描不一致。'); mergeVulnerabilityAIRecord(record); dismissVulnerabilityAIDialog();
      announce('模型请求已返回；请区分扫描事实、AI 判断和仍需核实的提案。没有提交安装。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && target.session===state.session && request===state.vulnerabilityAIRequest) { const refused=[403,404,409,422].includes(cause.status); if(refused) delete state.vulnerabilityAIRefs[id]; dismissVulnerabilityAIDialog(); state.vulnerabilityAIError=refused?'发送请求被服务端拒绝：'+errorMessage(cause)+' 请重新核对发送预览；本页没有重发。':'模型结果未能核实：'+errorMessage(cause)+' 已保留原分析 ID，只查询该记录，不自动重新发送。'; } }
    finally { if(target.session===state.session && request===state.vulnerabilityAIRequest) { state.vulnerabilityAIBusy=''; renderVulnerabilityAI(); } }
  }
  async function queryVulnerabilityAI(host,id) {
    if(!state.token || !vulnerabilityAISupported() || state.vulnerabilityAIBusy || !vulnerabilityAIHex(id,32)) return;
    const session=state.session,request=++state.vulnerabilityAIRequest; state.vulnerabilityAIBusy='query'; state.vulnerabilityAIError=''; renderVulnerabilityAI();
    try {
      const value=await api('/api/vulnerability-ai/analyses/'+encodeURIComponent(host)+'/'+id);
      if(session!==state.session || request!==state.vulnerabilityAIRequest) return;
      const record=checkedVulnerabilityAIRecord(value,host,id),ref=state.vulnerabilityAIRefs[id]; if(ref && ref.input_digest!==record.input_digest) throw new Error('原记录与已确认的输入指纹不一致。'); mergeVulnerabilityAIRecord(record);
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.vulnerabilityAIRequest) { state.vulnerabilityAIError='原分析记录未能取得：'+errorMessage(cause)+' 不能据此认定模型未处理或未计费，未重新发送。'; if(state.vulnerabilityAIRecord?.analysis_id===id) state.vulnerabilityAIRecord={...state.vulnerabilityAIRecord,applicable:false}; } }
    finally { if(session===state.session && request===state.vulnerabilityAIRequest) { state.vulnerabilityAIBusy=''; renderVulnerabilityAI(); } }
  }
  async function prepareVulnerabilityAIPlan(record,proposal) {
    if(!vulnerabilityAICanPlan(record,proposal)) return;
    invalidateRemediationPlan(); const context=vulnerabilityAIContext(),request=++state.vulnerabilityAIRequest,selection=state.remediationSelection;
    state.vulnerabilityAIBusy='plan'; state.remediationBusy='plan'; state.vulnerabilityAIError=''; renderRemediation(); renderVulnerabilityAI();
    try {
      const plan=await api('/api/vulnerability-ai/plans',{method:'POST',body:{host_id:record.host_id,analysis_id:record.analysis_id,proposal_id:proposal.proposal_id,expected_analysis_digest:record.analysis_digest,expected_mode_revision:context.revision}});
      if(!sameVulnerabilityAIContext(context,{mode:true}) || request!==state.vulnerabilityAIRequest || selection!==state.remediationSelection) return;
      state.remediationPlan=checkedRemediationPlan(plan,record.host_id); state.vulnerabilityAIPlanRef={analysis_id:record.analysis_id,proposal_id:proposal.proposal_id,plan_id:plan.plan_id}; announce('服务器已按 AI 提案重新核验真实计划。未安装；请核对版本、风险与精确授权。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && context.session===state.session && request===state.vulnerabilityAIRequest) state.vulnerabilityAIError='受控计划未生成：'+errorMessage(cause)+' 没有提交安装；模型建议不提供额外权限。'; }
    finally { if(context.session===state.session && request===state.vulnerabilityAIRequest) { state.vulnerabilityAIBusy=''; state.remediationBusy=''; renderRemediation(); renderVulnerabilityAI(); } }
  }
  const serviceActivationStates={prepared:'预览待批准',submission_intent:'批准已登记 · 结果待核实',queued:'激活已登记',preflight:'激活前重验',restarting:'服务正在激活',verifying:'正在重新验证',awaiting_transport_verification:'等待新的管理连接',running_overdue:'激活超时待核实',unknown:'结果未知 · 只查原 ID',verified:'本次激活验证通过',verification_failed:'激活后验证未通过',rejected:'本次激活已拒绝'};
  const serviceActivationPending=new Set(['submission_intent','queued','preflight','restarting','verifying','awaiting_transport_verification','running_overdue','unknown']);
  function serviceActivationSupported() { return state.capabilities?.service_activation===true; }
  function checkedServiceActivation(value,host=null,id=null) {
    if(!value || typeof value!=='object' || !remediationToken(value.host_id) || !vulnerabilityAIHex(value.activation_id,32) || !vulnerabilityAIHex(value.activation_digest) || !vulnerabilityAIHex(value.job_id,32) || !Object.hasOwn(serviceActivationStates,value.status) || !value.plan || value.plan.activation_id!==value.activation_id || value.plan.activation_digest!==value.activation_digest || value.plan.job_id!==value.job_id || value.plan.original_job_status!=='installed_restart_pending' || value.plan.requires_reboot!==false || value.plan.original_job_will_not_be_modified!==true || (host && value.host_id!==host) || (id && value.activation_id!==id)) throw new Error('激活记录缺少有效原任务、范围或状态绑定。');
    if(value.status==='verified' && (value.result?.status!=='verified' || value.result.effective_result!=='activation_verified' || value.result.original_job_unchanged!==true || value.result.original_safety_unchanged!==true)) throw new Error('激活记录没有完整验证回执。');
    return value;
  }
  function checkServiceActivationAnchor(value,anchor=null) {
    const original=anchor || remediationList(state.serviceActivationData?.records).find(r=>r.host_id===value.host_id && r.activation_id===value.activation_id) || (state.serviceActivationRef?.host_id===value.host_id && state.serviceActivationRef.activation_id===value.activation_id?state.serviceActivationRef:null);
    if(!original)return value;
    if(['activation_digest','job_id','scope_hash','policy_digest','controller_policy_digest'].some(key=>original[key]!==undefined && value[key]!==original[key]) || (original.plan?.context_digest || original.context_digest) && value.plan?.context_digest!==(original.plan?.context_digest || original.context_digest))throw new Error('激活回执与原预览的摘要、父任务或范围不一致；保留原 ID。');
    return value;
  }
  function mergeServiceActivation(value) {
    const record=checkServiceActivationAnchor(checkedServiceActivation(value)),previous=state.serviceActivationData || {enabled:false,records:[]};
    previous.records=[record,...previous.records.filter(r=>r.host_id!==record.host_id || r.activation_id!==record.activation_id)];state.serviceActivationData=previous;
    if(record.host_id===state.remediationHost) state.serviceActivationRecord=record;
    if(state.serviceActivationRef?.activation_id===record.activation_id && !serviceActivationPending.has(record.status)) state.serviceActivationRef=null;
    return record;
  }
  function stopServiceActivationPolling() { if(state.serviceActivationTimer!==null) window.clearTimeout(state.serviceActivationTimer);state.serviceActivationTimer=null; }
  function scheduleServiceActivationPolling() {
    stopServiceActivationPolling();
    if(state.token && state.view==='remediation' && !document.hidden && serviceActivationSupported() && !state.serviceActivationBusy) state.serviceActivationTimer=window.setTimeout(refreshServiceActivations,15000);
  }
  function dismissServiceActivationDialog() {
    if(state.serviceActivationExpiry!==null) window.clearTimeout(state.serviceActivationExpiry);state.serviceActivationExpiry=null;state.serviceActivationDialogTarget=null;
    if(state.serviceActivationBusy==='prepare') {state.serviceActivationRequest+=1;state.serviceActivationBusy='';}
    const dialog=$('service-activation-dialog');if(dialog?.open) dialog.close();
    $('service-activation-confirm').checked=false;$('service-activation-execute').disabled=true;$('service-activation-dialog-error').hidden=true;
  }
  function serviceActivationHasPending(host) {
    return state.serviceActivationRef?.host_id===host || remediationList(state.serviceActivationData?.records).some(r=>r.host_id===host && serviceActivationPending.has(r.status));
  }
  function serviceActivationCanPrepare(job) {
    const policy=state.automation?.policy?.service_activation;
    return Boolean(job && state.token && state.view==='remediation' && state.serviceActivationData?.enabled===true && policy?.enabled===true && policy.host_ids?.includes(job.host_id) && job.status==='installed_restart_pending' && job.host_id===state.remediationHost && Number.isSafeInteger(state.automation?.revision) && ['manual','assisted'].includes(state.automation?.mode) && state.automation.mode_sync_complete===true && !state.automationBusy && !state.automationNeedsReload && !state.remediationBusy && !state.serviceActivationBusy && !serviceActivationHasPending(job.host_id));
  }
  function serviceActivationCanSubmit(target) {
    const record=target?.record,plan=record?.plan,policy=state.automation?.policy?.service_activation;
    return Boolean(target && target.session===state.session && state.token && state.view==='remediation' && target.host===state.remediationHost && record?.status==='prepared' && record.stale===false && plan?.eligible===true && Array.isArray(plan.blockers) && plan.blockers.length===0 && plan.prepared_mode==='assisted' && state.serviceActivationData?.enabled===true && state.automation?.policy?.enabled===true && state.automation.policy.allow_service_restart===true && state.automation?.mode==='assisted' && state.automationDraft==='assisted' && plan.mode_revision===state.automation.revision && state.automation.mode_sync_complete===true && !state.automationBusy && !state.automationNeedsReload && policy?.enabled===true && policy.host_ids?.includes(target.host) && policy.allowed_units?.includes(plan.unit) && policy.allowed_packages?.includes(plan.package) && Date.parse(plan.expires_at)>Date.now() && !state.serviceActivationBusy && !serviceActivationHasPending(target.host));
  }
  function renderServiceActivations() {
    renderActivationRecoveries();
    const section=$('service-activation-section');if(!section)return;section.hidden=!serviceActivationSupported();if(section.hidden)return;
    if($('service-activation-dialog').open) $('service-activation-execute').disabled=!$('service-activation-confirm').checked || !serviceActivationCanSubmit(state.serviceActivationDialogTarget);
    $('refresh-service-activations').disabled=Boolean(state.serviceActivationBusy || !state.token);
    $('service-activation-summary').textContent=state.serviceActivationData?.enabled===true?'已登记独立激活范围。手动模式可核对预览，执行需要半自动模式下明确批准。':'当前部署未启用服务激活。原补丁与暂停保留，由部署者单独登记目标、包和服务。';
    $('service-activation-progress').textContent={refresh:'正在读取本地激活记录，不执行远端动作。',prepare:'正在核对原任务、旧进程和已登记服务，尚未重启。',submit:'原激活 ID 已固定，正在提交一次批准。',query:'只查询原激活 ID，不会重新提交。'}[state.serviceActivationBusy] || '';
    $('service-activation-error').textContent=state.serviceActivationError;$('service-activation-error').hidden=!state.serviceActivationError;
    const pending=$('service-activation-pending');clear(pending);
    const jobs=remediationList(state.remediation?.jobs).filter(j=>j.host_id===state.remediationHost && j.status==='installed_restart_pending');
    for(const job of jobs) {const card=node('article','remediation-job-card');card.append(node('strong','','原安装任务 · 等待服务激活'),node('p','mono small',job.job_id));const button=node('button','button','核对服务激活预览');button.type='button';button.dataset.serviceActivationPrepare=job.job_id;button.disabled=!serviceActivationCanPrepare(job);button.addEventListener('click',()=>prepareServiceActivation(job));card.append(button);pending.append(card);}
    if(!jobs.length) pending.append(node('p','empty-note','当前目标没有已登记的服务激活待办。'));
    const records=$('service-activation-records');clear(records);
    for(const record of remediationList(state.serviceActivationData?.records).filter(r=>r.host_id===state.remediationHost).slice(0,100)) {const button=node('button','vulnerability-ai-history-item');button.type='button';button.dataset.serviceActivationQuery=record.activation_id;button.disabled=Boolean(state.serviceActivationBusy);button.append(node('strong','',serviceActivationStates[record.status]),node('p','mono small',record.activation_id),node('p','small',record.plan.unit || '服务未能确定'));button.addEventListener('click',()=>queryServiceActivation(record.host_id,record.activation_id));records.append(button);}
    const ref=state.serviceActivationRef;if(ref?.host_id===state.remediationHost && !state.serviceActivationData?.records.some(r=>r.activation_id===ref.activation_id)) {const button=node('button','button','查询原激活 '+ref.activation_id);button.type='button';button.disabled=Boolean(state.serviceActivationBusy);button.addEventListener('click',()=>queryServiceActivation(ref.host_id,ref.activation_id));records.append(button);}
    const detail=$('service-activation-detail');clear(detail);const record=state.serviceActivationRecord;
    if(!record || record.host_id!==state.remediationHost) {detail.append(node('p','empty-note','选择激活记录，分别核对原安装状态和本次激活验证。'));return;}
    detail.append(node('h3','',serviceActivationStates[record.status]),node('p','small',record.detail || ''),detailList([['原安装任务',record.job_id],['原安装状态','已安装，历史服务激活待办保留'],['激活服务',record.plan.unit || '未确定'],['软件包',record.plan.package || '未确定'],['激活 ID',record.activation_id],['更新时间',record.updated_at?dateLabel(record.updated_at):'未知']]));
    if(record.stale===true) detail.append(node('p','notice','此记录的目标或权限范围已变化，仅保留原历史结果。'));
    if(record.status==='verified') detail.append(node('p','notice neutral','本次服务激活验证通过；原安装记录与暂停没有被改写或解除。'));
    if(record.original_job?.evidence_provenance?.classification==='synthetic_fixture') detail.append(node('p','notice','受控实验：原补丁和漏洞判定是合成前置件，不代表真实补丁安装或官方漏洞复扫。'));
    if(record.rescan_reference) detail.append(detailList([['独立复扫 ID',record.rescan_reference.rescan_request_id],['原安装任务',record.rescan_reference.original_job_id]]),node('p','small muted','独立复扫关联已登记；完成状态、实际采集与供应商覆盖缺口请核对导出的证据。'));
    if(serviceActivationPending.has(record.status)) detail.append(node('p','notice','原请求可能已经执行。只查询原 ID；不会换 ID 重启服务。'));
    const query=node('button','button','查询原激活记录');query.type='button';query.disabled=Boolean(state.serviceActivationBusy);query.addEventListener('click',()=>queryServiceActivation(record.host_id,record.activation_id));detail.append(query);
    const download=node('button','button','导出激活证据');download.type='button';download.disabled=Boolean(state.serviceActivationBusy);download.addEventListener('click',()=>downloadServiceActivation(record,download));detail.append(download);
    if(record.result?.verification) {const facts=node('details','');facts.append(node('summary','','查看本次验证回执'));const pre=node('pre','vulnerability-ai-input',JSON.stringify(record.result.verification,null,2));facts.append(pre);detail.append(facts);}
  }
  async function refreshServiceActivations() {
    if(!state.token || !serviceActivationSupported() || state.serviceActivationBusy)return;
    const session=state.session,request=++state.serviceActivationRequest;state.serviceActivationBusy='refresh';stopServiceActivationPolling();renderServiceActivations();
    try {const value=await api('/api/service-activations');if(session!==state.session || request!==state.serviceActivationRequest)return;
      if(!value || typeof value.enabled!=='boolean' || value.original_patch_jobs_modified!==false || !Array.isArray(value.records) || value.records.length>1000)throw new Error('激活清单格式未能核实。');
      value.records=value.records.map(r=>checkServiceActivationAnchor(checkedServiceActivation(r)));if(new Set(value.records.map(r=>r.host_id+'|'+r.activation_id)).size!==value.records.length)throw new Error('激活清单包含重复原身份。');state.serviceActivationData=value;const ref=state.serviceActivationRef;if(ref && value.records.some(r=>r.host_id===ref.host_id && r.activation_id===ref.activation_id && !serviceActivationPending.has(r.status)))state.serviceActivationRef=null;const selected=state.serviceActivationRecord;state.serviceActivationRecord=value.records.find(r=>r.activation_id===selected?.activation_id && r.host_id===state.remediationHost) || value.records.find(r=>r.host_id===state.remediationHost) || null;state.serviceActivationError='';
    } catch(cause) {if(!(cause instanceof SessionEnded) && session===state.session && request===state.serviceActivationRequest)state.serviceActivationError='读取激活记录未完成：'+errorMessage(cause);}
    finally {if(session===state.session && request===state.serviceActivationRequest) {state.serviceActivationBusy='';renderServiceActivations();scheduleServiceActivationPolling();}}
  }
  async function prepareServiceActivation(job) {
    if(!serviceActivationCanPrepare(job))return;dismissServiceActivationDialog();state.serviceActivationPlan=null;
    const context={session:state.session,host:job.host_id,job:job.job_id,revision:state.automation.revision,mode:state.automation.mode},request=++state.serviceActivationRequest;state.serviceActivationBusy='prepare';state.serviceActivationError='';stopServiceActivationPolling();renderServiceActivations();
    try {const value=await api('/api/service-activations/plans',{method:'POST',body:{host_id:context.host,job_id:context.job,expected_mode_revision:context.revision}});
      if(context.session!==state.session || request!==state.serviceActivationRequest || context.host!==state.remediationHost || context.revision!==state.automation?.revision || context.mode!==state.automation?.mode)return;
      const record=checkedServiceActivation(value,context.host),plan=record.plan;if(record.job_id!==context.job || plan.mode_revision!==context.revision || plan.prepared_mode!==context.mode || !Number.isFinite(Date.parse(plan.expires_at)))throw new Error('激活预览与当前原任务或模式不一致。');
      const evidence=JSON.stringify(plan,null,2);if(evidence.length>262144)throw new Error('激活预览超过可完整核对的预算。');mergeServiceActivation(record);state.serviceActivationPlan=record;
      const target={...context,record};state.serviceActivationDialogTarget=target;const summary=$('service-activation-dialog-summary');clear(summary);summary.append(detailList([['目标',remediationName(context.host)],['原安装任务',record.job_id],['唯一激活服务',plan.unit || '未确定'],['软件包 / 当前版本',[plan.package,plan.candidate_version].filter(Boolean).join(' / ')],['旧进程',remediationList(plan.processes).map(p=>String(p.pid)).join('、') || '未取得'],['预览有效至',dateLabel(plan.expires_at)]]));
      if(plan.eligible!==true) summary.append(node('p','notice','预览存在未通过检查，不能批准：'+remediationList(plan.blockers).join('、')));
      if(context.mode!=='assisted') summary.append(node('p','notice','当前仅查看预览。执行需要切到半自动模式后重新取得预览。'));
      $('service-activation-dialog-evidence').textContent=evidence;$('service-activation-confirm').checked=false;$('service-activation-confirm').disabled=plan.eligible!==true || context.mode!=='assisted';$('service-activation-execute').disabled=true;$('service-activation-dialog').showModal();$('service-activation-dialog-title').focus();
      state.serviceActivationExpiry=window.setTimeout(()=>{if(state.serviceActivationDialogTarget===target){dismissServiceActivationDialog();state.serviceActivationPlan=null;state.serviceActivationError='激活预览已过期，请重新核对。';renderServiceActivations();}},Math.max(0,Date.parse(plan.expires_at)-Date.now()));
    } catch(cause) {if(!(cause instanceof SessionEnded) && context.session===state.session && request===state.serviceActivationRequest)state.serviceActivationError='服务激活预览未就绪：'+errorMessage(cause);}
    finally {if(context.session===state.session && request===state.serviceActivationRequest){state.serviceActivationBusy='';renderServiceActivations();scheduleServiceActivationPolling();}}
  }
  async function executeServiceActivation() {
    const target=state.serviceActivationDialogTarget;if(!$('service-activation-confirm').checked || !serviceActivationCanSubmit(target))return;
    const record=target.record,ref={host_id:target.host,activation_id:record.activation_id,activation_digest:record.activation_digest,job_id:record.job_id,scope_hash:record.scope_hash,policy_digest:record.policy_digest,controller_policy_digest:record.controller_policy_digest,context_digest:record.plan.context_digest};state.serviceActivationRef=ref;dismissServiceActivationDialog();state.serviceActivationPlan=null;
    const session=state.session,request=++state.serviceActivationRequest;state.serviceActivationBusy='submit';state.serviceActivationError='';stopServiceActivationPolling();renderServiceActivations();
    try {const value=await api('/api/service-activations',{method:'POST',body:{host_id:target.host,activation_id:record.activation_id,expected_activation_digest:record.activation_digest,expected_mode_revision:target.revision,confirm_activate:true}});
      if(session!==state.session || request!==state.serviceActivationRequest)return;mergeServiceActivation(checkServiceActivationAnchor(checkedServiceActivation(value,ref.host_id,ref.activation_id),record));announce('本次激活批准已返回，按原 ID 跟进验证结果。');
    } catch(cause){if(!(cause instanceof SessionEnded) && session===state.session && request===state.serviceActivationRequest)state.serviceActivationError='激活结果未能核实：'+errorMessage(cause)+' 已保留原激活 ID，只查询，不重新提交。';}
    finally {if(session===state.session && request===state.serviceActivationRequest){state.serviceActivationBusy='';renderServiceActivations();scheduleServiceActivationPolling();}}
  }
  async function queryServiceActivation(host,id) {
    if(!state.token || state.serviceActivationBusy || !vulnerabilityAIHex(id,32))return;const session=state.session,request=++state.serviceActivationRequest;state.serviceActivationBusy='query';renderServiceActivations();
    try {const value=await api('/api/service-activations/'+encodeURIComponent(host)+'/'+id);if(session!==state.session || request!==state.serviceActivationRequest)return;mergeServiceActivation(checkedServiceActivation(value,host,id));state.serviceActivationError='';}
    catch(cause){if(!(cause instanceof SessionEnded) && session===state.session && request===state.serviceActivationRequest)state.serviceActivationError='原激活记录未取得：'+errorMessage(cause)+' 未重新提交。';}
    finally {if(session===state.session && request===state.serviceActivationRequest){state.serviceActivationBusy='';renderServiceActivations();scheduleServiceActivationPolling();}}
  }
  async function downloadServiceActivation(record,button) {
    const session=state.session;button.disabled=true;
    try {const blob=await api('/api/service-activations/'+encodeURIComponent(record.host_id)+'/'+record.activation_id+'/evidence',{blob:true});if(session!==state.session || !state.token)return;if(blob.size>4194304)throw new Error('激活证据超过下载预算。');const url=URL.createObjectURL(blob),link=node('a');link.href=url;link.download='opsark-activation-'+record.activation_id+'.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
    catch(cause){if(!(cause instanceof SessionEnded) && session===state.session){state.serviceActivationError='激活证据未导出：'+errorMessage(cause);renderServiceActivations();}}
    finally {if(session===state.session)button.disabled=false;}
  }
  const activationRecoveryStates={prepared:'恢复预览待批准',submission_intent:'恢复批准已登记 · 待核实',unknown:'恢复结果未知 · 只查原 ID',verified:'这条暂停已核验恢复',rejected:'本次恢复已拒绝',superseded:'上下文已变化 · 保留历史'};
  const activationRecoveryPending=new Set(['submission_intent','unknown']);
  const activationRecoveryAnchors=['recovery_id','recovery_digest','host_id','job_id','job_revision','job_digest','activation_id','activation_revision','activation_digest','activation_record_digest','activation_raw_sha256','original_job_sha256','original_plan_sha256','runtime_manifest_sha256','activation_plan_sha256','restart_intent_sha256','policy_digest','driver_source_digest','context_digest','root_safety_digest','root_safety_raw_sha256','ledger_digest','mode_revision'];
  function activationRecoverySupported() { return state.capabilities?.activation_recovery===true; }
  function activationRecoveryMode() { return state.automation?.mode==='manual' && state.automationDraft==='manual' && state.automation.mode_sync_complete===true && Number.isSafeInteger(state.automation.revision) && !state.automationBusy && !state.automationNeedsReload; }
  function activationRecoveryPolicy(host) { const policy=state.automation?.policy,activation=policy?.service_activation;return policy?.enabled===true && policy.host_ids?.includes(host) && policy.allowed_actions?.includes('os_security_upgrade') && activation?.enabled===true && activation.host_ids?.includes(host); }
  function checkedActivationRecoveryPlan(value,context=null,{live=false}={}) {
    if(!value || typeof value!=='object' || value.schema_version!==1 || value.kind!=='activation_recovery' || value.status!=='activation_recovery_prepared' || !remediationToken(value.host_id) || !recoveryIdentifier(value.recovery_id) || !recoveryIdentifier(value.job_id) || !recoveryIdentifier(value.activation_id) || !Number.isSafeInteger(value.job_revision) || value.job_revision<1 || !Number.isSafeInteger(value.activation_revision) || value.activation_revision<1 || !Number.isSafeInteger(value.mode_revision) || value.mode_revision<0 || typeof value.eligible!=='boolean' || !Array.isArray(value.checks) || !value.checks.length || value.checks.length>64 || !Array.isArray(value.blockers) || value.blockers.length>64 || !value.blockers.every(item=>typeof item==='string' && item.length<=2000)) throw new Error('恢复预览缺少原任务、已验证激活或模式绑定。');
    for(const key of activationRecoveryAnchors.filter(key=>!['host_id','recovery_id','job_id','job_revision','activation_id','activation_revision','mode_revision'].includes(key)))if(!(['root_safety_raw_sha256','root_safety_digest'].includes(key) && value.eligible===false && value[key]===null) && !recoveryDigest(value[key]))throw new Error('恢复预览的原始证据指纹不完整。');
    const seen=new Set();for(const check of value.checks){if(!check || typeof check.id!=='string' || !/^[a-z][a-z0-9_]{0,79}$/.test(check.id) || seen.has(check.id) || !['passed','failed','unavailable'].includes(check.status) || typeof check.detail!=='string' || check.detail.length>2000)throw new Error('恢复检查缺少有效结果。');seen.add(check.id);}
    const created=Date.parse(value.created_at),expires=Date.parse(value.expires_at);
    if(!recoveryTimestamp(value.created_at) || !recoveryTimestamp(value.expires_at) || expires-created<=0 || expires-created>300000 || live && (created>Date.now()+1000 || expires<=Date.now()))throw new Error('恢复预览的有效期未能核实。');
    if(context && (value.host_id!==context.host || value.job_id!==context.job || value.activation_id!==context.activation || value.mode_revision!==context.revision))throw new Error('恢复预览与当前原任务、激活或模式不一致。');
    if(value.eligible && (value.blockers.length || value.checks.some(check=>check.status!=='passed') || value.root_safety_before?.paused!==true || value.root_safety_before.job_id!==value.job_id || value.root_safety_before.reason!=='automatic_job_installed_restart_pending'))throw new Error('恢复预览没有证明同一条已存在的自动暂停。');
    if(!Object.hasOwn(value,'root_usage_before'))throw new Error('恢复预览没有保留原额度快照。');
    if(JSON.stringify(value).length>262144)throw new Error('恢复预览超过可完整核对的预算。');
    return value;
  }
  function checkActivationRecoveryAnchor(value,anchor=null) {
    const original=anchor?.plan || anchor || remediationList(state.activationRecoveryData?.records).find(record=>record.host_id===value.host_id && record.recovery_id===value.recovery_id)?.plan || (state.activationRecoveryRef?.host_id===value.host_id && state.activationRecoveryRef.recovery_id===value.recovery_id?state.activationRecoveryRef.plan:null);
    if(original && activationRecoveryAnchors.some(key=>original[key]!==value.plan?.[key]))throw new Error('恢复回执与原预览的任务、激活、暂停或范围指纹不一致；保留原 ID。');
    return value;
  }
  function checkedActivationRecovery(value,host=null,id=null,anchor=null) {
    if(!value || typeof value!=='object' || value.schema_version!==1 || value.kind!=='activation_recovery' || !remediationToken(value.host_id) || !recoveryIdentifier(value.recovery_id) || !recoveryDigest(value.recovery_digest) || !recoveryIdentifier(value.job_id) || !recoveryIdentifier(value.activation_id) || !Object.hasOwn(activationRecoveryStates,value.status) || typeof value.local_released!=='boolean' || (host && value.host_id!==host) || (id && value.recovery_id!==id))throw new Error('恢复记录的原身份或状态不完整。');
    const plan=checkedActivationRecoveryPlan(value.plan);
    if(['host_id','recovery_id','recovery_digest','job_id','activation_id'].some(key=>value[key]!==plan[key]))throw new Error('恢复记录与原预览身份不同。');
    if(value.status==='verified'){
      const receipt=value.receipt,completed=Date.parse(receipt?.completed_at);
      if(!receipt || !Object.hasOwn(receipt,'root_usage_before') || !Object.hasOwn(receipt,'root_usage_after'))throw new Error('恢复回执缺少恢复前后的额度快照。');
      if(value.local_released!==true || receipt?.schema_version!==1 || receipt.kind!=='activation_recovery' || receipt.status!=='verified' || !recoveryDigest(receipt.receipt_digest) || [...activationRecoveryAnchors.filter(key=>key!=='root_safety_digest'),'created_at','expires_at'].some(key=>receipt[key]!==plan[key]) || activationRecoveryCanonical(receipt.plan)!==activationRecoveryCanonical(plan) || receipt.resolved_safety_digest!==plan.root_safety_digest || receipt.verification?.fresh_ssh?.passed!==true || receipt.verification.fresh_ssh.mechanism!=='sshd_connection_started_after_activation_recovery_preview' || receipt.resolved_job?.status!=='installed_restart_pending' || receipt.resolved_job.job_id!==plan.job_id || receipt.resolved_job.revision!==plan.job_revision || receipt.resolved_job.job_digest!==plan.job_digest || receipt.verified_activation?.status!=='verified' || receipt.verified_activation.activation_id!==plan.activation_id || receipt.verified_activation.revision!==plan.activation_revision || receipt.verified_activation.activation_digest!==plan.activation_digest || receipt.verified_activation.record_digest!==plan.activation_record_digest || receipt.safety_after?.paused!==false || receipt.safety_after.job_id!==null || receipt.safety_after.reason!==null || !recoveryTimestamp(receipt.completed_at) || completed<Date.parse(plan.created_at) || completed>=Date.parse(plan.expires_at) || completed>Date.now()+1000 || !Array.isArray(receipt.checks) || !receipt.checks.length || receipt.checks.length>64 || receipt.checks.some(check=>check?.status!=='passed') || !Array.isArray(receipt.blockers) || receipt.blockers.length || receipt.verification.runtime?.status!=='complete' || receipt.verification.runtime.outdated_process_count!==0 || ['exact_package_version','vendor_rescan','health','activation_process','final_package_state'].some(key=>receipt.verification[key]?.passed!==true) || activationRecoveryCanonical(receipt.root_usage_before)!==activationRecoveryCanonical(plan.root_usage_before) || activationRecoveryCanonical(receipt.root_usage_after)!==activationRecoveryCanonical(plan.root_usage_before))throw new Error('恢复记录没有完整的 Root 回执与本地对账证明。');
    }else if(value.local_released===true)throw new Error('未完成的恢复不能宣称当前暂停已解除。');
    return checkActivationRecoveryAnchor(value,anchor);
  }
  function activationRecoveryCanonical(value) { const sorted=item=>Array.isArray(item)?item.map(sorted):item && typeof item==='object'?Object.fromEntries(Object.keys(item).sort().map(key=>[key,sorted(item[key])])):item;return JSON.stringify(sorted(value)); }
  function mergeActivationRecovery(value,anchor=null) {
    const record=checkedActivationRecovery(value,null,null,anchor),previous=state.activationRecoveryData || {enabled:false,records:[]};
    previous.records=[record,...previous.records.filter(item=>item.host_id!==record.host_id || item.recovery_id!==record.recovery_id)];state.activationRecoveryData=previous;
    if(record.host_id===state.remediationHost)state.activationRecoveryRecord=record;
    if(state.activationRecoveryRef?.host_id===record.host_id && state.activationRecoveryRef.recovery_id===record.recovery_id && ['verified','rejected','superseded'].includes(record.status))state.activationRecoveryRef=null;
    return record;
  }
  function stopActivationRecoveryPolling() { if(state.activationRecoveryTimer!==null)window.clearTimeout(state.activationRecoveryTimer);state.activationRecoveryTimer=null; }
  function scheduleActivationRecoveryPolling() { stopActivationRecoveryPolling();if(state.token && state.view==='remediation' && !document.hidden && activationRecoverySupported() && !state.activationRecoveryBusy)state.activationRecoveryTimer=window.setTimeout(refreshActivationRecoveries,15000); }
  function dismissActivationRecoveryDialog() {
    if(state.activationRecoveryExpiry!==null)window.clearTimeout(state.activationRecoveryExpiry);state.activationRecoveryExpiry=null;state.activationRecoveryDialogTarget=null;
    if(state.activationRecoveryBusy==='prepare'){state.activationRecoveryRequest+=1;state.activationRecoveryBusy='';}
    const dialog=$('activation-recovery-dialog');if(dialog?.open)dialog.close();$('activation-recovery-confirm').checked=false;$('activation-recovery-confirm').disabled=false;$('activation-recovery-execute').disabled=true;$('activation-recovery-dialog-error').hidden=true;
  }
  function activationRecoveryHasPending(host) { return state.activationRecoveryRef?.host_id===host || remediationList(state.activationRecoveryData?.records).some(record=>record.host_id===host && activationRecoveryPending.has(record.status)); }
  function activationRecoveryPause(host,job,{allowRefreshing=false}={}) {
    const status=state.automaticStatus,entry=remediationList(status?.hosts).find(item=>item.host_id===host),latch=entry?.latch || remediationList(status?.latched_hosts).find(item=>item.host_id===host),remote=entry?.remote_status?.remote?.safety || latch?.remote_safety;
    return !state.automaticError && (!state.automaticBusy || allowRefreshing) && latch?.job_id===job && remote?.paused===true && remote.job_id===job && remote.reason==='automatic_job_installed_restart_pending'?{latch,remote}:null;
  }
  function activationRecoverySourceAnchor(host,job) { const pause=activationRecoveryPause(host,job,{allowRefreshing:true});return pause?JSON.stringify({latch:pause.latch,safety:pause.remote,policy:state.automation?.policy}):null; }
  function activationRecoveryCanPrepare(record) {
    const job=remediationList(state.remediation?.jobs).find(item=>item.host_id===record.host_id && item.job_id===record.job_id) || record.original_job;
    return Boolean(state.token && state.view==='remediation' && state.activationRecoveryData?.enabled===true && !state.activationRecoveryError && activationRecoveryMode() && activationRecoveryPolicy(record.host_id) && record.host_id===state.remediationHost && record.status==='verified' && record.stale===false && job?.status==='installed_restart_pending' && job.authorization==='automatic' && activationRecoveryPause(record.host_id,record.job_id) && !state.activationRecoveryBusy && !state.remediationBusy && !state.serviceActivationBusy && !activationRecoveryHasPending(record.host_id));
  }
  function activationRecoveryCanSubmit(target) {
    const plan=target?.plan;
    return Boolean(target && target.session===state.session && state.token && target.host===state.remediationHost && state.view==='remediation' && state.activationRecoveryData?.enabled===true && activationRecoveryMode() && activationRecoveryPolicy(target.host) && !state.automaticBusy && target.sourceAnchor!==null && target.sourceAnchor===activationRecoverySourceAnchor(target.host,target.job) && plan?.eligible===true && plan.blockers.length===0 && plan.checks.every(check=>check.status==='passed') && plan.mode_revision===state.automation.revision && Date.parse(plan.expires_at)>Date.now() && !state.activationRecoveryBusy && !activationRecoveryHasPending(target.host));
  }
  function renderActivationRecoveries() {
    const section=$('activation-recovery-section');if(!section)return;section.hidden=!activationRecoverySupported();if(section.hidden)return;
    const dialogTarget=state.activationRecoveryDialogTarget;if($('activation-recovery-dialog').open && dialogTarget && !state.automaticBusy && dialogTarget.sourceAnchor!==activationRecoverySourceAnchor(dialogTarget.host,dialogTarget.job)){dismissActivationRecoveryDialog();state.activationRecoveryPlan=null;state.activationRecoveryError='暂停原因或授权快照已变化，旧恢复确认已取消。';}
    if($('activation-recovery-dialog').open)$('activation-recovery-execute').disabled=!$('activation-recovery-confirm').checked || !activationRecoveryCanSubmit(state.activationRecoveryDialogTarget);
    $('refresh-activation-recoveries').disabled=Boolean(!state.token || state.activationRecoveryBusy);
    $('activation-recovery-summary').textContent=state.activationRecoveryData?.enabled===true?'当前入口仅接受手动模式下的独立明确批准。先核对自动安装原任务、已验证激活和同一条持续暂停。':'当前部署未启用激活后的暂停恢复。原任务、激活回执与暂停继续保留。';
    $('activation-recovery-progress').textContent={refresh:'正在读取已保留的恢复记录，不执行远端动作。',prepare:'正在核对原任务、已验证激活与当前服务；尚未解除暂停。',submit:'批准意图已固定，正在核验；结果未知时只查原 ID。',query:'只查询原恢复 ID，核对原回执，不重新批准。'}[state.activationRecoveryBusy] || '';
    $('activation-recovery-error').textContent=state.activationRecoveryError;$('activation-recovery-error').hidden=!state.activationRecoveryError;
    const candidates=$('activation-recovery-candidates');clear(candidates);
    const activations=remediationList(state.serviceActivationData?.records).filter(record=>record.host_id===state.remediationHost && record.status==='verified');
    for(const record of activations){const card=node('article','remediation-job-card');card.append(node('strong','','已验证激活 · 原安装待办保留'),detailList([['原安装任务',record.job_id],['已验证激活',record.activation_id]]));const button=node('button','button','核对激活后的暂停恢复');button.type='button';button.dataset.activationRecoveryPrepare=record.activation_id;button.disabled=!activationRecoveryCanPrepare(record);button.addEventListener('click',()=>prepareActivationRecovery(record));card.append(button);if(button.disabled)card.append(node('p','small muted',activationRecoveryHasPending(record.host_id)?'已有恢复批准待核实，只查询原恢复 ID。':!activationRecoveryMode()?'请在已同步的手动模式下核对恢复，模式选择本身不解除暂停。':'仅有真实自动父任务、同一条当前暂停及明确授权时开放；缺件或未暂停不创建恢复权限。'));candidates.append(card);}
    if(!activations.length)candidates.append(node('p','empty-note','当前目标没有可关联的已验证服务激活。'));
    const records=$('activation-recovery-records');clear(records);const rows=remediationList(state.activationRecoveryData?.records).filter(record=>record.host_id===state.remediationHost);
    for(const record of rows.slice(0,100)){const button=node('button','vulnerability-ai-history-item');button.type='button';button.dataset.activationRecoveryQuery=record.recovery_id;button.disabled=Boolean(state.activationRecoveryBusy);button.append(node('strong','',activationRecoveryStates[record.status]),node('p','mono small',record.recovery_id));button.addEventListener('click',()=>queryActivationRecovery(record.host_id,record.recovery_id));records.append(button);}
    const ref=state.activationRecoveryRef;if(ref?.host_id===state.remediationHost && !rows.some(record=>record.recovery_id===ref.recovery_id)){const button=node('button','button','查询原恢复 '+ref.recovery_id);button.type='button';button.disabled=Boolean(state.activationRecoveryBusy);button.addEventListener('click',()=>queryActivationRecovery(ref.host_id,ref.recovery_id));records.append(button);}
    if(!rows.length && ref?.host_id!==state.remediationHost)records.append(node('p','empty-note','尚无该目标的独立恢复记录。'));
    const detail=$('activation-recovery-detail');clear(detail);const record=state.activationRecoveryRecord;
    if(!record || record.host_id!==state.remediationHost){detail.append(node('p','empty-note','选择原恢复 ID，核对批准、远端回执及本地对账。'));return;}
    detail.append(node('h3','',activationRecoveryStates[record.status]),node('p','small',record.detail || ''),detailList([['原安装任务',record.job_id],['原安装历史','已安装，原 pending 状态不改写'],['已验证激活',record.activation_id],['独立恢复 ID',record.recovery_id],['更新时间',record.updated_at?dateLabel(record.updated_at):'未知']]));
    if(record.status==='verified' && record.local_released===true)detail.append(node('p','notice neutral',record.stale===true?'此份历史恢复曾完成，当前范围已变化，不能据此判断当前暂停。':'这一条原暂停已完成独立对账；原安装和激活历史保留，模式、授权和配额没有改变。'));
    if(record.status==='superseded')detail.append(node('p','notice','上下文已变化，此记录未解除当前暂停；原 Root 结果另行保留，不能用旧批准覆盖新原因。'));
    if(activationRecoveryPending.has(record.status) || ref?.recovery_id===record.recovery_id)detail.append(node('p','notice','Root 可能已经接受批准。保留原 ID，只查询，不重新提交。'));
    const query=node('button','button','查询原恢复回执');query.type='button';query.disabled=Boolean(state.activationRecoveryBusy);query.addEventListener('click',()=>queryActivationRecovery(record.host_id,record.recovery_id));detail.append(query);
    const facts=node('details','');facts.append(node('summary','','查看保留的恢复证据'));facts.append(node('pre','vulnerability-ai-input',JSON.stringify({plan:record.plan,receipt:record.receipt,local_released:record.local_released},null,2)));detail.append(facts);
  }
  async function refreshActivationRecoveries() {
    if(!state.token || !activationRecoverySupported() || state.activationRecoveryBusy)return;
    const session=state.session,request=++state.activationRecoveryRequest;state.activationRecoveryBusy='refresh';stopActivationRecoveryPolling();renderActivationRecoveries();
    try{const value=await api('/api/activation-recoveries');if(session!==state.session || request!==state.activationRecoveryRequest)return;if(!value || typeof value.enabled!=='boolean' || !Array.isArray(value.records) || value.records.length>1000)throw new Error('恢复清单格式未能核实。');value.records=value.records.map(record=>checkedActivationRecovery(record));if(new Set(value.records.map(record=>record.host_id+'|'+record.recovery_id)).size!==value.records.length)throw new Error('恢复清单包含重复身份。');state.activationRecoveryData=value;const selected=state.activationRecoveryRecord;state.activationRecoveryRecord=value.records.find(record=>record.host_id===state.remediationHost && record.recovery_id===selected?.recovery_id) || value.records.find(record=>record.host_id===state.remediationHost) || null;const ref=state.activationRecoveryRef;if(ref && value.records.some(record=>record.host_id===ref.host_id && record.recovery_id===ref.recovery_id && ['verified','rejected','superseded'].includes(record.status)))state.activationRecoveryRef=null;state.activationRecoveryError='';}
    catch(cause){if(!(cause instanceof SessionEnded) && session===state.session && request===state.activationRecoveryRequest)state.activationRecoveryError='恢复记录读取未完成：'+errorMessage(cause)+' 保留的记录仅供历史核对。';}
    finally{if(session===state.session && request===state.activationRecoveryRequest){state.activationRecoveryBusy='';renderActivationRecoveries();scheduleActivationRecoveryPolling();}}
  }
  async function prepareActivationRecovery(activation) {
    if(!activationRecoveryCanPrepare(activation))return;dismissActivationRecoveryDialog();state.activationRecoveryPlan=null;
    const context={session:state.session,host:activation.host_id,job:activation.job_id,activation:activation.activation_id,revision:state.automation.revision,sourceAnchor:activationRecoverySourceAnchor(activation.host_id,activation.job_id)},request=++state.activationRecoveryRequest;state.activationRecoveryBusy='prepare';state.activationRecoveryError='';stopActivationRecoveryPolling();renderActivationRecoveries();
    try{const value=await api('/api/activation-recoveries/plans',{method:'POST',body:{host_id:context.host,job_id:context.job,activation_id:context.activation,expected_mode_revision:context.revision}});if(context.session!==state.session || request!==state.activationRecoveryRequest || context.host!==state.remediationHost || context.revision!==state.automation?.revision || !activationRecoveryMode() || context.sourceAnchor!==activationRecoverySourceAnchor(context.host,context.job))return;const plan=checkedActivationRecoveryPlan(value,context,{live:true});state.activationRecoveryPlan=plan;const target={...context,plan};state.activationRecoveryDialogTarget=target;const summary=$('activation-recovery-dialog-summary');clear(summary);summary.append(detailList([['目标',remediationName(context.host)],['原安装任务',plan.job_id],['已验证激活',plan.activation_id],['原暂停原因',automaticPauseReason(plan.root_safety_before?.reason)],['恢复 ID',plan.recovery_id],['预览摘要',plan.recovery_digest],['Root 暂停指纹',plan.root_safety_digest || '未取得'],['模式绑定','手动 / 版本 '+String(plan.mode_revision)],['预览有效至',dateLabel(plan.expires_at)]]));const checks=node('ul','activation-recovery-checks');for(const check of plan.checks){const row=node('li','');row.dataset.checkStatus=check.status;row.append(node('strong','',({passed:'通过',failed:'未通过',unavailable:'未核实'}[check.status])+' · '+check.id),node('p','small muted',check.detail));checks.append(row);}summary.append(checks);if(!plan.eligible)summary.append(node('p','notice','存在未通过检查，不能批准：'+plan.blockers.join('、')));$('activation-recovery-dialog-evidence').textContent=JSON.stringify(plan,null,2);$('activation-recovery-confirm').checked=false;$('activation-recovery-confirm').disabled=!plan.eligible;$('activation-recovery-execute').disabled=true;$('activation-recovery-dialog').showModal();$('activation-recovery-dialog-title').focus();state.activationRecoveryExpiry=window.setTimeout(()=>{if(state.activationRecoveryDialogTarget===target){dismissActivationRecoveryDialog();state.activationRecoveryPlan=null;state.activationRecoveryError='恢复预览已过期，原暂停保持，请重新核对。';renderActivationRecoveries();}},Math.max(0,Date.parse(plan.expires_at)-Date.now()));}
    catch(cause){if(!(cause instanceof SessionEnded) && context.session===state.session && request===state.activationRecoveryRequest)state.activationRecoveryError='恢复预览未就绪：'+errorMessage(cause);}
    finally{if(context.session===state.session && request===state.activationRecoveryRequest){state.activationRecoveryBusy='';renderActivationRecoveries();scheduleActivationRecoveryPolling();}}
  }
  async function executeActivationRecovery() {
    const target=state.activationRecoveryDialogTarget;if(!$('activation-recovery-confirm').checked || !activationRecoveryCanSubmit(target))return;const plan=target.plan;state.activationRecoveryRef={host_id:target.host,recovery_id:plan.recovery_id,recovery_digest:plan.recovery_digest,plan};dismissActivationRecoveryDialog();state.activationRecoveryPlan=null;const session=state.session,request=++state.activationRecoveryRequest;state.activationRecoveryBusy='submit';state.activationRecoveryError='';stopActivationRecoveryPolling();renderActivationRecoveries();
    try{const value=await api('/api/activation-recoveries',{method:'POST',body:{host_id:target.host,recovery_id:plan.recovery_id,expected_recovery_digest:plan.recovery_digest,expected_mode_revision:target.revision,confirm_recover:true}});if(session!==state.session || request!==state.activationRecoveryRequest || target.host!==state.remediationHost || target.revision!==state.automation?.revision || !activationRecoveryMode() || state.view!=='remediation')return;const saved=mergeActivationRecovery(checkedActivationRecovery(value,target.host,plan.recovery_id,plan),plan);if(saved.local_released===true)refreshAutomatic({quiet:true});announce('恢复批准已返回，继续核对原恢复 ID；没有切换模式或重新执行修复。');}
    catch(cause){if(!(cause instanceof SessionEnded) && session===state.session && request===state.activationRecoveryRequest)state.activationRecoveryError='恢复结果未能核实：'+errorMessage(cause)+' 已保留原恢复 ID，只查询，不重新批准。';}
    finally{if(session===state.session && request===state.activationRecoveryRequest){state.activationRecoveryBusy='';renderActivationRecoveries();scheduleActivationRecoveryPolling();}}
  }
  async function queryActivationRecovery(host,id) {
    if(!state.token || !activationRecoverySupported() || state.activationRecoveryBusy || !remediationToken(host) || !recoveryIdentifier(id))return;const session=state.session,revision=state.automation?.revision,mode=state.automation?.mode,draft=state.automationDraft,request=++state.activationRecoveryRequest;state.activationRecoveryBusy='query';renderActivationRecoveries();
    try{const value=await api('/api/activation-recoveries/'+encodeURIComponent(host)+'/'+id);if(session!==state.session || request!==state.activationRecoveryRequest || host!==state.remediationHost || revision!==state.automation?.revision || mode!==state.automation?.mode || draft!==state.automationDraft || state.view!=='remediation')return;const saved=mergeActivationRecovery(checkedActivationRecovery(value,host,id));if(saved.local_released===true)refreshAutomatic({quiet:true});state.activationRecoveryError='';}
    catch(cause){if(!(cause instanceof SessionEnded) && session===state.session && request===state.activationRecoveryRequest)state.activationRecoveryError='原恢复结果未取得：'+errorMessage(cause)+' 只保留原 ID，不重新批准。';}
    finally{if(session===state.session && request===state.activationRecoveryRequest){state.activationRecoveryBusy='';renderActivationRecoveries();scheduleActivationRecoveryPolling();}}
  }
  function remediationScanStamp(scan) { return scan?String(scan.scan_id || scan.id || '')+'|'+String(scan.collected_at || '')+'|'+String(scan.inventory_digest || ''):''; }
  function stopRemediationPolling() { if(state.remediationPoll!==null) window.clearTimeout(state.remediationPoll); state.remediationPoll=null; }
  function scheduleRemediationPolling() {
    stopRemediationPolling();
    if(state.token && state.view==='remediation' && !document.hidden && !state.remediationBusy && state.remediationJobRef && remediationActiveStates.has(state.remediationJob?.status)) state.remediationPoll=window.setTimeout(()=>queryRemediationJob(state.remediationJobRef,{quiet:true}),10000);
  }
  function dismissRemediationDialog() {
    if(state.remediationExpiry!==null) window.clearTimeout(state.remediationExpiry); state.remediationExpiry=null;
    state.remediationDialogTarget=null; $('remediation-confirm').checked=false; $('remediation-execute').disabled=true;
    $('remediation-dialog-error').textContent=''; $('remediation-dialog-error').hidden=true; clear($('remediation-dialog-summary'));
    if($('remediation-dialog').open) $('remediation-dialog').close();
  }
  function invalidateRemediationPlan(reason='') {
    const hadPlan=Boolean(state.remediationPlan || state.remediationDialogTarget);
    state.remediationPlan=null; state.remediationSelection+=1; dismissRemediationDialog();
    if(reason && hadPlan) state.remediationError=reason;
  }
  function remediationCanApprove(plan=state.remediationPlan) {
    return Boolean(plan && state.token && state.view==='remediation' && state.remediation?.configured===true && state.remediation?.execution_available===true && remediationList(state.remediation?.supported_execution_modes).includes('assisted') && state.automation?.mode==='assisted' && !state.automationBusy && !state.automationNeedsReload && plan.mode_revision===state.automation.revision && plan.host_id===state.remediationHost && Date.parse(plan.expires_at)>Date.now() && plan.risk_level!=='unknown' && plan.restart_assessment!=='unknown' && !state.remediationBusy && !remediationHasPendingTask());
  }
  function remediationGaps(parent,gaps) {
    if(!Array.isArray(gaps) || !gaps.length) return;
    const list=node('ul','plain-list remediation-gaps');
    for(const gap of gaps.slice(0,20)) list.append(node('li','',typeof gap==='string'?vulnerabilityGapLabel(gap):remediationJSON(gap)));
    if(gaps.length>20) list.append(node('li','','还有 '+String(gaps.length-20)+' 项缺口未在此处展开。'));
    parent.append(list);
  }
  function remediationDetails(parent,label,value) {
    const details=node('details','remediation-evidence'); details.append(node('summary','',label),node('pre','remediation-json',remediationJSON(value))); parent.append(details);
  }
  function remediationPlanContent(parent,plan) {
    parent.append(node('h2','','具体修复方案'),node('p','small muted',remediationName(plan.host_id)+' · Ubuntu 官方安全更新'));
    for(const change of plan.package_changes) {
      const item=node('div','remediation-package-change'); item.append(node('h3','mono',change.name));
      const values=node('dl','change-values');
      for(const [label,value] of [['当前版本',change.current_version],['目标版本',change.candidate_version],['修复版本',change.fixed_version]]) values.append(node('dt','',label),node('dd','mono',value));
      item.append(values); parent.append(item);
    }
    const restart={none:'已评估为无需重启',possible:'可能重启服务',required:'需要重启',unknown:'重启影响未知'};
    const risk={low:'低',medium:'中',high:'高',unknown:'未知'};
    parent.append(detailList([['风险',risk[plan.risk_level] || '未知'],['重启影响',restart[plan.restart_assessment] || '未知'],['方案有效期',dateLabel(plan.expires_at)],['模式版本',plan.mode_revision],['方案摘要',plan.plan_digest]]));
    if(plan.health_before!==undefined) remediationDetails(parent,'查看修复前健康检查',plan.health_before);
    parent.append(node('p','small muted','授权绑定当前主机、状态和精确计划。软件、依赖、策略或模式变化后需要重新规划；配置备份和包降级不等于完整回滚。'));
  }
  function renderRemediationPlan() {
    const parent=$('remediation-plan'); clear(parent); const plan=state.remediationPlan;
    if(!plan) { parent.append(node('p','empty-note','从已确认受影响的记录生成方案，核对版本、影响和授权后再执行。')); return; }
    remediationPlanContent(parent,plan);
    if(state.vulnerabilityAIPlanRef?.plan_id===plan.plan_id) parent.append(node('p','notice neutral','此计划由 AI 提案触发，包变化、风险和授权已由服务器重新核验。模型没有执行安装。'));
    const button=node('button','button primary','复核并批准这份方案'); button.type='button'; button.id='review-remediation-plan'; button.disabled=!remediationCanApprove(plan); button.addEventListener('click',openRemediationDialog); parent.append(button);
    if(Date.parse(plan.expires_at)<=Date.now()) parent.append(node('p','error','方案已过期，请重新扫描或生成新方案。'));
    else if(!remediationCanApprove(plan)) parent.append(node('p','small muted',automaticSupported()?'此人工批准通道仅在半自动模式执行，请核对执行器、授权版本和已有任务。自动处置由后台另行核对预授权计划，本按钮不创建自动任务。':'当前不能执行：请核对半自动模式、执行器、授权版本和已有任务。全自动模式尚未开放此首轮补丁通道。'));
  }
  function renderRemediationScan() {
    const summary=$('remediation-scan-summary'),list=$('remediation-findings'); clear(summary); clear(list);
    const scan=state.remediationScan; $('remediation-scan-time').textContent=scan?.collected_at?dateLabel(scan.collected_at):'';
    if(!scan) { summary.append(node('p','empty-note','当前目标尚无扫描记录。扫描不会自动重复提交，耗时可能达到一分钟。')); return; }
    if(scan.host_id && scan.host_id!==state.remediationHost) { summary.append(node('p','error','扫描记录与所选目标不匹配，未展示或开放修复。')); return; }
    const findings=remediationList(scan.findings);
    summary.append(node('p','small muted','目标：'+remediationName(state.remediationHost)+'；此记录仅代表所覆盖的软件、供应商情报和采集时间，不证明整机无漏洞。'));
    if(scan.coverage!==undefined) remediationDetails(summary,'查看扫描覆盖范围',scan.coverage);
    remediationGaps(summary,scan.gaps);
    if(!findings.length) list.append(node('p','empty-note','本次覆盖范围未形成漏洞记录。请同时核对情报新鲜度与采集缺口。'));
    for(const finding of findings.slice(0,100)) {
      const row=node('article','remediation-finding'); row.append(node('h3','',String(finding.package || '软件包未确认')));
      const metadata=node('div','remediation-finding-meta');
      metadata.append(node('span','badge '+(finding.affected===true?'amber':'neutral'),finding.affected===true?'确认受影响':finding.affected===false?'本次匹配未受影响':'受影响状态未知'));
      if(typeof finding.advisory==='string') {
        const advisory=/^USN-[0-9]+-[0-9]+$/.test(finding.advisory)?node('a','evidence-link',finding.advisory):node('span','mono',finding.advisory);
        if(advisory.tagName==='A') { advisory.href='https://ubuntu.com/security/notices/'+encodeURIComponent(finding.advisory); advisory.target='_blank'; advisory.rel='noopener noreferrer'; }
        metadata.append(advisory);
      }
      row.append(metadata);
      const cves=Array.isArray(finding.cve)?finding.cve.filter(value=>typeof value==='string').join('、'):typeof finding.cve==='string'?finding.cve:'';
      if(cves) row.append(node('p','mono small',cves));
      row.append(detailList([['当前版本',finding.current_version || '未取得'],['供应商修复版',finding.fixed_binary_version || '尚无可用修复版本'],['情报状态',finding.vendor_evidence_fresh===true?'供应商证据新鲜':'需要补齐或更新证据'],['补丁条件',finding.candidate_fixable===true?'候选版本可用于此修复':'目前不能自动修复']]));
      remediationGaps(row,finding.gaps);
      const button=node('button','button','预览修复方案'); button.type='button'; button.dataset.remediationFinding=String(finding.finding_id || '');
      button.disabled=Boolean(state.remediationBusy || state.automationBusy || !state.automation || state.remediation?.configured!==true || finding.affected!==true || finding.candidate_fixable!==true || finding.vendor_evidence_fresh!==true || !finding.finding_id || remediationHasPendingTask());
      button.addEventListener('click',()=>prepareRemediationPlan(finding,scan)); row.append(button); list.append(row);
    }
    if(findings.length>100) list.append(node('p','small muted','此处展示前 100 条，共 '+String(findings.length)+' 条；不能把显示范围当作全部扫描范围。'));
  }
  function renderRemediationJob() {
    const list=$('remediation-job-list'),detail=$('remediation-job-detail'); clear(list); clear(detail);
    const jobs=remediationList(state.remediation?.jobs);
    for(const job of jobs.slice(0,100)) {
      const ref=remediationJobReference(job); if(!ref) continue;
      const button=node('button','remediation-job-button'); button.type='button'; button.disabled=Boolean(state.remediationBusy); button.dataset.remediationJob=ref.job_id;
      button.append(node('strong','',remediationName(ref.host_id)),node('span','badge '+(job.status==='verified'?'neutral':'amber'),remediationJobLabel(job.status)),node('span','mono small',ref.job_id));
      if(state.remediationJobRef?.job_id===ref.job_id && state.remediationJobRef?.host_id===ref.host_id) button.setAttribute('aria-pressed','true');
      button.addEventListener('click',()=>queryRemediationJob(ref)); list.append(button);
    }
    if(!jobs.length) list.append(node('p','empty-note','当前实例没有已登记的修复任务。'));
    const ref=state.remediationJobRef,job=state.remediationJob;
    if(!ref) { detail.append(node('p','empty-note','选择任务，核对安装、重启待办和业务验证。')); return; }
    detail.append(node('h2','',job?remediationJobLabel(job.status):'提交结果尚未确认'),node('p','small muted',remediationName(ref.host_id)),node('p','mono small',ref.job_id));
    if(state.remediationSubmission?.uncertain || job?.status==='unknown') {
      const warning=node('div','notice'); warning.append(node('strong','','保留原任务，不重新安装'),node('p','','请求超时或失联不能证明安装失败。只查询此任务，不能换新任务 ID 重试。')); detail.append(warning);
    }
    const query=node('button','button','查询原任务'); query.type='button'; query.id='query-remediation-job'; query.disabled=Boolean(state.remediationBusy); query.addEventListener('click',()=>queryRemediationJob(ref)); detail.append(query);
    if(job) {
      detail.append(node('p','small muted',job.status==='verified'?'本任务已完成所记录的复扫与验证；这不代表其他漏洞或未覆盖业务均已解决。':['installed_restart_pending','reboot_pending','awaiting_transport_verification'].includes(job.status)?'补丁安装与生效验证分别记录；当前仍有待办，不能标记彻底修复。':'以阶段记录和验证证据核对结果，软件包安装返回成功不等于漏洞已经解除。'));
      if(job.verification!==undefined) remediationDetails(detail,'查看修复后验证证据',job.verification);
      else detail.append(node('p','small muted','尚无修复后验证记录。'));
      const history=remediationList(job.history);
      if(history.length) {
        const timeline=node('ol','remediation-timeline');
        for(const event of history.slice(-30)) { const item=node('li',''); item.append(node('strong','',remediationJobLabel(event.status || event.stage || event.state)),node('span','small muted',event.at || event.timestamp || event.created_at?dateLabel(event.at || event.timestamp || event.created_at):'时间未记录')); if(typeof event.detail==='string') item.append(node('p','small',event.detail)); timeline.append(item); }
        detail.append(timeline);
      }
    }
  }
  function remediationViewSupported() {
    return state.capabilities?.vulnerability_remediation===true || state.capabilities?.nginx_managed_actions===true ||
      state.capabilities?.container_restart===true;
  }
  function remediationViewLabel() {
    return state.capabilities?.vulnerability_remediation===true ? '漏洞与修复' : '受控处置';
  }
  function nginxActionsContext() {
    return {signedIn:Boolean(state.token),session:state.session,visible:state.view==='remediation',hosts:state.hosts,
      capabilities:state.capabilities,automation:state.automation,modeDraft:state.automationDraft,
      modePending:Boolean(state.automationBusy || state.automationNeedsReload)};
  }
  function actionReportLink(host) {
    const report=state.report, target=report?.target;
    if(state.capabilities?.action_handoff!==true || !state.token || state.loadingReport || !host ||
      report?.source!=='ssh' || target?.source!=='ssh' || report.host_id!==host.id || target.id!==host.id ||
      !/^[A-Za-z0-9_-]{1,80}$/.test(report.id) || !/^[0-9a-f]{64}$/.test(report.scope_hash) ||
      !/^[0-9a-f]{64}$/.test(host.trusted_hosts_digest) ||
      !state.reports.some(row=>row.id===report.id && row.source==='ssh' && row.host_id===host.id)) return null;
    // The server revalidates the canonical report and management scopes before preview.
    const fields=['address','port','username','site_domain','container_name','expected_upstream_port',
      'nginx_config_path','trusted_hosts_digest'];
    if(fields.some(field=>target[field]!==host[field])) return null;
    const checks=value=>JSON.stringify((value.health_checks || []).map(check=>[
      check.id,check.domain,check.port,check.path,check.expected_status,check.expected_body,check.read_only_confirmed,
    ]).sort(([left],[right])=>left.localeCompare(right)));
    if(!Array.isArray(target.health_checks) || !Array.isArray(host.health_checks) || checks(target)!==checks(host)) return null;
    return {id:report.id,session:state.session,selection:state.reportRequest};
  }
  function syncNginxActions() {
    if(nginxActions) { nginxActions.configure(); return; }
    if(nginxActionsLoading || !state.token || state.view!=='remediation' || state.capabilities?.nginx_managed_actions!==true) return;
    const root=$('nginx-actions-section');
    const session=state.session;
    nginxActionsLoading=true;
    import('/nginx-actions.js').then(({create})=>{
      nginxActions=create({root,api,getContext:nginxActionsContext,announce,actionReportLink});
      nginxActions.configure();
    }).catch(()=>{
      if(session!==state.session || state.view!=='remediation' || !state.token) return;
      root.hidden=false;
      root.replaceChildren(node('h2','','Nginx 受控变更'),node('p','notice error-notice','处置界面未能加载，请刷新页面。'));
    }).finally(()=>{nginxActionsLoading=false;});
  }
  function syncContainerRestarts() {
    if(containerRestarts) { containerRestarts.configure(); return; }
    if(containerRestartsLoading || !state.token || state.view!=='remediation' || state.capabilities?.container_restart!==true) return;
    const root=$('container-restarts-section'), session=state.session;
    containerRestartsLoading=true;
    import('/container-restarts.js').then(({create})=>{
      containerRestarts=create({root,api,getContext:nginxActionsContext,actionReportLink});
      containerRestarts.configure();
    }).catch(()=>{
      if(session!==state.session || state.view!=='remediation' || !state.token) return;
      root.hidden=false;
      root.replaceChildren(node('h2','','受控容器重启'),node('p','notice error-notice','处置界面未能加载，请刷新页面。'));
    }).finally(()=>{containerRestartsLoading=false;});
  }
  function renderRemediation() {
    const supported=state.capabilities?.vulnerability_remediation===true;
    const available=remediationViewSupported();
    $('remediation-nav').hidden=!available;
    $('remediation-nav-label').textContent=remediationViewLabel();
    $('view-remediation').hidden=!available || state.view!=='remediation';
    $('view-remediation').setAttribute('aria-label',supported?'漏洞扫描与受控处置':'受控处置');
    $('remediation-patch-workspace').hidden=!supported;
    $('refresh-remediation').hidden=!supported;
    $('remediation-title').textContent=supported?'让修复，走到验证这一步。':'受控处置';
    $('remediation-description').textContent=supported?'核实已安装软件与供应商修复版本，逐项预览真实变化，并追踪同一个任务的执行结果。':'核对登记目标、变更与业务影响，再查询原计划的结果。';
    syncNginxActions();
    syncContainerRestarts();
    if(!supported) {
      ['remediation-boundary','remediation-scan-summary','remediation-findings','remediation-plan','remediation-job-list','remediation-job-detail','remediation-host-select'].forEach(id=>clear($(id)));
      $('remediation-host-select').disabled=true; $('run-remediation-scan').disabled=true; $('refresh-remediation').disabled=true;
      $('remediation-error').textContent=''; $('remediation-error').hidden=true; $('remediation-progress').textContent=''; $('remediation-scan-time').textContent=''; renderVulnerabilityAI(); return;
    }
    const settings=state.remediation,hosts=remediationList(settings?.hosts),select=$('remediation-host-select'); clear(select);
    if(!hosts.length) select.append(option('','尚无配置的修复目标'));
    for(const host of hosts) select.append(option(host.host_id,host.name || host.host_id)); select.value=state.remediationHost; select.disabled=Boolean(state.remediationBusy || state.vulnerabilityAIBusy || !hosts.length);
    $('refresh-remediation').disabled=Boolean(state.remediationBusy); $('run-remediation-scan').disabled=Boolean(state.remediationBusy || !state.remediationHost || settings?.configured!==true);
    $('run-remediation-scan').textContent=state.remediationBusy==='scan'?'正在扫描…':'扫描漏洞';
    const progress={refresh:'正在读取登记范围和任务记录…',scan:'正在读取本机软件并核对供应商情报，可能需要一分钟；不会自动重复提交。',plan:'正在核对精确版本、依赖和执行前健康状态…',submit:'任务 ID 已固定，正在提交。请勿重复安装。',query:'正在查询原任务状态…'};
    $('remediation-progress').textContent=progress[state.remediationBusy] || '';
    const boundary=$('remediation-boundary'); clear(boundary);
    boundary.append(node('strong','',settings?.execution_available===true?(automaticSupported()?'人工批准与预授权自动处置分别核对':'本轮仅开放半自动补丁修复'):'补丁执行能力尚未就绪'));
    boundary.append(node('p','',settings?.detail || '正在核对部署端的扫描与修复配置。'));
    boundary.append(node('p','small',!state.automation || state.automationNeedsReload?'尚未取得有效操作模式，修复执行保持关闭。':state.automation.mode==='automatic'?(automaticSupported()?'已选择全自动。仅后台已获预授权的范围可能执行；逐个核对上方目标、窗口、配额与暂停原因。下方预览不会由本页自动提交。':'已选择全自动，但此首轮通道仅支持半自动，不会因模式选择自动安装补丁。'):state.automation.mode==='assisted'?'半自动模式：复核具体计划后批准安装，再查看复扫和业务验证。':'手动模式提供扫描和方案建议；人工批准执行需要切换到已授权的半自动模式。'));
    if(remediationHasPendingTask()) boundary.append(node('p','small','已有进行中、结果未知或重启待处理的任务。先查询原任务并核对结果，再发起新的安装。'));
    $('remediation-error').textContent=state.remediationError; $('remediation-error').hidden=!state.remediationError;
    renderRemediationScan(); renderRemediationPlan(); renderRemediationJob(); renderVulnerabilityAI(); renderServiceActivations();
  }
  function setRemediationHost(id) {
    if(state.remediationBusy || state.vulnerabilityAIBusy) { renderRemediation(); return; }
    invalidateVulnerabilityAIPreview(); state.vulnerabilityAIRequest+=1; state.vulnerabilityAIRecord=null;
    dismissServiceActivationDialog();state.serviceActivationPlan=null;state.serviceActivationRecord=null;
    dismissActivationRecoveryDialog();state.activationRecoveryPlan=null;state.activationRecoveryRecord=null;
    invalidateRemediationPlan(); state.remediationHost=id; state.remediationError='';
    state.remediationScan=remediationList(state.remediation?.hosts).find(host=>host.host_id===id)?.scan || null; renderRemediation();
    refreshVulnerabilityAI({quiet:true});
  }
  async function refreshRemediation() {
    if(!state.token || state.capabilities?.vulnerability_remediation!==true || state.remediationBusy) return;
    const session=state.session,request=++state.remediationRequest; state.remediationBusy='refresh'; state.remediationError=''; stopRemediationPolling(); renderRemediation();
    try {
      const value=await api('/api/remediation');
      if(session!==state.session || request!==state.remediationRequest) return;
      if(!value || !Array.isArray(value.hosts) || !Array.isArray(value.jobs) || !value.hosts.every(host=>host && remediationToken(host.host_id)) || new Set(value.hosts.map(host=>host.host_id)).size!==value.hosts.length) throw new Error('修复记录缺少有效的目标或任务清单。');
      state.remediation=value;
      if(!value.hosts.some(host=>host.host_id===state.remediationHost)) { invalidateRemediationPlan(); state.remediationHost=value.hosts[0]?.host_id || ''; }
      const scan=value.hosts.find(host=>host.host_id===state.remediationHost)?.scan || null;
      if(remediationScanStamp(scan)!==remediationScanStamp(state.remediationScan)) { invalidateRemediationPlan('扫描记录已变化，旧修复确认已取消。'); invalidateVulnerabilityAIPreview(); if(state.vulnerabilityAIRecord) state.vulnerabilityAIRecord={...state.vulnerabilityAIRecord,stale:true,applicable:false}; }
      state.remediationScan=scan;
      const ref=state.remediationJobRef; const job=ref?value.jobs.find(item=>item.job_id===ref.job_id && item.host_id===ref.host_id):null;
      if(job) acceptRemediationJob(job,ref);
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && session===state.session && request===state.remediationRequest) { invalidateRemediationPlan(); state.remediationError='记录读取未完成：'+errorMessage(cause)+' 历史记录不能证明当前任务状态。'; }
    } finally { if(session===state.session && request===state.remediationRequest) { state.remediationBusy=''; renderRemediation(); scheduleRemediationPolling(); refreshVulnerabilityAI({quiet:true}); } }
  }
  async function scanRemediation(event) {
    event.preventDefault();
    if(!state.token || state.remediationBusy || state.remediation?.configured!==true || !state.remediationHost) return;
    invalidateVulnerabilityAIPreview(); invalidateRemediationPlan(); const host=state.remediationHost,session=state.session,request=++state.remediationRequest;
    state.remediationBusy='scan'; state.remediationError=''; stopRemediationPolling(); renderRemediation();
    try {
      const value=await api('/api/remediation/scans',{method:'POST',body:{host_id:host}});
      if(session!==state.session || request!==state.remediationRequest || host!==state.remediationHost) return;
      if(!value || !Array.isArray(value.findings) || (value.host_id && value.host_id!==host)) throw new Error('扫描结果缺少有效记录或目标不匹配。');
      state.remediationScan=value; const target=state.remediation.hosts.find(item=>item.host_id===host); if(target) target.scan=value;
      if(state.vulnerabilityAIRecord) state.vulnerabilityAIRecord={...state.vulnerabilityAIRecord,stale:true,applicable:false};
      announce('扫描已返回，请核对覆盖范围、情报新鲜度和受影响证据。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.remediationRequest) state.remediationError='扫描未完成：'+errorMessage(cause)+' 不会自动重发扫描，也不能据此判定目标安全。'; }
    finally { if(session===state.session && request===state.remediationRequest) { state.remediationBusy=''; renderRemediation(); scheduleRemediationPolling(); } }
  }
  function checkedRemediationPlan(value,host) {
    if(!value || value.host_id!==host || !remediationToken(value.plan_id) || !/^[0-9a-f]{64}$/.test(value.plan_digest || '') || !/^[0-9a-f]{64}$/.test(value.state_digest || '') || !/^[0-9a-f]{64}$/.test(value.policy_digest || '') || !Number.isSafeInteger(value.mode_revision) || value.mode_revision!==state.automation?.revision || value.action!=='os_security_upgrade' || !['low','medium','high','unknown'].includes(value.risk_level) || !['none','possible','required','unknown'].includes(value.restart_assessment) || typeof value.expires_at!=='string' || !/(Z|[+-][0-9]{2}:[0-9]{2})$/.test(value.expires_at) || !(Date.parse(value.expires_at)>Date.now()) || !Array.isArray(value.package_changes) || !value.package_changes.length || value.package_changes.length>5 || !value.package_changes.every(change=>['name','current_version','candidate_version','fixed_version'].every(key=>typeof change[key]==='string' && change[key].length>0 && change[key].length<=160))) throw new Error('修复方案缺少有效绑定、精确版本或已过期，未开放确认。');
    return value;
  }
  async function prepareRemediationPlan(finding,scan) {
    if(!state.token || state.remediationBusy || state.automationBusy || scan!==state.remediationScan || (scan.host_id && scan.host_id!==state.remediationHost) || finding.affected!==true || finding.candidate_fixable!==true || finding.vendor_evidence_fresh!==true || remediationHasPendingTask()) return;
    invalidateRemediationPlan(); const host=state.remediationHost,session=state.session,selection=state.remediationSelection,request=++state.remediationRequest;
    state.remediationBusy='plan'; state.remediationError=''; stopRemediationPolling(); renderRemediation();
    try {
      const value=await api('/api/remediation/plans',{method:'POST',body:{host_id:host,finding_id:finding.finding_id}});
      if(session!==state.session || request!==state.remediationRequest || selection!==state.remediationSelection || host!==state.remediationHost) return;
      state.remediationPlan=checkedRemediationPlan(value,host); announce('具体方案已生成。请先核对软件包差异、重启影响和有效期。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.remediationRequest) state.remediationError='方案未就绪：'+errorMessage(cause); }
    finally { if(session===state.session && request===state.remediationRequest) { state.remediationBusy=''; renderRemediation(); scheduleRemediationPolling(); } }
  }
  function openRemediationDialog() {
    const plan=state.remediationPlan; if(!remediationCanApprove(plan)) { renderRemediation(); return; }
    dismissRemediationDialog(); const target={plan,session:state.session,selection:state.remediationSelection}; state.remediationDialogTarget=target;
    remediationPlanContent($('remediation-dialog-summary'),plan); $('remediation-dialog').showModal(); $('remediation-confirm').focus();
    state.remediationExpiry=window.setTimeout(()=>{if(state.remediationDialogTarget===target) { invalidateRemediationPlan('方案已过期，确认已取消。请重新生成。'); renderRemediation(); }},Math.max(0,Math.min(2147483647,Date.parse(plan.expires_at)-Date.now())));
  }
  function acceptRemediationJob(value,ref) {
    if(!value || typeof value.status!=='string' || (value.job_id && value.job_id!==ref.job_id) || (value.host_id && value.host_id!==ref.host_id)) throw new Error('返回任务与原任务标识不匹配。');
    const job={...value,host_id:ref.host_id,job_id:ref.job_id}; state.remediationJobRef=ref; state.remediationJob=job;
    if(state.remediation) { const jobs=remediationList(state.remediation.jobs); state.remediation.jobs=[job,...jobs.filter(item=>item.job_id!==ref.job_id || item.host_id!==ref.host_id)]; }
    if(state.remediationSubmission?.job_id===ref.job_id && state.remediationSubmission.host_id===ref.host_id) state.remediationSubmission.uncertain=!Object.hasOwn(remediationJobStates,job.status) || job.status==='unknown';
  }
  async function executeRemediation() {
    const target=state.remediationDialogTarget,plan=target?.plan;
    if(!target || target.session!==state.session || target.selection!==state.remediationSelection || state.remediationPlan!==plan || !$('remediation-confirm').checked || !remediationCanApprove(plan)) { dismissRemediationDialog(); renderRemediation(); return; }
    if(typeof crypto.randomUUID!=='function') { $('remediation-dialog-error').textContent='浏览器缺少安全任务标识能力，不能提交安装。'; $('remediation-dialog-error').hidden=false; return; }
    const id=crypto.randomUUID().replaceAll('-',''); if(!/^[0-9a-f]{32}$/.test(id)) return;
    const ref={host_id:plan.host_id,job_id:id}; state.remediationSubmission={...ref,plan_id:plan.plan_id,uncertain:true}; state.remediationJobRef=ref; state.remediationJob=null;
    const session=state.session,request=++state.remediationRequest; state.remediationBusy='submit'; state.remediationError=''; invalidateRemediationPlan(); stopRemediationPolling(); renderRemediation();
    try {
      const value=await api('/api/remediation/jobs',{method:'POST',body:{host_id:ref.host_id,plan_id:plan.plan_id,expected_plan_digest:plan.plan_digest,expected_mode_revision:plan.mode_revision,confirm_execute:true,job_id:id}});
      if(session!==state.session || request!==state.remediationRequest) return;
      acceptRemediationJob(value,ref); announce('原任务已登记。请查看执行阶段和修复后验证，不要重复提交安装。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.remediationRequest) state.remediationError='提交结果未确认：'+errorMessage(cause)+' 已保留原任务 ID，请只查询原任务，不要换新 ID 重试。'; }
    finally { if(session===state.session && request===state.remediationRequest) { state.remediationBusy=''; renderRemediation(); scheduleRemediationPolling(); } }
  }
  async function queryRemediationJob(ref,{quiet=false}={}) {
    if(!state.token || state.remediationBusy || !remediationJobReference(ref)) return;
    const session=state.session,request=++state.remediationRequest;
    if(state.remediationJobRef?.job_id!==ref.job_id || state.remediationJobRef?.host_id!==ref.host_id) state.remediationJob=null;
    state.remediationJobRef={...ref}; state.remediationBusy='query'; if(!quiet) state.remediationError=''; stopRemediationPolling(); renderRemediation();
    try {
      const value=await api('/api/remediation/jobs/'+encodeURIComponent(ref.host_id)+'/'+encodeURIComponent(ref.job_id));
      if(session!==state.session || request!==state.remediationRequest) return;
      acceptRemediationJob(value,ref);
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session && request===state.remediationRequest) state.remediationError='原任务查询未完成：'+errorMessage(cause)+' 没有查到记录也不能证明未安装；请保留原任务继续核对。'; }
    finally { if(session===state.session && request===state.remediationRequest) { state.remediationBusy=''; renderRemediation(); scheduleRemediationPolling(); } }
  }

  const securityStates={starting:'等待首轮采集',ok:'本轮采集完成',degraded:'采集存在缺口',unavailable:'采集未完成',busy:'采集通道忙',stopped:'观察已停止',stale:'观察记录已过期'};
  const securityOrigins={system_ssh:'系统 SSH 日志',controlled_probe:'实验演练',collector:'采集通道',system_web:'Web 日志',controlled_web_probe:'Web 实验演练',web_collector:'Web 采集通道'};
  const webPathClasses={health:'健康检查',normal:'普通页面',static:'静态资源',robots:'爬虫说明/站点索引',callback:'已登记回调',secret_probe:'敏感配置探测类别',repo_probe:'仓库元数据探测类别',cms_probe:'CMS 入口探测类别',admin_probe:'管理入口探测类别',traversal_probe:'路径穿越样式类别',other:'其他类别（未采集 URL）'};
  const webSourceTrust={direct_peer:'TCP 邻居（不保证最终用户）',trusted_proxy:'登记可信代理',forwarded_ignored:'转发头不可信 · 已忽略',unresolved_proxy:'代理来源未解析 · 不能归因网关',site_aggregate:'站点聚合 · 不归因单个来源'};
  const securityRecommendationKinds={collect_more_evidence:'补充证据',review_access:'复核访问授权',review_origin_protection:'复核源站保护',propose_rate_limit:'评估限流方案',propose_challenge:'评估访问挑战',propose_sensitive_path_rule:'评估敏感路径规则',contact_upstream_ddos:'向上游核实 DDoS 防护'};
  function isWebSecurity(value) { return value?.channel==='web' || ['system_web','controlled_web_probe','web_collector'].includes(value?.origin) || value?.kind==='web_request'; }
  function controlledSecurity(value) { return ['controlled_probe','controlled_web_probe'].includes(value); }
  function securityTime(value) { return value?dateLabel(value):'尚无记录'; }
  function securityCount(value) { return Number.isSafeInteger(value) && value>=0?value:0; }
  function securityOrigin(value) { return securityOrigins[value] || '来源未确认'; }
  function securityHostName(id) { return state.hosts.find(host=>host.id===id)?.name || id || '目标未确认'; }
  function historicalSecurityScope(alert) { const hosts=Array.isArray(state.securityStatus?.hosts)?state.securityStatus.hosts:[]; const host=hosts.find(host=>host.host_id===alert.host_id); const current=isWebSecurity(alert)?host?.channels?.web?.scope_hash:host?.channels?.ssh?.scope_hash || host?.scope_hash; return Boolean(current && alert.scope_hash && current!==alert.scope_hash); }
  function securityMessage(text) { $('security-error').textContent=text; $('security-error').hidden=!text; }
  function stopSecurityPolling() { if(state.securityTimer!==null) window.clearTimeout(state.securityTimer); state.securityTimer=null; }
  function scheduleSecurityPolling() {
    stopSecurityPolling();
    if(state.token && state.view==='security' && !document.hidden && !state.securityAITarget && !state.securityAIBusy && state.capabilities?.security_observation===true && state.securitySupported!==false) {
      state.securityTimer=window.setTimeout(()=>refreshSecurity({quiet:true}),15000);
    }
  }

  function renderSecuritySummary() {
    const summary=$('security-monitor-summary'),list=$('security-host-list'); clear(summary); clear(list);
    const supported=state.capabilities?.security_observation===true && state.securitySupported!==false;
    $('refresh-security').disabled=state.securityBusy || state.securityAckBusy!==null || !supported;
    $('refresh-security').textContent=state.securityBusy?'正在读取…':'刷新观察';
    if(!supported) {
      summary.append(node('p','notice neutral','当前实例未开放持续观察接口。按需 SSH 调查仍可使用；没有观察记录不能解释为服务器安全。'));
      list.append(node('p','empty-note','尚无持续观察目标。')); return;
    }
    const status=state.securityStatus;
    if(!status) { summary.append(node('p','empty-note','正在读取观察状态；尚未取得结果。')); return; }
    const metrics=node('div','security-metrics');
    const mode=status.enabled?(status.running?'观察进程运行中':'观察已配置 · 进程未运行'):'持续观察未启用';
    const interval=securityCount(status.interval_seconds),open=state.securityAlerts.filter(alert=>alert.status==='open').length;
    for(const [label,value] of [['运行状态',mode],['采集间隔',interval?String(interval)+' 秒':'未提供'],['列表待阅',String(open)],['通知渠道','仅控制台']]) {
      const metric=node('div','security-metric'); metric.append(node('span','small muted',label),node('strong','',value)); metrics.append(metric);
    }
    summary.append(metrics,node('p','small muted','此页可见时每 15 秒刷新。采集完成不代表服务器安全；超时、缺口或停止会单独标记。'));
    const windowSeconds=securityCount(status.window_seconds),threshold=securityCount(status.threshold);
    if(windowSeconds && threshold) summary.append(node('p','small muted','当前规则：最近 '+String(Math.round(windowSeconds/60))+' 分钟，同一来源至少 '+String(threshold)+' 条去重认证失败触发关注；失败后的成功记录需要另行核对授权。'));
    if(state.capabilities?.security_web===true) summary.append(node('p','small muted','Web 观察结合敏感路径类别、意外错误及耗时；请求量、声明爬虫或 HTTP 错误不能单独证明攻击或 DDoS。'));
    if(!status.enabled) summary.append(node('p','notice neutral','部署者尚未启用持续观察；历史告警保留，当前不运行新采集。'));
    else if(!status.running) summary.append(node('p','notice','观察进程当前未运行，请核对服务端状态；不能依赖历史成功结果判断当前覆盖。'));
    const hosts=Array.isArray(status.hosts)?status.hosts.slice(0,100):[];
    if(!hosts.length) list.append(node('p','empty-note','未返回启用的观察目标，覆盖范围尚未确认。'));
    for(const host of hosts) {
      const card=node('article','security-host-card'); card.dataset.securityHost=String(host.host_id || '');
      const known=Object.hasOwn(securityStates,host.status),label=known?securityStates[host.status]:'状态未知';
      const head=node('div','security-host-title'); head.append(node('h3','',host.name || securityHostName(host.host_id)),node('span','badge '+(host.status==='ok'?'neutral':'amber'),label));
      card.append(head,node('p','mono small muted',host.host_id || '目标未确认'));
      card.append(detailList([['最近尝试',securityTime(host.last_attempt)],['最近有效读取',securityTime(host.last_success)],['下轮计划',securityTime(host.next_poll)]]));
      if(host.channels && typeof host.channels==='object') {
        const channels=node('div','security-channel-list');
        for(const key of ['ssh','web']) {
          const channel=host.channels[key];
          if(!channel || typeof channel!=='object') continue;
          const row=node('section','security-channel'); row.dataset.securityChannel=key;
          const heading=node('div','security-alert-meta'); heading.append(node('strong','',key==='web'?'Web 请求观察':'SSH 认证观察'),node('span','badge '+(channel.status==='ok'?'neutral':'amber'),securityStates[channel.status] || '状态未知'));
          row.append(heading,node('p','small muted','最近有效读取：'+securityTime(channel.last_success)));
          if(channel.detail) row.append(node('p','small muted',channel.detail));
          channels.append(row);
        }
        card.append(channels);
      } else if(state.capabilities?.security_web===true) card.append(node('p','small muted','尚未返回分通道状态，不能据此确认 Web 已启用。'));
      if(host.detail) card.append(node('p','security-host-note',host.detail));
      if(!host.last_success || ['stale','unavailable','degraded','busy'].includes(host.status) || !known) card.append(node('p','small muted','存在观察缺口或时效限制；不能据此排除异常。'));
      list.append(card);
    }
    $('security-last-refresh').textContent=state.securityRefreshedAt?'页面读取：'+securityTime(state.securityRefreshedAt):'';
  }

  function renderSecurityAlerts() {
    const list=$('security-alert-list'),focused=document.activeElement?.dataset.securityAlert; clear(list);
    const open=state.securityAlerts.filter(alert=>alert.status==='open').length;
    $('security-list-count').textContent=state.securityStatus?String(state.securityAlerts.length)+' 条 · '+String(open)+' 条待阅':'';
    const badge=$('security-alert-count'); badge.textContent=open>99?'99+':String(open); badge.hidden=!state.securityStatus; badge.setAttribute('aria-label','当前列表 '+String(open)+' 条待阅告警');
    if(!state.securityAlerts.length) {
      list.append(node('p','empty-note',state.securityStatus?'当前列表没有告警。这只说明本次规则未形成告警，仍需结合采集状态与覆盖缺口。':'尚未读取安全告警。')); return;
    }
    for(const alert of state.securityAlerts) {
      const button=node('button','security-alert-button'); button.type='button'; button.dataset.securityAlert=String(alert.id); button.setAttribute('aria-pressed',String(state.securitySelected===alert.id));
      const meta=node('div','security-alert-meta'); meta.append(node('span','badge '+(alert.severity==='high'?'red':'amber'),alert.severity==='high'?'高关注':'关注'),node('span','badge '+(controlledSecurity(alert.origin)?'amber':'neutral'),securityOrigin(alert.origin)),node('span','small muted',alert.status==='acknowledged'?'已阅':'待阅'));
      if(historicalSecurityScope(alert)) meta.append(node('span','badge amber','历史登记范围'));
      button.append(meta,node('strong','',alert.title || '待核对的安全观察'),node('p','small',securityHostName(alert.host_id)),node('p','mono small',alert.source_ip || '未关联来源 IP'),node('p','small muted',securityTime(alert.last_seen)));
      button.addEventListener('click',()=>selectSecurityAlert(alert.id)); list.append(button); if(focused===String(alert.id)) button.focus({preventScroll:true});
    }
  }

  function renderSecurityDetail() {
    const panel=$('security-alert-detail'),expanded=new Set(Array.from(panel.querySelectorAll('details[open][data-security-event]'),item=>item.dataset.securityEvent)),ackFocused=document.activeElement?.id==='ack-security-alert'; clear(panel);
    const alert=state.securityAlert;
    if(!alert || alert.id!==state.securitySelected) { panel.append(node('p','empty-note',state.securitySelected?'正在读取告警证据…':'选择一条告警，核对来源、发生时间和证据。')); return; }
    const header=node('div','security-detail-header'),meta=node('div','security-alert-meta');
    meta.append(node('span','badge '+(alert.severity==='high'?'red':'amber'),alert.severity==='high'?'高关注':'关注'),node('span','badge '+(controlledSecurity(alert.origin)?'amber':'neutral'),securityOrigin(alert.origin)),node('span','badge neutral',alert.status==='acknowledged'?'已阅 · 未证明风险解除':'待阅'));
    header.append(meta,node('h2','',alert.title || '待核对的安全观察'),node('p','security-detail-copy',alert.detail || '没有提供补充说明，请结合事件及采集缺口判断。')); panel.append(header);
    if(alert.origin==='controlled_probe') panel.append(node('p','notice','这是受控 SSH 实验产生的演练告警，用于验证观察链路，不能作为真实攻击或入侵的证据。'));
    if(alert.origin==='controlled_web_probe') panel.append(node('p','notice','这是受控 Web 实验产生的演练告警，用于验证观察链路，不能作为真实攻击、入侵或 DDoS 的证据。'));
    if(isWebSecurity(alert)) {
      panel.append(node('p','small muted','Web 证据只含路径类别、方法、状态与耗时，不含原始 URL、查询、Cookie、认证头或请求体。'));
      if(alert.source_trust==='unresolved_proxy') panel.append(node('p','notice','来源尚未通过可信代理链解析。邻居或网关地址不能视为攻击源，也不能据此封禁。'));
      panel.append(detailList([['站点标识',alert.site_id || '未提供'],['来源归属',webSourceTrust[alert.source_trust] || '未提供']]));
      if(Number.isSafeInteger(alert.observed_request_count) && alert.observed_request_count>=0 && Number.isSafeInteger(alert.matching_event_count) && alert.matching_event_count>=0) {
        panel.append(node('p','notice neutral','告警观察样本 '+String(alert.observed_request_count)+' 条，其中规则匹配 '+String(alert.matching_event_count)+' 条'+(Number.isSafeInteger(alert.window_seconds)?'，规则窗口 '+String(alert.window_seconds)+' 秒':'')+'；这不是全量访问计数。下方保留事件是代表证据，不能将其数量作为错误率分母。'));
      }
      if(alert.metric_basis==='observed_evidence' || (alert.coverage_status && alert.coverage_status!=='complete')) panel.append(node('p','small muted','当前依据为有界或不完整证据；可提示已观察到的线索，不能据此计算完整站点错误率。'));
    }
    if(historicalSecurityScope(alert)) panel.append(node('p','notice','该告警属于历史登记范围，和当前目标范围不同；请按本条证据范围复核，不能直接关联到当前登记的服务器。'));
    panel.append(detailList([['目标',historicalSecurityScope(alert)?String(alert.host_id)+'（历史登记范围）':securityHostName(alert.host_id)],['证据范围',alert.scope_hash || '未提供'],['来源 IP',alert.source_ip || '未关联'],['首次记录',securityTime(alert.first_seen)],['最近证据',securityTime(alert.last_seen)],['告警证据窗口事件',String(securityCount(alert.current_window_count))],['累计去重事件',String(securityCount(alert.unique_event_count))],['通知次数',String(securityCount(alert.notification_count))],['最近通知',securityTime(alert.last_notified_at)]]));
    panel.append(node('p','small muted','最近证据时间和告警证据窗口记录的是最后一次新增证据时的情况，不表示这些失败仍在发生。当前采集状态请查看上方目标卡片。'));
    const actions=node('div','security-detail-actions'),button=node('button','button',state.securityAckBusy===alert.id?'正在记录已阅…':alert.status==='acknowledged'?'已标记已阅':'标记已阅'); button.type='button'; button.id='ack-security-alert'; button.disabled=alert.status==='acknowledged' || state.securityAckBusy!==null || state.securityBusy;
    button.addEventListener('click',()=>acknowledgeSecurityAlert(alert.id)); actions.append(button,node('p','small muted','只记录已阅，不改变服务器、不关闭事件，也不代表风险解除。')); panel.append(actions);
    panel.append(sectionHeading('观察证据'),node('p','small muted',isWebSecurity(alert)?'下方最多展示 20 条分类请求证据及关联覆盖信息，不表示已收集完整访问历史。':'下方最多展示 20 条关联事件及最近观察的覆盖信息，不表示已收集完整登录历史。'));
    const observation=alert.observation;
    if(observation && typeof observation==='object') {
      const observationStates={complete:'本轮读取完成',degraded:'本轮存在缺口',unavailable:'本轮未完成'};
      panel.append(node('p','small muted',(observationStates[observation.status] || '观察状态未知')+' · 采集：'+securityTime(observation.collected_at)));
      panel.append(node('p','small muted','历史证据窗口：'+securityTime(observation.window_started_at)+' → '+securityTime(observation.window_ended_at)));
      if(Array.isArray(observation.gaps) && observation.gaps.length) panel.append(plainList(observation.gaps,'没有提供额外缺口。'));
    } else panel.append(node('p','small muted','没有取得关联观察元数据，覆盖范围尚未核实。'));
    const events=Array.isArray(alert.events)?alert.events.slice(0,20):[];
    if(!events.length) panel.append(node('p','empty-note',isWebSecurity(alert)?'没有可展示的 Web 请求事件；采集告警需结合上方观察缺口核对。':'没有可展示的认证事件；采集告警需结合上方观察缺口核对。'));
    const eventList=node('div','security-event-list');
    for(const event of events) {
      const item=node('details','security-event'); item.dataset.securityEvent=String(event.id || ''); item.open=expanded.has(item.dataset.securityEvent);
      const summary=node('summary'); summary.append(node('strong','',isWebSecurity(event)?'Web 分类请求记录':event.kind==='authentication_accepted'?'认证成功记录':event.kind==='authentication_failed'?'认证失败记录':'未识别事件'),node('span','small muted',securityTime(event.occurred_at)));
      if(isWebSecurity(event)) {
        const clients={browser:'浏览器特征（未核实身份）',declared_crawler:'自称爬虫（未验证）',probe:'声明演练客户端',other:'其他/未分类客户端'};
        const number=value=>Number.isSafeInteger(value) && value>=0?String(value):'未提供';
        const pairs=[['来源',securityOrigin(event.origin)],['站点',event.site_id || '未提供'],['来源 IP',event.source_ip || '未解析'],['连接邻居',event.peer_ip || '未提供'],['来源归属',webSourceTrust[event.source_trust] || '未提供'],['方法',event.method || '未提供'],['HTTP 状态',number(event.status)],['路径类别',webPathClasses[event.path_class] || '未分类（未采集 URL）'],['客户端特征',clients[event.client_class] || '未提供'],['耗时',number(event.request_time_ms)+' 毫秒'],['响应字节',number(event.bytes_sent)],['登记预期错误',event.expected_error===true?'是':event.expected_error===false?'否':'未提供'],['事件编号',event.id || '未提供'],['Journal 游标',event.journal_cursor || '未提供']];
        item.append(summary,detailList(pairs));
        if(event.source_trust==='unresolved_proxy') item.append(node('p','notice security-event-note','无法归因实际客户端；不能将连接邻居作为封禁对象。'));
        if(event.source_trust==='forwarded_ignored') item.append(node('p','small muted security-event-note','转发头来自未登记的代理，已忽略其声明地址，按连接邻居记录。'));
      } else {
        const accounts={root:'root 账号',invalid:'无效账号',other:'其他账号（未采集名称）'};
        item.append(summary,detailList([['来源',securityOrigin(event.origin)],['来源 IP',event.source_ip || '未知'],['认证方式',event.method || '未知'],['账号类型',accounts[event.account_type] || '未知'],['日志单位',event.unit || '未知'],['事件编号',event.id || '未提供'],['Journal 游标',event.journal_cursor || '未提供']]));
      }
      eventList.append(item);
    }
    panel.append(eventList,node('p','security-footnote',isWebSecurity(alert)?'敏感路径请求只是探测线索，HTTP 错误也可能来自正常业务。声明爬虫不代表已验证机器人，站点聚合不能归罪于单个来源；当前只观察，不执行封禁。':'认证失败可能来自合法任务或共享出口；失败后出现成功记录需要核对授权，不能单独认定已入侵。当前只观察，不执行封禁。'));
    renderSecurityAI(panel,alert);
    if(ackFocused && !button.disabled) button.focus({preventScroll:true});
  }

  function securityAIReference(id) {
    const reference=node('button','evidence-link',String(id).slice(0,16)+' ↗'); reference.type='button';
    reference.addEventListener('click',()=>{
      const item=Array.from($('security-alert-detail').querySelectorAll('[data-security-event]')).find(item=>item.dataset.securityEvent===String(id));
      if(item) { item.open=true; item.scrollIntoView({block:'nearest'}); }
    });
    return reference;
  }

  function renderSecurityAI(panel,alert) {
    if(state.capabilities?.security_ai!==true) return;
    const section=node('section','security-ai-section'); section.id='security-ai-section';
    section.append(sectionHeading('AI 策略建议'),node('p','small muted','建议仅用于复核，不改变规则事实或执行权限；完整防御还依赖可信来源、边缘/上游能力及经过验证的处置。'));
    const current=state.securityAIResult?.id===alert.id?state.securityAIResult.value:null;
    const analysis=current?.status==='completed'?current:alert.analysis;
    if(alert.analysis_stale) section.append(node('p','notice','证据已变化，历史 AI 建议不再对应当前输入；需要重新预览和确认。'));
    if(current && current.status!=='completed') section.append(node('p','notice',current.summary || 'AI 建议未完成，原告警和证据保留。'));
    if(analysis?.status==='completed' && analysis.actions_executable===false) {
      section.append(node('p','notice neutral','以下为模型建议，尚未独立核实；没有执行封禁、修改配置或清洗攻击流量。'),node('p','security-ai-summary',analysis.summary || '未提供摘要。'));
      if(Array.isArray(analysis.uncertainty) && analysis.uncertainty.length) section.append(sectionHeading('模型列出的不确定性'),plainList(analysis.uncertainty.slice(0,8),'未提供；不代表没有不确定性。'));
      for(const recommendation of Array.isArray(analysis.recommendations)?analysis.recommendations.slice(0,6):[]) {
        const item=node('article','security-ai-recommendation');
        item.append(node('h3','',securityRecommendationKinds[recommendation.kind] || '建议类型待复核'),node('p','',recommendation.rationale || '未提供依据。'));
        if(Array.isArray(recommendation.evidence_ids)) { const refs=node('div','finding-references'); recommendation.evidence_ids.slice(0,20).forEach(id=>refs.append(securityAIReference(id))); item.append(refs); }
        section.append(item);
      }
      section.append(node('p','small muted','模型：'+String(analysis.model || '实例配置模型')+' · 本建议没有执行入口。'));
    } else if(analysis?.status==='failed' && !current) section.append(node('p','notice',analysis.summary || 'AI 建议未通过校验，原告警保留。'));
    if(!state.capabilities?.model_configured) section.append(node('p','notice neutral','AI 提供方待配置。可接入 OpenAI 兼容 API；凭据由部署者在服务端设置，不在此页面或聊天中填写。'));
    const button=node('button','button',state.securityAIBusy?'模型正在分析…':analysis?.status==='completed'?'重新预览 AI 分析':'预览并请求 AI 分析'); button.type='button'; button.id='request-security-ai';
    button.disabled=!state.capabilities?.model_configured || state.securityAIBusy || state.securityBusy || state.securityAckBusy!==null;
    button.addEventListener('click',openSecurityAIDialog); section.append(button); panel.append(section);
  }

  function sameSecurityAITarget(target) {
    return Boolean(target && state.token && target.session===state.session && state.view==='security' && state.securitySelected===target.id && state.securityAlert?.id===target.id && state.securityAlert?.scope_hash===target.scope && state.securityDetailRequest===target.selection);
  }

  function dismissSecurityAIDialog() {
    state.securityAITarget=null;
    const dialog=$('security-ai-dialog'); if(dialog?.open) dialog.close();
    if($('security-ai-confirm')) { $('security-ai-confirm').checked=false; $('security-ai-confirm').disabled=true; }
    if($('security-ai-send')) { $('security-ai-send').disabled=true; $('security-ai-send').textContent='发送分类证据并分析'; }
    if($('security-ai-cancel')) $('security-ai-cancel').disabled=false;
    if($('security-ai-preview')) $('security-ai-preview').textContent='';
    if($('security-ai-dialog-error')) { $('security-ai-dialog-error').textContent=''; $('security-ai-dialog-error').hidden=true; }
    scheduleSecurityPolling();
  }

  async function openSecurityAIDialog() {
    const alert=state.securityAlert;
    if(!alert || state.securitySelected!==alert.id || state.capabilities?.security_ai!==true || !state.capabilities?.model_configured || state.securityAIBusy || state.securityBusy || state.securityAckBusy!==null) return;
    dismissAIDialog(); dismissBaselineDialog(); dismissSecurityAIDialog();
    const target={id:alert.id,scope:alert.scope_hash,session:state.session,selection:state.securityDetailRequest,digest:null,invalid:false};
    state.securityAITarget=target; stopSecurityPolling();
    $('security-ai-dialog-target').textContent='告警：'+String(alert.id)+' · 模型：'+String(state.capabilities.model_name || '实例配置模型');
    $('security-ai-preview').textContent='正在读取将发送的分类证据…'; $('security-ai-dialog').showModal();
    try {
      const preview=await api('/api/security/alerts/'+encodeURIComponent(target.id)+'/analysis-input');
      if(!sameSecurityAITarget(target) || state.securityAITarget!==target) return;
      if(typeof preview.input_digest!=='string' || !/^[0-9a-f]{64}$/.test(preview.input_digest) || !preview.input || typeof preview.input!=='object') throw new Error('预览缺少有效的输入指纹，未允许发送。');
      target.digest=preview.input_digest;
      const model=typeof preview.model_name==='string' && preview.model_name.trim()?preview.model_name:state.capabilities.model_name || '实例配置模型';
      const provider=typeof preview.provider_host==='string' && preview.provider_host.trim()?preview.provider_host:'当前实例配置的提供方';
      $('security-ai-dialog-target').textContent='告警：'+String(target.id)+' · 模型：'+String(model)+' · 接收方：'+String(provider);
      $('security-ai-preview').textContent=JSON.stringify(preview.input,null,2);
      $('security-ai-confirm').disabled=false;
    } catch(cause) {
      if(cause instanceof SessionEnded || !sameSecurityAITarget(target) || state.securityAITarget!==target) return;
      target.invalid=true; $('security-ai-dialog-error').textContent='无法取得发送预览：'+errorMessage(cause); $('security-ai-dialog-error').hidden=false;
    }
  }

  async function sendSecurityAI() {
    const target=state.securityAITarget;
    if(!target || target.invalid || !target.digest || !$('security-ai-confirm').checked || state.securityAIBusy) return;
    if(!sameSecurityAITarget(target)) { dismissSecurityAIDialog(); securityMessage('告警或登记范围已变化，请重新打开对应证据预览。'); return; }
    state.securityAIBusy=true; $('security-ai-send').disabled=true; $('security-ai-confirm').disabled=true; $('security-ai-cancel').disabled=true; $('security-ai-send').textContent='正在生成建议…';
    try {
      const analysis=await api('/api/security/alerts/'+encodeURIComponent(target.id)+'/analyze',{method:'POST',body:{confirm_send:true,expected_input_digest:target.digest}});
      if(!sameSecurityAITarget(target) || state.securityAITarget!==target) return;
      dismissSecurityAIDialog();
      if(analysis.status==='completed' && analysis.actions_executable===false) {
        // Re-read canonical evidence: it can have advanced since the preview.
        await selectSecurityAlert(target.id);
      } else { state.securityAIResult={id:target.id,value:analysis}; renderSecurityDetail(); }
      announce('AI 建议已返回；没有执行任何防御动作。');
    } catch(cause) {
      if(cause instanceof SessionEnded || !sameSecurityAITarget(target) || state.securityAITarget!==target) return;
      if(cause.status===409) target.invalid=true;
      $('security-ai-dialog-error').textContent='分析未完成：'+errorMessage(cause)+(target.invalid?' 请取消后重新读取最新预览。':''); $('security-ai-dialog-error').hidden=false;
    } finally {
      if(target.session===state.session) {
        state.securityAIBusy=false;
        if(state.securityAITarget===target) { $('security-ai-cancel').disabled=false; $('security-ai-confirm').disabled=target.invalid; $('security-ai-send').disabled=target.invalid || !$('security-ai-confirm').checked; $('security-ai-send').textContent='发送分类证据并分析'; }
        renderSecurityDetail();
        scheduleSecurityPolling();
      }
    }
  }

  async function selectSecurityAlert(id) {
    if(!state.token) return;
    if(state.securityAITarget) dismissSecurityAIDialog();
    const session=state.session,request=++state.securityDetailRequest;
    if(state.securitySelected!==id) state.securityAlert=null;
    state.securitySelected=id; renderSecurityAlerts(); renderSecurityDetail();
    try {
      const alert=await api('/api/security/alerts/'+encodeURIComponent(id));
      if(session!==state.session || request!==state.securityDetailRequest || state.securitySelected!==id) return;
      state.securityAlert=alert; state.securityAIResult=null; renderSecurityDetail();
    } catch(cause) {
      if(cause instanceof SessionEnded || session!==state.session || request!==state.securityDetailRequest) return;
      securityMessage('告警详情未完成：'+errorMessage(cause));
      clear($('security-alert-detail')); $('security-alert-detail').append(node('p','empty-note','无法读取这条告警的证据，请刷新后重试；未取得结果不代表风险解除。'));
    }
  }

  async function refreshSecurity({quiet=false}={}) {
    if(!state.token) return;
    if(state.capabilities?.security_observation!==true || state.securitySupported===false) { renderSecuritySummary(); renderSecurityAlerts(); renderSecurityDetail(); stopSecurityPolling(); return; }
    if(state.securityBusy || state.securityAckBusy!==null || state.securityAITarget || state.securityAIBusy) { scheduleSecurityPolling(); return; }
    const session=state.session,request=++state.securityRequest;
    const previousOpen=state.securityAlerts.filter(alert=>alert.status==='open').length;
    const previousNotifications=state.securityAlerts.reduce((total,alert)=>total+securityCount(alert.notification_count),0);
    state.securityBusy=true; if(!quiet) securityMessage(''); renderSecuritySummary(); if($('ack-security-alert')) $('ack-security-alert').disabled=true;
    try {
      const [status,alerts]=await Promise.all([api('/api/security/status'),api('/api/security/alerts')]);
      if(session!==state.session || request!==state.securityRequest) return;
      state.securityStatus=status; state.securityAlerts=Array.isArray(alerts)?alerts.slice(0,100):[]; state.securitySupported=true; state.securityRefreshedAt=new Date().toISOString(); securityMessage('');
      if(!state.securityAlerts.some(alert=>alert.id===state.securitySelected)) { state.securitySelected=state.securityAlerts[0]?.id || null; state.securityAlert=null; state.securityDetailRequest+=1; }
      renderSecuritySummary(); renderSecurityAlerts(); renderSecurityDetail();
      const open=state.securityAlerts.filter(alert=>alert.status==='open').length;
      const notifications=state.securityAlerts.reduce((total,alert)=>total+securityCount(alert.notification_count),0);
      if(open>previousOpen || notifications>previousNotifications) announce('安全观察更新：'+String(open)+' 条告警待阅，请核对来源和证据。');
      if(state.securitySelected) await selectSecurityAlert(state.securitySelected);
    } catch(cause) {
      if(cause instanceof SessionEnded || session!==state.session || request!==state.securityRequest) return;
      if(cause.status===404) { state.securitySupported=false; state.securityStatus=null; state.securityAlerts=[]; state.securitySelected=null; state.securityAlert=null; renderSecurityAlerts(); renderSecurityDetail(); }
      securityMessage('安全观察读取失败：'+errorMessage(cause)+' 已显示的历史记录不代表当前覆盖。');
    } finally {
      if(session===state.session && request===state.securityRequest) { state.securityBusy=false; renderSecuritySummary(); renderSecurityDetail(); scheduleSecurityPolling(); }
    }
  }

  async function acknowledgeSecurityAlert(id) {
    if(!state.token || state.securityAckBusy!==null || state.securityBusy || state.securityAlert?.id!==id) return;
    const session=state.session;
    state.securityAckBusy=id; stopSecurityPolling(); renderSecuritySummary(); renderSecurityDetail(); securityMessage('');
    let completed=false;
    try {
      await api('/api/security/alerts/'+encodeURIComponent(id)+'/ack',{method:'POST',body:{acknowledge:true}});
      if(session!==state.session) return;
      completed=true; announce('已记录告警已阅；这不表示事件解决或风险解除。');
    } catch(cause) { if(!(cause instanceof SessionEnded) && session===state.session) securityMessage('未能记录已阅：'+errorMessage(cause)); }
    finally { if(session===state.session) { state.securityAckBusy=null; renderSecuritySummary(); renderSecurityDetail(); if(completed) await refreshSecurity({quiet:true}); else scheduleSecurityPolling(); } }
  }

  async function unlock(event) {
    event.preventDefault();
    const token=$('token-input').value.trim(); if(!token) return;
    const session=++state.session;
    state.token=token;
    $('login-error').hidden=true; $('login-button').disabled=true; $('login-button').textContent='正在读取实例…';
    try {
      const [capabilities,samples,hosts,reports]=await Promise.all([api('/api/capabilities'),api('/api/samples'),api('/api/hosts'),api('/api/reports')]);
      if(session!==state.session) return;
      state.capabilities=capabilities; state.samples=Array.isArray(samples)?samples:[]; state.hosts=(Array.isArray(hosts)?hosts:[]).filter(host=>host.source==='ssh'); state.reports=Array.isArray(reports)?reports:[];
      defenseWorkspace?.configure();
      $('token-input').value=''; $('login-screen').hidden=true; $('app-shell').hidden=false;
      fillSelections(); reportList(); renderHosts(); renderCapabilities(); showView('workspace');
      $('workspace-heading').focus();
      renderAutomation(); if(capabilities.automation_modes===true) refreshAutomation();
      renderRemediation();
      renderVulnerabilityWatch();
      renderAutomatic();
      if(capabilities.security_observation===true) refreshSecurity({quiet:true});
      $('login-button').disabled=false; $('login-button').textContent='进入控制台 →';
      if(state.reports.length) await selectReport(state.reports[0].id);
    } catch(cause) {
      if(cause instanceof SessionEnded) return;
      lockConsole(errorMessage(cause));
    }
  }

  async function runInvestigation(event) {
    event.preventDefault();
    if(state.busy || !state.token) return;
    const source=$('source-select').value;
    let body;
    if(source==='replay') {
      const sample=state.samples.find(item=>item.id===$('sample-select').value);
      if(!sample) { error('请选择可用的回放样本。'); return; }
      body={source:'replay',scenario:sample.scenario,sample_id:sample.id};
    } else {
      const host=state.hosts.find(item=>item.id===$('host-select').value);
      if(!host) { error('请选择已登记的 SSH 主机。'); return; }
      body={source:'ssh',scenario:$('scenario-select').value,host_id:host.id};
    }
    const session=state.session;
    dismissAIDialog(); dismissBaselineDialog(); state.busy=true; updateSelection(); updateBaselineButton(); error(''); message('');
    if(containerReportRecheck) redrawContainerReportRecheck(containerReportRecheck);
    $('investigation-form').setAttribute('aria-busy','true'); $('run-investigation').textContent='正在调查…'; $('investigation-progress').textContent=source==='replay'?'正在读取合成检查结果并运行诊断规则…':'正在执行有时间与输出限制的只读采集，请等待本次结果…'; $('investigation-progress').hidden=false;
    try {
      const report=await api('/api/investigations',{method:'POST',body});
      if(session!==state.session) return;
      dismissHandoffDialog(); state.reportRequest += 1; state.loadingReport=false; state.report=report; state.tab='diagnosis'; renderReport();
      message(source==='replay'?'样本诊断已完成。此报告来自合成数据，不代表真实服务器检查。':'只读调查已生成报告，请检查证据状态与缺失信息。诊断结果不代表业务恢复。');
      announce('调查已生成报告：'+report.title+'。');
      try { await refreshReports(); } catch(cause) { if(!(cause instanceof SessionEnded)) error('报告已生成，但历史列表刷新失败：'+errorMessage(cause)); }
    } catch(cause) {
      if(cause instanceof SessionEnded) return;
      error(errorMessage(cause)+' 本次请求不会自动重试；如连接中断，请先刷新历史报告确认结果。');
    } finally {
      if(session===state.session) {
        state.busy=false; updateSelection(); updateBaselineButton(); $('run-investigation').textContent='运行只读调查 →';
        $('investigation-form').removeAttribute('aria-busy'); $('investigation-progress').hidden=true;
        if(containerReportRecheck) redrawContainerReportRecheck(containerReportRecheck);
      }
    }
  }

  function saveReportFile(blob,filename) {
    const url=URL.createObjectURL(blob),link=node('a'); link.href=url; link.download=filename;
    document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
  }

  async function exportReport(handoff=false) {
    const button=$(handoff?'export-handoff':'export-report');
    if(!state.report || button.disabled || (handoff && state.loadingReport)) return;
    const report=state.report,session=state.session,selection=state.reportRequest;
    const isCurrent=()=>session===state.session && (!handoff || selection===state.reportRequest);
    const route=handoff?'handoff':'export';
    const filename=handoff?'opsark-handoff.md':'opsark-'+String(report.id).replace(/[^a-zA-Z0-9_-]/g,'_')+'.md';
    button.disabled=true; error('');
    try {
      const blob=await api('/api/reports/'+encodeURIComponent(report.id)+'/'+route,{blob:true});
      if(!isCurrent()) return;
      saveReportFile(blob,filename);
      announce(handoff?'客户交接摘要已生成。':'报告文件已生成，保留数据来源与未解决事项。');
    } catch(cause) {
      if(!(cause instanceof SessionEnded) && isCurrent()) error(handoff?'客户交接摘要下载失败，请稍后重试。':errorMessage(cause));
    } finally { if(session===state.session) button.disabled=false; }
  }

  function sameReportTarget(target) {
    const report=state.report;
    return target && report && target.session===state.session && target.selection===state.reportRequest && report.id===target.id && (report.scope_hash || null)===target.scope && report.host_id===target.hostId && report.source===target.source;
  }

  function handoffError(text='') {
    const element=$('handoff-dialog-error'); element.textContent=text; element.hidden=!text;
  }

  function dismissHandoffDialog() {
    handoffTarget=null;
    const dialog=$('handoff-dialog');
    if(dialog.open) dialog.close();
    const job=$('handoff-job'),recheck=$('handoff-recheck'),download=$('handoff-download');
    job.replaceChildren(option('','仅导出本次调查')); job.disabled=true;
    recheck.replaceChildren(option('','暂不附加复验记录')); recheck.disabled=true;
    download.disabled=true; download.textContent='下载 Markdown';
    $('handoff-cancel').disabled=false;
    $('handoff-recheck-action').hidden=true; $('handoff-run-recheck').disabled=true;
    $('handoff-run-recheck').textContent='运行只读复验'; $('handoff-run-recheck-note').textContent='';
    $('handoff-recheck-result').hidden=true; $('handoff-recheck-result').textContent='';
    $('handoff-dialog-status').textContent=''; $('handoff-action-list-status').textContent=''; handoffError();
    $('handoff-action').replaceChildren(option('','使用调查或补丁摘要'));
    $('handoff-action-recheck').replaceChildren(option('','使用当前复验状态'));
    renderActionHandoffControls(null);
  }

  function currentHandoffTarget(target) {
    return handoffTarget===target && sameReportTarget(target) && $('handoff-dialog').open;
  }

  function validHandoffRow(row,keyCount,pattern) {
    return row && Object.keys(row).length===keyCount && typeof row.id==='string' && pattern.test(row.id) &&
      typeof row.at==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(row.at) &&
      Number.isFinite(Date.parse(row.at));
  }

  function validHandoffRows(rows,validRow) {
    return Array.isArray(rows) && rows.length<=20 && rows.every(validRow) && new Set(rows.map(row=>row.id)).size===rows.length;
  }

  function checkedHandoffOptions(value) {
    if(!value || Object.keys(value).length!==2 || !validHandoffRows(value.jobs,row=>validHandoffRow(row,3,/^[a-f0-9]{32}$/)) ||
      !value.jobs.every(row=>typeof row.status==='string' && Object.hasOwn(remediationJobStates,row.status)) ||
      !validHandoffRows(value.rechecks,row=>validHandoffRow(row,2,/^[A-Za-z0-9_-]{1,80}$/))) throw new Error();
    return value;
  }

  const handoffRecheckStatuses={pending:'待验收',failed:'复验未通过',passed:'登记业务复验通过'};

  function validHandoffRecheck(row) {
    if(!validHandoffRow(row,5,/^[A-Za-z0-9_-]{1,80}$/) || typeof row.status!=='string' ||
      !Object.hasOwn(handoffRecheckStatuses,row.status)) return false;
    const {matched_checks:matched,configured_checks:configured}=row;
    if(!Number.isInteger(matched) || !Number.isInteger(configured) || matched<0 || matched>configured || configured>3) return false;
    if(configured===0) return row.status==='pending';
    return (row.status==='passed')===(matched===configured);
  }

  function handoffRecheckLabel(row) {
    return handoffRecheckStatuses[row.status]+' · '+row.matched_checks+'/'+row.configured_checks+' 项符合 · '+dateLabel(row.at);
  }

  function handoffRechecks(target) {
    return (target?.directRecheck ? target.history?.rechecks : target?.options?.rechecks) || [];
  }

  function renderHandoffRechecks(target,selected='') {
    const select=$('handoff-recheck'),rows=handoffRechecks(target);
    select.replaceChildren(option('','暂不附加复验记录'));
    for(const row of rows) select.append(option(row.id,target.directRecheck?handoffRecheckLabel(row):row.id.slice(0,8)+' · '+dateLabel(row.at)));
    if(rows.some(row=>row.id===selected)) select.value=selected;
  }

  const actionHandoffKinds = new Map([['nginx',new Set(['apply','restore'])],['container_restart',new Set(['restart'])]]);
  const actionHandoffNames = {apply:'Nginx 配置变更',restore:'Nginx 配置回退',restart:'容器重启'};
  const actionHandoffVerdicts = {passed:'复验通过',failed:'复验未通过',pending:'待验收'};

  function closedHandoffObject(value,keys) {
    return Boolean(value && typeof value==='object' && !Array.isArray(value) &&
      Object.keys(value).length===keys.length && keys.every(key=>Object.hasOwn(value,key)));
  }

  function validActionHandoffTime(value) {
    return typeof value==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value));
  }

  function validActionHandoffAction(row) {
    return closedHandoffObject(row,['kind','plan_id','action','approved_at']) &&
      actionHandoffKinds.get(row.kind)?.has(row.action) && typeof row.plan_id==='string' &&
      /^[0-9a-f]{32}$/.test(row.plan_id) && validActionHandoffTime(row.approved_at);
  }

  function validActionHandoffRecheck(row) {
    return closedHandoffObject(row,['id','selection','verdict','started_at','finished_at']) &&
      typeof row.id==='string' && /^ar-[0-9a-f]{32}$/.test(row.id) && ['current','historical'].includes(row.selection) &&
      typeof row.verdict==='string' && Object.hasOwn(actionHandoffVerdicts,row.verdict) && validActionHandoffTime(row.started_at) &&
      (row.finished_at===null ? row.verdict==='pending' :
        validActionHandoffTime(row.finished_at) && Date.parse(row.finished_at)>=Date.parse(row.started_at));
  }

  function actionHandoffKey(row) { return `${row.kind}/${row.plan_id}`; }
  function actionHandoffPath(target) { return '/api/reports/'+encodeURIComponent(target.id)+'/handoff-actions'; }
  function selectedHandoffAction(target) {
    return target?.actions?.find(row=>actionHandoffKey(row)===$('handoff-action').value);
  }

  function renderActionHandoffControls(target) {
    const action=selectedHandoffAction(target), busy=Boolean(target?.downloading || target?.rechecking);
    $('handoff-action-field').hidden=!target?.actions?.length;
    $('handoff-action').disabled=!target?.actions?.length || busy;
    $('handoff-action-detail').hidden=!action;
    $('handoff-patch-fields').hidden=Boolean(action);
    $('handoff-action-recheck').disabled=!target?.actionHistory?.rechecks.length || busy || target.actionLoading;
    const run=$('handoff-action-run');
    run.disabled=!action || !target?.actionHistory?.can_run || busy || target.actionLoading || target.actionNeedsRead;
    run.textContent=target?.rechecking && action?'正在复验…':'运行只读复验';
    $('handoff-action-refresh').hidden=!action || !target.actionNeedsRead;
    $('handoff-action-refresh').disabled=busy || Boolean(target?.actionLoading);
    const selected=target?.actionHistory?.rechecks.find(row=>row.id===$('handoff-action-recheck').value) ||
      target?.actionHistory?.rechecks.find(row=>row.selection==='current');
    let status='';
    if(action) {
      if(target.rechecking) status='正在采集登记的只读业务检查。';
      else if(target.actionLoading) status='正在读取原任务的复验记录…';
      else if(target.actionNeedsRead) status='请重新核对复验记录。';
      else if(selected) status=(selected.selection==='historical'?'历史复验 · ':'当前复验 · ')+actionHandoffVerdicts[selected.verdict];
      else status=target.actionHistory?.can_run?'待验收。可运行登记的只读业务检查。':'待验收。当前任务暂不能运行只读复验。';
    }
    $('handoff-action-status').textContent=status;
    if(action) $('handoff-download').disabled=busy || target.actionLoading;
  }

  async function loadHandoffActions(target) {
    try {
      const value=await api(actionHandoffPath(target));
      if(!currentHandoffTarget(target)) return;
      if(!closedHandoffObject(value,['actions']) || !Array.isArray(value.actions) || value.actions.length>20 ||
        !value.actions.every(validActionHandoffAction) || new Set(value.actions.map(actionHandoffKey)).size!==value.actions.length) throw new Error();
      target.actions=value.actions;
      for(const row of target.actions) $('handoff-action').append(option(actionHandoffKey(row),actionHandoffNames[row.action]+' · '+dateLabel(row.approved_at)+' · '+row.plan_id.slice(0,8)));
    } catch(cause) {
      if(cause instanceof SessionEnded || !currentHandoffTarget(target)) return;
      $('handoff-action-list-status').textContent='未能核对关联的处置任务。关闭后可重新读取。';
    } finally { if(currentHandoffTarget(target)) updateHandoffControls(); }
  }

  async function selectHandoffAction({preserveError=false,preferredId=''}={}) {
    const target=handoffTarget,action=selectedHandoffAction(target);
    if(!currentHandoffTarget(target) || target.downloading || target.rechecking) return;
    const revision=++target.actionRequest;
    const current=()=>currentHandoffTarget(target) && target.actionRequest===revision && selectedHandoffAction(target)===action;
    target.actionHistory=null; target.actionNeedsRead=false;
    target.actionLoading=Boolean(action);
    $('handoff-action-recheck').replaceChildren(option('','使用当前复验状态'));
    if(!preserveError) handoffError();
    updateHandoffControls();
    if(!action) return;
    try {
      const value=await api(actionHandoffPath(target)+'/'+actionHandoffKey(action)+'/rechecks');
      if(!current()) return;
      if(!closedHandoffObject(value,['can_run','rechecks']) || typeof value.can_run!=='boolean' ||
        !Array.isArray(value.rechecks) || value.rechecks.length>20 || !value.rechecks.every(validActionHandoffRecheck) ||
        new Set(value.rechecks.map(row=>row.id)).size!==value.rechecks.length ||
        value.rechecks.filter(row=>row.selection==='current').length>1) throw new Error();
      target.actionHistory=value;
      for(const row of value.rechecks) $('handoff-action-recheck').append(option(row.id,
        (row.selection==='historical'?'历史 · ':'当前 · ')+actionHandoffVerdicts[row.verdict]+' · '+dateLabel(row.started_at)));
      if(preferredId && value.rechecks.some(row=>row.id===preferredId)) $('handoff-action-recheck').value=preferredId;
    } catch(cause) {
      if(cause instanceof SessionEnded || !current()) return;
      target.actionNeedsRead=true;
      handoffError('未能读取该处置任务的复验记录。');
    } finally { if(current()) { target.actionLoading=false; updateHandoffControls(); } }
  }

  async function runActionHandoffRecheck() {
    const target=handoffTarget,action=selectedHandoffAction(target);
    if(!action || !currentHandoffTarget(target) || $('handoff-action-run').disabled) return;
    const current=()=>currentHandoffTarget(target) && selectedHandoffAction(target)===action;
    target.rechecking=true; handoffError(); updateHandoffControls();
    let id='';
    try {
      const row=await api(actionHandoffPath(target)+'/'+actionHandoffKey(action)+'/rechecks',{method:'POST'});
      if(!current()) return;
      if(!validActionHandoffRecheck(row) || target.actionHistory.rechecks.some(previous=>previous.id===row.id)) throw new Error();
      id=row.id;
    } catch(cause) {
      if(cause instanceof SessionEnded || !current()) return;
      target.actionNeedsRead=true;
      handoffError('本次复验结果待核对。请先读取原任务的复验记录。');
    } finally {
      if(current()) { target.rechecking=false; updateHandoffControls(); }
    }
    if(id && current()) await selectHandoffAction({preferredId:id});
  }

  function updateHandoffControls() {
    const target=handoffTarget;
    const job=$('handoff-job'),recheck=$('handoff-recheck'),download=$('handoff-download');
    const hasJob=target?.options?.jobs.some(item=>item.id===job.value)===true;
    const busy=target?.downloading || target?.rechecking;
    const rows=handoffRechecks(target);
    job.disabled=!target?.options?.jobs.length || Boolean(busy);
    recheck.disabled=!hasJob || !rows.length || Boolean(busy) || target.loadingHistory;
    download.disabled=!target || target.options===undefined || Boolean(busy) || target.loadingHistory;
    download.textContent=target?.downloading?'正在生成…':'下载 Markdown';
    $('handoff-cancel').disabled=target?.rechecking===true;
    $('handoff-recheck-action').hidden=target?.directRecheck!==true;
    const run=$('handoff-run-recheck');
    run.disabled=!hasJob || target.history?.can_run!==true || Boolean(busy) || target.loadingHistory;
    run.textContent=target?.rechecking?'正在复验…':'运行只读复验';
    const note=$('handoff-run-recheck-note');
    if(!target?.directRecheck) note.textContent='';
    else if(!hasJob) note.textContent='选择补丁任务后可以核对复验条件。';
    else if(target.loadingHistory) note.textContent='正在核对所选任务和历史复验…';
    else if(target.rechecking) note.textContent='正在采集已登记的业务检查，请等待本次结果。';
    else if(target.history?.can_run===true) note.textContent='通过 SSH 执行只读复验，并保存一条复验记录。';
    else note.textContent='当前任务暂不能发起复验。请核对任务状态和登记的只读业务检查。';
    const result=$('handoff-recheck-result');
    const selected=target?.directRecheck && rows.find(row=>row.id===recheck.value);
    result.classList.toggle('neutral',selected?.status!=='failed');
    result.textContent=selected?handoffRecheckLabel(selected):'';
    result.hidden=!selected;
    renderActionHandoffControls(target);
  }

  async function openHandoffDialog() {
    const report=state.report;
    if(!report || state.loadingReport || $('export-handoff').disabled) return;
    if(report.source!=='ssh' || (state.capabilities?.handoff_timeline!==true && state.capabilities?.action_handoff!==true)) { await exportReport(true); return; }
    if($('handoff-dialog').open) return;
    dismissHandoffDialog(); error('');
    const target={id:report.id,scope:report.scope_hash || null,session:state.session,selection:state.reportRequest,hostId:report.host_id,source:report.source,options:undefined,downloading:false,directRecheck:state.capabilities?.handoff_recheck===true,history:null,historyRequest:0,loadingHistory:false,rechecking:false,actions:[],actionHistory:null,actionRequest:0,actionLoading:false,actionNeedsRead:false};
    handoffTarget=target;
    const status=$('handoff-dialog-status');
    status.textContent='正在读取同范围的本地记录…';
    $('handoff-dialog').showModal(); $('handoff-dialog-title').focus();
    updateHandoffControls();
    if(state.capabilities?.action_handoff===true) void loadHandoffActions(target);
    try {
      const value=await api('/api/reports/'+encodeURIComponent(report.id)+'/handoff-options');
      if(!currentHandoffTarget(target)) return;
      target.options=checkedHandoffOptions(value);
      for(const row of target.options.jobs) $('handoff-job').append(option(row.id,remediationJobStates[row.status]+' · '+row.id.slice(0,8)+' · '+dateLabel(row.at)));
      renderHandoffRechecks(target);
      status.textContent=target.options.jobs.length?'':'当前没有同范围的补丁任务。仍可下载本次调查摘要。';
    } catch(cause) {
      if(cause instanceof SessionEnded || !currentHandoffTarget(target)) return;
      target.options=null;
      status.textContent=''; handoffError('未能核对时间线选项。可下载本次调查摘要，或关闭后重新打开。');
    } finally { if(currentHandoffTarget(target)) updateHandoffControls(); }
  }

  function handoffRecheckPath(target) {
    return '/api/reports/'+encodeURIComponent(target.id)+'/handoff-rechecks';
  }

  async function selectHandoffJob() {
    const target=handoffTarget,jobId=$('handoff-job').value;
    if(!currentHandoffTarget(target) || target.downloading || target.rechecking) return;
    handoffError();
    if(!target.directRecheck) {
      $('handoff-recheck').value=''; updateHandoffControls(); return;
    }
    const request=++target.historyRequest;
    const current=()=>currentHandoffTarget(target) && target.historyRequest===request && $('handoff-job').value===jobId;
    target.history=null;
    target.loadingHistory=target.options?.jobs.some(row=>row.id===jobId)===true;
    renderHandoffRechecks(target); updateHandoffControls();
    if(!target.loadingHistory) return;
    try {
      const value=await api(handoffRecheckPath(target)+'?'+new URLSearchParams({job_id:jobId}));
      if(!current()) return;
      if(!value || Object.keys(value).length!==2 || typeof value.can_run!=='boolean' ||
        !validHandoffRows(value.rechecks,validHandoffRecheck) || value.rechecks.some(row=>row.id===target.id)) throw new Error();
      target.history=value;
      renderHandoffRechecks(target);
    } catch(cause) {
      if(cause instanceof SessionEnded || !current()) return;
      handoffError('未能读取所选任务的复验记录。请重新选择任务后核对。');
    } finally {
      if(current()) { target.loadingHistory=false; updateHandoffControls(); }
    }
  }

  async function runHandoffRecheck() {
    const target=handoffTarget,jobId=$('handoff-job').value;
    if(!currentHandoffTarget(target) || $('handoff-run-recheck').disabled) return;
    const current=()=>currentHandoffTarget(target) && $('handoff-job').value===jobId;
    target.rechecking=true; handoffError(); updateHandoffControls();
    try {
      const row=await api(handoffRecheckPath(target),{method:'POST',body:{job_id:jobId}});
      if(!current()) return;
      if(!validHandoffRecheck(row) || row.id===target.id || target.history.rechecks.some(item=>item.id===row.id)) throw new Error();
      target.history.rechecks=[row,...target.history.rechecks].slice(0,20);
      renderHandoffRechecks(target,row.id);
      try { await refreshReports(); } catch(cause) {
        if(!(cause instanceof SessionEnded) && current()) handoffError('复验已保存，但工作台历史列表暂未刷新。');
      }
    } catch(cause) {
      if(cause instanceof SessionEnded || !current()) return;
      target.history.can_run=false;
      handoffError('未能确认本次复验结果。请重新选择任务并核对历史，再决定是否重试。');
    } finally {
      if(current()) { target.rechecking=false; updateHandoffControls(); }
    }
  }

  async function downloadHandoffTimeline() {
    const target=handoffTarget;
    if(!currentHandoffTarget(target) || $('handoff-download').disabled) return;
    const action=selectedHandoffAction(target),actionRecheckId=$('handoff-action-recheck').value;
    const jobId=$('handoff-job').value,recheckId=$('handoff-recheck').value;
    if(($('handoff-action').value && !action) ||
      (action && actionRecheckId && !target.actionHistory?.rechecks.some(row=>row.id===actionRecheckId)) ||
      (!action && ((jobId && !target.options?.jobs.some(row=>row.id===jobId)) || (recheckId && (!jobId || !handoffRechecks(target).some(row=>row.id===recheckId)))))) {
      handoffError('所选记录需要重新核对，请关闭后重新打开。'); return;
    }
    const params=new URLSearchParams();
    if(action) {
      if(actionRecheckId) params.set('recheck_id',actionRecheckId);
    } else {
      if(jobId) params.set('job_id',jobId);
      if(recheckId) params.set('recheck_report_id',recheckId);
    }
    const query=params.toString();
    const stillSelected=()=>currentHandoffTarget(target) && selectedHandoffAction(target)===action &&
      (action ? $('handoff-action-recheck').value===actionRecheckId :
        $('handoff-job').value===jobId && $('handoff-recheck').value===recheckId);
    target.downloading=true; updateHandoffControls(); handoffError();
    try {
      const path=action?actionHandoffPath(target)+'/'+actionHandoffKey(action):'/api/reports/'+encodeURIComponent(target.id)+'/handoff';
      const blob=await api(path+(query?'?'+query:''),{blob:true});
      if(!stillSelected()) return;
      if(!/^text\/markdown(?:;|$)/i.test(blob.type)) throw new Error();
      saveReportFile(blob,'opsark-handoff.md'); dismissHandoffDialog(); announce('客户交接摘要已生成。');
    } catch(cause) {
      if(cause instanceof SessionEnded || !currentHandoffTarget(target)) return;
      handoffError(action || jobId?'无法导出所选记录。请关闭后重新核对记录。':'客户交接摘要下载失败，请稍后重试。');
    } finally {
      if(currentHandoffTarget(target)) { target.downloading=false; updateHandoffControls(); }
    }
  }

  function dismissAIDialog() {
    state.aiTarget=null;
    $('ai-confirm').checked=false; $('ai-send').disabled=true; $('ai-send').textContent='发送摘要并解释'; $('ai-cancel').disabled=false;
    $('ai-dialog-model').textContent=''; $('ai-dialog-error').textContent=''; $('ai-dialog-error').hidden=true;
    if($('ai-dialog').open) $('ai-dialog').close();
  }

  function openAIDialog() {
    if(!state.report || !state.capabilities?.model_configured || state.aiBusy) return;
    if(state.loadingReport || state.busy) { announce('请等待当前调查或报告读取完成，再确认发送的报告。'); return; }
    const report=state.report;
    state.aiTarget={id:report.id,scope:report.scope_hash || null,session:state.session,selection:state.reportRequest,hostId:report.host_id,source:report.source};
    message(''); error('');
    $('ai-confirm').checked=false; $('ai-send').disabled=true; $('ai-dialog-error').hidden=true;
    $('ai-dialog-model').textContent='模型：'+(state.capabilities.model_name || '实例已配置模型')+' · 报告 '+state.report.id;
    $('ai-dialog').showModal();
  }

  async function sendAI() {
    const target=state.aiTarget;
    if(!$('ai-confirm').checked || state.aiBusy || !target) return;
    if(!sameReportTarget(target) || state.loadingReport || state.busy) { dismissAIDialog(); error('当前报告或目标范围已变化，请重新确认需要发送的报告。'); return; }
    const id=target.id,session=target.session;
    state.aiBusy=true; $('ai-send').disabled=true; $('ai-cancel').disabled=true; $('ai-send').textContent='正在请求解释…'; $('ai-dialog-error').hidden=true;
    try {
      const explanation=await api('/api/reports/'+encodeURIComponent(id)+'/explain',{method:'POST',body:{confirm_send:true}});
      if(!sameReportTarget(target) || state.aiTarget!==target) return;
      state.report.ai=explanation; renderReport();
      dismissAIDialog();
      if(explanation.status==='completed') message('AI 补充解释已保存。诊断事实、执行权限与验收状态保持原有边界。');
      else error(explanation.text || '模型解释未完成，原诊断报告已保留。');
    } catch(cause) {
      if(cause instanceof SessionEnded || !sameReportTarget(target) || state.aiTarget!==target) return;
      $('ai-dialog-error').textContent=errorMessage(cause); $('ai-dialog-error').hidden=false;
    } finally {
      if(session===state.session) { state.aiBusy=false; if(state.aiTarget===target) { $('ai-send').disabled=!$('ai-confirm').checked; $('ai-cancel').disabled=false; $('ai-send').textContent='发送摘要并解释'; } if(sameReportTarget(target)) renderReport(); }
    }
  }

  function dismissBaselineDialog() {
    state.baselineTarget=null;
    $('baseline-confirm').checked=false; $('baseline-send').disabled=true; $('baseline-send').textContent='保存观测基线'; $('baseline-cancel').disabled=false;
    $('baseline-dialog-report').textContent=''; $('baseline-dialog-error').textContent=''; $('baseline-dialog-error').hidden=true;
    if($('baseline-dialog').open) $('baseline-dialog').close();
  }

  function openBaselineDialog() {
    const eligibility=baselineEligibility();
    if(!eligibility.allowed) { announce(eligibility.reason); return; }
    const report=state.report;
    state.baselineTarget={id:report.id,scope:report.scope_hash,session:state.session,selection:state.reportRequest,hostId:report.host_id,source:report.source};
    message(''); error('');
    $('baseline-confirm').checked=false; $('baseline-send').disabled=true; $('baseline-send').textContent='保存观测基线'; $('baseline-cancel').disabled=false; $('baseline-dialog-error').textContent=''; $('baseline-dialog-error').hidden=true;
    $('baseline-dialog-report').textContent='报告 '+report.id+' · '+(report.host_name || report.host_id)+' · '+sourceLabel(report.source);
    $('baseline-dialog').showModal();
  }

  async function saveBaseline() {
    const target=state.baselineTarget;
    if(!target || !$('baseline-confirm').checked || state.baselineBusy) return;
    if(!sameReportTarget(target) || !baselineEligibility().allowed) {
      dismissBaselineDialog(); error('当前报告或目标范围已变化，请重新打开观测基线确认。'); return;
    }
    state.baselineBusy=true; updateBaselineButton(); $('baseline-send').disabled=true; $('baseline-cancel').disabled=true; $('baseline-send').textContent='正在保存…'; $('baseline-dialog-error').hidden=true;
    try {
      const baseline=await api('/api/reports/'+encodeURIComponent(target.id)+'/baseline',{method:'POST',body:{confirm_observation_only:true}});
      if(!sameReportTarget(target) || state.baselineTarget!==target) return;
      if(baseline.report_id!==target.id || baseline.host_id!==target.hostId || baseline.source!==target.source || baseline.scope_hash!==target.scope || baseline.purpose!=='observation_only' || baseline.restore_capable!==false) throw new Error('服务返回的观测基线与已确认报告或用途不一致，请重新核对。');
      dismissBaselineDialog(); message('观测基线已保存，用于后续新调查的字段对照。当前历史报告未改写，也没有证明健康或建立回退点。'); announce('观测基线已保存，当前报告与验收状态保持不变。');
    } catch(cause) {
      if(cause instanceof SessionEnded || !sameReportTarget(target) || state.baselineTarget!==target) return;
      $('baseline-dialog-error').textContent=errorMessage(cause)+' 本次请求不会自动重试；连接中断时保存状态可能未知。'; $('baseline-dialog-error').hidden=false;
    } finally {
      if(target.session===state.session) {
        state.baselineBusy=false; updateBaselineButton();
        if(state.baselineTarget===target) { $('baseline-send').disabled=!$('baseline-confirm').checked; $('baseline-cancel').disabled=false; $('baseline-send').textContent='保存观测基线'; }
      }
    }
  }

  $('login-form').addEventListener('submit',unlock);
  $('open-host-onboarding').addEventListener('click',()=>{
    if(!canOpenHostOnboarding()) return;
    showView('hosts');
    const wizard=$('host-onboarding');
    wizard.open=true;
    wizard.querySelector('summary').focus();
  });
  $('host-onboarding-form').addEventListener('submit',prepareHostOnboarding);
  $('host-onboarding-form').addEventListener('input',event=>{
    if(['address','port','host_key','expected_fingerprint'].includes(event.target.name)) $('host-onboarding-confirm').checked=false;
    resetHostOnboardingResult();
  });
  document.querySelectorAll('[data-onboarding-copy]').forEach(button=>button.addEventListener('click',()=>copyHostOnboarding(button.dataset.onboardingCopy)));
  $('host-onboarding-preflight').addEventListener('click',()=>{
    const target=hostOnboardingPreflight(hostOnboardingMaterials);
    if(target) { target.scrollIntoView({block:'center'}); target.focus({preventScroll:true}); }
  });
  $('retry-status').addEventListener('click',checkService);
  $('logout-button').addEventListener('click',()=>{lockConsole();$('token-input').focus();});
  $('refresh-security').addEventListener('click',()=>refreshSecurity());
  document.addEventListener('visibilitychange',()=>{stopSecurityPolling();stopRemediationPolling();stopVulnerabilityWatchPolling();stopAutomaticPolling();stopActivationRecoveryPolling();if(!document.hidden && state.view==='security' && state.token) refreshSecurity({quiet:true});if(!document.hidden && state.view==='remediation' && state.token) { scheduleRemediationPolling();refreshVulnerabilityWatch({quiet:true});refreshAutomatic({quiet:true});refreshActivationRecoveries(); }});
  window.addEventListener('pagehide',()=>{stopSecurityPolling();stopRemediationPolling();stopVulnerabilityWatchPolling();stopAutomaticPolling();});
  document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>showView(button.dataset.view)));
  ['source-select','sample-select','host-select'].forEach(id=>$(id).addEventListener('change',updateSelection));
  $('investigation-form').addEventListener('submit',runInvestigation);
  $('refresh-reports').addEventListener('click',async()=>{
    $('refresh-reports').disabled=true; error('');
    try { await refreshReports(); } catch(cause) { if(!(cause instanceof SessionEnded)) error(errorMessage(cause)); }
    finally { $('refresh-reports').disabled=false; }
  });
  document.querySelectorAll('[data-tab]').forEach(button=>{
    button.addEventListener('click',()=>setTab(button.dataset.tab));
    button.addEventListener('keydown',event=>{
      const tabs=[...document.querySelectorAll('[data-tab]')]; let index=tabs.indexOf(button);
      if(event.key==='ArrowRight') index=(index+1)%tabs.length;
      else if(event.key==='ArrowLeft') index=(index+tabs.length-1)%tabs.length;
      else if(event.key==='Home') index=0;
      else if(event.key==='End') index=tabs.length-1;
      else return;
      event.preventDefault(); setTab(tabs[index].dataset.tab,true);
    });
  });
  $('export-report').addEventListener('click',()=>exportReport());
  $('export-handoff').addEventListener('click',openHandoffDialog);
  $('handoff-job').addEventListener('change',selectHandoffJob);
  $('handoff-action').addEventListener('change',()=>selectHandoffAction());
  $('handoff-action-recheck').addEventListener('change',updateHandoffControls);
  $('handoff-action-run').addEventListener('click',runActionHandoffRecheck);
  $('handoff-action-refresh').addEventListener('click',()=>selectHandoffAction());
  $('handoff-recheck').addEventListener('change',updateHandoffControls);
  $('handoff-run-recheck').addEventListener('click',runHandoffRecheck);
  $('handoff-download').addEventListener('click',downloadHandoffTimeline);
  $('handoff-cancel').addEventListener('click',dismissHandoffDialog);
  $('handoff-dialog').addEventListener('cancel',event=>{event.preventDefault(); if(!handoffTarget?.rechecking) dismissHandoffDialog();});
  $('handoff-dialog').addEventListener('close',()=>{if(!$('handoff-dialog').open) dismissHandoffDialog();});
  $('ai-confirm').addEventListener('change',()=>{$('ai-send').disabled=!$('ai-confirm').checked || state.aiBusy;});
  $('ai-cancel').addEventListener('click',()=>{if(!state.aiBusy)dismissAIDialog();});
  $('ai-dialog').addEventListener('cancel',event=>{if(state.aiBusy)event.preventDefault();else dismissAIDialog();});
  $('ai-dialog').addEventListener('close',()=>{if(!$('ai-dialog').open) { state.aiTarget=null; $('ai-confirm').checked=false; $('ai-send').disabled=true; }});
  $('ai-send').addEventListener('click',sendAI);
  $('baseline-confirm').addEventListener('change',()=>{$('baseline-send').disabled=!$('baseline-confirm').checked || state.baselineBusy;});
  $('baseline-cancel').addEventListener('click',()=>{if(!state.baselineBusy)dismissBaselineDialog();});
  $('baseline-dialog').addEventListener('cancel',event=>{if(state.baselineBusy)event.preventDefault();else dismissBaselineDialog();});
  $('baseline-dialog').addEventListener('close',()=>{if(!$('baseline-dialog').open) { state.baselineTarget=null; $('baseline-confirm').checked=false; $('baseline-send').disabled=true; }});
  $('baseline-send').addEventListener('click',saveBaseline);
  $('security-ai-confirm').addEventListener('change',()=>{const target=state.securityAITarget; $('security-ai-send').disabled=!$('security-ai-confirm').checked || !target?.digest || target.invalid || state.securityAIBusy;});
  $('security-ai-cancel').addEventListener('click',()=>{if(!state.securityAIBusy)dismissSecurityAIDialog();});
  $('security-ai-dialog').addEventListener('cancel',event=>{if(state.securityAIBusy)event.preventDefault();else dismissSecurityAIDialog();});
  $('security-ai-dialog').addEventListener('close',()=>{if(!$('security-ai-dialog').open) { state.securityAITarget=null; $('security-ai-confirm').checked=false; $('security-ai-send').disabled=true; scheduleSecurityPolling(); }});
  $('security-ai-send').addEventListener('click',sendSecurityAI);
  $('refresh-automation').addEventListener('click',refreshAutomation);
  $('automation-mode-select').addEventListener('change',()=>{state.automationDraft=$('automation-mode-select').value; invalidateAutomaticRecoveryPlan('模式草稿发生变化，旧恢复确认已取消。'); invalidateVulnerabilityAIPreview();dismissServiceActivationDialog();state.serviceActivationPlan=null;dismissActivationRecoveryDialog();state.activationRecoveryPlan=null; renderAutomation(); renderAutomatic();});
  $('automation-mode-form').addEventListener('submit',saveAutomation);
  $('refresh-remediation').addEventListener('click',refreshRemediation);
  $('refresh-vulnerability-watch').addEventListener('click',()=>refreshVulnerabilityWatch());
  $('refresh-automatic-repair').addEventListener('click',()=>refreshAutomatic());
  $('remediation-host-select').addEventListener('change',()=>setRemediationHost($('remediation-host-select').value));
  $('remediation-scan-form').addEventListener('submit',scanRemediation);
  $('remediation-confirm').addEventListener('change',()=>{$('remediation-execute').disabled=!$('remediation-confirm').checked || !state.remediationDialogTarget || !remediationCanApprove(state.remediationDialogTarget.plan);});
  $('remediation-cancel').addEventListener('click',dismissRemediationDialog);
  $('remediation-dialog').addEventListener('cancel',()=>dismissRemediationDialog());
  $('remediation-dialog').addEventListener('close',()=>{if(!$('remediation-dialog').open) dismissRemediationDialog();});
  $('remediation-execute').addEventListener('click',executeRemediation);
  $('automatic-recovery-confirm').addEventListener('change',()=>{$('automatic-recovery-execute').disabled=!$('automatic-recovery-confirm').checked || !automaticRecoveryCanApprove(state.automaticRecoveryDialogTarget?.plan);});
  $('automatic-recovery-cancel').addEventListener('click',()=>{if(!state.automaticRecoveryBusy)dismissAutomaticRecoveryDialog();});
  $('automatic-recovery-dialog').addEventListener('cancel',event=>{if(state.automaticRecoveryBusy)event.preventDefault();else dismissAutomaticRecoveryDialog();});
  $('automatic-recovery-dialog').addEventListener('close',()=>{if(!$('automatic-recovery-dialog').open)dismissAutomaticRecoveryDialog();});
  $('automatic-recovery-execute').addEventListener('click',executeAutomaticRecovery);
  $('refresh-vulnerability-ai').addEventListener('click',()=>refreshVulnerabilityAI());
  $('preview-vulnerability-ai').addEventListener('click',openVulnerabilityAIDialog);
  $('vulnerability-ai-confirm').addEventListener('change',()=>{const target=state.vulnerabilityAITarget; $('vulnerability-ai-send').disabled=!$('vulnerability-ai-confirm').checked || !target?.preview?.configured || target.invalid || Boolean(state.vulnerabilityAIBusy) || !sameVulnerabilityAIContext(target,{mode:true});});
  $('vulnerability-ai-cancel').addEventListener('click',()=>{if(state.vulnerabilityAIBusy!=='analyze') dismissVulnerabilityAIDialog();});
  $('vulnerability-ai-dialog').addEventListener('cancel',event=>{if(state.vulnerabilityAIBusy==='analyze') event.preventDefault(); else dismissVulnerabilityAIDialog();});
  $('vulnerability-ai-dialog').addEventListener('close',()=>{if(!$('vulnerability-ai-dialog').open) dismissVulnerabilityAIDialog();});
  $('vulnerability-ai-send').addEventListener('click',sendVulnerabilityAI);
  $('vulnerability-ai-selection').addEventListener('change',changeVulnerabilityAISelection);
  $('refresh-service-activations').addEventListener('click',refreshServiceActivations);
  $('service-activation-confirm').addEventListener('change',()=>{$('service-activation-execute').disabled=!$('service-activation-confirm').checked || !serviceActivationCanSubmit(state.serviceActivationDialogTarget);});
  $('service-activation-execute').addEventListener('click',executeServiceActivation);
  $('service-activation-cancel').addEventListener('click',dismissServiceActivationDialog);
  $('service-activation-dialog').addEventListener('cancel',dismissServiceActivationDialog);
  $('service-activation-dialog').addEventListener('close',()=>{if(!$('service-activation-dialog').open)dismissServiceActivationDialog();});
  $('refresh-activation-recoveries').addEventListener('click',refreshActivationRecoveries);
  $('activation-recovery-confirm').addEventListener('change',()=>{$('activation-recovery-execute').disabled=!$('activation-recovery-confirm').checked || !activationRecoveryCanSubmit(state.activationRecoveryDialogTarget);});
  $('activation-recovery-execute').addEventListener('click',executeActivationRecovery);
  $('activation-recovery-cancel').addEventListener('click',dismissActivationRecoveryDialog);
  $('activation-recovery-dialog').addEventListener('cancel',dismissActivationRecoveryDialog);
  $('activation-recovery-dialog').addEventListener('close',()=>{if(!$('activation-recovery-dialog').open)dismissActivationRecoveryDialog();});
  checkService();
})();
