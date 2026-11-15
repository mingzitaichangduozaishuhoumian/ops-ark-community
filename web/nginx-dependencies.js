/* Read-only disk and route evidence. Values are rendered as text nodes. */
((root) => {
  'use strict';
  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  const integer = value => Number.isSafeInteger(value) && value > 0;
  const file = value => typeof value === 'string' && value.length <= 256 && /^\/etc\/nginx\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(value) && !value.split('/').some(part => part === '.' || part === '..');
  const domain = value => typeof value === 'string' && /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(value) && !value.includes('..');
  const domains = value => Array.isArray(value) && value.length <= 32 && value.every(domain) && new Set(value).size === value.length;
  const endpoint = value => exact(value, ['ip', 'port']) && typeof value.ip === 'string' && (value.ip === '::1' || /^127\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}$/.test(value.ip)) && integer(value.port) && value.port <= 65535;
  const bindings = {unique:'磁盘关系 · 唯一 Compose 候选',unmatched:'未找到匹配的授权 Compose 发布端口',ambiguous:'多个候选，关系存在歧义',unsupported:'配置关系无法可靠解析'};
  const pathStatuses = {
    failed:['响应不符','red'], inconclusive:['证据不足','amber'],
    uncovered:['未覆盖','neutral'], passed:['响应符合登记条件','green'],
  };
  const checkKeys = ['id','status','http_status','status_matches','body_matches'];
  const utc = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value));
  function checkedPath(value, hostId, expectedBinding) {
    if (!exact(value, ['host_id','binding_digest','observed_at','status','checks']) ||
        value.host_id !== hostId || !hash(expectedBinding) || value.binding_digest !== expectedBinding ||
        !utc(value.observed_at) || !Array.isArray(value.checks) || value.checks.length < 1 || value.checks.length > 3) throw new Error('Route observation rejected');
    const identifiers = new Set(), statuses = new Set();
    for (const check of value.checks) {
      if (!exact(check, checkKeys) || typeof check.id !== 'string' || !/^[a-z][a-z0-9_]{0,39}$/.test(check.id) || identifiers.has(check.id) || !Object.hasOwn(pathStatuses, check.status)) throw new Error('Route check rejected');
      const {status,http_status,status_matches,body_matches} = check;
      const valid = status === 'uncovered' || status === 'inconclusive'
        ? http_status === null && status_matches === null && body_matches === null
        : Number.isSafeInteger(http_status) && http_status >= 200 && http_status <= 599 && (status === 'passed'
          ? status_matches === true && body_matches === true
          : (status_matches === false && body_matches === null) || (status_matches === true && body_matches === false));
      if (!valid) throw new Error('Route check outcome rejected');
      identifiers.add(check.id); statuses.add(status);
    }
    if (statuses.size === 1 && statuses.has('uncovered') || Object.keys(pathStatuses).find(status => statuses.has(status)) !== value.status) throw new Error('Route observation outcome rejected');
    return value;
  }
  function checked(value, hostId, expectedScope, expectedBinding) {
    const keys = ['host_id','status','reason','scope_digest','binding_digest','snapshot_digest','compose_snapshot_digest','collected_at','duration_ms','files','relationships','shared_dependencies','disk_configuration','loaded_generation','actions_enabled','model_calls'];
    if (!exact(value, keys) || value.host_id !== hostId || !['observed','unavailable'].includes(value.status) || value.loaded_generation !== 'unknown' || value.actions_enabled !== false || value.model_calls !== 0 || typeof value.collected_at !== 'string' || !Number.isFinite(Date.parse(value.collected_at)) || !Number.isSafeInteger(value.duration_ms) || value.duration_ms < 0 || !Array.isArray(value.files) || !Array.isArray(value.relationships) || !Array.isArray(value.shared_dependencies) || new TextEncoder().encode(JSON.stringify(value)).length > 65536) throw new Error('Dependency evidence rejected');
    if (value.status === 'unavailable') {
      if (!['collection_unavailable','evidence_changed'].includes(value.reason) || value.scope_digest !== null || value.binding_digest !== null || value.snapshot_digest !== null || value.compose_snapshot_digest !== null || value.disk_configuration !== 'unavailable' || value.files.length || value.relationships.length || value.shared_dependencies.length) throw new Error('Partial evidence rejected');
      return value;
    }
    if (value.reason !== null || !hash(expectedScope) || !hash(expectedBinding) || value.scope_digest !== expectedScope || value.binding_digest !== expectedBinding || !hash(value.snapshot_digest) || !hash(value.compose_snapshot_digest) || value.disk_configuration !== 'observed' || !value.files.length || value.files.length > 32 || value.relationships.length > 2048 || value.shared_dependencies.length > 2048) throw new Error('Dependency identity rejected');
    const files = new Set(), servers = new Set();
    for (const item of value.files) {
      if (!exact(item, ['path','sha256']) || !file(item.path) || !hash(item.sha256) || files.has(item.path)) throw new Error('Source evidence rejected');
      files.add(item.path);
    }
    for (const item of value.relationships) {
      if (!exact(item, ['server_id','domains','file','line','endpoint','binding','candidate_id','service_name','container_name','container_state']) || !hash(item.server_id) || !domains(item.domains) || !files.has(item.file) || !integer(item.line) || !Object.hasOwn(bindings, item.binding)) throw new Error('Relationship rejected');
      if (item.binding === 'unsupported' ? item.endpoint !== null : !endpoint(item.endpoint)) throw new Error('Endpoint rejected');
      if (item.binding === 'unique') {
        if (!hash(item.candidate_id) || typeof item.service_name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(item.service_name) || typeof item.container_name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/.test(item.container_name) || !['created','running','paused','restarting','removing','exited','dead'].includes(item.container_state)) throw new Error('Candidate rejected');
      } else if ([item.candidate_id,item.service_name,item.container_name,item.container_state].some(item => item !== null)) throw new Error('Unconfirmed candidate rejected');
      servers.add(item.server_id);
    }
    for (const item of value.shared_dependencies) {
      if (!exact(item, ['kind','resource_ref','server_ids','domains']) || !['upstream','compose_service'].includes(item.kind) || !hash(item.resource_ref) || !domains(item.domains) || !Array.isArray(item.server_ids) || item.server_ids.length < 2 || item.server_ids.length > 32 || new Set(item.server_ids).size !== item.server_ids.length || item.server_ids.some(id => !servers.has(id))) throw new Error('Shared evidence rejected');
    }
    return value;
  }
  function node(tag, className, text) {
    const element = document.createElement(tag);
    element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
  }
  const anchor = host => JSON.stringify([host?.id,host?.address,host?.port,host?.username,host?.trusted_hosts_digest,host?.nginx_dependencies_configured,host?.nginx_dependency_scope_digest,host?.nginx_dependency_binding_digest]);
  const pathAnchor = host => JSON.stringify([anchor(host),host?.nginx_path_observation_binding_digest]);
  function registeredHost(hosts, hostId) {
    if (!Array.isArray(hosts) || hosts.length > 1000) throw new Error('Registered hosts rejected');
    const matches = hosts.filter(item => item?.id === hostId);
    if (matches.length !== 1) throw new Error('Registered host rejected');
    return matches[0];
  }
  function create({host, api, getContext}) {
    const section = node('section', 'host-preflight nginx-dependencies');
    section.setAttribute('aria-label', 'Nginx 依赖证据'); section.dataset.nginxDependencies = host.id;
    const initial = getContext(), identity = anchor(host), expectedScope = host.nginx_dependency_scope_digest, expectedBinding = host.nginx_dependency_binding_digest;
    const disk = node('div', ''); section.append(disk);
    const pathIdentity = pathAnchor(host), expectedPathBinding = host.nginx_path_observation_binding_digest;
    const pathConfigured = host.nginx_dependencies_configured === true && hash(expectedScope) && hash(expectedBinding) && hash(expectedPathBinding);
    const pathPanel = node('section', ''); pathPanel.setAttribute('aria-label', '登记路径响应'); pathPanel.dataset.nginxPathObservation = '';
    if (pathConfigured) section.append(pathPanel);
    let busy = false, sequence = 0, result = null, message = '', diskStale = false;
    let pathBusy = false, pathSequence = 0, pathResult = null, pathMessage = '', pathStale = false;
    const current = request => { const context = getContext(); return section.isConnected && context.signedIn && context.session === initial.session && request === sequence && anchor(context.hosts.find(item => item.id === host.id)) === identity; };
    const currentPath = request => { const context = getContext(); return pathPanel.isConnected && context.signedIn && context.session === initial.session && request === pathSequence && pathAnchor(context.hosts.find(item => item.id === host.id)) === pathIdentity; };
    function invalidatePath(currentHost) {
      if (!pathConfigured || pathAnchor(currentHost) === pathIdentity) return;
      pathSequence += 1; pathBusy = false; pathResult = null; pathStale = true;
      pathMessage = '登记范围已变更。刷新主机登记后可重新检查。'; renderPath();
    }
    function invalidateDisk(currentHost) {
      if (anchor(currentHost) === identity) return;
      sequence += 1; busy = false; result = null; diskStale = true;
      message = '登记范围已变更，未显示部分关系。刷新主机登记后可重新观察。'; render();
    }
    async function discover() {
      if (busy || diskStale || host.nginx_dependencies_configured !== true || !hash(expectedScope) || !hash(expectedBinding)) return;
      const request = ++sequence; busy = true; result = null; message = ''; render();
      try {
        const data = await api('/api/hosts/' + encodeURIComponent(host.id) + '/nginx-dependencies', {method:'POST',body:{}});
        if (!current(request)) return;
        const validated = checked(data, host.id, expectedScope, expectedBinding);
        // Metadata is independently read again: the deployment may have changed
        // while this request was in flight, even if the old card is still visible.
        const hosts = await api('/api/hosts');
        if (!current(request)) return;
        const liveHost = registeredHost(hosts, host.id);
        invalidatePath(liveHost);
        if (anchor(liveHost) !== identity) { invalidateDisk(liveHost); return; }
        result = validated;
      }
      catch (error) { if (current(request)) message = error.status === 409 ? '范围未登记或已有只读任务，请稍后重新观察。' : '本次证据未能核实，未显示部分关系。'; }
      finally { if (current(request)) { busy = false; render(); } }
    }
    async function observePath() {
      if (!pathConfigured || pathBusy || pathStale || !currentPath(pathSequence)) return;
      const request = ++pathSequence; pathBusy = true; pathResult = null; pathMessage = ''; renderPath();
      try {
        const data = await api('/api/hosts/' + encodeURIComponent(host.id) + '/nginx-path-observation', {method:'POST',body:{}});
        if (!currentPath(request)) return;
        const validated = checkedPath(data, host.id, expectedPathBinding);
        const hosts = await api('/api/hosts');
        if (!currentPath(request)) return;
        const liveHost = registeredHost(hosts, host.id);
        invalidateDisk(liveHost);
        if (pathAnchor(liveHost) !== pathIdentity) { invalidatePath(liveHost); return; }
        pathResult = validated;
      }
      catch (error) { if (currentPath(request)) pathMessage = error.status === 409 ? '路径检查暂不可用，请刷新登记或稍后重试。' : '本次路径响应未能核实。'; }
      finally { if (currentPath(request)) { pathBusy = false; renderPath(); } }
    }
    function renderPath() {
      pathPanel.replaceChildren(node('h4', '', '登记路径响应'), node('p', 'small muted', '从主机回环地址探测登记的只读路径。结果仅反映探测时的 HTTP 响应。'));
      const button = node('button', 'button', pathBusy ? '正在检查…' : '检查登记路径响应');
      button.type = 'button'; button.dataset.nginxPathObservationRun = ''; button.disabled = pathBusy || pathStale;
      button.addEventListener('click', observePath);
      const output = node('div', 'nginx-path-observation-result'); output.setAttribute('aria-live', 'polite');
      pathPanel.append(button, output);
      if (pathMessage) output.append(node('p', 'notice neutral', pathMessage));
      if (!pathResult) return;
      const [label,color] = pathStatuses[pathResult.status];
      output.append(node('strong', 'badge ' + color, label), node('p', 'small muted', new Date(pathResult.observed_at).toLocaleString()));
      const checks = node('ul', 'host-preflight-checks');
      const match = value => value === true ? '匹配' : value === false ? '不匹配' : '未确认';
      for (const check of pathResult.checks) {
        const [checkLabel,checkColor] = pathStatuses[check.status];
        const row = node('li', 'check-row'), detail = node('div', ''); row.dataset.nginxPathCheck = check.id;
        detail.append(node('strong', '', check.id), node('p', 'small muted', 'HTTP ' + (check.http_status ?? '未取得') + ' · 状态 ' + match(check.status_matches) + ' · 正文 ' + match(check.body_matches)));
        row.append(detail, node('span', 'badge ' + checkColor, checkLabel)); checks.append(row);
      }
      output.append(checks);
    }
    function render() {
      disk.replaceChildren(node('h3', '', 'Nginx → Compose 依赖证据'), node('p', 'small muted', '自动关联磁盘配置中的本机 TCP 上游与授权项目发布端口。当前已加载配置代次未知；没有修改或模型调用。'));
      const button = node('button', 'button', busy ? '正在观察…' : '观察 Nginx 依赖'); button.type = 'button'; button.dataset.nginxDependenciesRun = ''; button.disabled = busy || diskStale || host.nginx_dependencies_configured !== true || !hash(expectedScope) || !hash(expectedBinding); button.addEventListener('click', discover); disk.append(button);
      const output = node('div', 'nginx-dependencies-result'); output.setAttribute('aria-live', 'polite'); disk.append(output);
      if (host.nginx_dependencies_configured !== true) output.append(node('p','small muted','部署者尚未登记服务器端配置读取范围与摘要；网页不能自行扩大权限。'));
      if (message) output.append(node('p','notice neutral',message));
      if (!result) return;
      if (result.status === 'unavailable') { output.append(node('p','notice neutral',result.reason === 'evidence_changed' ? '采集期间项目证据发生变化，请重新观察。' : '未取得完整、可分类的依赖证据。')); return; }
      output.append(node('p','small muted',new Date(result.collected_at).toLocaleString() + ' · 仅磁盘配置观察 · 已加载代次未知 · 执行动作不可用'));
      const list = node('ul','host-checks');
      for (const edge of result.relationships) {
        const item = node('li','');
        item.append(node('strong','',edge.domains.join(' / ') || '域名无法确认'),node('p','mono small',edge.endpoint ? edge.endpoint.ip + ':' + edge.endpoint.port + ' → ' + (edge.service_name || '未知服务') : '上游关系无法确认'),node('p','small',bindings[edge.binding]),node('p','small muted',edge.file + ':' + edge.line));
        if (edge.container_name) item.append(node('p','small muted',edge.container_name + ' · ' + edge.container_state));
        list.append(item);
      }
      output.append(list);
      if (!result.relationships.length) output.append(node('p','small muted','允许范围内没有可展示的代理关系；不能据此认定站点没有依赖。'));
      for (const shared of result.shared_dependencies) output.append(node('p','notice neutral',(shared.kind === 'upstream' ? '共享本机上游' : '共享 Compose 服务') + '：' + shared.domains.join(' / ') + '（' + shared.server_ids.length + ' 个站点配置）'));
      const details = node('details',''), summary = node('summary','','配置证据摘要'); details.append(summary);
      for (const item of result.files) details.append(node('p','mono small',item.path + ' · SHA256 ' + item.sha256));
      output.append(details,node('p','small muted','共享关系仅覆盖本次观察的上游和服务，不证明卷、数据库或完整跨机依赖，也不代表业务验收通过。'));
    }
    render(); if (pathConfigured) renderPath(); return section;
  }
  root.OpsArkNginxDependencies = Object.freeze({checked, create});
})(globalThis);
