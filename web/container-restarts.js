const base = '/api/container-restarts';
const id = /^[a-f0-9]{32}$/;
const sha = /^[a-f0-9]{64}$/;
const hostName = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/;
const image = /^sha256:[a-f0-9]{64}$/;
const valid = (value, pattern) => typeof value === 'string' && pattern.test(value);
const revision = value => Number.isSafeInteger(value) && value >= 0;
const date = value => typeof value === 'string' && value.length <= 40 && /(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value));
const exact = (row, keys) => row !== null && typeof row === 'object' && !Array.isArray(row) &&
  Object.keys(row).length === keys.length && keys.every(key => Object.hasOwn(row, key));
const states = {
  prepare_pending: '预览待核实', ready: '待批准', unknown: '执行结果待核实',
  verified: '容器重启已验证', refused: '已拒绝', not_started: '已核实未开始',
};
const reasons = {
  policy_refused: '目标机策略拒绝', scope_changed: '容器或登记范围已变化', expired: '预览已过期',
  busy: '目标机正忙', conflict: '存在冲突的原任务', not_found: '原记录未找到',
  operation_unconfirmed: '处置结果待核实',
};
const knownReason = value => value === null || (typeof value === 'string' && Object.hasOwn(reasons, value));
const rowKeys = ['plan_id', 'host_id', 'binding_digest', 'status', 'created_at', 'approved', 'blocking', 'plan', 'receipt', 'prepare_reason'];
const planKeys = ['schema_version', 'status', 'policy_digest', 'plan_id', 'action_id', 'mode_revision',
  'plan_digest', 'container_id', 'image_id', 'expires_at', 'impact'];
const receiptKeys = ['schema_version', 'status', 'policy_digest', 'action_id', 'plan_id', 'plan_digest',
  'mode_revision', 'reason', 'reconciliation_status'];

export function checkedRecord(row, host, planId) {
  if (!exact(row, rowKeys) || !valid(row.plan_id, id) || !valid(row.host_id, hostName) ||
      !valid(row.binding_digest, sha) || (planId && row.plan_id !== planId) ||
      (host && row.host_id !== host) || !Object.hasOwn(states, row.status) || !date(row.created_at) ||
      typeof row.approved !== 'boolean' || typeof row.blocking !== 'boolean' || !knownReason(row.prepare_reason)) {
    throw new Error('Invalid container restart record');
  }
  const plan = row.plan;
  if (plan === null) {
    if (!['prepare_pending', 'refused'].includes(row.status) || row.approved || row.blocking ||
        row.receipt !== null || (row.status === 'prepare_pending' && row.prepare_reason !== null)) {
      throw new Error('Invalid pending container restart');
    }
    return row;
  }
  if (!exact(plan, planKeys) || plan.schema_version !== 1 || plan.status !== 'ready' ||
      plan.plan_id !== row.plan_id || row.prepare_reason !== null || !revision(plan.mode_revision) ||
      !date(plan.expires_at) || !valid(plan.image_id, image) ||
      !['policy_digest', 'action_id', 'plan_digest', 'container_id'].every(key => valid(plan[key], sha)) ||
      !exact(plan.impact, ['expected_downtime_seconds', 'no_recreate', 'no_volume_changes']) ||
      plan.impact.expected_downtime_seconds !== null || plan.impact.no_recreate !== true ||
      plan.impact.no_volume_changes !== true) throw new Error('Invalid container restart plan');
  const receipt = row.receipt;
  if (receipt === null) {
    if (row.blocking !== row.approved || row.status !== (row.approved ? 'unknown' : 'ready')) {
      throw new Error('Invalid approval state');
    }
  } else if (!exact(receipt, receiptKeys) || receipt.schema_version !== 1 || !row.approved ||
      !['verified', 'unknown', 'refused', 'not_started'].includes(receipt.status) || receipt.status !== row.status ||
      !['policy_digest', 'action_id', 'plan_id', 'plan_digest', 'mode_revision'].every(key => receipt[key] === plan[key]) ||
      !knownReason(receipt.reason) || (receipt.status === 'verified' && receipt.reason !== null) ||
      (receipt.status === 'not_started' && receipt.reason !== 'expired') ||
      (receipt.reconciliation_status !== null && (receipt.status !== 'unknown' || receipt.reconciliation_status !== 'verified')) ||
      row.blocking !== (receipt.status === 'unknown' && receipt.reconciliation_status === null)) {
    throw new Error('Invalid container restart receipt');
  }
  return row;
}

const enrolled = host => host?.source === 'ssh' && valid(host.id, hostName) &&
  host.container_restart_configured === true && valid(host.container_restart_binding_digest, sha);
const dependencyBinding = host => host?.nginx_dependencies_configured === true &&
  valid(host.nginx_dependency_binding_digest, sha) ? host.nginx_dependency_binding_digest : null;
const modeFor = context => {
  const mode = context?.automation;
  if (!mode || context.modePending || context.modeDraft !== mode.mode || mode.mode_sync_complete !== true ||
      !revision(mode.revision) || !['manual', 'assisted'].includes(mode.mode)) return null;
  return mode;
};
const statusLabel = row => row.receipt?.reconciliation_status === 'verified' ?
  '原回执未知 · 容器重启已复验' : states[row.status];
const impact = '现有容器会中断服务，进程内存状态会丢失。容器及挂载保留。中断时长和业务恢复需要现场验证。';
const impactReasons = {
  collection_unavailable: '未取得完整的 Nginx 和 Compose 观察。',
  evidence_changed: '采集期间证据或预览范围发生变化。',
  container_not_observed: '当前 Compose 观察未核实预览中的容器。',
  ambiguous_binding: '站点与容器的关联存在歧义。',
};
const impactDomain = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const impactFile = /^\/etc\/nginx\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/;

function checkedImpact(value, planId, binding) {
  if (!exact(value, ['plan_id', 'binding_digest', 'status', 'reason', 'observed_at', 'loaded_generation', 'sites']) ||
      value.plan_id !== planId || value.binding_digest !== binding || value.loaded_generation !== 'unknown' ||
      !Array.isArray(value.sites) || value.sites.length > 128) throw new Error('Invalid restart impact');
  if (value.status === 'unavailable' && typeof value.reason === 'string' && Object.hasOwn(impactReasons, value.reason) &&
      value.observed_at === null && !value.sites.length) return value;
  if (value.status !== 'observed' || value.reason !== null || !date(value.observed_at) ||
      value.sites.some(site => !exact(site, ['domain', 'file', 'line']) ||
        !valid(site.domain, impactDomain) || site.domain.includes('..') || !valid(site.file, impactFile) ||
        site.file.length > 256 || site.file.split('/').some(part => part === '.' || part === '..') ||
        !Number.isSafeInteger(site.line) || site.line < 1 || site.line > 131072)) {
    throw new Error('Invalid restart impact evidence');
  }
  return value;
}

function element(tag, css = '', text = '') {
  const node = document.createElement(tag);
  if (css) node.className = css;
  if (text) node.textContent = text;
  return node;
}

function button(text, callback, disabled = false) {
  const item = element('button', 'button', text);
  item.type = 'button';
  item.disabled = disabled;
  item.addEventListener('click', callback);
  return item;
}

export function create({root, api, getContext, actionReportLink = () => null}) {
  const panel = element('div');
  const dialog = element('dialog');
  dialog.setAttribute('aria-label', '确认重启容器');
  root.replaceChildren(panel, dialog);
  let session = null, visible = false, hostId = '', selected = '', rows = [], busy = '', error = '';
  let request = 0, expiry = null, confirming = null;
  let impactRead = null, impactExpiry = null;
  const approvals = new Set();
  const uncertainPreviews = new Set();

  function closeDialog() {
    confirming = null;
    window.clearTimeout(expiry);
    if (dialog.open) dialog.close();
    dialog.replaceChildren();
  }
  dialog.addEventListener('cancel', event => { event.preventDefault(); closeDialog(); });

  function reset() {
    request += 1;
    session = null;
    visible = false;
    hostId = selected = busy = error = '';
    rows = [];
    window.clearTimeout(impactExpiry);
    impactRead = null;
    approvals.clear();
    uncertainPreviews.clear();
    closeDialog();
    panel.replaceChildren();
    root.hidden = true;
  }

  function contextNow() {
    const context = getContext();
    return context.signedIn && context.visible && context.capabilities?.container_restart === true &&
      context.session === session ? context : null;
  }

  function target(context) {
    const available = context?.hosts.filter(host => host?.id === hostId) || [];
    return available.length === 1 && enrolled(available[0]) ? available[0] : null;
  }

  function blocked(id) {
    return rows.some(row => row.host_id === id && (row.blocking ||
      (approvals.has(row.plan_id) && !row.approved)));
  }

  function samePlan(previous, row) {
    return previous.host_id === row.host_id && previous.binding_digest === row.binding_digest &&
      (!previous.plan || (row.plan && planKeys.filter(key => key !== 'impact').every(key => previous.plan[key] === row.plan[key])));
  }

  function mayApprove(row, context) {
    const mode = modeFor(context);
    return row?.plan && row.status === 'ready' && !row.approved && !blocked(row.host_id) &&
      target(context)?.container_restart_binding_digest === row.binding_digest && hostId === row.host_id &&
      mode?.mode === 'assisted' && row.plan.mode_revision === mode.revision && Date.parse(row.plan.expires_at) > Date.now();
  }

  function mayInspectImpact(row, context) {
    const host = target(context);
    return row?.plan && row.plan_id === selected && row.status === 'ready' && !row.approved &&
      !approvals.has(row.plan_id) && hostId === row.host_id &&
      host?.container_restart_binding_digest === row.binding_digest && dependencyBinding(host) &&
      modeFor(context)?.revision === row.plan.mode_revision &&
      Date.parse(row.plan.expires_at) > Date.now();
  }

  function matchesImpactContext(read, row, context) {
    return mayInspectImpact(row, context) && samePlan(read.row, row) &&
      dependencyBinding(target(context)) === read.binding;
  }

  async function inspectImpact(row) {
    const context = contextNow();
    if (busy || impactRead?.pending || !mayInspectImpact(row, context)) return;
    const read = {row, binding: dependencyBinding(target(context)), pending: true, result: null, bindingChanged: false};
    impactRead = read;
    render();
    const current = () => impactRead === read && matchesImpactContext(read,
      rows.find(item => item.plan_id === selected), contextNow());
    try {
      const response = await api(base + '/' + row.plan_id + '/impact', {method: 'POST', body: {}});
      if (!current()) return;
      const result = checkedImpact(response, row.plan_id, read.binding);
      if (result.status === 'observed') {
        const hosts = await api('/api/hosts');
        if (!current()) return;
        const matches = Array.isArray(hosts) ? hosts.filter(host => host?.id === row.host_id) : [];
        const live = matches.length === 1 ? matches[0] : null;
        if (!enrolled(live) || live.container_restart_binding_digest !== row.binding_digest ||
            dependencyBinding(live) !== read.binding) {
          read.bindingChanged = true;
          return;
        }
      }
      read.result = result;
    } catch { /* An unverifiable reply never supplies evidence for this preview. */ }
    finally {
      if (impactRead === read) {
        read.pending = false;
        if (contextNow()) render();
      }
    }
  }

  function impactDetails(read) {
    const details = element('div');
    details.setAttribute('role', 'status');
    if (read.pending) {
      details.textContent = '正在检查磁盘配置中的站点关联…';
    } else if (read.bindingChanged) {
      details.textContent = 'Nginx 或 Compose 登记范围已变化或无法核实，未显示本次站点关联。';
    } else if (!read.result) {
      details.textContent = '未取得可核实的站点影响检查结果。';
    } else if (read.result.status === 'unavailable') {
      details.textContent = impactReasons[read.result.reason];
    } else {
      const result = read.result;
      details.append(element('p', 'small', result.sites.length ? '磁盘配置中关联的站点' : '本次未发现可核实的磁盘站点关联。'));
      if (result.sites.length) {
        const sites = element('ul', 'small');
        for (const site of result.sites) sites.append(element('li', '', `${site.domain} · ${site.file}:${site.line}`));
        details.append(sites);
      }
      const observed = element('time', 'small muted', new Date(result.observed_at).toLocaleString());
      observed.dateTime = result.observed_at;
      details.append(observed);
    }
    details.append(element('p', 'small muted', '当前生效的 Nginx 配置尚未核实。'));
    return details;
  }

  function merge(row) {
    const previous = rows.find(item => item.plan_id === row.plan_id);
    if (previous && !samePlan(previous, row)) throw new Error('Original plan changed');
    rows = [row, ...rows.filter(item => item.plan_id !== row.plan_id)];
    selected = row.plan_id;
  }

  async function perform(label, execute, failure) {
    if (!contextNow() || busy) return;
    const sequence = ++request;
    busy = label;
    error = '';
    render();
    const current = () => sequence === request && Boolean(contextNow());
    try { await execute(current); }
    catch { if (current()) error = failure; }
    finally {
      if (sequence === request) {
        busy = '';
        if (contextNow()) render();
      }
    }
  }

  function refresh() {
    return perform('正在读取原任务…', async current => {
      const response = await api(base);
      if (!current()) return;
      if (!Array.isArray(response) || response.length > 250) throw new Error('Invalid history');
      const next = response.map(row => checkedRecord(row));
      if (new Set(next.map(row => row.plan_id)).size !== next.length) throw new Error('Duplicate plans');
      const previous = new Map(rows.map(row => [row.plan_id, row]));
      if (next.some(row => previous.has(row.plan_id) && !samePlan(previous.get(row.plan_id), row))) {
        throw new Error('Original plan changed');
      }
      rows = next;
      uncertainPreviews.clear();
      if (!rows.some(row => row.plan_id === selected)) selected = rows[0]?.plan_id || '';
    }, '未取得任务列表，请稍后刷新。');
  }

  function prepare(reportLink = null) {
    const context = contextNow();
    const mode = modeFor(context);
    const host = target(context);
    if (!mode || !host || uncertainPreviews.has(host.id) || blocked(host.id)) return;
    return perform('正在生成单容器预览…', async current => {
      if (reportLink) {
        const currentLink = actionReportLink(target(contextNow()));
        if (!currentLink || currentLink.id !== reportLink.id || currentLink.session !== reportLink.session ||
            currentLink.selection !== reportLink.selection) throw new Error('Changed report selection');
      }
      uncertainPreviews.add(host.id);
      const body = {host_id: host.id, expected_mode_revision: mode.revision};
      if (reportLink) body.report_id = reportLink.id;
      const response = await api(base + '/prepare', {method: 'POST', body});
      if (current()) {
        merge(checkedRecord(response, host.id));
        uncertainPreviews.delete(host.id);
      }
    }, '预览回执待核实，请先刷新原任务列表。');
  }

  function query(row, verify) {
    const url = base + '/' + row.plan_id + (verify ? '/observe' : '');
    return perform('正在查询同一个原任务…', async current => {
      const response = await api(url, verify ? {method: 'POST'} : {});
      if (current()) merge(checkedRecord(response, row.host_id, row.plan_id));
    }, '未取得原任务的新回执。');
  }

  function confirm(row) {
    if (busy || !mayApprove(row, contextNow())) return;
    closeDialog();
    const active = {id: row.plan_id, binding: row.binding_digest};
    confirming = active;
    const content = element('div', 'dialog-content');
    const title = element('h2', '', '批准本次容器重启？');
    title.tabIndex = -1;
    const check = element('input');
    check.type = 'checkbox';
    const consent = element('label', 'checkbox-line');
    consent.append(check, element('span', '', '我已核对容器 ID，并接受本次服务中断。'));
    const approve = button('批准一次重启', () => {
      if (!check.checked || confirming !== active || busy || !mayApprove(row, contextNow())) return;
      approvals.add(row.plan_id);
      closeDialog();
      perform('批准已发出，正在核对原任务…', async current => {
        const response = await api(base + '/' + row.plan_id + '/approve', {method: 'POST', body: {
          expected_plan_digest: row.plan.plan_digest, expected_mode_revision: row.plan.mode_revision, confirm: true,
        }});
        if (current()) merge(checkedRecord(response, row.host_id, row.plan_id));
      }, '批准结果待核实。请查询这条原任务。');
    }, true);
    approve.classList.add('primary');
    check.addEventListener('change', () => { approve.disabled = !check.checked; });
    const actions = element('div', 'dialog-actions');
    actions.append(button('取消', closeDialog), approve);
    content.append(title, element('p', 'mono small', row.plan.container_id), element('p', 'small', impact), consent, actions);
    dialog.replaceChildren(content);
    dialog.showModal();
    title.focus();
    expiry = window.setTimeout(closeDialog, Math.max(0, Date.parse(row.plan.expires_at) - Date.now()));
  }

  function render() {
    const context = contextNow();
    if (!context) return;
    root.hidden = false;
    const hosts = context.hosts.filter(enrolled);
    if (!target(context)) hostId = hosts[0]?.id || '';
    const mode = modeFor(context);
    if (confirming && (!mayApprove(rows.find(row => row.plan_id === confirming.id), context) ||
        target(context)?.container_restart_binding_digest !== confirming.binding)) closeDialog();
    const actions = element('div', 'nginx-actions-toolbar');
    const select = element('select');
    select.disabled = !hosts.length || Boolean(busy);
    for (const item of hosts) {
      const option = element('option', '', item.name || item.id);
      option.value = item.id;
      select.append(option);
    }
    select.value = hostId;
    select.addEventListener('change', () => { hostId = select.value; closeDialog(); render(); });
    const field = element('label', 'field', '登记目标');
    field.append(select);
    const reportLink = actionReportLink(target(context));
    const includeReport = element('input'); includeReport.type = 'checkbox'; includeReport.disabled = Boolean(busy);
    actions.append(field, button('生成重启预览', () => prepare(includeReport.checked ? reportLink : null),
      Boolean(busy || !mode || !hostId || uncertainPreviews.has(hostId) || blocked(hostId))),
    button('刷新任务', refresh, Boolean(busy)));
    const progress = element('p', 'small muted', busy || (mode?.mode === 'manual' ?
      '手动模式可生成预览。批准重启需要已同步的半自动模式。' :
      mode ? '' : '请先核对已同步的手动或半自动模式。'));
    progress.setAttribute('role', 'status');
    panel.replaceChildren(element('h2', '', '受控容器重启'), actions, progress);
    if (reportLink) {
      const label = element('label', 'checkbox-line small');
      label.append(includeReport, element('span', '', '关联当前 SSH 调查报告'));
      actions.after(label);
    }
    if (error) {
      const message = element('p', 'notice error-notice', error);
      message.setAttribute('role', 'alert');
      panel.append(message);
    }
    const layout = element('div', 'remediation-jobs-layout');
    const list = element('div', 'remediation-job-list');
    list.setAttribute('aria-label', '容器重启原任务');
    for (const row of rows) {
      const item = button(row.host_id + ' · ' + statusLabel(row), () => { selected = row.plan_id; render(); });
      item.className = 'remediation-job-button';
      item.setAttribute('aria-pressed', String(row.plan_id === selected));
      item.append(element('span', 'mono small', row.plan_id));
      list.append(item);
    }
    const detail = element('article', 'remediation-job-detail');
    detail.setAttribute('aria-label', '容器重启计划与回执');
    const row = rows.find(item => item.plan_id === selected);
    const inspectable = mayInspectImpact(row, context);
    window.clearTimeout(impactExpiry);
    if (inspectable) {
      const remaining = Date.parse(row.plan.expires_at) - Date.now();
      impactExpiry = window.setTimeout(render, Math.max(1, remaining));
    }
    if (impactRead && !matchesImpactContext(impactRead, row, context)) impactRead = null;
    if (row) {
      detail.append(element('h3', '', statusLabel(row)));
      if (row.plan) {
        const values = element('dl', 'detail-list');
        for (const [label, value] of [
          ['容器 ID', row.plan.container_id], ['镜像 ID', row.plan.image_id],
          ['预览期限', new Date(row.plan.expires_at).toLocaleString()], ['计划摘要', row.plan.plan_digest],
        ]) values.append(element('dt', '', label), element('dd', 'mono small', value));
        detail.append(values, element('p', 'small muted', impact));
      }
      const refusal = row.receipt?.reason || row.prepare_reason;
      if (refusal) detail.append(element('p', 'small muted', reasons[refusal]));
      const controls = element('div', 'nginx-actions-buttons');
      controls.append(button('查询原任务', () => query(row, false), Boolean(busy)));
      if (inspectable) controls.append(button('检查站点影响（只读）', () => inspectImpact(row), Boolean(busy || impactRead?.pending)));
      if (row.blocking) controls.append(button('只读复验原任务', () => query(row, true), Boolean(busy)));
      if (mayApprove(row, context)) controls.append(button('复核并批准', () => confirm(row), Boolean(busy)));
      detail.append(controls);
      if (impactRead) detail.append(impactDetails(impactRead));
    } else detail.append(element('p', 'empty-note', '生成预览后，可在这里核对原计划与处置回执。'));
    layout.append(list, detail);
    panel.append(layout);
  }

  function configure() {
    const context = getContext();
    if (!context.signedIn || context.capabilities?.container_restart !== true) { reset(); return; }
    if (context.session !== session) { reset(); session = context.session; }
    if (!context.visible) {
      if (visible) {
        request += 1;
        busy = '';
        window.clearTimeout(impactExpiry);
        impactRead = null;
        closeDialog();
      }
      visible = false;
      root.hidden = true;
      return;
    }
    const opening = !visible;
    visible = true;
    render();
    if (opening) refresh();
  }

  return {configure, reset};
}
