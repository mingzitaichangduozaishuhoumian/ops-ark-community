const base = '/api/nginx-actions';
const id = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const hostId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(value);
const siteId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value);
const revision = value => Number.isSafeInteger(value) && value >= 0;
const utc = value => typeof value === 'string' && value.length <= 40 && /(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value));
const endpoint = value => typeof value === 'string' && /^127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(value) && Number(value.split(':')[1]) <= 65535;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const recordKeys = ['plan_id','host_id','status','created_at','approved','blocking','plan','receipt','prepare_reason'];
const planKeys = ['schema_version','status','plan_id','action','action_id','policy_digest','plan_digest','mode_revision','source_sha256','candidate_sha256','backup_sha256','context_sha256','expires_at','upstream_before','upstream_after','affected_site_ids','syntax','original_action_id'];
const receiptKeys = ['schema_version','status','action_id','action','policy_digest','plan_id','plan_digest','mode_revision','reason','reconciliation_status'];
const labels = {
  prepare_pending:'预览待核实', ready:'待批准', unknown:'结果待核实', verified:'已验证', refused:'已拒绝',
  not_started:'未开始 · 已核实',
};
const reasons = {
  policy_refused:'目标机策略拒绝', scope_changed:'目标或配置范围已变化', syntax_refused:'语法检查未通过',
  expired:'预览已过期', busy:'目标机正忙', business_unconfirmed:'业务结果待核实',
  conflict:'目标机存在冲突任务', not_found:'原记录未找到', operation_unconfirmed:'处置结果待核实',
};
const reason = value => value === null || (typeof value === 'string' && Object.hasOwn(reasons, value));
const settled = row => row.approved && !row.blocking;
const verified = row => row.status === 'verified' || row.receipt?.reconciliation_status === 'verified';
const previousLive = row => row.receipt?.reconciliation_status === 'disk_published_live_previous';
const unchanged = row => row.receipt?.reconciliation_status === 'unchanged_from_preview';
const restorable = row => row.plan?.action === 'apply' && (verified(row) || (row.blocking && previousLive(row)));
const fingerprint = plan => JSON.stringify(planKeys.map(key => plan[key]));

function statusLabel(row) {
  if (previousLive(row)) return row.blocking ? '磁盘已变更 · 原服务已复验' : '回退已核实 · 原结果未知';
  if (unchanged(row)) return '配置和服务已核实未变 · 原结果未知';
  if (row.receipt?.reconciliation_status === 'verified') return '独立复验通过 · 原结果未知';
  return labels[row.status];
}

function checkedRecord(row, expectedHost, expectedId) {
  if (!exact(row, recordKeys) || !id(row.plan_id) || !hostId(row.host_id) ||
      (expectedHost && row.host_id !== expectedHost) || (expectedId && row.plan_id !== expectedId) ||
      typeof row.status !== 'string' || !Object.hasOwn(labels, row.status) || !utc(row.created_at) || typeof row.approved !== 'boolean' ||
      typeof row.blocking !== 'boolean' || !reason(row.prepare_reason)) throw new Error('Invalid Nginx action record');

  const plan = row.plan;
  if (plan === null) {
    if (!['prepare_pending','refused'].includes(row.status) || row.approved || row.blocking || row.receipt !== null ||
        (row.status === 'prepare_pending' && row.prepare_reason !== null)) throw new Error('Invalid pending Nginx action');
    return row;
  }
  if (!exact(plan, planKeys) || plan.schema_version !== 1 || plan.status !== 'ready' || plan.plan_id !== row.plan_id ||
      !['apply','restore'].includes(plan.action) || !revision(plan.mode_revision) || !utc(plan.expires_at) ||
      !['action_id','policy_digest','plan_digest','source_sha256','candidate_sha256','backup_sha256','context_sha256'].every(key => hash(plan[key])) ||
      plan.source_sha256 === plan.candidate_sha256 || !endpoint(plan.upstream_before) ||
      !endpoint(plan.upstream_after) || plan.upstream_before === plan.upstream_after || plan.syntax !== 'passed' ||
      !Array.isArray(plan.affected_site_ids) || !plan.affected_site_ids.length || plan.affected_site_ids.length > 8 ||
      !plan.affected_site_ids.every(siteId) || new Set(plan.affected_site_ids).size !== plan.affected_site_ids.length ||
      (plan.action === 'apply' ? plan.original_action_id !== null || plan.backup_sha256 !== plan.source_sha256 :
        !hash(plan.original_action_id) || plan.backup_sha256 !== plan.candidate_sha256) || row.prepare_reason !== null) {
    throw new Error('Invalid Nginx action preview');
  }

  const receipt = row.receipt;
  if (receipt === null) {
    if (row.blocking !== row.approved || (row.approved ? row.status !== 'unknown' : row.status !== 'ready')) throw new Error('Invalid approval state');
  } else if (!exact(receipt, receiptKeys) || receipt.schema_version !== 1 || !row.approved ||
      !['unknown','verified','refused','not_started'].includes(receipt.status) || receipt.status !== row.status ||
      !['action','action_id','plan_id','plan_digest','mode_revision','policy_digest'].every(key => receipt[key] === plan[key]) ||
      !reason(receipt.reason) || (receipt.status === 'verified' && receipt.reason !== null) ||
      (receipt.status === 'not_started' && receipt.reason !== 'expired') ||
      (receipt.reconciliation_status !== null && (receipt.status !== 'unknown' ||
        !['verified','disk_published_live_previous','unchanged_from_preview'].includes(receipt.reconciliation_status))) ||
      (receipt.status !== 'unknown' && row.blocking) ||
      (receipt.status === 'unknown' && receipt.reconciliation_status === null && !row.blocking) ||
      (['verified','unchanged_from_preview'].includes(receipt.reconciliation_status) && row.blocking) ||
      (receipt.reconciliation_status === 'disk_published_live_previous' && plan.action !== 'apply')) {
    throw new Error('Invalid Nginx action receipt');
  }
  return row;
}

function enrolled(host) {
  return host && hostId(host.id) && host.source === 'ssh' && host.nginx_action_configured === true && hash(host.nginx_action_binding_digest);
}

function target(hosts, selected) {
  if (!Array.isArray(hosts) || hosts.length > 1000) return null;
  const matches = hosts.filter(host => host?.id === selected);
  return matches.length === 1 && enrolled(matches[0]) ? matches[0] : null;
}

function anchor(host) {
  return host ? JSON.stringify([host.id,host.address,host.port,host.username,host.trusted_hosts_digest,host.nginx_action_binding_digest]) : '';
}

function savedMode(context, approving = false) {
  const mode = context.automation;
  if (!mode || context.modePending || context.modeDraft !== mode.mode || mode.mode_sync_complete !== true ||
      !revision(mode.revision) || !(approving ? ['assisted'] : ['manual','assisted']).includes(mode.mode)) return null;
  return mode;
}

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function button(label, run, disabled = false, primary = false) {
  const item = node('button', primary ? 'button primary' : 'button', label);
  item.type = 'button';
  item.disabled = disabled;
  item.addEventListener('click', run);
  return item;
}

function facts(pairs, className = 'detail-list') {
  const list = node('dl', className);
  for (const [label, value] of pairs) list.append(node('dt', '', label), node('dd', '', String(value)));
  return list;
}

function preview(plan, host) {
  const result = node('div', 'nginx-action-preview');
  result.append(facts([
    ['登记目标', host.name || host.id], ['影响站点', plan.affected_site_ids.join('、')],
    ['模式修订', plan.mode_revision], ['有效至', new Date(plan.expires_at).toISOString()],
  ]));
  const change = node('div', 'nginx-action-diff');
  for (const [label, value] of [['当前上游',plan.upstream_before],['计划上游',plan.upstream_after]]) {
    const part = node('div');
    part.append(node('span', 'small muted', label), node('strong', 'mono', value));
    change.append(part);
  }
  const digests = node('details', 'nginx-action-fingerprints');
  digests.append(node('summary', '', '配置与备份摘要'), facts([
    ['当前配置', plan.source_sha256], ['候选配置', plan.candidate_sha256],
    ['备份', plan.backup_sha256], ['上下文', plan.context_sha256],
    ...(plan.original_action_id ? [['原动作 ID', plan.original_action_id]] : []),
  ], 'detail-list mono'));
  result.append(change, node('p', 'small muted', '候选语法检查通过。'),
    facts([['预览摘要', plan.plan_digest]], 'detail-list mono'), digests);
  return result;
}

export function create({root, api, getContext, announce, actionReportLink = () => null}) {
  const panel = node('div');
  const dialog = node('dialog', 'nginx-action-dialog');
  dialog.setAttribute('aria-labelledby', 'nginx-action-confirm-title');
  root.replaceChildren(panel, dialog);

  let session = null, visible = false, selectedHost = '', identity = '', epoch = 0, displayKey = '';
  let records = [], selectedId = '', busy = '', message = '', confirmation = null, expiry = null;
  const approvals = new Map(), expectations = new Map(), previewReads = new Set();

  function closeDialog() {
    confirmation = null;
    clearTimeout(expiry);
    if (dialog.open) dialog.close();
    dialog.replaceChildren();
  }

  dialog.addEventListener('cancel', event => { event.preventDefault(); closeDialog(); });

  function clearTarget() {
    epoch += 1;
    records = []; selectedId = ''; busy = ''; message = '';
    closeDialog();
  }

  function reset() {
    clearTarget();
    session = null; visible = false; selectedHost = ''; identity = ''; displayKey = '';
    approvals.clear(); expectations.clear(); previewReads.clear();
    panel.replaceChildren(); root.hidden = true;
  }

  function configured(context) {
    return context.signedIn && context.capabilities?.nginx_managed_actions === true;
  }

  function configure() {
    const context = getContext();
    if (!configured(context)) { reset(); return; }
    if (session !== context.session) { reset(); session = context.session; }
    const hosts = context.hosts.filter(host => target(context.hosts, host?.id));
    if (!target(hosts, selectedHost)) selectedHost = hosts[0]?.id || '';
    const nextIdentity = anchor(target(hosts, selectedHost));
    if (visible !== context.visible || nextIdentity !== identity) {
      clearTarget();
      records = [...approvals.values()].filter(item => item.identity === nextIdentity).map(item => item.row);
      selectedId = records[0]?.plan_id || '';
    }
    visible = context.visible;
    identity = nextIdentity;
    root.hidden = !visible;
    if (!visible) { panel.replaceChildren(); displayKey = ''; return; }
    const mode = savedMode(context);
    if (confirmation && !canApprove(confirmation)) closeDialog();
    const nextKey = JSON.stringify([hosts.map(host => [anchor(host), host.name]), identity, mode?.mode, mode?.revision]);
    if (displayKey !== nextKey) { displayKey = nextKey; render(); }
  }

  function choose(host) {
    if (!target(getContext().hosts, host) || host === selectedHost) return;
    selectedHost = host;
    configure();
  }

  function current(ref) {
    const context = getContext();
    return configured(context) && context.visible && ref.session === session && context.session === session &&
      ref.epoch === epoch && ref.hostId === selectedHost && ref.identity === anchor(target(context.hosts, selectedHost));
  }

  function readRemote(mode) {
    return Promise.all([
      api('/api/hosts'), mode ? api('/api/automation') : null,
    ]);
  }

  function checkRemote(ref, [hosts, remoteMode], mode) {
    if (!current(ref)) return false;
    const now = savedMode(getContext());
    if (anchor(target(hosts, ref.hostId)) !== ref.identity || (mode && (
      !now || now.mode !== mode.mode || now.revision !== mode.revision || remoteMode?.mode !== mode.mode ||
      remoteMode?.revision !== mode.revision || remoteMode?.mode_sync_complete !== true
    ))) throw new Error('Changed Nginx action context');
    return true;
  }

  async function run(activity, perform, failedMessage) {
    const ref = {session, epoch, hostId:selectedHost, identity};
    if (busy || !identity || !current(ref)) return;
    busy = activity; message = ''; render();
    try { await perform(ref); }
    catch { if (current(ref) && !message) message = failedMessage; }
    finally { if (current(ref)) { busy = ''; render(); } }
  }

  function checkBinding(row) {
    const previous = records.find(item => item.plan_id === row.plan_id);
    const expected = expectations.get(row.plan_id);
    if (row.plan && expected && (row.plan.action !== expected.action || row.plan.original_action_id !== expected.original ||
        row.plan.mode_revision !== expected.revision)) throw new Error('Changed Nginx plan binding');
    if (previous?.plan && (!row.plan || fingerprint(previous.plan) !== fingerprint(row.plan))) throw new Error('Changed Nginx plan');
    // A list snapshot may precede the current receipt. Keep the stronger record.
    if (previous && ((previous.approved && !row.approved) || (settled(previous) && !settled(row)))) return previous;
    if (previous && previousLive(previous)) {
      if (row.status === 'unknown' && !row.receipt?.reconciliation_status) return previous;
      if (!previousLive(row)) throw new Error('Changed Nginx publication proof');
    }
    if (previous && settled(previous) && settled(row) &&
        receiptKeys.some(key => previous.receipt[key] !== row.receipt[key])) throw new Error('Changed final Nginx receipt');
    return row;
  }

  function accept(row) {
    const value = checkBinding(row);
    records = [value, ...records.filter(item => item.plan_id !== value.plan_id)];
    selectedId = value.plan_id;
    const pending = approvals.get(value.plan_id);
    if (pending) pending.row = value;
    return value;
  }

  function refresh() {
    return run('正在读取处置记录…', async ref => {
      const data = await api(base);
      if (!current(ref) || !checkRemote(ref, await readRemote())) return;
      if (!Array.isArray(data) || data.length > 50) throw new Error('Invalid Nginx action history');
      const all = data.map(row => checkedRecord(row));
      if (new Set(all.map(row => row.plan_id)).size !== all.length) throw new Error('Duplicate Nginx action history');
      const next = all.filter(row => row.host_id === ref.hostId).map(checkBinding);
      // Preserve locally known IDs for interrupted approvals even if the list is paginated.
      const retained = records.filter(row => approvals.has(row.plan_id) && !next.some(item => item.plan_id === row.plan_id));
      records = [...retained, ...next];
      if (!records.some(row => row.plan_id === selectedId)) selectedId = records[0]?.plan_id || '';
      previewReads.delete(ref.identity);
    }, '处置记录未能核实，请重新读取。');
  }

  function blocked(allowPlanId = '') {
    return previewReads.has(identity) || [...approvals.entries()].some(([planId, item]) => planId !== allowPlanId && item.identity === identity) ||
      records.some(row => row.plan_id !== allowPlanId && row.blocking);
  }

  function rollbackException(original) {
    return original?.plan?.action === 'apply' && original.blocking && previousLive(original) ? original.plan_id : '';
  }

  function prepare(original = null, reportLink = null) {
    const mode = savedMode(getContext());
    if (!mode || blocked(rollbackException(original)) || (original && (!restorable(original) ||
        original.host_id !== selectedHost || original.plan_id !== selectedId || !records.includes(original)))) return;
    return run('正在核对预览…', async ref => {
      const snapshot = await readRemote(mode);
      if (!checkRemote(ref, snapshot, mode)) return;
      if (reportLink) {
        const currentLink = actionReportLink(target(snapshot[0], ref.hostId));
        if (!currentLink || currentLink.id !== reportLink.id || currentLink.session !== reportLink.session ||
            currentLink.selection !== reportLink.selection) throw new Error('Changed report selection');
      }
      previewReads.add(ref.identity);
      const path = original ? `${base}/${original.plan_id}/rollback/prepare` : `${base}/prepare`;
      const body = {expected_mode_revision:mode.revision};
      if (!original) body.host_id = ref.hostId;
      if (reportLink && !original) body.report_id = reportLink.id;
      const data = await api(path, {method:'POST',body});
      if (!current(ref) || !checkRemote(ref, await readRemote(mode), mode)) return;
      const row = checkedRecord(data, ref.hostId);
      if (row.approved || expectations.has(row.plan_id) || records.some(item => item.plan_id === row.plan_id)) throw new Error('Invalid Nginx preview identity');
      expectations.set(row.plan_id, {action:original ? 'restore' : 'apply', original:original?.plan.action_id || null,
        revision:mode.revision, identity:ref.identity});
      accept(row);
      previewReads.delete(ref.identity);
      announce('预览记录已返回。');
    }, '预览未能核实，请先读取处置记录并查询原计划。');
  }

  function canApprove(row) {
    const context = getContext(), mode = savedMode(context, true);
    const original = row?.plan?.action === 'restore' ? records.find(item => item.plan?.action_id === row.plan.original_action_id) : null;
    return configured(context) && context.visible && identity && identity === anchor(target(context.hosts, selectedHost)) &&
      !busy && !blocked(rollbackException(original)) && row?.plan && row.status === 'ready' &&
      row.host_id === selectedHost && row.plan_id === selectedId && records.includes(row) &&
      expectations.get(row.plan_id)?.identity === identity &&
      mode?.revision === row.plan.mode_revision && Date.parse(row.plan.expires_at) > Date.now();
  }

  function confirm(row) {
    if (!canApprove(row)) return;
    const host = target(getContext().hosts, selectedHost);
    if (!host) return;
    confirmation = row;
    const content = node('div', 'dialog-content');
    const title = node('h2', '', row.plan.action === 'restore' ? '批准这份 Nginx 回退？' : '批准这份 Nginx 变更？');
    title.id = 'nginx-action-confirm-title'; title.tabIndex = -1;
    const checkbox = node('input'); checkbox.type = 'checkbox';
    const consent = node('label', 'checkbox-line');
    consent.append(checkbox, node('span', '', '我已核对这份预览的摘要、模式修订和影响站点。'));
    const approve = button(row.plan.action === 'restore' ? '批准回退' : '批准变更', () => {
      if (!checkbox.checked || confirmation !== row || !canApprove(row)) return;
      closeDialog();
      submit(row);
    }, true, true);
    checkbox.addEventListener('change', () => { approve.disabled = !checkbox.checked || !canApprove(row); });
    const actions = node('div', 'dialog-actions'); actions.append(button('取消', closeDialog), approve);
    content.append(title, preview(row.plan, host), consent, actions);
    dialog.replaceChildren(content); dialog.showModal(); title.focus();
    expiry = setTimeout(() => { closeDialog(); render(); }, Math.min(2147483647, Math.max(0, Date.parse(row.plan.expires_at) - Date.now())));
  }

  function submit(row) {
    if (!canApprove(row)) return;
    const mode = savedMode(getContext(), true);
    return run('正在核对并提交这份批准…', async ref => {
      if (!checkRemote(ref, await readRemote(mode), mode)) return;
      if (Date.parse(row.plan.expires_at) <= Date.now()) throw new Error('Nginx preview expired');
      const pending = {identity:ref.identity, row, refused:false};
      approvals.set(row.plan_id, pending);
      let data;
      try {
        data = await api(`${base}/${row.plan_id}/approve`, {method:'POST', body:{
          expected_plan_digest:row.plan.plan_digest, expected_mode_revision:row.plan.mode_revision, confirm:true,
        }});
      } catch (cause) {
        if (ref.session !== session || ![403,409].includes(cause?.status)) throw cause;
        pending.refused = true;
        if (current(ref)) message = '批准被拒绝。请查询原计划确认状态。';
        return;
      }
      if (!current(ref) || !checkRemote(ref, await readRemote())) return;
      const result = checkedRecord(data, ref.hostId, row.plan_id);
      if (!result.approved) throw new Error('Approval was not confirmed');
      if (settled(accept(result))) approvals.delete(row.plan_id);
      announce('批准回执已返回，请跟进原计划。');
    }, '批准未能核实。请查询原计划。');
  }

  function follow(row, observe = false) {
    if (row.host_id !== selectedHost || row.plan_id !== selectedId || !records.includes(row) ||
        (observe && (!row.approved || row.status !== 'unknown' || settled(row)))) return;
    return run(observe ? '正在复验原动作…' : '正在查询原计划…', async ref => {
      if (observe && !checkRemote(ref, await readRemote())) return;
      const path = `${base}/${row.plan_id}${observe ? '/observe' : ''}`;
      const data = await api(path, {method:observe ? 'POST' : 'GET'});
      if (!current(ref) || !checkRemote(ref, await readRemote())) return;
      const result = checkedRecord(data, ref.hostId, row.plan_id);
      accept(result);
      if (settled(result)) approvals.delete(row.plan_id);
      else if (!observe && approvals.get(row.plan_id)?.refused && result.status === 'ready' && !result.approved && !result.blocking) {
        approvals.delete(row.plan_id);
        expectations.delete(row.plan_id);
      }
      announce(observe ? '已读取原动作复验结果。' : '已读取原计划状态。');
    }, observe ? '原动作复验未完成，请继续核对原计划。' : '原计划未能核实，请稍后继续查询。');
  }

  function render() {
    if (!visible) return;
    const context = getContext();
    const hosts = context.hosts.filter(host => target(context.hosts, host?.id));
    const host = target(hosts, selectedHost), mode = savedMode(context);
    const selected = records.find(row => row.plan_id === selectedId);
    const heading = node('h2', '', 'Nginx 受控变更');
    const toolbar = node('div', 'nginx-actions-toolbar');
    const select = node('select'); select.id = 'nginx-action-host'; select.disabled = !hosts.length;
    for (const item of hosts) { const choice = node('option', '', item.name || item.id); choice.value = item.id; select.append(choice); }
    select.value = selectedHost;
    select.addEventListener('change', () => choose(select.value));
    const field = node('label', 'field', '登记目标'); field.htmlFor = select.id; field.append(select);
    const reportLink = actionReportLink(host);
    const includeReport = node('input'); includeReport.type = 'checkbox'; includeReport.disabled = Boolean(busy);
    toolbar.append(field, button('生成变更预览', () => prepare(null, includeReport.checked ? reportLink : null), Boolean(!host || !mode || busy || blocked()), true),
      button('读取处置记录', refresh, Boolean(!host || busy)));
    const status = node('p', 'small muted', busy || ''); status.setAttribute('role', 'status');
    panel.replaceChildren(heading, toolbar, status);
    if (reportLink) {
      const label = node('label', 'checkbox-line small');
      label.append(includeReport, node('span', '', '关联当前 SSH 调查报告'));
      toolbar.after(label);
    }
    if (!host) panel.append(node('p', 'small muted', '当前没有登记的 Nginx 处置目标。'));
    else if (!mode) panel.append(node('p', 'small muted', '请先核对已同步的手动或半自动模式。'));
    else if (mode.mode === 'manual') panel.append(node('p', 'small muted', '手动模式可生成预览，批准需要半自动模式下的有效预览。'));
    if (message) { const error = node('p', 'notice error-notice', message); error.setAttribute('role', 'alert'); panel.append(error); }
    if (!records.length) return;

    const layout = node('div', 'remediation-jobs-layout');
    const list = node('div', 'remediation-job-list'); list.setAttribute('aria-label', 'Nginx 处置记录');
    for (const row of records) {
      const title = row.plan?.action === 'restore' ? '回退' : row.plan ? '变更' : '预览';
      const item = button('', () => { selectedId = row.plan_id; closeDialog(); render(); }, Boolean(busy));
      item.className = 'remediation-job-button'; item.dataset.nginxPlanId = row.plan_id;
      item.setAttribute('aria-pressed', String(row.plan_id === selectedId));
      item.append(node('strong', '', `${title} · ${statusLabel(row)}`), node('span', 'mono small', row.plan_id));
      list.append(item);
    }
    const detail = node('article', 'remediation-job-detail'); detail.setAttribute('aria-label', '原计划与回执');
    if (selected) {
      detail.append(node('h3', '', statusLabel(selected)),
        facts([['计划 ID', selected.plan_id], ...(selected.plan ? [['动作 ID', selected.plan.action_id]] : [])], 'detail-list mono'));
      const refusal = selected.prepare_reason || selected.receipt?.reason;
      if (refusal && !unchanged(selected)) detail.append(node('p', 'small muted', reasons[refusal]));
      if (selected.plan) detail.append(preview(selected.plan, host));
      if (previousLive(selected) && selected.blocking) detail.append(node('p', 'small muted', '原变更结果未知。该主机当前仅可生成这次变更的回退预览。'));
      if (approvals.has(selected.plan_id)) detail.append(node('p', 'small muted', '批准已发出，请查询原计划确认回执。'));
      const actions = node('div', 'nginx-actions-buttons');
      actions.append(button('查询原计划', () => follow(selected), Boolean(busy)));
      if (selected.status === 'ready' && !approvals.has(selected.plan_id)) {
        actions.append(button('核对批准', () => confirm(selected), !canApprove(selected), true));
        if (expectations.get(selected.plan_id)?.identity !== identity) {
          detail.append(node('p', 'small muted', '历史预览可查询。批准前需按当前登记生成预览。'));
        } else if (mode && (mode.revision !== selected.plan.mode_revision || Date.parse(selected.plan.expires_at) <= Date.now())) {
          detail.append(node('p', 'small muted', '原预览的模式修订或期限已变化，请生成新预览。'));
        }
      }
      if (selected.approved && selected.status === 'unknown' && !settled(selected)) actions.append(button('独立复验原动作', () => follow(selected, true), Boolean(busy)));
      if (restorable(selected)) actions.append(button('生成回退预览', () => prepare(selected), Boolean(!mode || busy || blocked(rollbackException(selected)))));
      detail.append(actions);
    }
    layout.append(list, detail); panel.append(layout);
  }

  return {configure, reset, refresh};
}
