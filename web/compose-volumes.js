/* Registered Compose volume observations are temporary and read-only. */
((root) => {
  'use strict';
  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const alias = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
  const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
  const bounded = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
  const ordered = values => values.every((value, index) => index === 0 || values[index-1] < value);
  const reasons = new Set(['scope_invalid','scope_unavailable','collection_unavailable','collection_timeout','metadata_invalid','metadata_limit','evidence_changed']);

  function checked(value, host) {
    const keys = ['schema','host_id','status','reason','scope_digest','snapshot_digest','binding_digest','observed_containers','coverage','mount_mode','volumes','actions_enabled','model_calls','collected_at','duration_ms'];
    if (!exact(value, keys) || value.schema !== 'opsark-compose-volume-metadata/v1' || value.host_id !== host.id || value.mount_mode !== 'unknown' || value.actions_enabled !== false || value.model_calls !== 0 || !bounded(value.duration_ms,0,60000) || typeof value.collected_at !== 'string' || !Number.isFinite(Date.parse(value.collected_at)) || !Array.isArray(value.volumes) || value.volumes.length > 16 || !bounded(value.observed_containers,0,32)) throw new Error('Volume evidence rejected');
    if (value.status === 'unavailable') {
      if (!reasons.has(value.reason) || value.coverage !== 'unavailable' || value.observed_containers || value.volumes.length || [value.scope_digest,value.binding_digest,value.snapshot_digest].some(item => item !== null)) throw new Error('Partial volume evidence rejected');
      return value;
    }
    if (value.status !== 'observed' || value.reason !== null || value.coverage !== 'compose_labeled_local_named_volumes' || !hash(value.snapshot_digest) || !hash(host.compose_volume_scope_digest) || !hash(host.compose_volume_binding_digest) || value.scope_digest !== host.compose_volume_scope_digest || value.binding_digest !== host.compose_volume_binding_digest) throw new Error('Volume scope changed');
    const volumes = [], services = new Map();
    for (const volume of value.volumes) {
      if (!exact(volume,['volume_ref','sharing','services']) || !alias(volume.volume_ref) || !Array.isArray(volume.services) || !bounded(volume.services.length,1,32) || volume.sharing !== (volume.services.length > 1 ? 'shared_across_services' : 'one_service')) throw new Error('Volume relationship rejected');
      volumes.push(volume.volume_ref);
      const refs = [];
      for (const item of volume.services) {
        if (!exact(item,['service_ref','container_count']) || !alias(item.service_ref) || !bounded(item.container_count,1,32)) throw new Error('Service attachment rejected');
        refs.push(item.service_ref);
        services.set(item.service_ref,Math.max(services.get(item.service_ref) ?? 0,item.container_count));
      }
      if (!ordered(refs)) throw new Error('Attachment coverage rejected');
    }
    if (!ordered(volumes) || volumes.some(ref => services.has(ref)) || [...services.values()].reduce((sum,count)=>sum+count,0) > value.observed_containers) throw new Error('Volume identity rejected');
    return value;
  }

  const node = (tag, text, className = '') => {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = text;
    return element;
  };
  const binding = host => JSON.stringify([host?.id, host?.source, host?.compose_volume_scope_digest, host?.compose_volume_binding_digest]);

  function create({host, api, getContext}) {
    const section = node('section', '', 'host-preflight');
    section.setAttribute('aria-label','Compose 命名卷观察');
    const button = node('button','观察命名卷共享','button');
    button.type = 'button';
    const output = node('div','','host-preflight-result');
    output.setAttribute('aria-live','polite');
    section.append(node('h3','Compose 命名卷共享'), button,
      node('p','仅观察登记项目中由 Docker 内置 local 驱动登记的本地范围命名卷。卷名、路径和内容留在主机。底层存储位置、挂载读写模式及跨项目关系未知。','small muted'), output);
    const original = binding(host);
    const initial = getContext().session;
    const current = () => {
      const context = getContext();
      return section.isConnected && context.signedIn && context.session === initial &&
        binding(context.hosts.find(item => item.id === host.id && item.source === 'ssh')) === original;
    };
    button.addEventListener('click', async () => {
      if (button.disabled || !current()) return;
      button.disabled = true;
      button.textContent = '正在观察…';
      output.replaceChildren();
      try {
        const path = '/api/hosts/' + encodeURIComponent(host.id) + '/compose-volume-metadata';
        const result = checked(await api(path,{method:'POST',body:{}}), host);
        if (!current()) return;
        const hosts = await api('/api/hosts');
        if (!current()) return;
        if (!Array.isArray(hosts) || hosts.length > 1000) throw new Error('Host metadata rejected');
        const selected = hosts.filter(item => item.id === host.id && item.source === 'ssh');
        if (selected.length !== 1 || binding(selected[0]) !== original) throw new Error('Volume scope changed');
        if (result.status === 'unavailable') {
          const message = result.reason === 'evidence_changed' ? '采集中挂载关系发生变化，请重新观察。' : '本次未取得完整挂载证据。';
          output.append(node('p',message,'notice neutral'));
          return;
        }
        output.append(node('p','观察到 '+result.observed_containers+' 个容器，'+result.volumes.length+' 个命名卷。','small muted'));
        const serviceNumber = new Map();
        for (const volume of result.volumes) for (const service of volume.services) if (!serviceNumber.has(service.service_ref)) serviceNumber.set(service.service_ref,serviceNumber.size+1);
        const list = node('ul','','host-checks');
        for (const [index,volume] of result.volumes.entries()) {
          const label = volume.sharing === 'shared_across_services' ? '多个服务挂载' : '观察到一个服务挂载';
          const item = node('li','');
          item.append(node('strong','卷 '+(index+1)+' · '+label));
          item.append(node('p',volume.services.map(service => '服务 '+serviceNumber.get(service.service_ref)+'（'+service.container_count+' 个容器）').join('、'),'small'));
          list.append(item);
        }
        output.append(list);
      } catch (error) {
        if (current()) output.append(node('p',error.status === 409 ? '范围未登记或已有只读检查。' : '卷观察结果未能核实。','notice neutral'));
      } finally {
        if (current()) { button.disabled = false; button.textContent = '观察命名卷共享'; }
      }
    });
    return section;
  }
  root.OpsArkComposeVolumes = Object.freeze({checked,create});
})(globalThis);
