const profile = document.querySelector('#profile');
if (profile) {
  const custom = document.querySelector('#custom-fields'); const flag = document.querySelector('#use_custom');
  const sync = () => { const active = profile.value === 'custom'; custom.hidden = !active; flag.value = active ? '1' : '0'; };
  profile.addEventListener('change', sync); sync();
}
const progress = document.querySelector('#scan-progress');
if (progress) {
  const poll = async () => { try { const response = await fetch(progress.dataset.statusUrl, {headers: {'Accept': 'application/json'}}); if (!response.ok) return; const job = await response.json(); document.querySelector('#phase').textContent = job.phase; document.querySelector('#progress-label').textContent = `${job.progress}%`; document.querySelector('#progress-bar').style.width = `${job.progress}%`; if (!['queued', 'running'].includes(job.status)) { window.location.reload(); return; } } catch (_) {} window.setTimeout(poll, 1000); };
  window.setTimeout(poll, 500);
}
