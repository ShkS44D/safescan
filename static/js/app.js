const profile = document.querySelector('#profile');
if (profile) {
  const custom = document.querySelector('#custom-fields'); const flag = document.querySelector('#use_custom');
  const help = document.querySelector('#profile-help');
  const startPort = document.querySelector('#port_start');
  const endPort = document.querySelector('#port_end');
  const descriptions = {
    fast: 'Checks frequently exposed TCP ports for the quickest result.',
    quick: 'Checks every TCP port from 1–100.',
    standard: 'Checks every TCP port from 1–1024 for broader coverage.',
    full: 'Checks all 65,535 TCP ports and can take several minutes.',
    custom: 'Choose the TCP ports you want to check.'
  };
  const sync = () => {
    const active = profile.value === 'custom';
    custom.hidden = !active;
    flag.value = active ? '1' : '0';
    custom.querySelectorAll('input[type="number"]').forEach(input => { input.disabled = !active; });
    if (help) help.textContent = descriptions[profile.value] || descriptions.fast;
  };
  profile.addEventListener('change', sync); sync();
  if (startPort && endPort) {
    const validateRange = () => {
      endPort.setCustomValidity('');
      if (profile.value !== 'custom' || !startPort.value || !endPort.value) return;
      const start = Number(startPort.value), end = Number(endPort.value);
      if (end < start) endPort.setCustomValidity('End port must be greater than or equal to start port.');
      else if (document.querySelector('.hosted-form') && end - start + 1 > 1024)
        endPort.setCustomValidity('Choose no more than 1,024 consecutive ports.');
    };
    profile.addEventListener('change', validateRange);
    startPort.addEventListener('input', validateRange);
    endPort.addEventListener('input', validateRange);
    validateRange();
  }
}
const scanForm = document.querySelector('#scan-form');
if (scanForm) {
  scanForm.addEventListener('submit', () => {
    const button = document.querySelector('#scan-submit');
    const status = document.querySelector('#submit-status');
    if (button) { button.disabled = true; button.setAttribute('aria-busy', 'true'); button.querySelector('.submit-label').textContent = 'Scanning…'; }
    if (status) status.hidden = false;
  });
}
const progress = document.querySelector('#scan-progress');
if (progress) {
  const poll = async () => { try { const response = await fetch(progress.dataset.statusUrl, {headers: {'Accept': 'application/json'}}); if (!response.ok) return; const job = await response.json(); document.querySelector('#phase').textContent = job.phase; document.querySelector('#progress-label').textContent = `${job.progress}%`; document.querySelector('#progress-bar').value = job.progress; if (!['queued', 'running'].includes(job.status)) { window.location.reload(); return; } } catch (_) {} window.setTimeout(poll, 1000); };
  window.setTimeout(poll, 500);
}

const tabList = document.querySelector('[role="tablist"]');
if (tabList) {
  const tabs = Array.from(tabList.querySelectorAll('[role="tab"]'));
  const panels = tabs.map(tab => document.getElementById(tab.getAttribute('aria-controls')));
  const topbar = document.querySelector('.topbar');
  const syncStickyOffset = () => {
    if (topbar) document.documentElement.style.setProperty('--tabs-sticky-top', `${Math.ceil(topbar.getBoundingClientRect().height)}px`);
  };
  syncStickyOffset();
  if ('ResizeObserver' in window && topbar) new ResizeObserver(syncStickyOffset).observe(topbar);

  const activateTab = (tab, { updateAddress = true, focus = false } = {}) => {
    const panelId = tab.getAttribute('aria-controls');
    tabs.forEach(item => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
    });
    panels.forEach(panel => {
      if (!panel) return;
      const selected = panel.id === panelId;
      panel.hidden = !selected;
      panel.setAttribute('aria-hidden', String(!selected));
    });
    if (updateAddress && new URLSearchParams(window.location.search).get('view') !== panelId) {
      const params = new URLSearchParams(window.location.search);
      params.set('view', panelId);
      window.history.replaceState(null, '', `${window.location.pathname}?${params.toString()}`);
    }
    if (focus) tab.focus({ preventScroll: true });
    const scrollBehavior = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
    const left = tab.offsetLeft;
    const right = left + tab.offsetWidth;
    if (left < tabList.scrollLeft) tabList.scrollTo({ left, behavior: scrollBehavior });
    else if (right > tabList.scrollLeft + tabList.clientWidth) {
      tabList.scrollTo({ left: right - tabList.clientWidth, behavior: scrollBehavior });
    }
  };

  tabList.addEventListener('click', event => {
    const tab = event.target.closest('[role="tab"]');
    if (tab) activateTab(tab);
  });
  tabList.addEventListener('keydown', event => {
    const index = tabs.indexOf(document.activeElement);
    if (index < 0) return;
    let next = index;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else return;
    event.preventDefault();
    activateTab(tabs[next], { focus: true });
  });

  const requestedView = new URLSearchParams(window.location.search).get('view') || window.location.hash.slice(1);
  const initial = panels.find(panel => panel && panel.id === requestedView);
  if (initial) activateTab(tabs[panels.indexOf(initial)], { updateAddress: false });
}
