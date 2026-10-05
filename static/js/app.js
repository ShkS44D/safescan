const CHUNK_SIZE = 1000;
const PARALLEL_CHUNKS = 3;
const COMMON_RANGES = [
  [20, 25], [53, 53], [67, 69], [80, 81], [88, 88], [110, 111], [123, 123],
  [135, 139], [143, 143], [161, 162], [179, 179], [389, 389], [443, 445],
  [465, 465], [500, 500], [514, 515], [548, 548], [554, 554], [587, 587],
  [631, 631], [636, 636], [873, 873], [902, 902], [989, 990], [993, 995],
  [1080, 1080], [1099, 1099], [1194, 1194], [1433, 1433], [1521, 1521],
  [1723, 1723], [1883, 1883], [2049, 2049], [2181, 2181], [2375, 2376],
  [2379, 2379], [3000, 3000], [3306, 3306], [3389, 3389], [3690, 3690],
  [4000, 4000], [4369, 4369], [5000, 5000], [5060, 5060], [5432, 5432],
  [5672, 5672], [5900, 5900], [5985, 5986], [6379, 6379], [6443, 6443],
  [6667, 6667], [7001, 7001], [8000, 8000], [8008, 8008], [8080, 8081],
  [8086, 8086], [8088, 8088], [8181, 8181], [8443, 8443], [8500, 8500],
  [8888, 8888], [9000, 9000], [9042, 9042], [9090, 9092], [9200, 9200],
  [9300, 9300], [9418, 9418], [9443, 9443], [10000, 10000], [10250, 10250],
  [11211, 11211], [15672, 15672], [27015, 27015], [27017, 27018], [50000, 50000]
];

const form = document.querySelector('#scan-form');
const mode = document.querySelector('#scan-mode');
const customRange = document.querySelector('#custom-range');
const startInput = document.querySelector('#start-port');
const endInput = document.querySelector('#end-port');
const statusPanel = document.querySelector('#scan-status');
const resultsPanel = document.querySelector('#results');
const resultsBody = document.querySelector('#results-body');
const emptyState = document.querySelector('#empty-state');
const formError = document.querySelector('#form-error');
let controllers = [];
let cancelled = false;
let resultData = null;
let sortState = { key: 'port', direction: 1 };

mode.addEventListener('change', () => {
  customRange.hidden = mode.value !== 'custom';
  validateRange();
});

function validateRange() {
  const error = document.querySelector('#range-error');
  error.textContent = '';
  if (mode.value !== 'custom') return true;
  if (!startInput.value || !endInput.value) error.textContent = 'Enter both a start and end port.';
  else if (!Number.isInteger(Number(startInput.value)) || !Number.isInteger(Number(endInput.value)))
    error.textContent = 'Ports must be whole numbers.';
  else if (Number(startInput.value) < 1 || Number(endInput.value) > 65535)
    error.textContent = 'Ports must be between 1 and 65,535.';
  else if (Number(startInput.value) > Number(endInput.value))
    error.textContent = 'Start port must be less than or equal to end port.';
  return !error.textContent;
}

startInput.addEventListener('input', validateRange);
endInput.addEventListener('input', validateRange);

function rangeChunks(start, end) {
  const chunks = [];
  for (let port = start; port <= end; port += CHUNK_SIZE) {
    chunks.push([port, Math.min(port + CHUNK_SIZE - 1, end)]);
  }
  return chunks;
}

function selectedChunks() {
  if (mode.value === 'common') return COMMON_RANGES;
  if (mode.value === 'well-known') return rangeChunks(1, 1024);
  if (mode.value === 'all') return rangeChunks(1, 65535);
  return rangeChunks(Number(startInput.value), Number(endInput.value));
}

async function api(url, body, controller) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
    signal: controller.signal
  });
  const payload = await response.json().catch(() => ({error: 'The server returned an invalid response.'}));
  if (!response.ok) throw new Error(payload.error || 'The request failed.');
  return payload;
}

function formatDuration(seconds) {
  const minutes = Math.floor(seconds / 60);
  return `${String(minutes).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

function setProgress(scanned, total) {
  const percent = total ? Math.round(scanned / total * 100) : 0;
  document.querySelector('#progress').value = percent;
  document.querySelector('#progress-percent').textContent = `${percent}%`;
  document.querySelector('#progress-copy').textContent = `Ports scanned ${scanned.toLocaleString()} / ${total.toLocaleString()}`;
}

function productLabel(item) {
  return [item.product, item.version].filter(Boolean).join(' ') || '—';
}

function renderResults() {
  if (!resultData) return;
  const rows = [...resultData.open].sort((a, b) => {
    const left = sortState.key === 'product' ? productLabel(a) : a[sortState.key];
    const right = sortState.key === 'product' ? productLabel(b) : b[sortState.key];
    return (typeof left === 'number' ? left - right : String(left).localeCompare(String(right))) * sortState.direction;
  });
  resultsBody.replaceChildren(...rows.map(item => {
    const row = document.createElement('tr');
    const banner = item.banner
      ? `<details><summary>View banner</summary><code></code></details>` : '<span class="muted">No banner</span>';
    row.innerHTML = `<td><strong>${item.port}</strong></td><td><span class="open-state">open</span></td><td>${escapeHtml(item.service)}</td><td>${escapeHtml(productLabel(item))}<small>${escapeHtml(item.confidence)}</small></td><td>${banner}</td>`;
    const code = row.querySelector('code');
    if (code) code.textContent = item.banner;
    return row;
  }));
  emptyState.hidden = rows.length !== 0;
  document.querySelector('#summary-open').textContent = resultData.open.length;
}

function escapeHtml(value) {
  const element = document.createElement('span');
  element.textContent = value == null ? '' : String(value);
  return element.innerHTML;
}

async function worker(queue, resolved, total, progressState) {
  while (queue.length && !cancelled) {
    const [start, end] = queue.shift();
    const controller = new AbortController();
    controllers.push(controller);
    const chunk = await api('/api/scan', {
      ip: resolved.ip, host: resolved.host, start, end, authorized: true
    }, controller);
    resultData.open.push(...chunk.open);
    resultData.open.sort((a, b) => a.port - b.port);
    progressState.scanned += chunk.scanned;
    setProgress(progressState.scanned, total);
    renderResults();
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  formError.hidden = true;
  document.querySelector('#target-error').textContent = '';
  if (!validateRange()) return;
  if (!document.querySelector('#authorized').checked) {
    formError.textContent = 'Confirm that you have permission to scan this target.';
    formError.hidden = false;
    return;
  }
  const target = document.querySelector('#target').value.trim();
  if (!target) {
    document.querySelector('#target-error').textContent = 'Enter a domain, IP address, or URL.';
    return;
  }
  cancelled = false;
  controllers = [];
  resultsBody.replaceChildren();
  emptyState.hidden = true;
  resultsPanel.hidden = true;
  statusPanel.hidden = false;
  document.querySelector('#cancel-button').hidden = false;
  document.querySelector('#scan-button').disabled = true;
  document.querySelector('#status-label').textContent = 'Resolving target…';
  const startedAt = Date.now();
  const timer = setInterval(() => {
    document.querySelector('#elapsed').textContent = formatDuration(Math.floor((Date.now() - startedAt) / 1000));
  }, 1000);
  try {
    const resolveController = new AbortController();
    controllers.push(resolveController);
    const resolved = await api('/api/resolve', {target}, resolveController);
    const chunks = selectedChunks();
    const total = chunks.reduce((sum, item) => sum + item[1] - item[0] + 1, 0);
    resultData = {target: resolved.host, ip: resolved.ip, ips: resolved.ips, open: [], scanned: total,
      durationSeconds: 0, mode: mode.options[mode.selectedIndex].text};
    resultsPanel.hidden = false;
    document.querySelector('#summary-target').textContent = `${resolved.host} (${resolved.ip})`;
    document.querySelector('#summary-scanned').textContent = total.toLocaleString();
    document.querySelector('#status-label').textContent = 'Scanning target…';
    setProgress(0, total);
    const progressState = {scanned: 0};
    await Promise.all(Array.from({length: Math.min(PARALLEL_CHUNKS, chunks.length)}, () =>
      worker(chunks, resolved, total, progressState)));
    if (!cancelled) {
      resultData.durationSeconds = Math.floor((Date.now() - startedAt) / 1000);
      document.querySelector('#summary-duration').textContent = formatDuration(resultData.durationSeconds);
      document.querySelector('#status-label').textContent = 'Scan complete';
      renderResults();
    }
  } catch (error) {
    if (error.name !== 'AbortError') {
      formError.textContent = error.message;
      formError.hidden = false;
      document.querySelector('#status-label').textContent = 'Scan stopped';
    }
  } finally {
    clearInterval(timer);
    document.querySelector('#cancel-button').hidden = true;
    document.querySelector('#scan-button').disabled = false;
  }
});

document.querySelector('#cancel-button').addEventListener('click', () => {
  cancelled = true;
  controllers.forEach(controller => controller.abort());
  document.querySelector('#status-label').textContent = 'Scan cancelled';
});

document.querySelectorAll('.sort-button').forEach(button => button.addEventListener('click', () => {
  const key = button.dataset.sort;
  sortState.direction = sortState.key === key ? sortState.direction * -1 : 1;
  sortState.key = key;
  renderResults();
}));

function download(filename, type, content) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([content], {type}));
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

document.querySelector('#download-json').addEventListener('click', () => {
  download('safescan-results.json', 'application/json', JSON.stringify(resultData, null, 2));
});

document.querySelector('#download-csv').addEventListener('click', () => {
  const quote = value => `"${String(value ?? '').replaceAll('"', '""')}"`;
  const rows = [['Port', 'State', 'Service', 'Product', 'Version', 'Confidence', 'Banner'],
    ...resultData.open.map(item => [item.port, item.state, item.service, item.product, item.version,
      item.confidence, item.banner])];
  download('safescan-results.csv', 'text/csv', rows.map(row => row.map(quote).join(',')).join('\n'));
});

document.querySelector('#copy-results').addEventListener('click', async event => {
  await navigator.clipboard.writeText(JSON.stringify(resultData, null, 2));
  event.currentTarget.textContent = 'Copied';
  setTimeout(() => { event.currentTarget.textContent = 'Copy results'; }, 1500);
});

document.querySelector('#scan-again').addEventListener('click', () => {
  statusPanel.hidden = true;
  resultsPanel.hidden = true;
  form.scrollIntoView({behavior: 'smooth'});
  document.querySelector('#target').focus();
});
