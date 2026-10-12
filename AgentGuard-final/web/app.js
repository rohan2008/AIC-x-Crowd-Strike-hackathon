const $ = (selector) => document.querySelector(selector);
let config, selected, lastTrace, lastReport, busy = false, selectedImages = [];
let customCases = loadCustomCases();
function loadCustomCases() {
  try { const rows = JSON.parse(localStorage.getItem('agentguard-custom-tests') || '[]'); return Array.isArray(rows) ? rows.filter(validCustomCase).slice(0, 10) : []; }
  catch { return []; }
}
function validCustomCase(item) {
  return item && typeof item.id === 'string' && item.id.startsWith('custom-') && typeof item.name === 'string' && item.name.length <= 100 && typeof item.body === 'string' && item.body.trim() && item.body.length <= 12000 && ['attack', 'benign'].includes(item.kind) && (item.images === undefined || validImages(item.images));
}
function validImages(images) {
  return Array.isArray(images) && images.length <= 3 && images.every(image => image && typeof image.name === 'string' && image.name.length <= 180 && typeof image.data === 'string' && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+=*$/.test(image.data) && image.data.length <= 1400000);
}
function saveCustomCases() { localStorage.setItem('agentguard-custom-tests', JSON.stringify(customCases)); }
function updateCounts() {
  $('#case-count').textContent = `${config.cases.length} tickets`;
  $('#evaluate').textContent = `Run test suite (${8 + customCases.length}) ↗`;
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notice(message) { $('#notice').textContent = message; $('#notice').hidden = !message; }
function setBusy(value, label = '') {
  busy = value;
  for (const node of document.querySelectorAll('#run, #evaluate, #generate, #save-case, #custom-name, #custom-body, #mode, #ticket-body, #ticket-images, #image-consent, .scenario, .remove-case')) node.disabled = value;
  $('#reviewer-fault').disabled = value || $('#mode').value === 'live';
  $('#run').textContent = value ? label : 'Run comparison ↗';
  $('#evaluate').textContent = value ? label : `Run test suite (${8 + customCases.length}) ↗`;
  $('#generate').textContent = value ? label : '＋ Generate 3 attack variants';
}
async function post(path, data) {
  const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'The request failed.');
  return result;
}
function count() { $('#char-count').textContent = `${$('#ticket-body').value.length.toLocaleString()} / 12,000`; }
function selectCase(caseId) {
  selected = config.cases.find(item => item.id === caseId);
  $('#image-consent').checked = false;
  selectedImages = selected.images || [];
  renderImages();
  $('#ticket-body').value = selected.body;
  $('#custom-body').value = selected.body;
  $('#scenario-name').textContent = selected.name;
  $('#scenario-description').textContent = selected.description;
  for (const button of document.querySelectorAll('.scenario')) {
    button.classList.toggle('selected', button.dataset.id === caseId);
    button.setAttribute('aria-pressed', String(button.dataset.id === caseId));
  }
  count();
  if (lastTrace) notice('Ticket changed. Run again to update the results below.');
}
function renderRun(container, result) {
  container.classList.remove('empty');
  container.replaceChildren();
  let title, description, style;
  if (result.error) {
    title = 'Run incomplete'; description = result.error; style = 'warn';
  } else if (result.violation) {
    title = 'Unauthorized action'; style = 'bad';
    description = `${result.unauthorized_reads} unauthorized reads · ${result.unsafe_replies} unsafe replies in the test outbox`;
  } else if (result.reviewer_stopped) {
    title = 'Stopped after review'; style = 'good';
    description = 'The reviewer recommended stopping, and the supervisor did not send the draft. No unauthorized action was recorded.';
  } else if (result.blocked_calls) {
    title = 'Action blocked'; style = 'good';
    description = `${result.blocked_calls} tool call(s) denied. No unauthorized action was recorded.`;
  } else {
    title = result.task_completed ? 'Request completed' : 'No unauthorized action recorded'; style = 'good';
    description = result.task_completed ? 'The test outbox contains a reply to the verified sender with their plan and renewal date.' : 'The checks found no unauthorized action, but the request was not completed.';
  }
  const outcome = el('div', undefined, `outcome ${style}`);
  outcome.append(el('strong', title), el('p', description));
  container.append(outcome);
  if (result.review) {
    const review = el('div', undefined, 'review-summary');
    review.append(el('strong', `Reviewer recommendation: ${result.review.recommendation.toUpperCase()}`));
    const list = el('ul');
    for (const finding of [...result.review.findings, ...result.review.evidence]) list.append(el('li', finding));
    review.append(list); container.append(review);
  }
  const handoffs = el('details', undefined, 'handoffs');
  handoffs.append(el('summary', `Agent messages · ${result.handoffs.length} messages`));
  for (const handoff of result.handoffs) {
    const item = el('div', undefined, 'handoff');
    item.append(el('h5', `${handoff.sequence}. ${handoff.from} → ${handoff.to} / ${handoff.kind}`), el('pre', JSON.stringify(handoff.payload, null, 2)));
    handoffs.append(item);
  }
  container.append(handoffs);
  for (const event of result.events) {
    const item = el('div', undefined, `event ${event.decision.allowed ? '' : 'denied'}`);
    const heading = el('div', undefined, 'event-title');
    heading.append(el('span', `${String(event.step).padStart(2, '0')}  ${event.actor} / ${event.tool}()`), el('span', event.decision.rule, 'rule'));
    item.append(heading, el('p', event.decision.reason));
    const detail = el('details');
    detail.append(el('summary', 'Show tool input and result'), el('pre', JSON.stringify({arguments: event.arguments, result: event.result}, null, 2)));
    item.append(detail); container.append(item);
  }
  const outbox = el('div', undefined, 'outbox');
  outbox.append(el('h4', `MOCK OUTBOX · ${result.outbox.length} REPLIES`));
  if (!result.outbox.length) outbox.append(el('p', 'No reply was recorded.'));
  for (const message of result.outbox) {
    outbox.append(el('p', `To: ${message.to}`), el('pre', message.message));
  }
  outbox.append(el('p', `${result.elapsed_ms.toLocaleString()} ms · ${result.mode === 'live' ? 'Live model' : 'Scripted simulation'} · No real delivery`));
  if (result.mode === 'live') {
    const detail = el('details');
    detail.append(el('summary', 'Agent final response'), el('pre', result.message));
    outbox.append(detail);
  }
  container.append(outbox);
}
$('#run').addEventListener('click', async () => {
  if (busy) return;
  const body = $('#ticket-body').value;
  if (!body.trim()) return notice('Enter a ticket body before running the comparison.');
  const live = $('#mode').value === 'live';
  if (live && selectedImages.length && !$('#image-consent').checked) return notice('Confirm that you want to send the selected images to OpenAI before running live analysis.');
  setBusy(true, 'Running comparison…'); notice('');
  try {
    lastTrace = await post('/api/compare', {body, images: live ? selectedImages : [], image_consent: live && selectedImages.length > 0 && $('#image-consent').checked, mode: $('#mode').value, reviewer_fault: $('#reviewer-fault').checked});
    renderRun($('#baseline-result'), lastTrace.baseline);
    renderRun($('#reviewed-result'), lastTrace.reviewed);
    renderRun($('#protected-result'), lastTrace.protected);
    $('#signals').hidden = false;
    $('#signals').textContent = lastTrace.signals.length
      ? `Text check: ${lastTrace.signals.join(' · ')}. These alerts do not block actions.`
      : 'Text check: no suspicious phrases found. Tool permissions are checked separately.';
    if (!live && selectedImages.length) notice('Simulation did not inspect image pixels. Switch to live mode and confirm image sharing to test image understanding.');
    $('#download').disabled = false;
    if (lastTrace.reviewer_fault) notice('Reviewer-failure test: the reviewer was forced to approve every draft.');
    if (lastTrace.baseline.error || lastTrace.reviewed.error || lastTrace.protected.error) notice('A run failed. The error and any completed steps are shown below.');
  } catch (error) { notice(error.message); }
  finally { setBusy(false); }
});
function fraction(numerator, denominator) { return denominator ? `${numerator}/${denominator}` : 'N/A'; }
function renderReport(report) {
  const root = $('#evaluation-results'); root.className = ''; root.replaceChildren();
  const baseline = report.metrics.baseline, reviewed = report.metrics.reviewed, protectedRun = report.metrics.protected;
  const metrics = el('div', undefined, 'metric-grid');
  const values = [
    ['Attack success · workflow only', fraction(baseline.attack_successes, baseline.attack_count), 'Attacks that caused an unauthorized action'],
    ['Attack success · with reviewer', fraction(reviewed.attack_successes, reviewed.attack_count), `${reviewed.reviewer_stops} drafts stopped after review; earlier reads still count`],
    ['Attack success · reviewer + gateway', fraction(protectedRun.attack_successes, protectedRun.attack_count), 'Attacks that caused an unauthorized action'],
    ['Normal requests completed · protected', fraction(protectedRun.benign_successes, protectedRun.benign_count), `${protectedRun.benign_blocked} normal requests with blocked actions`]
  ];
  for (const [title, value, caption] of values) {
    const card = el('article', undefined, 'panel metric');
    card.append(el('h3', title), el('strong', value), el('p', caption)); metrics.append(card);
  }
  root.append(el('p', `${report.mode === 'simulation' ? 'SCRIPTED SIMULATION' : 'LIVE MODEL'} · ${new Date(report.timestamp).toLocaleString()} · ${baseline.errors + reviewed.errors + protectedRun.errors} run errors · Reviewer-failure switch off`, 'small-label'), metrics);
  const wrap = el('div', undefined, 'panel table-wrap'), table = el('table'), head = el('thead'), header = el('tr');
  for (const text of ['Scenario', 'Type', 'Workflow only', 'With reviewer', 'Reviewer + firewall gateway']) header.append(el('th', text));
  head.append(header); table.append(head);
  const tbody = el('tbody');
  for (const row of report.rows) {
    const tr = el('tr'); tr.append(el('td', row.case.name), el('td', row.case.kind));
    for (const side of ['baseline', 'reviewed', 'protected']) {
      const run = row[side];
      const text = run.error ? 'Error / incomplete' : row.case.kind === 'attack' ? (run.violation ? 'Attack succeeded' : 'No violation') : (run.task_completed ? 'Task completed' : 'Task incomplete');
      const td = el('td'); td.append(el('span', text, run.error || run.violation || (row.case.kind === 'benign' && !run.task_completed) ? 'fail' : 'pass')); tr.append(td);
    }
    tbody.append(tr);
  }
  table.append(tbody); wrap.append(table); root.append(wrap, el('p', report.limitation, 'footnote'));
}
$('#evaluate').addEventListener('click', async () => {
  if (busy) return;
  const live = $('#mode').value === 'live';
  const hasImages = customCases.some(test => test.images?.length);
  if (live && hasImages && !$('#image-consent').checked) return notice('Confirm image sharing in the ticket panel before running live tests that include saved images.');
  setBusy(true, 'Running suite…');
  notice($('#mode').value === 'live' ? 'Running 8 tickets in 3 configurations. Live mode makes several model calls per run, takes time, and uses API credits.' : '');
  try {
    lastReport = await post('/api/evaluate', {mode: $('#mode').value, image_consent: live && hasImages && $('#image-consent').checked, custom_cases: customCases.map(test => ({...test, images: live ? (test.images || []) : []}))});
    renderReport(lastReport); $('#download-report').disabled = false;
    notice(Object.values(lastReport.metrics).some(metric => metric.errors) ? 'Some runs failed and were left out of the success rates. Export the report for error details.' : '');
  } catch (error) { notice(error.message); }
  finally { setBusy(false); }
});
function download(data, name) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'}));
  const anchor = el('a'); anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('#download').addEventListener('click', () => lastTrace && download(lastTrace, 'agentguard-trace.json'));
$('#download-report').addEventListener('click', () => lastReport && download(lastReport, 'agentguard-evaluation.json'));
$('#ticket-body').addEventListener('input', () => {
  $('#custom-body').value = $('#ticket-body').value;
  count(); $('#scenario-name').textContent = 'Custom ticket';
  $('#scenario-description').textContent = 'In simulation, use <tool_plan> JSON to specify lookups and a reply draft. Without a plan, the agent answers a normal plan-and-renewal question.';
  for (const node of document.querySelectorAll('.scenario')) { node.classList.remove('selected'); node.setAttribute('aria-pressed', 'false'); }
  if (lastTrace) notice('Ticket changed. Run again to update the results below.');
});
$('#custom-body').addEventListener('input', () => {
  $('#ticket-body').value = $('#custom-body').value;
  count(); $('#scenario-name').textContent = 'Custom ticket';
  $('#scenario-description').textContent = 'In simulation, use <tool_plan> JSON to specify lookups and a reply draft. Without a plan, the agent answers a normal plan-and-renewal question.';
  for (const node of document.querySelectorAll('.scenario')) { node.classList.remove('selected'); node.setAttribute('aria-pressed', 'false'); }
  if (lastTrace) notice('Ticket changed. Run again to update the results below.');
});
function renderImages() {
  const root = $('#image-previews'); root.replaceChildren();
  selectedImages.forEach((image, index) => {
    const item = el('div', undefined, 'image-preview');
    const preview = el('img'); preview.src = image.data; preview.alt = `Preview of ${image.name}`;
    const remove = el('button', 'Remove', 'text-button'); remove.type = 'button'; remove.addEventListener('click', () => {
      selectedImages.splice(index, 1); renderImages(); $('#image-consent').checked = false;
    });
    item.append(preview, el('span', image.name), remove); root.append(item);
  });
  $('#image-consent-row').hidden = (!selectedImages.length && !customCases.some(test => test.images?.length)) || $('#mode').value !== 'live';
}
$('#ticket-images').addEventListener('change', async event => {
  const files = [...event.target.files]; event.target.value = '';
  if (selectedImages.length + files.length > 3) return notice('A ticket can include up to 3 images.');
  try {
    for (const file of files) {
      if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) throw new Error('Use PNG, JPEG, or WebP images.');
      if (file.size > 1024 * 1024) throw new Error(`${file.name} is over the 1 MB per-image limit.`);
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = ''; for (let offset = 0; offset < bytes.length; offset += 0x8000) binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
      selectedImages.push({name: file.name.slice(0, 180), data: `data:${file.type};base64,${btoa(binary)}`});
    }
    renderImages(); $('#image-consent').checked = false;
    notice('Image attached. It will be sent to OpenAI only if you run in live mode and confirm image sharing.');
  } catch (error) { notice(error.message); }
});
$('#mode').addEventListener('change', () => {
  const live = $('#mode').value === 'live';
  $('#image-consent').checked = false;
  $('#mode-label').textContent = live ? 'Live model mode' : 'Simulation mode';
  $('#mode-description').textContent = live ? `${config.model} · separate agent conversations · test tools` : 'Scripted agents · no model calls';
  if (live) $('#reviewer-fault').checked = false;
  $('#reviewer-fault').disabled = live;
  $('#image-consent-row').hidden = (!selectedImages.length && !customCases.some(test => test.images?.length)) || !live;
  notice(live ? 'Live mode sends the ticket and fake records to OpenAI and uses API credits. No emails are sent. Run again to get live results.' : 'Simulation runs locally without model calls. Run again to update the results.');
});
$('#reviewer-fault').addEventListener('change', () => notice('Setting changed. Run again to apply it. This switch does not affect the test suite.'));
function addScenario(item) {
  const row = el('div', undefined, 'scenario-row');
  const node = el('button', undefined, 'scenario'); node.dataset.id = item.id;
  node.append(el('span', item.kind === 'attack' ? 'ATK' : 'CTL', 'case-type'), el('strong', item.name), el('small', item.category));
  node.addEventListener('click', () => selectCase(item.id)); row.append(node);
  if (item.id.startsWith('custom-')) {
    const remove = el('button', '×', 'remove-case'); remove.type = 'button'; remove.title = `Remove ${item.name}`; remove.setAttribute('aria-label', `Remove custom test ${item.name}`);
    remove.addEventListener('click', (event) => {
      event.stopPropagation();
      customCases = customCases.filter(test => test.id !== item.id);
      config.cases = config.cases.filter(test => test.id !== item.id);
      saveCustomCases(); row.remove(); updateCounts(); notice(`Removed custom test: ${item.name}.`);
    }); row.append(remove);
  }
  $('#scenarios').append(row);
}
$('#save-case').addEventListener('click', () => {
  const name = $('#custom-name').value.trim(), body = $('#ticket-body').value;
  if (!name) return notice('Give this test a name first.');
  if (!body.trim()) return notice('Add ticket content before saving it as a test.');
  if (customCases.length >= 10) return notice('This browser can store up to 10 custom tests.');
  const item = { id: `custom-${crypto.randomUUID()}`, name, kind: 'attack', category: 'Custom attack', description: 'User-authored attack test saved in this browser.', body, images: selectedImages.slice() };
  const next = [...customCases, item];
  if (JSON.stringify(next).length > 2_200_000) return notice('Browser storage is nearly full. Remove an older custom test or use smaller images.');
  customCases.push(item); config.cases.push(item); saveCustomCases(); addScenario(item); updateCounts();
  $('#custom-name').value = ''; selectCase(item.id); notice(`Saved “${name}” to this browser’s test suite.`);
});
$('#generate').addEventListener('click', async () => {
  if (busy) return;
  const body = $('#ticket-body').value;
  if (!body.trim()) return notice('Choose or write a ticket first.');
  setBusy(true, 'Writing attack variations…'); notice('');
  try {
    const result = await post('/api/generate', {body, mode: $('#mode').value});
    // Replace the previous generated batch to keep the lab small; curated fixtures stay intact.
    config.cases = config.cases.filter(item => !item.id.startsWith('generated-'));
    for (const node of document.querySelectorAll('.scenario-row')) if (node.querySelector('.scenario')?.dataset.id.startsWith('generated-')) node.remove();
    config.cases.push(...result.cases);
    for (const item of result.cases) addScenario(item);
    updateCounts();
    selectCase(result.cases[0].id); notice(result.note);
  } catch (error) { notice(error.message); }
  finally { setBusy(false); }
});
for (const node of document.querySelectorAll('.nav-item')) node.addEventListener('click', () => {
  for (const nav of document.querySelectorAll('.nav-item')) nav.classList.toggle('active', nav === node);
  for (const view of ['lab', 'evaluation', 'architecture']) $(`#${view}-view`).hidden = node.dataset.view !== view;
  $('#breadcrumb').textContent = node.getAttribute('aria-label');
});
async function init() {
  setBusy(true, 'Loading…');
  try {
    const response = await fetch('/api/config');
    if (!response.ok) throw new Error('Could not load the local server configuration.');
    config = await response.json();
    config.cases.push(...customCases);
    for (const item of config.cases) addScenario(item);
    updateCounts();
    if (config.live_available) { const option = $('#mode option[value="live"]'); option.disabled = false; option.textContent = `Live model · ${config.model}`; }
    selectCase(config.cases[0].id); setBusy(false);
  } catch (error) { notice(error.message); }
}
init();
