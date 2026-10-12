// Exercise folder traversal and shared validation without uploading files.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(require('node:path').join(__dirname, '../web/app.js'), 'utf8');
const nodes = new Map();
const attachmentPaths = new WeakMap();
const context = {
  files: [], busy: false, attachmentPaths, setTimeout, clearTimeout,
  attachmentName: file => attachmentPaths.get(file) || file.webkitRelativePath || file.name,
  notice: text => { context.message = text; }, renderFiles() {},
  $: id => { if (!nodes.has(id)) nodes.set(id, {checked: true, addEventListener() {}}); return nodes.get(id); },
};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function addFiles('), source.indexOf('const dropZone =')), context);
const file = (name, size = 100) => ({name, size});
const entry = f => ({name: f.name, isFile: true, file: resolve => resolve(f)});
const dir = (name, batches) => ({name, isDirectory: true, createReader() {
  let i = 0; return {readEntries: resolve => resolve(batches[i++] || [])};
}});
(async () => {
  const nested = file('report.pdf'), second = file('image.png'), ignored = file('notes.txt');
  const result = await context.collectEntries([dir('pack', [[dir('nested', [[entry(nested)]])], [entry(second), entry(ignored)]])]);
  assert.equal(result.length, 3, 'read all batches');
  assert.equal(context.attachmentName(nested), 'pack/nested/report.pdf');
  context.addFiles(result, true);
  assert.equal(context.files.length, 3);
  assert.match(context.message, /Added 3/);
  assert.equal(context.$('#consent').checked, false);
  assert.equal((await context.collectEntries([dir('empty', [])])).length, 0);
  await assert.rejects(context.collectEntries([{name: 'broken', isFile: true, file: (_, fail) => fail()}]), /Could not read/);
  context.files = [];
  context.addFiles(Array.from({length: 26}, (_, i) => file(`${i}.pdf`)), true);
  assert.equal(context.files.length, 0, 'over limit batch is atomic');
  context.addFiles([file('big.pdf', 11 * 1024 * 1024)], true);
  assert.equal(context.files.length, 0);
  context.addFiles([file('a.pdf', 10 * 1024 * 1024), file('b.pdf', 10 * 1024 * 1024), file('c.pdf')], true);
  assert.equal(context.files.length, 0);
  context.addFiles([file('notes.txt')], true);
  assert.equal(context.files.length, 1);
  context.files = [];
  context.busy = true; context.addFiles([file('wait.pdf')], true);
  assert.equal(context.files.length, 0);
  context.busy = false;
  context.addFiles([{...file('photo.jpg'), webkitRelativePath: 'selected/photos/photo.jpg'}], true);
  assert.equal(context.attachmentName(context.files[0]), 'selected/photos/photo.jpg');
  console.log('Folder checks passed: nested paths, batches, empty/unreadable folders, arbitrary types and upload limits.');
})().catch(error => { console.error(error); process.exitCode = 1; });
