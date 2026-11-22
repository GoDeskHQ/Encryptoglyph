const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const read = name => readFileSync(join(__dirname, name), 'utf8');

test('public page has both repositories, local assets, and a theme control', () => {
  const html = read('index.html');
  for (const url of ['https://github.com/GoDeskio/Encryptoglyph', 'https://gitgoat.io/Godeskadmin/Encryptoglyph']) {
    assert.ok(html.includes(`href="${url}"`));
  }
  assert.match(html, /id="theme-toggle"/);
  assert.match(html, /Light mode/);
  assert.match(html, /Apache-2\.0/);
  for (const [, asset] of html.matchAll(/(?:src|href)="([^"#:]+\.(?:css|js|svg))"/g)) assert.ok(read(asset));
  assert.doesNotMatch(html, /<form\b|<input\b|\/v1\//i);
  assert.match(read('styles.css'), /prefers-reduced-motion:reduce/);
});

function browser({ dark = false, stored = null, blocked = false } = {}) {
  const callbacks = {};
  const attributes = {};
  const toggle = { hidden: true, setAttribute: (k, v) => { attributes[k] = v; }, addEventListener: (k, f) => { callbacks[k] = f; } };
  const label = {};
  const document = { documentElement: { dataset: {} }, getElementById: id => id === 'theme-toggle' ? toggle : label, addEventListener: (k, f) => { callbacks[k] = f; } };
  const media = { matches: dark, addEventListener: (k, f) => { callbacks.system = f; } };
  const storage = { value: stored, getItem() { if (blocked) throw Error('blocked'); return this.value; }, setItem(k, v) { if (blocked) throw Error('blocked'); this.value = v; } };
  vm.runInNewContext(read('theme.js'), { document, window: { matchMedia: () => media }, localStorage: storage });
  callbacks.DOMContentLoaded();
  return { document, toggle, attributes, label, media, storage, callbacks };
}

test('system theme follows changes until a visitor persists a selection', () => {
  const b = browser({ dark: true });
  assert.equal(b.document.documentElement.dataset.theme, 'dark');
  assert.equal(b.toggle.hidden, false);
  b.media.matches = false;
  b.callbacks.system();
  assert.equal(b.document.documentElement.dataset.theme, 'light');
  b.callbacks.click();
  assert.equal(b.storage.value, 'dark');
  assert.equal(b.label.textContent, 'Light mode');
  b.callbacks.system();
  assert.equal(b.document.documentElement.dataset.theme, 'dark');
  assert.equal(browser({ stored: 'light', dark: true }).document.documentElement.dataset.theme, 'light');
});

test('unavailable or invalid storage does not break the toggle', () => {
  const b = browser({ blocked: true });
  b.callbacks.click();
  assert.equal(b.document.documentElement.dataset.theme, 'dark');
  assert.equal(browser({ stored: 'invalid', dark: true }).document.documentElement.dataset.theme, 'dark');
});
