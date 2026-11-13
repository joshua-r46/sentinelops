import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const dashboardPath = fileURLToPath(new URL('../agentshield-dashboard2(1).html', import.meta.url));
const html = readFileSync(dashboardPath, 'utf8');
const style = html.match(/<style>([\s\S]*?)<\/style>/i)?.[1] ?? '';

test('all existing dashboard sections have navigation and page containers', () => {
  const sections = [
    'overview', 'services', 'incidents', 'evidence', 'diagnosis', 'plans',
    'approvals', 'executions', 'verification', 'recovery', 'policies', 'simulation',
  ];
  for (const section of sections) {
    assert.match(html, new RegExp('data-page="' + section + '"'));
    assert.match(html, new RegExp('id="' + section + '" data-title='));
  }
});

test('live data stays on the existing same-origin dashboard API', () => {
  assert.match(html, /content="\/dashboard\/overview"/);
  assert.match(html, /credentials:\s*"same-origin"/);
  assert.match(html, /cache:\s*"no-store"/);
  assert.match(html, /No sample data is used/);
  assert.match(html, /No simulation feed is exposed by the live overview API/);
});

test('loading, empty, unavailable and error states are explicit', () => {
  for (const state of ['loading', 'empty', 'unavailable', 'error']) {
    assert.match(html, new RegExp(state));
  }
  assert.match(html, /function stateBlock\(kind, title, detail\)/);
  assert.match(html, /Live values are cleared until a successful refresh/);
});

test('all stylesheet colors use only the approved palette and its opacity variants', () => {
  const hexColors = [...style.matchAll(/#[0-9a-fA-F]{3,8}\b/g)].map(match => match[0].toLowerCase());
  assert.ok(hexColors.length > 0, 'expected approved color tokens');
  assert.ok(hexColors.every(color => ['#1f3d28', '#e8dcc4'].includes(color)),
    'found a prohibited hex color: ' + hexColors.filter(color => !['#1f3d28', '#e8dcc4'].includes(color)).join(', '));

  const rgbColors = [...style.matchAll(/rgba?\(([^)]+)\)/g)].map(match =>
    match[1].split(',').slice(0, 3).map(value => Number(value.trim())).join(','));
  assert.ok(rgbColors.every(color => ['31,61,40', '232,220,196'].includes(color)),
    'found a prohibited rgb color: ' + rgbColors.filter(color => !['31,61,40', '232,220,196'].includes(color)).join(', '));
});

test('layout has desktop and mobile breakpoints and respects reduced motion', () => {
  assert.match(style, /@media\s*\(max-width:\s*1120px\)/);
  assert.match(style, /@media\s*\(max-width:\s*720px\)/);
  assert.match(style, /@media\s*\(max-width:\s*430px\)/);
  assert.match(style, /prefers-reduced-motion/);
});
