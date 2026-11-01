import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('dashboard renders every required tab and mock banner', () => {
  const source = fs.readFileSync(new URL('./main.jsx', import.meta.url), 'utf8');
  for (const tab of ['Overview', 'Violations', 'Exposure', 'Risk evolution', 'Latency', 'Operations', 'Live monitor']) {
    assert.match(source, new RegExp(tab.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.match(source, /MOCK DATA - NOT RESULTS/);
  assert.match(source, /\/dash\/live\/stream/);
});
