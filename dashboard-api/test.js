const assert = require('assert');
process.env.DASHBOARD_USE_MOCK = 'true';
const { server } = require('./server');

async function get(path) {
  const response = await fetch(`http://localhost:4000${path}`);
  return { status: response.status, data: await response.json() };
}

async function runTests() {
  console.log('--- Testing Dashboard API Routes ---');
  try {
    const health = await get('/health');
    assert.strictEqual(health.status, 200);
    assert.strictEqual(health.data.status, 'ok');

    const benchmark = await get('/dash/benchmark');
    assert.strictEqual(benchmark.status, 200);
    assert.ok(benchmark.data.meta);
    assert.ok(benchmark.data.modes);

    const stats = await get('/dash/stats');
    if (stats.status === 200) {
      assert.ok(stats.data.mode_statistics);
    } else {
      assert.strictEqual(stats.status, 404);
    }

    const risk = await get('/dash/live/risk');
    assert.strictEqual(risk.status, 200);
    assert.ok(Array.isArray(risk.data.users));

    const decisions = await get('/dash/live/decisions?limit=10');
    assert.strictEqual(decisions.status, 200);
    assert.ok(Array.isArray(decisions.data.items));

    const quarantines = await get('/dash/live/quarantines');
    assert.strictEqual(quarantines.status, 200);
    assert.ok(Array.isArray(quarantines.data.items));
    console.log('All Dashboard API route tests passed successfully!');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

runTests().catch((error) => {
  console.error('Test failed:', error);
  process.exitCode = 1;
});
