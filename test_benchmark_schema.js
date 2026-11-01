const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { validateBenchmark } = require('./benchmark_schema');

console.log('--- Testing Benchmark Data Contract with Zod ---');

// 1. Validate generated mock data
const mockPath = path.join(__dirname, 'results', 'mock_benchmark.json');
assert.ok(fs.existsSync(mockPath), 'results/mock_benchmark.json must exist');
const mockData = JSON.parse(fs.readFileSync(mockPath, 'utf8'));

const result = validateBenchmark(mockData);
assert.strictEqual(result.success, true, 'Mock data must pass Zod schema validation');
console.log('✓ results/mock_benchmark.json matches Zod schema');

// 2. Reject invalid data missing meta
const badData = { ...mockData, meta: undefined };
const badResult = validateBenchmark(badData);
assert.strictEqual(badResult.success, false, 'Missing meta must be rejected');
console.log('✓ Invalid benchmark without meta rejected');

// 3. Reject invalid risk event type
const badEventData = JSON.parse(JSON.stringify(mockData));
badEventData.risk_timeseries.adaptive.events.push({ t_rel_s: 10, type: 'UNKNOWN_TYPE' });
const badEventResult = validateBenchmark(badEventData);
assert.strictEqual(badEventResult.success, false, 'Invalid event type must be rejected');
console.log('✓ Invalid risk event type rejected');

console.log('All Benchmark Schema validation tests passed successfully!');

