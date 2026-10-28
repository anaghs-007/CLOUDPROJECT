const assert = require('assert');
const {
  evaluateAdaptiveSCP,
  loadTemplates,
  loadThetaBest,
  validateTemplateSet,
} = require('./adaptivePolicyEngine');
const { firstViolation } = require('./staticPolicyEngine');

console.log('=== AC-SCP Phase 3 Verification Suite ===\n');

// 0. Browser defaults must allow the documented low-risk public request.
console.log('[0] Testing documented Scenario A defaults...');
const scenarioARequest = {
  ip: '127.0.0.1',
  path: '/api/public/status',
  originalUrl: '/api/public/status',
  headers: { 'x-region': 'us-east', 'x-risk-u': '0.10', 'x-risk-w': '0.10' },
};
assert.strictEqual(firstViolation(scenarioARequest, 'analyst', 'adaptive'), null);
const scenarioA = evaluateAdaptiveSCP({
  role: 'analyst',
  resource: '/api/public/status',
  action: 'GET',
  label: 'public',
  region: 'us-east',
  risk_u: 0.10,
  risk_w: 0.10,
}, loadTemplates());
assert.strictEqual(scenarioA.allowed, true);
console.log('✓ Scenario A low-risk public request is allowed.\n');

// 1. Template validation & theta parameters
console.log('[1] Validating Policy Templates & Theta Parameters...');
const templates = loadTemplates();
assert.strictEqual(templates.length, 3, 'Should have 3 policy templates (T1, T2, T3)');
assert.strictEqual(validateTemplateSet(templates), true, 'Template set must pass structural and threshold validation');
const theta = loadThetaBest();
console.log('    Loaded theta_best.json:', theta);
assert(theta.tau1 < theta.tau2, 'Threshold constraint tau1 < tau2 must hold');
console.log('✓ Template set and theta parameters validated successfully.\n');

// 2. T1: Region Lock Evaluation
console.log('[2] Testing T1_REGION_LOCK...');
// Risk below tau1 -> allowed even in other region
const r1 = evaluateAdaptiveSCP({
  role: 'admin',
  resource: '/api/admin/storage',
  action: 'GET',
  label: 'restricted',
  region: 'eu-central',
  risk_u: 0.1,
  risk_w: 0.1,
}, templates);
assert.strictEqual(r1.allowed, true, 'Low risk request should be allowed');

// Risk above tau1 in disallowed region eu-central -> blocked by T1
const r2 = evaluateAdaptiveSCP({
  role: 'admin',
  resource: '/api/admin/storage',
  action: 'GET',
  label: 'restricted',
  region: 'eu-central',
  risk_u: 0.6,
  risk_w: 0.1,
}, templates);
assert.strictEqual(r2.allowed, false);
assert.strictEqual(r2.template_id, 'T1_REGION_LOCK');
assert.strictEqual(r2.reason, 'region-lock');

// Risk above tau1 in allowed region us-east -> allowed
const r3 = evaluateAdaptiveSCP({
  role: 'admin',
  resource: '/api/admin/storage',
  action: 'GET',
  label: 'restricted',
  region: 'us-east',
  risk_u: 0.6,
  risk_w: 0.1,
}, templates);
assert.strictEqual(r3.allowed, true);
console.log('✓ T1_REGION_LOCK correctly enforces geographic confinement on elevated risk.\n');

// 3. T2: Minimal Allowlist Evaluation
console.log('[3] Testing T2_MINIMAL_ALLOWLIST...');
// Elevated risk >= tau2 (e.g. 0.85) accessing allowlisted public service -> allowed
const r4 = evaluateAdaptiveSCP({
  role: 'admin',
  resource: '/api/public/status',
  action: 'GET',
  label: 'public',
  region: 'us-east',
  risk_u: 0.85,
  risk_w: 0.1,
}, templates);
assert.strictEqual(r4.allowed, true, 'Allowlisted service GET /api/public/* should pass');

// Elevated risk >= tau2 accessing non-allowlisted service -> blocked by T2
const r5 = evaluateAdaptiveSCP({
  role: 'admin',
  resource: '/api/admin/storage',
  action: 'DELETE',
  label: 'restricted',
  region: 'us-east',
  risk_u: 0.85,
  risk_w: 0.1,
}, templates);
assert.strictEqual(r5.allowed, false);
assert.strictEqual(r5.template_id, 'T2_MINIMAL_ALLOWLIST');
assert.strictEqual(r5.reason, 'allowlist');
console.log('✓ T2_MINIMAL_ALLOWLIST restricts high-risk principals to minimal allowable services.\n');

// 4. T3: Workload Restrict Evaluation
console.log('[4] Testing T3_WORKLOAD_RESTRICT...');
// Elevated workload risk >= tau_w attempting write/delete -> blocked by T3
const r6 = evaluateAdaptiveSCP({
  role: 'admin',
  resource: '/api/workload/compute',
  action: 'POST',
  label: 'internal',
  region: 'us-east',
  risk_u: 0.1,
  risk_w: 0.65,
}, templates);
assert.strictEqual(r6.allowed, false);
assert.strictEqual(r6.template_id, 'T3_WORKLOAD_RESTRICT');
assert.strictEqual(r6.reason, 'workload-restrict');

// Misconfigured workload attempting admin operation -> blocked by T3
const r7 = evaluateAdaptiveSCP({
  role: 'admin',
  resource: '/api/admin/storage',
  action: 'GET',
  label: 'restricted',
  region: 'us-east',
  risk_u: 0.1,
  risk_w: 0.1,
  misconfigured: true,
}, templates);
assert.strictEqual(r7.allowed, false);
assert.strictEqual(r7.template_id, 'T3_WORKLOAD_RESTRICT');
console.log('✓ T3_WORKLOAD_RESTRICT protects compromised or misconfigured workloads.\n');

// 5. Hard Role Boundary
console.log('[5] Testing Hard Role Boundary...');
const r8 = evaluateAdaptiveSCP({
  role: 'developer',
  resource: '/api/admin/storage',
  action: 'GET',
  label: 'restricted',
  region: 'us-east',
  risk_u: 0.0,
  risk_w: 0.0,
}, templates);
assert.strictEqual(r8.allowed, false);
assert.strictEqual(r8.reason, 'ROLE_BOUNDARY');
console.log('✓ Developer role strictly blocked from administrative resources.\n');

console.log('=== All Phase 3 Core Adaptive Policies Verified & Working Correctly! ===');
process.exit(0);
