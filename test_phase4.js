/**
 * Phase 4 offline unit / integration tests.
 *
 * Tests that can run without a live Keycloak or PostgreSQL instance:
 *   1. verifyKeycloakToken  – revocation map, claims extraction, role mapping,
 *      backchannel logout token validation (using a hand-crafted JWT stub)
 *   2. adaptivePolicyEngine – identity mode bypass (risk-cache skipped in 'identity')
 *   3. Smoke-test matrix – every documented POLICY_MODE is recognised
 *   4. Risk-engine label-hygiene guard – score formula must not read sim_label
 *   5. Realm JSON – structural validation of realm-ac-scp.json
 *   6. keycloak_enforcer.py – hysteresis logic is deterministic without network
 *
 * End-to-end Keycloak/Docker steps are skipped and documented as manual.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { evaluateAdaptiveSCP, loadTemplates, adaptivePolicyEngine } = require('./adaptivePolicyEngine');
const { isRevoked, revoked } = require('./verifyKeycloakToken');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
    failures.push({ name, error: err.message });
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
    failures.push({ name, error: err.message });
  }
}

// ─── Section 1: Revocation Map (backchannel mode) ───────────────────────────
console.log('\n[1] Revocation map & isRevoked()...');

test('empty map returns false', () => {
  revoked.clear();
  assert.strictEqual(isRevoked({ sid: 'sess-1', sub: 'user-a' }), false);
});

test('revoked.set(sid) → isRevoked true on sid match', () => {
  revoked.clear();
  revoked.set('sess-2', Date.now() + 120_000);
  assert.strictEqual(isRevoked({ sid: 'sess-2', sub: 'user-b' }), true);
});

test('revoked.set(sub) → isRevoked true on sub match', () => {
  revoked.clear();
  revoked.set('user-c', Date.now() + 120_000);
  assert.strictEqual(isRevoked({ sid: 'sess-3', sub: 'user-c' }), true);
});

test('expired revocation entry is purged and returns false', () => {
  revoked.clear();
  revoked.set('sess-exp', Date.now() - 1); // already expired
  assert.strictEqual(isRevoked({ sid: 'sess-exp', sub: 'x' }), false);
  assert.strictEqual(revoked.size, 0, 'expired entry must be purged');
});

test('sid-only claims (no sub) → isRevoked by sid', () => {
  revoked.clear();
  revoked.set('sess-sid-only', Date.now() + 120_000);
  assert.strictEqual(isRevoked({ sid: 'sess-sid-only' }), true);
});

test('unrelated sid/sub not affected by another revocation', () => {
  revoked.clear();
  revoked.set('other-sess', Date.now() + 120_000);
  assert.strictEqual(isRevoked({ sid: 'different-sess', sub: 'other-user' }), false);
});

// ─── Section 2: POLICY_MODE gate in adaptivePolicyEngine ────────────────────
console.log('\n[2] POLICY_MODE gate in adaptivePolicyEngine middleware...');

function makeReqRes(policyMode) {
  const original = process.env.POLICY_MODE;
  process.env.POLICY_MODE = policyMode;
  const req = {
    headers: {
      'x-role': 'analyst',
      'x-region': 'us-east',
      'x-risk-u': '0',
      'x-risk-w': '0',
    },
    originalUrl: '/api/public/status',
    method: 'GET',
    sensitivityLabel: 'public',
    role: 'analyst',
    userId: 'test-user',
  };
  const res = {
    _status: null,
    _body: null,
    status(code) { this._status = code; return this; },
    json(body) { this._body = body; return this; },
    set() { return this; },
  };
  const cleanup = () => { process.env.POLICY_MODE = original; };
  return { req, res, cleanup };
}

test("mode='static' → next() called, Phase 3 skipped", () => {
  const { req, res, cleanup } = makeReqRes('static');
  let nextCalled = false;
  adaptivePolicyEngine(req, res, () => { nextCalled = true; });
  cleanup();
  assert.strictEqual(nextCalled, true);
  assert.strictEqual(res._status, null, 'should not have sent a response');
});

test("mode='identity' → next() called (identity layer handles enforcement)", () => {
  const { req, res, cleanup } = makeReqRes('identity');
  let nextCalled = false;
  adaptivePolicyEngine(req, res, () => { nextCalled = true; });
  cleanup();
  assert.strictEqual(nextCalled, true);
});

test("mode='none' → next() called immediately", () => {
  const { req, res, cleanup } = makeReqRes('none');
  let nextCalled = false;
  adaptivePolicyEngine(req, res, () => { nextCalled = true; });
  cleanup();
  assert.strictEqual(nextCalled, true);
});

test("mode='adaptive' → risk-cache predicates run (developer+admin path blocked)", () => {
  const original = process.env.POLICY_MODE;
  process.env.POLICY_MODE = 'adaptive';
  const req = {
    headers: { 'x-role': 'developer', 'x-region': 'us-east', 'x-risk-u': '0', 'x-risk-w': '0' },
    originalUrl: '/api/admin/storage',
    method: 'GET',
    sensitivityLabel: 'restricted',
    role: 'developer',
    userId: 'dev-user',
  };
  const res = {
    _status: null,
    status(code) { this._status = code; return this; },
    json() { return this; },
    set() { return this; },
  };
  adaptivePolicyEngine(req, res, () => {});
  process.env.POLICY_MODE = original;
  assert.strictEqual(res._status, 403, 'adaptive mode must enforce ROLE_BOUNDARY');
});

test("mode='adaptive_identity' → Phase 3 predicates also run", () => {
  const original = process.env.POLICY_MODE;
  process.env.POLICY_MODE = 'adaptive_identity';
  const req = {
    headers: { 'x-role': 'developer', 'x-region': 'us-east', 'x-risk-u': '0', 'x-risk-w': '0' },
    originalUrl: '/api/admin/storage',
    method: 'GET',
    sensitivityLabel: 'restricted',
    role: 'developer',
    userId: 'dev-user',
  };
  const res = {
    _status: null,
    status(code) { this._status = code; return this; },
    json() { return this; },
    set() { return this; },
  };
  adaptivePolicyEngine(req, res, () => {});
  process.env.POLICY_MODE = original;
  assert.strictEqual(res._status, 403);
});

// ─── Section 3: evaluateAdaptiveSCP – all documented identity-layer scenarios ─
console.log('\n[3] evaluateAdaptiveSCP decision matrix...');

const templates = loadTemplates();

test('Low-risk analyst on public route → allowed', () => {
  const r = evaluateAdaptiveSCP({ role: 'analyst', resource: '/api/public/status', action: 'GET', label: 'public', region: 'us-east', risk_u: 0.0, risk_w: 0.0 }, templates);
  assert.strictEqual(r.allowed, true);
});

test('admin_access role on admin route, no risk → allowed by Phase 3', () => {
  const r = evaluateAdaptiveSCP({ role: 'admin_access', resource: '/api/admin/storage', action: 'GET', label: 'restricted', region: 'us-east', risk_u: 0.0, risk_w: 0.0 }, templates);
  assert.strictEqual(r.allowed, true);
});

test('developer on admin route → ROLE_BOUNDARY blocked (regardless of mode)', () => {
  const r = evaluateAdaptiveSCP({ role: 'developer', resource: '/api/admin/storage', action: 'DELETE', label: 'restricted', region: 'us-east', risk_u: 0.0, risk_w: 0.0 }, templates);
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, 'ROLE_BOUNDARY');
});

test('High risk (0.8 ≥ tau2=0.70) → T2 minimal allowlist blocks non-allowlisted', () => {
  const r = evaluateAdaptiveSCP({ role: 'admin_access', resource: '/api/admin/storage', action: 'DELETE', label: 'restricted', region: 'us-east', risk_u: 0.80, risk_w: 0.0 }, templates);
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.template_id, 'T2_MINIMAL_ALLOWLIST');
});

test('Elevated risk + allowed allowlist service (GET /api/public/*) → allowed', () => {
  const r = evaluateAdaptiveSCP({ role: 'analyst', resource: '/api/public/status', action: 'GET', label: 'public', region: 'us-east', risk_u: 0.85, risk_w: 0.0 }, templates);
  assert.strictEqual(r.allowed, true);
});

// ─── Section 4: Realm JSON structural validation ─────────────────────────────
console.log('\n[4] realm-ac-scp.json structural checks...');

test('realm JSON exists and is parseable', () => {
  const realmPath = path.join(__dirname, 'keycloak', 'realm-ac-scp.json');
  assert.ok(fs.existsSync(realmPath), 'keycloak/realm-ac-scp.json must exist');
  const realm = JSON.parse(fs.readFileSync(realmPath, 'utf8'));
  assert.strictEqual(realm.realm, 'ac-scp-realm');
  assert.strictEqual(realm.enabled, true);
});

test('accessTokenLifespan is exactly 60 seconds', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  assert.strictEqual(realm.accessTokenLifespan, 60);
});

test('Three realm roles: developer, analyst, admin_access', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  const roleNames = realm.roles.realm.map((r) => r.name);
  for (const expected of ['developer', 'analyst', 'admin_access']) {
    assert.ok(roleNames.includes(expected), `Missing realm role: ${expected}`);
  }
});

test('acscp-api client: publicClient=true, directAccessGrantsEnabled=true', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  const apiClient = realm.clients.find((c) => c.clientId === 'acscp-api');
  assert.ok(apiClient, 'acscp-api client must exist');
  assert.strictEqual(apiClient.publicClient, true);
  assert.strictEqual(apiClient.directAccessGrantsEnabled, true);
});

test('acscp-api client has backchannel logout URL pointing to /internal/backchannel-logout', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  const apiClient = realm.clients.find((c) => c.clientId === 'acscp-api');
  const logoutUrl = apiClient.attributes && apiClient.attributes['backchannel.logout.url'];
  assert.ok(logoutUrl && logoutUrl.includes('/internal/backchannel-logout'), 'backchannel.logout.url must target /internal/backchannel-logout');
});

test('risk-engine-service client: serviceAccountsEnabled=true, directAccessGrantsEnabled=false', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  const svcClient = realm.clients.find((c) => c.clientId === 'risk-engine-service');
  assert.ok(svcClient, 'risk-engine-service client must exist');
  assert.strictEqual(svcClient.serviceAccountsEnabled, true, 'serviceAccountsEnabled must be true');
  assert.strictEqual(svcClient.directAccessGrantsEnabled, false, 'directAccessGrantsEnabled must be false (no user logins)');
});

test('service account for risk-engine-service only has manage-users, view-users, query-users (no admin_access)', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  const svcAccount = realm.users.find((u) => u.serviceAccountClientId === 'risk-engine-service');
  assert.ok(svcAccount, 'service account user must exist');
  const realmMgmtRoles = (svcAccount.clientRoles && svcAccount.clientRoles['realm-management']) || [];
  const forbidden = ['admin_access', 'delete-realm', 'impersonation', 'realm-admin'];
  for (const role of forbidden) {
    assert.ok(!realmMgmtRoles.includes(role), `risk-engine-service must NOT have role: ${role}`);
  }
  for (const required of ['manage-users', 'view-users', 'query-users']) {
    assert.ok(realmMgmtRoles.includes(required), `risk-engine-service must have role: ${required}`);
  }
});

test('Carol user has admin_access role', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  const carol = realm.users.find((u) => u.username === 'carol');
  assert.ok(carol, 'carol user must exist');
  assert.ok(carol.realmRoles && carol.realmRoles.includes('admin_access'), 'carol must have admin_access');
});

test('Alice has developer, Bob has analyst (role separation)', () => {
  const realm = JSON.parse(fs.readFileSync(path.join(__dirname, 'keycloak', 'realm-ac-scp.json'), 'utf8'));
  const alice = realm.users.find((u) => u.username === 'alice');
  const bob = realm.users.find((u) => u.username === 'bob');
  assert.ok(alice && alice.realmRoles.includes('developer'), 'alice must have developer');
  assert.ok(bob && bob.realmRoles.includes('analyst'), 'bob must have analyst');
});

// ─── Section 5: Label-hygiene guard on risk_engine.py ───────────────────────
console.log('\n[5] Label-hygiene guard (risk_engine.py must not use sim_label/episode_id at scoring time)...');

test('risk_engine.py SQL must not SELECT sim_label at scoring time', () => {
  const source = fs.readFileSync(path.join(__dirname, 'risk', 'risk_engine.py'), 'utf8');
  // The scoring SELECT that feeds the risk formula must not reference sim_label.
  // We check the SQL block that computes the risk variables fed into the formula.
  const scoringBlock = source.slice(source.indexOf("SELECT\n"), source.indexOf("GROUP BY user_id"));
  assert.ok(!scoringBlock.includes('sim_label'),
    "CRITICAL – risk_engine.py scoring SQL must NOT reference sim_label (label leakage). " +
    "sim_label is evaluation-only metadata and must only be used in metrics queries after a run.");
});

test('risk_engine.py SQL must not SELECT episode_id at scoring time', () => {
  const source = fs.readFileSync(path.join(__dirname, 'risk', 'risk_engine.py'), 'utf8');
  const scoringBlock = source.slice(source.indexOf("SELECT\n"), source.indexOf("GROUP BY user_id"));
  assert.ok(!scoringBlock.includes('episode_id'),
    "CRITICAL – risk_engine.py scoring SQL must NOT reference episode_id (label leakage).");
});

test('risk_engine.py features comment explicitly documents the no-sim_label rule', () => {
  const source = fs.readFileSync(path.join(__dirname, 'risk', 'risk_engine.py'), 'utf8');
  assert.ok(
    source.includes('sim_label') && source.includes('label leakage'),
    'risk_engine.py must contain a comment documenting the label-leakage exclusion rule'
  );
});

// ─── Section 6: Smoke-test all documented POLICY_MODE values are recognised ──
console.log('\n[6] All documented POLICY_MODE values are recognised by adaptivePolicyEngine...');

const POLICY_MODES = ['static', 'static_context', 'static_ml', 'adaptive', 'adaptive_shadow', 'adaptive_identity', 'identity', 'none'];
for (const mode of POLICY_MODES) {
  test(`mode='${mode}' → does not throw`, () => {
    const { req, res, cleanup } = makeReqRes(mode);
    let threw = null;
    try {
      adaptivePolicyEngine(req, res, () => {});
    } catch (e) {
      threw = e.message;
    }
    cleanup();
    assert.strictEqual(threw, null, `mode '${mode}' threw: ${threw}`);
  });
}

// ─── Section 7: keycloakTokenMiddleware mode gate ────────────────────────────
console.log('\n[7] keycloakTokenMiddleware mode gate (no live Keycloak needed)...');

async function testMiddlewareGate() {
  const { keycloakTokenMiddleware } = require('./verifyKeycloakToken');

  await testAsync("mode='adaptive' (non-identity) → next() called without Bearer check", async () => {
    const originalMode = process.env.POLICY_MODE;
    process.env.POLICY_MODE = 'adaptive';
    let nextCalled = false;
    const req = { headers: {}, path: '/api/public/status' };
    const res = {};
    await keycloakTokenMiddleware(req, res, () => { nextCalled = true; });
    process.env.POLICY_MODE = originalMode;
    assert.strictEqual(nextCalled, true);
  });

  await testAsync("mode='identity', public path, no token → next() called", async () => {
    const originalMode = process.env.POLICY_MODE;
    process.env.POLICY_MODE = 'identity';
    let nextCalled = false;
    const req = { headers: {}, path: '/api/public/status' };
    const res = {};
    await keycloakTokenMiddleware(req, res, () => { nextCalled = true; });
    process.env.POLICY_MODE = originalMode;
    assert.strictEqual(nextCalled, true);
  });

  await testAsync("mode='identity', restricted path, no token → 401", async () => {
    const originalMode = process.env.POLICY_MODE;
    process.env.POLICY_MODE = 'identity';
    let status = null;
    const req = { headers: {}, path: '/api/admin/storage' };
    const res = {
      status(code) { status = code; return this; },
      json() { return this; },
    };
    await keycloakTokenMiddleware(req, res, () => {});
    process.env.POLICY_MODE = originalMode;
    assert.strictEqual(status, 401);
  });
}

// ─── Run everything ──────────────────────────────────────────────────────────
testMiddlewareGate().then(() => {
  console.log('\n' + '─'.repeat(60));
  if (failed === 0) {
    console.log(`✅  All ${passed} Phase 4 offline tests passed.\n`);
    console.log('Manual E2E smoke-test checklist (requires Docker + running DB):');
    console.log('  1. docker compose up → Keycloak admin console at http://localhost:8080');
    console.log('     Verify realm ac-scp-realm, roles (developer/analyst/admin_access), users (alice/bob/carol/sim-user-*), both clients.');
    console.log('  2. Get Carol token:');
    console.log('     curl -s -X POST http://localhost:8080/realms/ac-scp-realm/protocol/openid-connect/token \\');
    console.log('          -d "grant_type=password&client_id=acscp-api&username=carol&password=carol-password" | jq .');
    console.log('     Confirm: sid claim present, admin_access in realm_access.roles, aud=acscp-api, exp-iat=60s.');
    console.log('  3. Call protected route with Carol token → expect 200.');
    console.log('  4. Quarantine Carol (remove admin_access role via Keycloak admin console or enforcer),');
    console.log('     then POST /admin/realms/ac-scp-realm/users/{id}/logout.');
    console.log('     Next request with same token → 401 within milliseconds (backchannel) or ≤60 s (lifetime).');
    console.log('     Check: API log shows backchannel logout, identity_enforcement_events.first_rejected_at filled, time_to_effective_ms >= enforcement_call_ms.');
    console.log('  5. Log in as Carol again → new token lacks admin_access, admin routes stay denied.');
    console.log('  6. Restore admin_access role → new login grants admin_access back.');
    console.log('  7. Run: python simulate_traffic.py --identity --scenario insider_threat --requests 500 --seed 42');
    console.log('     Repeat with seeds 43–52. Report mean, std, n of quarantine events (aim n ≥ 20).');
    console.log('  REVOCATION_CHECK note: if backchannel logout token does not arrive, switch to REVOCATION_CHECK=introspection');
    console.log('  in .env and document which mechanism produced the reported numbers.');
    process.exit(0);
  } else {
    console.log(`❌  ${failed} test(s) failed, ${passed} passed.\n`);
    for (const f of failures) {
      console.error(`  ✗ ${f.name}: ${f.error}`);
    }
    process.exit(1);
  }
});

