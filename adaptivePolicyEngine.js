const fs = require('fs');
const path = require('path');
const { insertShadowDecision } = require('./db');

const DEFAULTS = Object.freeze({
  tau1: 0.5,
  tau2: 0.8,
  tau_w: 0.6,
  delta: 0.1,
  N: 3,
  alpha: 1,
  beta: 0.5,
  gamma: 0.2,
});

function loadTemplates() {
  const file = path.join(__dirname, 'policyTemplates.json');
  const text = fs.readFileSync(file, 'utf8');
  const json = JSON.parse(text);
  return json.templates || [];
}

function loadThetaBest() {
  const file = path.join(__dirname, 'theta_best.json');
  if (!fs.existsSync(file)) return { ...DEFAULTS };
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { ...DEFAULTS, ...raw };
  } catch (_) {
    return { ...DEFAULTS };
  }
}

function validateTemplateSet(templates = loadTemplates()) {
  const ids = new Set();
  for (const template of templates) {
    if (!template || !template.id) throw new Error('Template missing id');
    if (ids.has(template.id)) throw new Error(`Duplicate template id: ${template.id}`);
    ids.add(template.id);
    if (template.id === 'T1_REGION_LOCK') {
      const allowed = template.theta && template.theta.allowed_regions;
      if (!allowed || !allowed.regulated || !allowed.regulated.length) {
        throw new Error('T1_REGION_LOCK has no regulated allowlist');
      }
    }
    if (template.id === 'T2_MINIMAL_ALLOWLIST') {
      const services = template.theta && template.theta.allowlisted_services;
      if (!Array.isArray(services) || services.length === 0) {
        throw new Error('T2_MINIMAL_ALLOWLIST has an empty allowlist');
      }
    }
    if (template.id === 'T3_WORKLOAD_RESTRICT') {
      if (!template.theta || !template.theta.write_delete_paths) {
        throw new Error('T3_WORKLOAD_RESTRICT missing write/delete paths');
      }
    }
  }
  if (templates.some((t) => t.id === 'T1_REGION_LOCK') && templates.some((t) => t.id === 'T2_MINIMAL_ALLOWLIST')) {
    const t1 = templates.find((t) => t.id === 'T1_REGION_LOCK');
    const t2 = templates.find((t) => t.id === 'T2_MINIMAL_ALLOWLIST');
    if ((t1.theta && t1.theta.tau1) >= (t2.theta && t2.theta.tau2)) {
      throw new Error('Conflicting template thresholds: tau1 >= tau2');
    }
  }
  return true;
}

function getRiskSnapshot() {
  return { user: {}, workload: {} };
}

function evaluateAdaptiveSCP(ctx, templates = loadTemplates()) {
  validateTemplateSet(templates);
  const state = { allowed: true, template_id: 'STATIC', reason: 'none' };
  const theta = loadThetaBest();
  const risk = Number(ctx.risk_u || 0);
  const workloadRisk = Number(ctx.risk_w || 0);
  const t1 = templates.find((template) => template.id === 'T1_REGION_LOCK');
  const t2 = templates.find((template) => template.id === 'T2_MINIMAL_ALLOWLIST');
  const t3 = templates.find((template) => template.id === 'T3_WORKLOAD_RESTRICT');

  // Hard organizational boundary: developer cannot access admin
  if (ctx.role === 'developer' && ctx.resource.startsWith('/api/admin')) {
    return { allowed: false, template_id: 'STATIC', reason: 'ROLE_BOUNDARY' };
  }

  // T1: Region Lock for regulated/restricted data when risk >= tau1
  const isRegulated = ctx.label === 'regulated' || ctx.label === 'restricted';
  const allowedRegions = (t1 && t1.theta && t1.theta.allowed_regions &&
    (t1.theta.allowed_regions[ctx.label] || t1.theta.allowed_regions['regulated'])) || [];
  if (t1 && isRegulated && risk >= (theta.tau1 ?? t1.theta.tau1 ?? DEFAULTS.tau1) && !allowedRegions.includes(ctx.region)) {
    return { allowed: false, template_id: t1.id, reason: 'region-lock' };
  }

  // T2: Minimal Allowlist when user risk >= tau2
  if (t2 && risk >= (theta.tau2 ?? t2.theta.tau2 ?? DEFAULTS.tau2)) {
    const allowlisted = (t2.theta.allowlisted_services || []).some((svc) => {
      const parts = svc.trim().split(/\s+/);
      let expectedMethod = null;
      let pattern = svc;
      if (parts.length === 2) {
        expectedMethod = parts[0].toUpperCase();
        pattern = parts[1];
      }
      if (expectedMethod && expectedMethod !== ctx.action.toUpperCase()) {
        return false;
      }
      if (pattern.endsWith('*')) {
        return ctx.resource.startsWith(pattern.slice(0, -1));
      }
      return ctx.resource === pattern;
    });
    if (!allowlisted) {
      return { allowed: false, template_id: t2.id, reason: 'allowlist' };
    }
  }

  // T3: Workload Restrict when workload risk >= tau_w or misconfigured
  if (t3 && (workloadRisk >= (theta.tau_w ?? t3.theta.tau_w ?? DEFAULTS.tau_w) || ctx.misconfigured)) {
    if (ctx.action === 'DELETE' || ctx.action === 'POST' || ctx.resource.includes('/api/admin')) {
      return { allowed: false, template_id: t3.id, reason: 'workload-restrict' };
    }
  }

  return state;
}

function adaptivePolicyEngine(req, res, next) {
  const mode = process.env.POLICY_MODE || 'adaptive';

  // In pure 'identity' mode, Keycloak is the sole enforcement mechanism.
  // The Phase 3 risk-cache predicates must NOT run so results are attributable
  // exclusively to the identity layer. Only 'adaptive_identity' combines both.
  if (!['adaptive', 'adaptive_identity', 'adaptive_shadow', 'static_context', 'static_ml'].includes(mode)) return next();

  if (process.env.PILOT_TENANT && req.headers['x-tenant-id'] && req.headers['x-tenant-id'] !== process.env.PILOT_TENANT) {
    return next();
  }

  const ctx = {
    role: req.role || req.headers['x-role'] || 'analyst',
    resource: req.originalUrl,
    action: req.method,
    label: req.sensitivityLabel || 'internal',
    region: req.headers['x-region'] || 'us-east',
    risk_u: Number(req.headers['x-risk-u'] || req.risk_u || 0),
    risk_w: Number(req.headers['x-risk-w'] || req.risk_w || 0),
    misconfigured: !!(req.headers['x-misconfigured'] === 'true' || req.workloadMisconfigured),
  };
  const decision = evaluateAdaptiveSCP(ctx);

  if (mode === 'adaptive_shadow') {
    insertShadowDecision({
      session_id: req.headers['x-session-id'] || 'shadow',
      user_id: req.userId || 'anonymous',
      resource: req.originalUrl,
      action: req.method,
      rule: decision.reason,
      template_id: decision.template_id,
      would_block: !decision.allowed,
    }).catch((err) => console.error('[shadow] insert failed:', err.message));
    return next();
  }

  if (!decision.allowed) {
    if (req.telemetryEntry) {
      req.telemetryEntry.decision = 'BLOCKED';
      req.telemetryEntry.enforced_template = decision.template_id;
      req.telemetryEntry.decision_reason = decision.reason;
    }
    if (req.telemetryIdPromise && req.updateTelemetryDecision) {
      req.telemetryIdPromise.then((id) => {
        if (id) {
          req.updateTelemetryDecision(id, 'BLOCKED', 0, ctx.role, {
            enforced_template: decision.template_id,
            decision_reason: decision.reason,
            risk_u_at_decision: ctx.risk_u,
            risk_w_at_decision: ctx.risk_w,
          }).catch(() => {});
        }
      }).catch(() => {});
    }
    if (mode === 'adaptive' || mode === 'adaptive_identity') {
      return res.set('X-ACSCP-Enforced', 'true').status(403).json({
        error: 'adaptive policy violation',
        rule: decision.reason,
        template: decision.template_id,
      });
    }
    return next();
  }

  return next();
}

module.exports = {
  adaptivePolicyEngine,
  evaluateAdaptiveSCP,
  loadTemplates,
  getRiskSnapshot,
  loadThetaBest,
  validateTemplateSet,
};
