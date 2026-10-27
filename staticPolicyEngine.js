const ipaddr = require('ipaddr.js');
const { insertBaselineViolation } = require('./db');

const STATIC_SCP_CONFIG = Object.freeze({
  ALLOWED_CIDRS: ['10.0.0.0/8', '192.168.0.0/16'],
  RESTRICTED_HOURS: { start: 22, end: 6 },
  ROLE_BOUNDARIES: { developer: ['/api/admin'] },
});

function normalizeIp(value) {
  if (!value) return null;
  const candidate = String(value).split(',')[0].trim();
  try {
    const address = ipaddr.parse(candidate);
    return address.kind() === 'ipv6' && address.isIPv4MappedAddress()
      ? address.toIPv4Address()
      : address;
  } catch (_) {
    return null;
  }
}

function isAllowedIp(value) {
  const address = normalizeIp(value);
  if (!address) return false;
  return STATIC_SCP_CONFIG.ALLOWED_CIDRS.some((cidr) => {
    const [range, bits] = cidr.split('/');
    try {
      return address.match([ipaddr.parse(range), Number(bits)]);
    } catch (_) {
      return false;
    }
  });
}

function extractRole(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    try {
      const payload = auth.slice(7).split('.')[1];
      const json = JSON.parse(Buffer.from(payload, 'base64url').toString());
      const role = json.role || (Array.isArray(json.roles) ? json.roles[0] : null);
      if (role) return role;
    } catch (_) {
      // Header fallback is intentional for the Phase 1 unverified-JWT simulator.
    }
  }
  return req.headers['x-role'] || 'analyst';
}

function simulatedHour(req) {
  const source = process.env.SIM_MODE === 'true'
    ? req.headers['x-simulated-time']
    : null;
  const date = source ? new Date(source) : new Date();
  if (Number.isNaN(date.getTime())) return new Date().getHours();
  return source ? date.getUTCHours() : date.getHours();
}

function firstViolation(req, role) {
  const path = req.path || req.originalUrl.split('?')[0];
  const adminPath = path.startsWith('/api/admin/');
  if (adminPath && role === 'developer') return 'ROLE_BOUNDARY';
  if (adminPath) {
    const hour = simulatedHour(req);
    if (hour >= STATIC_SCP_CONFIG.RESTRICTED_HOURS.start || hour < STATIC_SCP_CONFIG.RESTRICTED_HOURS.end) {
      return 'RESTRICTED_HOURS';
    }
  }
  if (!isAllowedIp(req.ip)) return 'IP_RANGE';
  return null;
}

function enforceStaticSCP(req, res, next) {
  const started = process.hrtime.bigint();
  const mode = process.env.POLICY_MODE || 'static';
  const role = extractRole(req);
  req.role = role;
  const rule = mode === 'static' ? firstViolation(req, role) : null;
  const latency = Number(process.hrtime.bigint() - started) / 1e6;
  req.policyDecision = rule ? 'BLOCKED' : 'ALLOWED';
  req.decisionLatencyMs = latency;

  if (req.telemetryEntry) {
    req.telemetryEntry.role = role;
    req.telemetryEntry.decision = req.policyDecision;
    req.telemetryEntry.decision_latency_ms = latency;
  }
  if (req.telemetryIdPromise) {
    req.telemetryIdPromise.then((id) => id && req.updateTelemetryDecision(
      id, req.policyDecision, latency, role))
      .catch((err) => console.error('[policy] telemetry decision update failed:', err.message));
  }

  if (rule) {
    const violation = {
      user_id: req.userId || 'anonymous',
      resource: req.originalUrl,
      ip_address: req.ip,
      rule_violated: rule,
      session_id: req.headers['x-session-id'] || null,
    };
    insertBaselineViolation(violation).catch((err) =>
      console.error('[policy] violation insert failed:', err.message));
    return res.status(403).json({ error: 'static policy violation', rule });
  }
  return next();
}

module.exports = {
  STATIC_SCP_CONFIG,
  enforceStaticSCP,
  extractRole,
  firstViolation,
  isAllowedIp,
};
