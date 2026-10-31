const { createRemoteJWKSet, jwtVerify } = require('jose');
const { pool } = require('./db');

const issuer = process.env.KEYCLOAK_ISSUER
  || `${process.env.KEYCLOAK_URL || 'http://localhost:8080'}/realms/${process.env.KEYCLOAK_REALM || 'ac-scp-realm'}`;
const jwks = createRemoteJWKSet(new URL(`${issuer}/protocol/openid-connect/certs`));
const revoked = new Map();
const allowedAlgorithms = ['RS256'];
const tokenLifespanMs = Number(process.env.KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SEC || 60) * 1000;

function purgeRevoked() {
  const now = Date.now();
  for (const [key, expiresAt] of revoked) {
    if (expiresAt <= now) revoked.delete(key);
  }
}

function rememberRevocation(claims) {
  const expiresAt = Date.now() + tokenLifespanMs;
  for (const key of [claims.sid, claims.sub].filter(Boolean)) revoked.set(key, expiresAt);
}

function isRevoked(claims) {
  purgeRevoked();
  return Boolean((claims.sid && revoked.has(claims.sid)) || (claims.sub && revoked.has(claims.sub)));
}

async function verifyClaims(token, options = {}) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    algorithms: allowedAlgorithms,
    ...(options.audience ? { audience: options.audience } : {}),
  });
  if (payload.azp && payload.azp !== (process.env.KEYCLOAK_API_CLIENT_ID || 'acscp-api')) {
    throw new Error('unexpected authorized party');
  }
  return payload;
}

function rolesFromClaims(claims) {
  return Array.isArray(claims.realm_access && claims.realm_access.roles)
    ? claims.realm_access.roles : [];
}

async function recordFirstRejected(claims) {
  await pool.query(
    `UPDATE identity_enforcement_events
     SET first_rejected_at = COALESCE(first_rejected_at, NOW()),
         time_to_effective_ms = COALESCE(time_to_effective_ms,
           EXTRACT(EPOCH FROM (NOW() - scored_at)) * 1000)
     WHERE id = (
       SELECT id FROM identity_enforcement_events
       WHERE user_id = $1 AND action = 'QUARANTINE'
       ORDER BY enforced_at DESC LIMIT 1
     )`,
    [claims.sub],
  );
}

async function introspect(token) {
  const endpoint = process.env.KEYCLOAK_INTROSPECTION_URL
    || `${issuer}/protocol/openid-connect/token/introspect`;
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      token,
      client_id: process.env.KEYCLOAK_API_CLIENT_ID || 'acscp-api',
      client_secret: process.env.KEYCLOAK_API_CLIENT_SECRET || '',
    }),
  });
  if (!response.ok) throw new Error(`Keycloak introspection failed: ${response.status}`);
  const body = await response.json();
  if (!body.active) throw new Error('inactive token');
  return body;
}

async function keycloakTokenMiddleware(req, res, next) {
  const mode = process.env.POLICY_MODE || 'adaptive';
  if (!['identity', 'adaptive_identity'].includes(mode)) return next();
  const authorization = req.headers.authorization;
  if (!authorization || !authorization.startsWith('Bearer ')) {
    if (req.path.startsWith('/api/public')) return next();
    return res.status(401).json({ error: 'Bearer token required' });
  }
  const token = authorization.slice(7);
  try {
    const started = process.hrtime.bigint();
    const check = process.env.REVOCATION_CHECK || 'backchannel';
    const verifiedClaims = await verifyClaims(token, {
      audience: process.env.KEYCLOAK_API_CLIENT_ID || 'acscp-api',
    });
    const claims = check === 'introspection'
      ? { ...await introspect(token), ...verifiedClaims }
      : verifiedClaims;
    if (check !== 'introspection' && isRevoked(claims)) {
      await recordFirstRejected(claims);
      return res.status(401).json({ error: 'token revoked' });
    }
    req.userId = claims.sub;
    req.identityValidationMs = Number(process.hrtime.bigint() - started) / 1e6;
    req.role = rolesFromClaims(claims)[0] || 'analyst';
    req.keycloakClaims = claims;
    if (req.path.startsWith('/api/admin') && !rolesFromClaims(claims).includes('admin_access')) {
      return res.status(403).json({ error: 'admin_access role required' });
    }
    return next();
  } catch (error) {
    return res.status(401).json({ error: 'invalid identity token', detail: error.message });
  }
}

async function backchannelLogout(req, res) {
  const logoutToken = req.body && req.body.logout_token;
  if (!logoutToken) return res.status(400).json({ error: 'logout_token is required' });
  try {
    const claims = await verifyClaims(logoutToken);
    const events = claims.events;
    if (!events || !Object.prototype.hasOwnProperty.call(events, 'http://schemas.openid.net/event/backchannel-logout')) {
      return res.status(400).json({ error: 'invalid backchannel logout events claim' });
    }
    rememberRevocation(claims);
    return res.status(204).end();
  } catch (error) {
    return res.status(400).json({ error: 'invalid logout token', detail: error.message });
  }
}

module.exports = {
  backchannelLogout,
  keycloakTokenMiddleware,
  verifyClaims,
  isRevoked,
  revoked,
};
