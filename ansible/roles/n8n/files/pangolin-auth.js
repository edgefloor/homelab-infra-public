'use strict';

// Pangolin authenticates the identity. Caddy maps its stable subject to an
// existing n8n ID, only for requests received from Newt. Never link by email,
// create users, change roles, or manufacture n8n JWTs in this hook.
function createMiddleware({ authService, userRepository, cookieName, config, logger }) {
  const allowedUsers = new Set(config.allowedUserIds);
  const trustedSources = new Set(config.trustedSources);
  const excluded = /^\/(?:healthz(?:\/|$)|assets\/|static\/|icons\/|types\/|api\/|webhook(?:-test|-waiting)?(?:\/|$)|rest\/oauth[12]-credential\/callback(?:\/|$))/;
  return async function pangolinSession(req, res, next) {
    if (req.path.match(excluded)) return next();
    const userId = req.headers[config.header];
    if (userId === undefined) return next(); // LAN recovery uses native auth.
    const peer = req.socket.remoteAddress?.replace(/^::ffff:/, '');
    if (!trustedSources.has(peer) || typeof userId !== 'string' || !allowedUsers.has(userId)) {
      return res.status(403).json({ message: 'Pangolin identity is not bound to an n8n account.' });
    }
    try {
      const user = await userRepository.findOne({ where: { id: userId }, relations: ['role'] });
      if (!user || user.disabled || !user.role?.slug || !user.password) {
        return res.status(403).json({ message: 'The bound n8n account is unavailable.' });
      }
      let hasSession = false;
      const token = req.cookies?.[cookieName];
      if (token) {
        try {
          const sessionUser = await authService.validateCookieToken(token);
          hasSession = sessionUser.id === user.id;
        } catch { /* Expired or revoked cookies are replaced on safe requests. */ }
      }
      if (!hasSession) {
        if (token) {
          delete req.cookies[cookieName];
          authService.clearCookie(res);
        }
        // Keep n8n's own MFA challenge when enabled. A local password/MFA login
        // can establish the session, which is checked against this binding.
        if (user.mfaEnabled) return next();
        if (!['GET', 'HEAD'].includes(req.method)) {
          return res.status(401).json({ message: 'Open n8n to establish your Pangolin session.' });
        }
        if (req.headers.origin && req.headers.origin !== config.origin) {
          return res.status(403).json({ message: 'Invalid session origin.' });
        }
        // Use n8n's cookie issuer and feed the same cookie to its normal auth
        // middleware for this first request. All native authorization stays on.
        authService.issueCookie({
          cookie(name, value, options) {
            res.cookie(name, value, options);
            req.cookies[name] = value;
          },
        }, user, false, req.headers['browser-id']);
        logger.info(`Pangolin session established for n8n user ${user.id}`);
      }
      if (req.method === 'GET' && req.path === '/signin') return res.redirect(303, '/');
      return next();
    } catch (error) {
      logger.error(`Pangolin session failed: ${error.message}`);
      return res.status(503).json({ message: 'Could not establish the n8n session.' });
    }
  };
}

module.exports = {
  n8n: {
    ready: [async function ({ app }) {
      const { createRequire } = require('node:module');
      const { readFileSync } = require('node:fs');
      const n8nRequire = createRequire('/opt/n8n/current/node_modules/n8n/package.json');
      const config = JSON.parse(readFileSync('/etc/n8n/pangolin-auth.json', 'utf8'));
      const installedVersion = n8nRequire('./package.json').version;
      // Change these reviewed versions only after exercising the native issuer
      // and middleware ordering against the new release.
      if (!['2.42.6', '2.43.7', '2.43.8'].includes(installedVersion) || installedVersion !== config.version) {
        throw new Error('Review Pangolin session hook for this n8n version');
      }
      const { Container } = n8nRequire('@n8n/di');
      const { AuthService } = n8nRequire('./dist/auth/auth.service.js');
      const { AUTH_COOKIE_NAME } = n8nRequire('./dist/constants.js');
      const { Logger } = n8nRequire('@n8n/backend-common');
      const stack = app.router.stack;
      const cookieIndex = stack.findIndex((layer) => layer.name === 'cookieParser');
      if (cookieIndex < 0) throw new Error('n8n cookie parser was not found');
      app.use(createMiddleware({
        authService: Container.get(AuthService),
        userRepository: this.dbCollections.User,
        cookieName: AUTH_COOKIE_NAME,
        config,
        logger: Container.get(Logger),
      }));
      // Express creates the Layer, so no router internals need to be imported.
      stack.splice(cookieIndex + 1, 0, stack.pop());
      Container.get(Logger).info('Pangolin session hook enabled');
    }],
  },
};

// Non-enumerable so n8n's hook loader sees only the n8n.ready hook.
Object.defineProperty(module.exports, 'createMiddleware', { value: createMiddleware });
