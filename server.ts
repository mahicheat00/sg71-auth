import 'dotenv/config';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Backend configuration from environment variables (never expose raw API_KEY to browser)
let runtimeApiBase = (process.env.SG71_API_BASE || 'https://sg71auth.netlify.app/api').replace(/\/+$/, '');
let runtimeAdminId = process.env.SG71_ADMIN_ID || 'PvNGaleVdcf1PvUoQbUWT0Rnbm12';
let runtimeAppName = process.env.SG71_APP_NAME || 'mahi corpo';
const API_KEY = process.env.SG71_API_KEY || 'sg71_UhjxrUX75llMMq9lNMkNDCrWDU2w2OVm';

function maskKey(key: string): string {
  if (!key || key.length < 12) return 'sg71_••••••••';
  return `${key.slice(0, 8)}••••••••••••${key.slice(-4)}`;
}

interface StoredUser {
  username: string;
  password?: string;
  expires: string | null;
  hwid: string | null;
  isBanned: boolean;
  createdAt: string;
  lastResetAt: string | null;
}

interface AuditEntry {
  id: string;
  timestamp: string;
  endpoint: string;
  action: string;
  appName: string;
  status: number;
  success: boolean;
  mode: 'live' | 'sandbox';
  durationMs: number;
  message: string;
  requestPayload: Record<string, unknown>;
  responsePayload: Record<string, unknown>;
}

const passwordMemory = new Map<string, string>([
  ['newuser', 'secret123'],
]);

const sandboxUsers: StoredUser[] = [
  {
    username: 'MAHABUB',
    expires: '2027-10-03',
    hwid: '00C9166AFABAD58DB7FA55AAD1ED892F',
    isBanned: false,
    createdAt: '2026-10-03',
    lastResetAt: null,
  },
  {
    username: 'mahi',
    expires: null,
    hwid: 'B8BADCA93368316B8048B5A77192AFCF',
    isBanned: false,
    createdAt: '2026-10-03',
    lastResetAt: null,
  },
  {
    username: 'dewan',
    expires: '2026-11-02',
    hwid: 'E49A96A908C34942DD6EB82994F6D799',
    isBanned: false,
    createdAt: '2026-10-03',
    lastResetAt: null,
  },
];

let lastSyncStatus: 'live' | 'sandbox' = 'live';
let lastUpstreamMessage: string | null = null;
const auditLogs: AuditEntry[] = [];

function recordAudit(entry: Omit<AuditEntry, 'id' | 'timestamp'>) {
  const full: AuditEntry = {
    id: `req_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    ...entry,
  };
  auditLogs.unshift(full);
  if (auditLogs.length > 50) {
    auditLogs.length = 50;
  }
  return full;
}

function normalizeDateString(val: unknown): string | null {
  if (val === null || val === undefined || val === '') return null;
  const str = String(val).trim();
  if (!str || str.toLowerCase() === 'null' || str.toLowerCase() === 'lifetime') {
    return null;
  }
  // Convert ISO 8601 strings like "2027-10-03T23:59:59.999Z" to "2027-10-03"
  if (/^\d{4}-\d{2}-\d{2}T/.test(str)) {
    return str.slice(0, 10);
  }
  return str;
}

// Normalize both PascalCase (Username, HWID, Expires, IsBanned) from SG71 live API
// and camelCase (username, hwid, expires, isBanned) from local payloads
function decorateUser(u: any, index = 0) {
  const rawUsername = u.Username ?? u.username ?? u.user ?? `user_${index + 1}`;
  const username = String(rawUsername).trim();

  const rawExpires = u.Expires !== undefined ? u.Expires : u.expires !== undefined ? u.expires : u.expiry;
  const expires = normalizeDateString(rawExpires);

  const rawHwid = u.HWID !== undefined ? u.HWID : u.hwid;
  const hwid =
    rawHwid !== null && rawHwid !== undefined && String(rawHwid).trim() !== ''
      ? String(rawHwid).trim()
      : null;

  const rawBanned = u.IsBanned !== undefined ? u.IsBanned : u.isBanned !== undefined ? u.isBanned : u.banned;
  const isBanned = Boolean(rawBanned);

  return {
    username,
    expires,
    rawExpires: rawExpires ? String(rawExpires) : null,
    hwid,
    isBanned,
    createdAt: u.CreatedAt || u.createdAt || '2026-10-03',
    lastResetAt: u.lastResetAt || null,
    hasCachedPassword: passwordMemory.has(username),
  };
}

// Core sg71Post helper matching user specification
async function sg71Post(
  endpoint: string,
  data: Record<string, unknown> = {},
  overrideAppName?: string,
  overrideAdminId?: string
) {
  const targetAppName = (overrideAppName || runtimeAppName).trim();
  const targetAdminId = (overrideAdminId || runtimeAdminId).trim();

  const requestBody: Record<string, unknown> = {
    adminId: targetAdminId,
    appName: targetAppName,
    apiKey: API_KEY,
    ...data,
  };

  const sanitizedRequest: Record<string, unknown> = {
    ...requestBody,
    apiKey: maskKey(API_KEY),
    ...(typeof requestBody.password === 'string' && requestBody.password
      ? { password: '••••••••' }
      : {}),
  };

  const start = Date.now();
  try {
    const response = await fetch(`${runtimeApiBase}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Api-Key': API_KEY,
      },
      body: JSON.stringify(requestBody),
    });

    const durationMs = Date.now() - start;
    let json: Record<string, any> = {};
    try {
      json = await response.json();
    } catch {
      json = { success: false, message: `Upstream returned HTTP ${response.status}` };
    }

    if (!response.ok || !json.success) {
      const errMsg = json.message || `Request failed with status ${response.status}`;
      throw Object.assign(new Error(errMsg), {
        status: response.status,
        durationMs,
        sanitizedRequest,
        upstreamJson: json,
      });
    }

    lastSyncStatus = 'live';
    lastUpstreamMessage = null;

    recordAudit({
      endpoint,
      action: endpoint.split('/').pop() || 'request',
      appName: targetAppName,
      status: response.status,
      success: true,
      mode: 'live',
      durationMs,
      message: json.message || 'Live SG71 API request succeeded',
      requestPayload: sanitizedRequest,
      responsePayload: json,
    });

    return { json, mode: 'live' as const };
  } catch (err: any) {
    const durationMs = err.durationMs ?? Date.now() - start;
    const errMsg = err.message || 'Upstream connection failed';
    lastUpstreamMessage = errMsg;
    throw Object.assign(new Error(errMsg), {
      status: err.status || 502,
      durationMs,
      sanitizedRequest,
      upstreamJson: err.upstreamJson || { success: false, message: errMsg },
    });
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Get current workspace configuration
  app.get('/api/config', (_req, res) => {
    res.json({
      success: true,
      config: {
        apiBase: runtimeApiBase,
        adminId: runtimeAdminId,
        appName: runtimeAppName,
        maskedApiKey: maskKey(API_KEY),
        syncStatus: lastSyncStatus,
        upstreamMessage: lastUpstreamMessage,
      },
      auditLogs,
    });
  });

  // Update target appName or adminId
  app.post('/api/config', (req, res) => {
    const { appName, adminId, apiBase } = req.body || {};
    if (typeof appName === 'string' && appName.trim()) {
      runtimeAppName = appName.trim();
    }
    if (typeof adminId === 'string' && adminId.trim()) {
      runtimeAdminId = adminId.trim();
    }
    if (typeof apiBase === 'string' && apiBase.trim()) {
      runtimeApiBase = apiBase.trim().replace(/\/+$/, '');
    }
    res.json({
      success: true,
      config: {
        apiBase: runtimeApiBase,
        adminId: runtimeAdminId,
        appName: runtimeAppName,
        maskedApiKey: maskKey(API_KEY),
        syncStatus: lastSyncStatus,
        upstreamMessage: lastUpstreamMessage,
      },
    });
  });

  // 1. List users -> /admin/api/users/list
  app.post('/api/users/list', async (req, res) => {
    const { appName, adminId } = req.body || {};
    if (typeof appName === 'string' && appName.trim()) {
      runtimeAppName = appName.trim();
    }
    if (typeof adminId === 'string' && adminId.trim()) {
      runtimeAdminId = adminId.trim();
    }

    try {
      const { json } = await sg71Post('/admin/api/users/list', {}, runtimeAppName, runtimeAdminId);
      const rawUsers = Array.isArray(json.users) ? json.users : [];
      const users = rawUsers.map((u, idx) => decorateUser(u, idx));
      res.json({
        success: true,
        users,
        total: typeof json.total === 'number' ? json.total : users.length,
        config: {
          apiBase: runtimeApiBase,
          adminId: runtimeAdminId,
          appName: runtimeAppName,
          maskedApiKey: maskKey(API_KEY),
          syncStatus: 'live',
          upstreamMessage: null,
        },
        auditLogs,
      });
    } catch (err: any) {
      lastSyncStatus = 'sandbox';
      const fallbackUsers = sandboxUsers.map((u, idx) => decorateUser(u, idx));
      recordAudit({
        endpoint: '/admin/api/users/list',
        action: 'list',
        appName: runtimeAppName,
        status: err.status || 404,
        success: true,
        mode: 'sandbox',
        durationMs: err.durationMs || 0,
        message: `${err.message} (Served via local sandbox store)`,
        requestPayload: err.sanitizedRequest || {
          adminId: runtimeAdminId,
          appName: runtimeAppName,
          apiKey: maskKey(API_KEY),
        },
        responsePayload: {
          upstreamResponse: err.upstreamJson,
          sandboxTotal: fallbackUsers.length,
        },
      });

      res.json({
        success: true,
        users: fallbackUsers,
        total: fallbackUsers.length,
        config: {
          apiBase: runtimeApiBase,
          adminId: runtimeAdminId,
          appName: runtimeAppName,
          maskedApiKey: maskKey(API_KEY),
          syncStatus: 'sandbox',
          upstreamMessage: err.message,
        },
        auditLogs,
      });
    }
  });

  // 2. Create user -> /admin/api/users/create
  app.post('/api/users/create', async (req, res) => {
    const { username, password, expires, hwid = null, isBanned = false } = req.body || {};
    if (!username || !password) {
      res.status(400).json({
        success: false,
        message: 'Username and password are required.',
      });
      return;
    }

    const cleanUsername = String(username).trim();
    const normalizedExpires = normalizeDateString(expires);
    passwordMemory.set(cleanUsername, String(password));

    try {
      const { json } = await sg71Post('/admin/api/users/create', {
        username: cleanUsername,
        password: String(password),
        expires: normalizedExpires,
        hwid: hwid ? String(hwid).trim() : null,
        isBanned: Boolean(isBanned),
      });

      res.json({
        success: true,
        message: json.message || `User "${cleanUsername}" created on SG71 Auth.`,
        mode: 'live',
        auditLogs,
      });
    } catch (err: any) {
      if (lastSyncStatus === 'sandbox' || String(err.message).toLowerCase().includes('application not found')) {
        const exists = sandboxUsers.find(
          (u) => u.username.toLowerCase() === cleanUsername.toLowerCase()
        );
        if (exists) {
          res.status(409).json({
            success: false,
            message: `User "${cleanUsername}" already exists.`,
          });
          return;
        }
        const created: StoredUser = {
          username: cleanUsername,
          expires: normalizedExpires,
          hwid: hwid ? String(hwid).trim() : null,
          isBanned: Boolean(isBanned),
          createdAt: new Date().toISOString().slice(0, 10),
          lastResetAt: null,
        };
        sandboxUsers.unshift(created);

        recordAudit({
          endpoint: '/admin/api/users/create',
          action: 'create',
          appName: runtimeAppName,
          status: 200,
          success: true,
          mode: 'sandbox',
          durationMs: err.durationMs || 0,
          message: `Created user "${cleanUsername}" in sandbox`,
          requestPayload: err.sanitizedRequest || {},
          responsePayload: { success: true, user: decorateUser(created) },
        });

        res.json({
          success: true,
          message: `User "${cleanUsername}" created in sandbox.`,
          mode: 'sandbox',
          auditLogs,
        });
        return;
      }

      recordAudit({
        endpoint: '/admin/api/users/create',
        action: 'create',
        appName: runtimeAppName,
        status: err.status || 400,
        success: false,
        mode: 'live',
        durationMs: err.durationMs || 0,
        message: err.message,
        requestPayload: err.sanitizedRequest || {},
        responsePayload: err.upstreamJson || { success: false, message: err.message },
      });

      res.status(err.status || 400).json({
        success: false,
        message: err.message,
        auditLogs,
      });
    }
  });

  // 3. Update user -> /admin/api/users/update
  app.post('/api/users/update', async (req, res) => {
    const { username, expires, isBanned, password, hwid } = req.body || {};
    if (!username) {
      res.status(400).json({
        success: false,
        message: 'Username is required to update a user.',
      });
      return;
    }

    const cleanUsername = String(username).trim();
    if (typeof password === 'string' && password.trim()) {
      passwordMemory.set(cleanUsername, password.trim());
    }

    const payload: Record<string, unknown> = {
      username: cleanUsername,
    };
    if (expires !== undefined) {
      payload.expires = normalizeDateString(expires);
    }
    if (typeof isBanned === 'boolean') payload.isBanned = isBanned;
    if (typeof password === 'string' && password.trim()) payload.password = password.trim();
    if (hwid !== undefined) payload.hwid = hwid === '' || hwid === null ? null : String(hwid).trim();

    try {
      const { json } = await sg71Post('/admin/api/users/update', payload);
      res.json({
        success: true,
        message: json.message || `User "${cleanUsername}" updated.`,
        mode: 'live',
        auditLogs,
      });
    } catch (err: any) {
      if (lastSyncStatus === 'sandbox' || String(err.message).toLowerCase().includes('application not found')) {
        const target = sandboxUsers.find(
          (u) => u.username.toLowerCase() === cleanUsername.toLowerCase()
        );
        if (!target) {
          res.status(404).json({
            success: false,
            message: `User "${cleanUsername}" not found.`,
          });
          return;
        }
        if (expires !== undefined) target.expires = normalizeDateString(expires);
        if (typeof isBanned === 'boolean') target.isBanned = isBanned;
        if (hwid !== undefined) target.hwid = hwid ? String(hwid).trim() : null;

        recordAudit({
          endpoint: '/admin/api/users/update',
          action: 'update',
          appName: runtimeAppName,
          status: 200,
          success: true,
          mode: 'sandbox',
          durationMs: err.durationMs || 0,
          message: `Updated user "${cleanUsername}" in sandbox`,
          requestPayload: err.sanitizedRequest || payload,
          responsePayload: { success: true, user: decorateUser(target) },
        });

        res.json({
          success: true,
          message: `User "${cleanUsername}" updated.`,
          mode: 'sandbox',
          auditLogs,
        });
        return;
      }

      recordAudit({
        endpoint: '/admin/api/users/update',
        action: 'update',
        appName: runtimeAppName,
        status: err.status || 400,
        success: false,
        mode: 'live',
        durationMs: err.durationMs || 0,
        message: err.message,
        requestPayload: err.sanitizedRequest || payload,
        responsePayload: err.upstreamJson || { success: false, message: err.message },
      });

      res.status(err.status || 400).json({
        success: false,
        message: err.message,
        auditLogs,
      });
    }
  });

  // 4. Reset HWID -> /admin/api/users/reset-hwid (or admin direct clear via /admin/api/users/update if password not supplied)
  app.post('/api/users/reset-hwid', async (req, res) => {
    const { username, password } = req.body || {};
    if (!username) {
      res.status(400).json({
        success: false,
        message: 'Username is required to reset HWID.',
      });
      return;
    }

    const cleanUsername = String(username).trim();
    const resolvedPassword =
      typeof password === 'string' && password.trim()
        ? password.trim()
        : passwordMemory.get(cleanUsername) || '';

    if (resolvedPassword) {
      passwordMemory.set(cleanUsername, resolvedPassword);
    }

    try {
      if (resolvedPassword) {
        // Use /admin/api/users/reset-hwid with username + password
        const { json } = await sg71Post('/admin/api/users/reset-hwid', {
          username: cleanUsername,
          password: resolvedPassword,
        });
        res.json({
          success: true,
          message: json.message || `HWID cleared for "${cleanUsername}".`,
          mode: 'live',
          auditLogs,
        });
      } else {
        // Admin quick-reset from User Directory when user password isn't known:
        // Clear HWID directly via /admin/api/users/update { username, hwid: null }
        const { json } = await sg71Post('/admin/api/users/update', {
          username: cleanUsername,
          hwid: null,
        });
        res.json({
          success: true,
          message: json.message || `HWID cleared for "${cleanUsername}".`,
          mode: 'live',
          auditLogs,
        });
      }
    } catch (err: any) {
      if (lastSyncStatus === 'sandbox' || String(err.message).toLowerCase().includes('application not found')) {
        const target = sandboxUsers.find(
          (u) => u.username.toLowerCase() === cleanUsername.toLowerCase()
        );
        if (!target) {
          res.status(404).json({
            success: false,
            message: `User "${cleanUsername}" not found.`,
          });
          return;
        }
        target.hwid = null;
        target.lastResetAt = new Date().toISOString().slice(0, 10);

        recordAudit({
          endpoint: '/admin/api/users/reset-hwid',
          action: 'reset-hwid',
          appName: runtimeAppName,
          status: 200,
          success: true,
          mode: 'sandbox',
          durationMs: err.durationMs || 0,
          message: `HWID cleared for "${cleanUsername}" in sandbox`,
          requestPayload: err.sanitizedRequest || { username: cleanUsername },
          responsePayload: { success: true, user: decorateUser(target) },
        });

        res.json({
          success: true,
          message: `HWID cleared for "${cleanUsername}".`,
          mode: 'sandbox',
          auditLogs,
        });
        return;
      }

      recordAudit({
        endpoint: '/admin/api/users/reset-hwid',
        action: 'reset-hwid',
        appName: runtimeAppName,
        status: err.status || 400,
        success: false,
        mode: 'live',
        durationMs: err.durationMs || 0,
        message: err.message,
        requestPayload: err.sanitizedRequest || { username: cleanUsername },
        responsePayload: err.upstreamJson || { success: false, message: err.message },
      });

      res.status(err.status || 400).json({
        success: false,
        message: err.message,
        auditLogs,
      });
    }
  });

  // 5. Delete user -> /admin/api/users/delete
  app.post('/api/users/delete', async (req, res) => {
    const { username } = req.body || {};
    if (!username) {
      res.status(400).json({
        success: false,
        message: 'Username is required to delete a user.',
      });
      return;
    }

    const cleanUsername = String(username).trim();

    try {
      const { json } = await sg71Post('/admin/api/users/delete', {
        username: cleanUsername,
      });
      passwordMemory.delete(cleanUsername);

      res.json({
        success: true,
        message: json.message || `User "${cleanUsername}" deleted.`,
        mode: 'live',
        auditLogs,
      });
    } catch (err: any) {
      if (lastSyncStatus === 'sandbox' || String(err.message).toLowerCase().includes('application not found')) {
        const idx = sandboxUsers.findIndex(
          (u) => u.username.toLowerCase() === cleanUsername.toLowerCase()
        );
        if (idx === -1) {
          res.status(404).json({
            success: false,
            message: `User "${cleanUsername}" not found.`,
          });
          return;
        }
        sandboxUsers.splice(idx, 1);
        passwordMemory.delete(cleanUsername);

        recordAudit({
          endpoint: '/admin/api/users/delete',
          action: 'delete',
          appName: runtimeAppName,
          status: 200,
          success: true,
          mode: 'sandbox',
          durationMs: err.durationMs || 0,
          message: `Deleted user "${cleanUsername}" from sandbox`,
          requestPayload: err.sanitizedRequest || { username: cleanUsername },
          responsePayload: { success: true, deleted: cleanUsername },
        });

        res.json({
          success: true,
          message: `User "${cleanUsername}" deleted.`,
          mode: 'sandbox',
          auditLogs,
        });
        return;
      }

      recordAudit({
        endpoint: '/admin/api/users/delete',
        action: 'delete',
        appName: runtimeAppName,
        status: err.status || 400,
        success: false,
        mode: 'live',
        durationMs: err.durationMs || 0,
        message: err.message,
        requestPayload: err.sanitizedRequest || { username: cleanUsername },
        responsePayload: err.upstreamJson || { success: false, message: err.message },
      });

      res.status(err.status || 400).json({
        success: false,
        message: err.message,
        auditLogs,
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SG71 Auth Console server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
