const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');

const app = express();
app.set('trust proxy', true);
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use('/screenshots', express.static('public/screenshots'));
app.use('/avatars', express.static('public/avatars'));

// ===== JSON DATABASE =====
const DB_PATH = path.join(__dirname, 'data.json');

// ===== VPN DETECTION =====
async function isVPN(ip) {
    return new Promise((resolve) => {
        // Simple VPN detection using ip-api.com
        const req = http.get(`http://ip-api.com/json/${ip}?fields=proxy,hosting`, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const result = JSON.parse(data);
                    resolve(result.proxy === true || result.hosting === true);
                } catch (e) {
                    resolve(false);
                }
            });
        });
        req.on('error', () => resolve(false));
        req.setTimeout(3000, () => {
            req.destroy();
            resolve(false);
        });
    });
}

// ===== JSON DATABASE =====
function loadDB() {
    const defaults = {
        keys: [],
        menu_keys: [],
        users: [],
        sessions: [],
        suspicious_activities: [],
        hwid_resets: [],
        tickets: [],
        settings: {
            hwid_enabled: true,
            ip_enabled: true,
            block_inject: false
        }
    };
    if (!fs.existsSync(DB_PATH)) return defaults;
    try {
        const data = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
        if (!data.settings) data.settings = defaults.settings;
        if (!data.tickets) data.tickets = [];
        if (!data.menu_keys) data.menu_keys = [];
        if (!data.suspicious_activities) data.suspicious_activities = [];
        if (!data.sessions) data.sessions = [];
        if (!data.hwid_resets) data.hwid_resets = [];
        if (!data.users) data.users = [];
        if (!data.keys) data.keys = [];
        return data;
    }
    catch { return defaults; }
}

function saveDB(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

// ===== ADMIN TOKEN =====
const ADMIN_TOKEN = 'likinho-admin-2024';
function adminAuth(req, res, next) {
    if (req.headers['x-admin-token'] !== ADMIN_TOKEN) return res.status(403).json({ error: 'Unauthorized' });
    next();
}

// ===== HELPERS =====
function generateKey() {
    const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let p1 = '', p2 = '';
    for (let i = 0; i < 8; i++) p1 += c[Math.floor(Math.random() * c.length)];
    for (let i = 0; i < 12; i++) p2 += c[Math.floor(Math.random() * c.length)];
    return `LIKINHO-${p1}-${p2}`;
}
function generateMenuKey() {
    const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let p1 = '', p2 = '';
    for (let i = 0; i < 8; i++) p1 += c[Math.floor(Math.random() * c.length)];
    for (let i = 0; i < 7; i++) p2 += c[Math.floor(Math.random() * c.length)];
    return `LIKINHO-${p1}-${p2}-MENU`;
}
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function now() { return new Date().toISOString(); }
function getNextId(arr) { return arr.length ? Math.max(...arr.map(x => x.id || 0)) + 1 : 1; }
function hashHWID(hwid) { return crypto.createHash('sha256').update(hwid).digest('hex'); }
function getClientIP(req) {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || '';
    if (ip.includes(',')) ip = ip.split(',')[0].trim();
    ip = ip.replace('::ffff:', '');
    // When running locally, use client-provided public IP if available
    if ((ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') && req.body && req.body.client_ip) {
        ip = req.body.client_ip;
    }
    return ip;
}
function getLocalIP() {
    const nets = os.networkInterfaces();
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) return net.address;
        }
    }
    return '127.0.0.1';
}

// ===== CLIENT API =====

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ success: true, message: 'Server is working' });
});

// Session validation endpoint
app.get('/api/user/validate', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!token) return res.json({ success: false, message: 'No token provided' });

    const db = loadDB();
    const session = db.sessions.find(s => s.token === token);
    if (!session) return res.json({ success: false, message: 'Invalid session' });

    const user = db.users.find(u => u.username === session.username);
    if (!user) return res.json({ success: false, message: 'User not found' });

    const clientIP = getClientIP(req);
    let vpnDetected = false;
    let hwidMismatch = false;
    let ipChanged = false;

    // Check for IP change
    if (user.registered_ip && clientIP !== user.registered_ip) {
        ipChanged = true;
    }

    // Check for HWID mismatch (if HWID is locked)
    const key = db.keys.find(k => k.key_code === user.key_code);
    if (key && key.hwid_locked && user.hwid && req.body && req.body.hwid) {
        const currentHwid = hashHWID(req.body.hwid);
        if (currentHwid !== user.hwid) {
            hwidMismatch = true;
        }
    }

    res.json({
        success: true,
        vpn_detected: vpnDetected,
        hwid_mismatch: hwidMismatch,
        ip_changed: ipChanged
    });
});

// Check inject blocked status
app.get('/api/user/inject-status', (req, res) => {
    const db = loadDB();
    res.json({
        success: true,
        block_inject: db.settings.block_inject || false
    });
});

app.post('/api/register', (req, res) => {
    const { username, password, key_code, hwid } = req.body;
    if (!username || !password || !key_code) return res.json({ success: false, message: 'All fields are required' });
    if (username.length < 3) return res.json({ success: false, message: 'Username must be at least 3 characters' });

    const db = loadDB();
    const key = db.keys.find(k => k.key_code === key_code);
    if (!key) return res.json({ success: false, message: 'Invalid key' });
    if (key.status === 'banned') return res.json({ success: false, message: key.ban_message || 'This key has been banned' });
    if (key.status === 'disabled') return res.json({ success: false, message: 'This key has been disabled' });
    if (key.status === 'active') return res.json({ success: false, message: 'This key is already in use' });
    if (key.status === 'expired') return res.json({ success: false, message: 'This key has expired' });
    if (key.status === 'blacklisted') return res.json({ success: false, message: 'This key has been blacklisted' });

    if (db.users.find(u => u.username === username)) return res.json({ success: false, message: 'Username already taken' });

    const hash = bcrypt.hashSync(password, 10);
    const clientIP = getClientIP(req);
    const expiresAt = new Date(Date.now() + key.days * 86400000).toISOString();
    key.status = 'active'; key.used_by = username; key.activated_at = now(); key.expires_at = expiresAt;

    // HWID handling
    const hwidHash = hwid ? hashHWID(hwid) : null;
    if (hwidHash) {
        key.hwid_locked = true;
    }

    const user = {
        id: getNextId(db.users),
        username,
        password: hash,
        key_code,
        hwid: hwidHash,
        hwid_registered_at: hwidHash ? now() : null,
        registered_ip: clientIP,
        ip_registered_at: now(),
        blacklisted: false,
        blacklist_reason: null,
        discord_id: null,
        discord_avatar: null,
        avatar_base64: "",
        created_at: now(),
        last_login: now()
    };
    db.users.push(user);

    const token = genToken();
    db.sessions.push({ id: getNextId(db.sessions), token, username, last_heartbeat: now(), ip: clientIP, created_at: now() });
    saveDB(db);

    res.json({ success: true, token, hwid_registered: !!hwidHash, message: 'Account created successfully' });
});

app.post('/api/login', async (req, res) => {
    const { username, password, hwid } = req.body;
    if (!username || !password) return res.json({ success: false, message: 'Username and password required' });

    const db = loadDB();
    const user = db.users.find(u => u.username === username);
    if (!user || !bcrypt.compareSync(password, user.password)) return res.json({ success: false, message: 'Invalid credentials' });

    // Check blacklist
    if (user.blacklisted) return res.json({ success: false, message: user.blacklist_reason || 'Account blacklisted' });

    const key = db.keys.find(k => k.key_code === user.key_code);
    if (!key) return res.json({ success: false, message: 'Key not found' });
    if (key.status === 'banned') return res.json({ success: false, message: key.ban_message || 'Your key has been banned' });
    if (key.status === 'disabled') return res.json({ success: false, message: 'Your key has been disabled' });
    if (key.status === 'paused') return res.json({ success: false, message: 'Your key is currently paused by admin' });
    if (key.status === 'blacklisted') return res.json({ success: false, message: 'Your key has been blacklisted' });
    if (key.expires_at && new Date(key.expires_at) < new Date()) { key.status = 'expired'; saveDB(db); return res.json({ success: false, message: 'Your key has expired' }); }

    const clientIP = getClientIP(req);
    let isVPNConnection = false;
    let suspiciousReason = null;

    // VPN Detection
    if (clientIP !== '127.0.0.1' && clientIP !== 'localhost' && !clientIP.startsWith('192.168.') && !clientIP.startsWith('10.')) {
        try {
            isVPNConnection = await isVPN(clientIP);
            if (isVPNConnection) {
                db.suspicious_activities.push({
                    id: getNextId(db.suspicious_activities),
                    user_id: user.id, username: user.username,
                    process_name: 'VPN_DETECTED', threat_type: 'vpn_connection',
                    screenshot_base64: null, hwid: user.hwid,
                    old_hwid: null, ip: clientIP,
                    detected_at: now(), auto_action: 'blocked'
                });
                saveDB(db);
                return res.json({ success: false, message: 'VPN connection detected. Please disable your VPN to login.' });
            }
        } catch (e) {
            console.log('VPN detection error:', e.message);
        }
    }

    // IP validation (if enabled)
    let ipChanged = false;
    if (db.settings.ip_enabled && user.registered_ip) {
        if (clientIP !== user.registered_ip) {
            ipChanged = true;
            suspiciousReason = suspiciousReason || 'IP_CHANGE';
            db.suspicious_activities.push({
                id: getNextId(db.suspicious_activities),
                user_id: user.id, username: user.username,
                process_name: 'IP_MISMATCH', threat_type: 'ip_change',
                screenshot_base64: null, hwid: user.hwid,
                old_hwid: null, ip: clientIP,
                detected_at: now(), auto_action: 'logged'
            });
        }
    } else if (!user.registered_ip) {
        user.registered_ip = clientIP;
        user.ip_registered_at = now();
    }

    // HWID validation (if enabled)
    let hwidChanged = false;
    if (db.settings.hwid_enabled) {
        if (hwid && user.hwid) {
            const hwidHash = hashHWID(hwid);
            if (hwidHash !== user.hwid) {
                hwidChanged = true;
                suspiciousReason = 'HWID_CHANGE';
                user.blacklisted = true;
                user.blacklist_reason = 'AUTOMATIC BLACKLIST: HWID RESET - Contact Administrator';
                key.status = 'blacklisted';
                db.suspicious_activities.push({
                    id: getNextId(db.suspicious_activities),
                    user_id: user.id, username: user.username,
                    process_name: 'HWID_MISMATCH', threat_type: 'hwid_change',
                    screenshot_base64: null, hwid: hwidHash,
                    old_hwid: user.hwid, ip: clientIP,
                    detected_at: now(), auto_action: 'blacklist'
                });
                saveDB(db);
                return res.json({ success: false, hwid_mismatch: true, message: 'HWID Reset Required - Contact Administrator' });
            }
        } else if (hwid && !user.hwid) {
            user.hwid = hashHWID(hwid);
            user.hwid_registered_at = now();
            key.hwid_locked = true;
        }
    }

    user.last_login = now();
    db.sessions = db.sessions.filter(s => s.username !== username);
    const token = genToken();
    db.sessions.push({ id: getNextId(db.sessions), token, username, last_heartbeat: now(), ip: clientIP, created_at: now() });
    saveDB(db);

    const daysLeft = key.expires_at ? Math.ceil((new Date(key.expires_at) - new Date()) / 86400000) : 0;

    // Check menu key status
    let menuKeyStatus = 'none';
    let menuKeyDays = 0;
    if (db.menu_keys) {
        const menuKey = db.menu_keys.find(k => k.used_by === user.username);
        if (menuKey) {
            if (menuKey.status === 'active' && menuKey.expires_at) {
                if (new Date(menuKey.expires_at) < new Date()) {
                    menuKey.status = 'expired';
                    saveDB(db);
                } else {
                    menuKeyDays = Math.ceil((new Date(menuKey.expires_at) - new Date()) / 86400000);
                }
            }
            menuKeyStatus = menuKey.status;
        }
    }

    let response = {
        success: true,
        token,
        username: user.username,
        discord_avatar: user.discord_avatar,
        avatar_base64: user.avatar_base64 || "",
        days_left: daysLeft,
        menu_key_status: menuKeyStatus,
        menu_key_days: menuKeyDays,
        message: 'Login successful'
    };

    // Add VPN warning if detected
    if (isVPNConnection) {
        response.vpn_warning = "You are connecting with a VPN. This may be monitored.";
    }

    res.json(response);
});

app.post('/api/heartbeat', (req, res) => {
    const { token } = req.body;
    if (!token) return res.json({ success: false });
    const db = loadDB();
    const s = db.sessions.find(x => x.token === token);
    if (s) { s.last_heartbeat = now(); saveDB(db); }
    res.json({ success: !!s });
});

app.post('/api/logout', (req, res) => {
    const { token } = req.body;
    const db = loadDB();
    db.sessions = db.sessions.filter(s => s.token !== token);
    saveDB(db);
    res.json({ success: true });
});

app.post('/api/user/discord', (req, res) => {
    const token = req.headers['x-auth-token'];
    const { discord_id, discord_avatar } = req.body;
    const db = loadDB();
    const s = db.sessions.find(x => x.token === token);
    if (!s) return res.json({ success: false });
    const u = db.users.find(x => x.username === s.username);
    if (u) { u.discord_id = discord_id; u.discord_avatar = discord_avatar; saveDB(db); }
    res.json({ success: true });
});

app.post('/api/user/avatar', (req, res) => {
    const token = req.headers['x-auth-token'];
    const { avatar_base64 } = req.body;
    if (!avatar_base64) return res.json({ success: false, message: 'avatar_base64 required' });
    const db = loadDB();
    const s = db.sessions.find(x => x.token === token);
    if (!s) return res.json({ success: false, message: 'Invalid session' });
    const u = db.users.find(x => x.username === s.username);
    if (u) { u.avatar_base64 = avatar_base64; saveDB(db); }
    res.json({ success: true });
});

// ===== SECURITY API =====

app.post('/api/security/report', (req, res) => {
    const token = req.headers['x-auth-token'];
    const { process_name, threat_type, screenshot_base64, username: bodyUsername } = req.body;

    if (!process_name || !threat_type) return res.json({ success: false, message: 'Missing required fields' });

    const db = loadDB();
    let user = null;
    let session = null;

    if (token) {
        session = db.sessions.find(s => s.token === token);
        if (session) {
            user = db.users.find(u => u.username === session.username);
        }
    }

    // Determine reporting username
    const reportingUsername = user ? user.username : (bodyUsername || "unauthenticated_user");
    const reportingIP = session ? session.ip : getClientIP(req);
    const reportingHWID = user ? user.hwid : null;

    // determine screen filename
    let screenshot_url = null;
    if (screenshot_base64 && screenshot_base64.length > 100) {
        const activityId = getNextId(db.suspicious_activities);
        const filename = `screenshot_${activityId}.jpg`;
        const base64Data = screenshot_base64.replace(/^data:image\/\w+;base64,/, '');
        try {
            fs.writeFileSync(path.join(__dirname, 'public/screenshots', filename), base64Data, 'base64');
            screenshot_url = `/screenshots/${filename}`;
        } catch (e) {
            console.error('[SECURITY] Failed to save screenshot:', e);
        }
    }

    // Log suspicious activity
    const activity = {
        id: getNextId(db.suspicious_activities),
        user_id: user ? user.id : null,
        username: reportingUsername,
        process_name,
        threat_type,
        screenshot_url,
        hwid: reportingHWID,
        ip: reportingIP,
        detected_at: now(),
        auto_action: 'logged'
    };

    db.suspicious_activities.push(activity);
    console.log(`[SECURITY] New report from ${reportingUsername} (${reportingIP}): ${threat_type} in ${process_name}`);

    // Auto-blacklist after 3 suspicious activities (only for authenticated users)
    if (user) {
        const userActivities = db.suspicious_activities.filter(a => a.user_id === user.id);
        if (userActivities.length >= 3) {
            user.blacklisted = true;
            user.blacklist_reason = `AUTOMATIC BLACKLIST: ${userActivities.length} suspicious activities detected`;
            activity.auto_action = 'blacklist';

            const key = db.keys.find(k => k.key_code === user.key_code);
            if (key) key.status = 'blacklisted';
            console.log(`[SECURITY] User ${user.username} has been AUTOMATICALLY BLACKLISTED.`);
        }
    }

    saveDB(db);

    res.json({
        success: true,
        action: activity.auto_action,
        blacklisted: user ? user.blacklisted : false,
        message: 'Activity reported successfully'
    });
});

// ===== ADMIN ROUTES =====

// Dashboard stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
    const db = loadDB();
    res.json({
        success: true,
        totalKeys: db.keys.length,
        activeKeys: db.keys.filter(k => k.status === 'active').length,
        totalUsers: db.users.length,
        online: db.sessions.length,
        blacklisted: db.users.filter(u => u.blacklisted).length,
        suspicious_today: (db.suspicious_activities || []).filter(a => {
            const activityDate = new Date(a.detected_at);
            const today = new Date();
            return activityDate.toDateString() === today.toDateString();
        }).length
    });
});

// List all keys
app.get('/api/admin/keys', adminAuth, (req, res) => {
    const db = loadDB();
    res.json({
        success: true,
        keys: db.keys
    });
});

// Generate multiple keys
app.post('/api/admin/keys/generate', adminAuth, (req, res) => {
    const { days, count } = req.body;
    const keyDays = days || 30;
    const keyCount = Math.min(count || 1, 50);

    const db = loadDB();
    const newKeys = [];

    for (let i = 0; i < keyCount; i++) {
        const keyCode = generateKey();
        const newKey = {
            id: getNextId(db.keys),
            key_code: keyCode,
            days: keyDays,
            status: 'available',
            hwid_locked: false,
            ban_message: null,
            used_by: null,
            created_at: now(),
            activated_at: null,
            expires_at: null
        };
        db.keys.push(newKey);
        newKeys.push(keyCode);
    }

    saveDB(db);

    res.json({
        success: true,
        message: `${keyCount} key(s) generated`,
        keys: newKeys
    });
});

// Generate menu keys
app.post('/api/admin/menu-keys/generate', adminAuth, (req, res) => {
    const { days, count } = req.body;
    const keyDays = days || 30;
    const keyCount = Math.min(count || 1, 50);

    const db = loadDB();
    const newKeys = [];

    for (let i = 0; i < keyCount; i++) {
        const keyCode = generateMenuKey();
        const newKey = {
            id: getNextId(db.menu_keys),
            key_code: keyCode,
            days: keyDays,
            status: 'available',
            used_by: null,
            activated_at: null,
            expires_at: null
        };
        db.menu_keys.push(newKey);
        newKeys.push(keyCode);
    }

    saveDB(db);

    res.json({
        success: true,
        message: `${keyCount} menu key(s) generated`,
        keys: newKeys
    });
});

// List menu keys
app.get('/api/admin/menu-keys', adminAuth, (req, res) => {
    const db = loadDB();
    res.json({
        success: true,
        keys: db.menu_keys
    });
});

// Delete menu key
app.delete('/api/admin/menu-keys/:id', adminAuth, (req, res) => {
    const { id } = req.params;
    const keyId = parseInt(id);

    const db = loadDB();
    const index = db.menu_keys.findIndex(k => k.id === keyId);
    if (index === -1) return res.json({ success: false, message: 'Key not found' });

    db.menu_keys.splice(index, 1);
    saveDB(db);

    res.json({ success: true, message: 'Menu key deleted successfully' });
});

// Redeem menu key (CLIENT)
app.post('/api/menu-keys/redeem', (req, res) => {
    const { username, key_code } = req.body;
    if (!username || !key_code) return res.json({ success: false, message: 'Missing fields' });

    const db = loadDB();
    const user = db.users.find(u => u.username === username);
    if (!user) return res.json({ success: false, message: 'User not found' });

    // Check if user already has an active menu key
    const existingKey = db.menu_keys.find(k => k.used_by === username && k.status === 'active');
    if (existingKey) {
        // Optional: you could allow stacking time here, but for now let's say one at a time
        // or just return error
        if (new Date(existingKey.expires_at) > new Date()) {
            return res.json({ success: false, message: 'You already have an active menu subscription' });
        }
        // If expired, we can allow redeeming a new one
    }

    const key = db.menu_keys.find(k => k.key_code === key_code);
    if (!key) return res.json({ success: false, message: 'Invalid key' });
    if (key.status !== 'available') return res.json({ success: false, message: 'Key already used or invalid' });

    const expiresAt = new Date(Date.now() + key.days * 86400000).toISOString();
    key.status = 'active';
    key.used_by = username;
    key.activated_at = now();
    key.expires_at = expiresAt;

    saveDB(db);

    res.json({
        success: true,
        message: 'Key redeemed successfully!',
        days: key.days,
        expires_at: expiresAt
    });
});

// Ban a key (Normal or Menu)
app.post('/api/admin/:type(keys|menu-keys)/:id/ban', adminAuth, (req, res) => {
    const { type, id } = req.params;
    const { message } = req.body;
    const keyId = parseInt(id);

    const db = loadDB();
    const collection = type === 'keys' ? db.keys : db.menu_keys;
    const key = collection.find(k => k.id === keyId);
    if (!key) return res.json({ success: false, message: 'Key not found' });

    key.status = 'banned';
    key.ban_message = message || 'Banned';
    saveDB(db);

    res.json({ success: true, message: 'Key banned successfully' });
});

// Enable a key (Normal or Menu)
app.post('/api/admin/:type(keys|menu-keys)/:id/enable', adminAuth, (req, res) => {
    const { type, id } = req.params;
    const keyId = parseInt(id);

    const db = loadDB();
    const collection = type === 'keys' ? db.keys : db.menu_keys;
    const key = collection.find(k => k.id === keyId);
    if (!key) return res.json({ success: false, message: 'Key not found' });

    key.status = key.used_by ? 'active' : 'available';
    key.ban_message = null;
    saveDB(db);

    res.json({ success: true, message: 'Key enabled successfully' });
});

// Pause a key (Normal or Menu)
app.post('/api/admin/:type(keys|menu-keys)/:id/pause', adminAuth, (req, res) => {
    const { type, id } = req.params;
    const keyId = parseInt(id);

    const db = loadDB();
    const collection = type === 'keys' ? db.keys : db.menu_keys;
    const key = collection.find(k => k.id === keyId);
    if (!key) return res.json({ success: false, message: 'Key not found' });

    if (key.status !== 'active') return res.json({ success: false, message: 'Only active keys can be paused' });

    const remainingMs = new Date(key.expires_at) - new Date();
    key.remaining_ms = remainingMs;
    key.status = 'paused';
    saveDB(db);

    res.json({ success: true, message: 'Key paused successfully' });
});

// Resume a key (Normal or Menu)
app.post('/api/admin/:type(keys|menu-keys)/:id/resume', adminAuth, (req, res) => {
    const { type, id } = req.params;
    const keyId = parseInt(id);

    const db = loadDB();
    const collection = type === 'keys' ? db.keys : db.menu_keys;
    const key = collection.find(k => k.id === keyId);
    if (!key) return res.json({ success: false, message: 'Key not found' });

    if (key.status !== 'paused') return res.json({ success: false, message: 'Only paused keys can be resumed' });

    const newExpires = new Date(Date.now() + (key.remaining_ms || 0)).toISOString();
    key.expires_at = newExpires;
    key.status = 'active';
    key.remaining_ms = null;
    saveDB(db);

    res.json({ success: true, message: 'Key resumed successfully', expires_at: newExpires });
});

// Disable a key (Normal or Menu) - Old behavior (just stops login)
app.post('/api/admin/:type(keys|menu-keys)/:id/disable', adminAuth, (req, res) => {
    const { type, id } = req.params;
    const keyId = parseInt(id);

    const db = loadDB();
    const collection = type === 'keys' ? db.keys : db.menu_keys;
    const key = collection.find(k => k.id === keyId);
    if (!key) return res.json({ success: false, message: 'Key not found' });

    key.status = 'disabled';
    saveDB(db);

    res.json({ success: true, message: 'Key disabled successfully' });
});

// Delete a key (Normal or Menu)
app.delete('/api/admin/:type(keys|menu-keys)/:id', adminAuth, (req, res) => {
    const { type, id } = req.params;
    const keyId = parseInt(id);

    const db = loadDB();
    const collection = type === 'keys' ? db.keys : db.menu_keys;
    const index = collection.findIndex(k => k.id === keyId);
    if (index === -1) return res.json({ success: false, message: 'Key not found' });

    collection.splice(index, 1);
    saveDB(db);

    res.json({ success: true, message: 'Key deleted successfully' });
});

// List all users
app.get('/api/admin/users', adminAuth, (req, res) => {
    const db = loadDB();
    const usersWithKeyInfo = db.users.map(u => {
        const key = db.keys.find(k => k.key_code === u.key_code);
        return {
            ...u,
            key_status: key ? key.status : 'unknown',
            days: key ? key.days : 0
        };
    });
    res.json({
        success: true,
        users: usersWithKeyInfo
    });
});

// List online users
app.get('/api/admin/online', adminAuth, (req, res) => {
    const db = loadDB();
    const onlineUsers = db.sessions.map(s => ({
        username: s.username,
        ip: s.ip,
        session_start: s.created_at,
        last_heartbeat: s.last_heartbeat
    }));
    res.json({
        success: true,
        count: onlineUsers.length,
        online: onlineUsers
    });
});

// Admin Settings
app.get('/api/admin/settings', adminAuth, (req, res) => {
    const db = loadDB();
    res.json({ success: true, settings: db.settings });
});

app.post('/api/admin/settings/toggle-hwid', adminAuth, (req, res) => {
    const db = loadDB();
    db.settings.hwid_enabled = !db.settings.hwid_enabled;
    saveDB(db);
    res.json({ success: true, hwid_enabled: db.settings.hwid_enabled });
});

app.post('/api/admin/settings/toggle-ip', adminAuth, (req, res) => {
    const db = loadDB();
    db.settings.ip_enabled = !db.settings.ip_enabled;
    saveDB(db);
    res.json({ success: true, ip_enabled: db.settings.ip_enabled });
});

// Block Inject Management
app.get('/api/admin/block-inject/status', adminAuth, (req, res) => {
    const db = loadDB();
    res.json({
        success: true,
        block_inject: db.settings.block_inject || false
    });
});

app.post('/api/admin/block-inject/toggle', adminAuth, (req, res) => {
    const db = loadDB();
    db.settings.block_inject = !db.settings.block_inject;
    saveDB(db);
    res.json({ success: true, block_inject: db.settings.block_inject });
});

// HWID Management
app.get('/api/admin/hwid/list', adminAuth, (req, res) => {
    const db = loadDB();
    const hwidList = db.users.map(u => {
        const key = db.keys.find(k => k.key_code === u.key_code);
        const session = db.sessions.find(s => s.username === u.username);

        // Check for recent suspicious activities
        const recentSuspicious = db.suspicious_activities
            .filter(s => s.user_id === u.id && new Date(s.detected_at) > new Date(Date.now() - 24 * 60 * 60 * 1000))
            .sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at))[0];

        let suspiciousStatus = null;
        if (recentSuspicious) {
            if (recentSuspicious.threat_type === 'hwid_change') {
                suspiciousStatus = 'hwid_change';
            } else if (recentSuspicious.threat_type === 'ip_change' || recentSuspicious.threat_type === 'vpn_connection') {
                suspiciousStatus = 'ip_change';
            }
        }

        return {
            user_id: u.id,
            username: u.username,
            hwid: u.hwid ? u.hwid.substring(0, 16) + '...' : 'Not registered',
            hwid_full: u.hwid,
            hwid_registered_at: u.hwid_registered_at,
            registered_ip: u.registered_ip || 'Not registered',
            ip_registered_at: u.ip_registered_at,
            key_code: u.key_code,
            key_locked: key ? key.hwid_locked : false,
            blacklisted: u.blacklisted,
            blacklist_reason: u.blacklist_reason,
            online: !!session,
            last_login: u.last_login,
            suspicious_status: suspiciousStatus,
            last_suspicious: recentSuspicious ? recentSuspicious.detected_at : null
        };
    });

    res.json({
        success: true,
        hwids: hwidList,
        total: hwidList.length,
        locked: hwidList.filter(h => h.key_locked).length,
        blacklisted: hwidList.filter(h => h.blacklisted).length,
        settings: db.settings
    });
});

app.post('/api/admin/hwid/:userId/reset', adminAuth, (req, res) => {
    const { userId } = req.params;
    const { reason } = req.body;
    const uid = parseInt(userId);

    const db = loadDB();
    const user = db.users.find(u => u.id === uid);
    if (!user) return res.json({ success: false, message: 'User not found' });

    const oldHwid = user.hwid;

    // Reset HWID and IP
    user.hwid = null;
    user.hwid_registered_at = null;
    user.registered_ip = null;
    user.ip_registered_at = null;
    user.blacklisted = false;
    user.blacklist_reason = null;

    const key = db.keys.find(k => k.key_code === user.key_code);
    if (key) {
        key.hwid_locked = false;
        if (key.status === 'blacklisted') key.status = 'active';
    }

    // Log reset
    db.hwid_resets.push({
        id: getNextId(db.hwid_resets),
        user_id: uid,
        username: user.username,
        old_hwid: oldHwid,
        new_hwid: null,
        reset_by: 'admin',
        reason: reason || 'Manual reset',
        reset_at: now()
    });

    saveDB(db);

    res.json({ success: true, message: 'HWID reset successfully' });
});

// Suspicious Activities
app.get('/api/admin/suspicious/list', adminAuth, (req, res) => {
    const db = loadDB();
    const { limit = 50, offset = 0, user, type } = req.query;

    let activities = db.suspicious_activities || [];

    // Filter by user
    if (user) {
        activities = activities.filter(a => a.username.toLowerCase().includes(user.toLowerCase()));
    }

    // Filter by type
    if (type) {
        activities = activities.filter(a => a.threat_type === type);
    }

    // Sort by date (newest first)
    activities.sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at));

    const total = activities.length;
    const paginatedActivities = activities.slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    // Group by threat type for stats
    const threatStats = {};
    activities.forEach(a => {
        threatStats[a.threat_type] = (threatStats[a.threat_type] || 0) + 1;
    });

    res.json({
        success: true,
        activities: paginatedActivities,
        total,
        threat_stats: threatStats,
        has_more: total > (parseInt(offset) + parseInt(limit))
    });
});

app.delete('/api/admin/suspicious/:id', adminAuth, (req, res) => {
    const { id } = req.params;
    const activityId = parseInt(id);

    const db = loadDB();
    const index = db.suspicious_activities.findIndex(a => a.id === activityId);
    if (index === -1) return res.json({ success: false, message: 'Activity not found' });

    db.suspicious_activities.splice(index, 1);
    saveDB(db);

    res.json({ success: true, message: 'Activity deleted successfully' });
});

// ===== CHAT SYSTEM =====
const CHAT_PATH = path.join(__dirname, 'chat.json');
function loadChat() {
    if (!fs.existsSync(CHAT_PATH)) return { messages: [], locked: false };
    try { return JSON.parse(fs.readFileSync(CHAT_PATH, 'utf8')); }
    catch { return { messages: [], locked: false }; }
}
function saveChat(chat) { fs.writeFileSync(CHAT_PATH, JSON.stringify(chat, null, 2)); }

// Get messages (client polls this) - refresh avatars from current user data
app.get('/api/chat/messages', (req, res) => {
    const chat = loadChat();
    const db = loadDB();
    const msgs = chat.messages.slice(-100).map(m => {
        if (m.role === 'admin') return m;
        const u = db.users.find(x => x.username === m.username);
        return { ...m, avatar: u ? (u.avatar_url || u.avatar_base64 || '') : (m.avatar || '') };
    });
    res.json(msgs);
});

// Get chat status (locked state)
app.get('/api/chat/status', (req, res) => {
    const chat = loadChat();
    res.json({ locked: chat.locked });
});

// Send message (from client)
app.post('/api/chat/send', (req, res) => {
    const { username, text } = req.body;
    if (!username || !text || text.length > 500) return res.json({ success: false });

    const chat = loadChat();
    if (chat.locked) return res.json({ success: false, locked: true });

    // Get user avatar
    const db = loadDB();
    const u = db.users.find(x => x.username === username);
    const avatar = u ? (u.avatar_url || u.avatar_base64 || '') : '';

    chat.messages.push({
        username,
        text,
        role: 'user',
        avatar,
        time: new Date().toLocaleTimeString(),
        timestamp: Date.now()
    });
    if (chat.messages.length > 200) chat.messages = chat.messages.slice(-200);
    saveChat(chat);
    res.json({ success: true });
});

// Admin: send message as "LiKinho Admin"
app.post('/api/admin/chat/send', adminAuth, (req, res) => {
    const { text } = req.body;
    if (!text) return res.json({ success: false });

    const chat = loadChat();
    chat.messages.push({
        username: 'LiKinho Admin',
        text,
        role: 'admin',
        time: new Date().toLocaleTimeString(),
        timestamp: Date.now()
    });
    if (chat.messages.length > 200) chat.messages = chat.messages.slice(-200);
    saveChat(chat);
    res.json({ success: true });
});

// Admin: clear chat
app.post('/api/admin/chat/clear', adminAuth, (req, res) => {
    const chat = loadChat();
    chat.messages = [];
    saveChat(chat);
    res.json({ success: true });
});

// Admin: lock/unlock chat
app.post('/api/admin/chat/lock', adminAuth, (req, res) => {
    const chat = loadChat();
    chat.locked = !chat.locked;
    saveChat(chat);
    res.json({ success: true, locked: chat.locked });
});

app.get('/api/users/count', (req, res) => {
    const db = loadDB();
    res.json({ success: true, count: db.sessions.length });
});

// ===== TICKET SYSTEM =====

// Create ticket (from client)
app.post('/api/tickets/create', (req, res) => {
    const { username, subject, message } = req.body;
    if (!username || !subject || !message) return res.json({ success: false, message: 'Missing fields' });

    const db = loadDB();
    const ticket = {
        id: getNextId(db.tickets),
        username,
        subject,
        status: 'open',
        created_at: now(),
        messages: [{ from: username, text: message, role: 'user', time: now() }]
    };
    db.tickets.push(ticket);
    saveDB(db);
    res.json({ success: true, ticket_id: ticket.id });
});

// Get user's tickets
app.post('/api/tickets/mine', (req, res) => {
    const { username } = req.body;
    if (!username) return res.json({ success: false });
    const db = loadDB();
    const tickets = db.tickets.filter(t => t.username === username).map(t => ({
        id: t.id, subject: t.subject, status: t.status, created_at: t.created_at,
        last_message: t.messages[t.messages.length - 1],
        message_count: t.messages.length
    }));
    res.json({ success: true, tickets });
});

// Get ticket messages
app.post('/api/tickets/messages', (req, res) => {
    const { username, ticket_id } = req.body;
    if (!username || !ticket_id) return res.json({ success: false });
    const db = loadDB();
    const ticket = db.tickets.find(t => t.id === parseInt(ticket_id) && t.username === username);
    if (!ticket) return res.json({ success: false, message: 'Ticket not found' });
    res.json({ success: true, ticket: { id: ticket.id, subject: ticket.subject, status: ticket.status, messages: ticket.messages } });
});

// Reply to ticket (from client)
app.post('/api/tickets/reply', (req, res) => {
    const { username, ticket_id, message } = req.body;
    if (!username || !ticket_id || !message) return res.json({ success: false });
    const db = loadDB();
    const ticket = db.tickets.find(t => t.id === parseInt(ticket_id) && t.username === username);
    if (!ticket || ticket.status === 'closed') return res.json({ success: false, message: 'Ticket not found or closed' });
    ticket.messages.push({ from: username, text: message, role: 'user', time: now() });
    saveDB(db);
    res.json({ success: true });
});

// Admin: list all tickets
app.get('/api/admin/tickets', adminAuth, (req, res) => {
    const db = loadDB();
    const tickets = db.tickets.map(t => ({
        id: t.id, username: t.username, subject: t.subject, status: t.status,
        created_at: t.created_at,
        last_message: t.messages[t.messages.length - 1],
        message_count: t.messages.length
    }));
    res.json({ success: true, tickets });
});

// Admin: get ticket messages
app.get('/api/admin/tickets/:id', adminAuth, (req, res) => {
    const db = loadDB();
    const ticket = db.tickets.find(t => t.id === parseInt(req.params.id));
    if (!ticket) return res.json({ success: false });
    res.json({ success: true, ticket });
});

// Admin: reply to ticket
app.post('/api/admin/tickets/:id/reply', adminAuth, (req, res) => {
    const { text } = req.body;
    if (!text) return res.json({ success: false });
    const db = loadDB();
    const ticket = db.tickets.find(t => t.id === parseInt(req.params.id));
    if (!ticket) return res.json({ success: false });
    ticket.messages.push({ from: 'LiKinho Admin', text, role: 'admin', time: now() });
    saveDB(db);
    res.json({ success: true });
});

// Admin: close ticket
app.post('/api/admin/tickets/:id/close', adminAuth, (req, res) => {
    const db = loadDB();
    const ticket = db.tickets.find(t => t.id === parseInt(req.params.id));
    if (!ticket) return res.json({ success: false });
    ticket.status = 'closed';
    saveDB(db);
    res.json({ success: true });
});

// Admin: reopen ticket
app.post('/api/admin/tickets/:id/reopen', adminAuth, (req, res) => {
    const db = loadDB();
    const ticket = db.tickets.find(t => t.id === parseInt(req.params.id));
    if (!ticket) return res.json({ success: false });
    ticket.status = 'open';
    saveDB(db);
    res.json({ success: true });
});

// Cleanup old sessions every minute
setInterval(() => {
    const db = loadDB();
    const cutoff = new Date(Date.now() - 300000).toISOString();
    const before = db.sessions.length;
    db.sessions = db.sessions.filter(s => s.last_heartbeat > cutoff);
    if (db.sessions.length !== before) saveDB(db);
}, 60000);

// Cleanup old screenshots (older than 30 days)
setInterval(() => {
    const db = loadDB();
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString();
    const before = db.suspicious_activities.length;
    db.suspicious_activities = db.suspicious_activities.filter(a => a.detected_at > cutoff);
    if (db.suspicious_activities.length !== before) {
        console.log(`Cleaned ${before - db.suspicious_activities.length} old suspicious activity logs`);
        saveDB(db);
    }
}, 86400000); // Run daily

const PORT = process.env.PORT || 3000;
const LOCAL_IP = getLocalIP();
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  LiKinho KeyAuth Server`);
    console.log(`  ─────────────────────────────`);
    console.log(`  Local:   http://localhost:${PORT}`);
    console.log(`  Network: http://${LOCAL_IP}:${PORT}`);
    console.log(`  ─────────────────────────────\n`);
});
