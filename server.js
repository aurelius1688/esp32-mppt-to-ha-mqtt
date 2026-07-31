const express = require('express');
const mqtt = require('mqtt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG_PATH = path.join(__dirname, 'config.json');
const PORT = process.env.PORT || 18080;

// ── 加密工具（AES-256-GCM）────────────────────────────
let ENC_KEY = null; // 持久化加密密钥

function encrypt(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}

function decrypt(text) {
  if (!text || typeof text !== 'string' || !text.includes(':')) return text;
  try {
    const parts = text.split(':');
    if (parts.length !== 3) return text;
    const iv = Buffer.from(parts[0], 'hex');
    const tag = Buffer.from(parts[1], 'hex');
    const enc = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc) + decipher.final();
  } catch { return text; }
}

// ── 密码管理 ──────────────────────────────────────────
let ADMIN_HASH = null;
const DEFAULT_PASS = 'admin';

function hashPassword(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = crypto.scryptSync(pass, salt, 64).toString('hex');
  return salt + ':' + key;
}

function verifyPassword(pass, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, key] = stored.split(':');
  if (!salt || !key) return false;
  const hash = crypto.scryptSync(pass, salt, 64).toString('hex');
  return key === hash;
}

function createToken() {
  const payload = JSON.stringify({ t: Date.now() });
  const hmac = crypto.createHmac('sha256', ENC_KEY).update(payload).digest('hex');
  return Buffer.from(payload).toString('base64url') + '.' + hmac;
}

function verifyToken(token) {
  try {
    if (!token || typeof token !== 'string' || !token.includes('.')) return false;
    const [b64, hmac] = token.split('.');
    if (!b64 || !hmac || hmac.length < 10) return false;
    const payload = Buffer.from(b64, 'base64url').toString();
    const expected = crypto.createHmac('sha256', ENC_KEY).update(payload).digest('hex');
    if (hmac !== expected) return false;
    const { t } = JSON.parse(payload);
    return (Date.now() - t) < 86400000;
  } catch { return false; }
}

// ── 登录频率限制 ──────────────────────────────────────
const loginAttempts = new Map();
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;

function checkRateLimit(ip) {
  const now = Date.now();
  let r = loginAttempts.get(ip);
  if (!r) {
    r = { fails: 0, lockedUntil: 0, ban: false, lockCycles: 0 };
    loginAttempts.set(ip, r);
  }
  if (r.ban) return { allowed: false, locked: true, banned: true, remaining: 0 };
  if (r.lockedUntil > now) return { allowed: false, locked: true, remaining: 0, waitMinutes: Math.ceil((r.lockedUntil - now) / 60000) };
  // 锁定期已过，只重置失败计数，保留锁周期
  if (r.fails >= MAX_FAILS) r.fails = 0;
  return { allowed: true, remaining: MAX_FAILS - r.fails };
}

function recordLoginFail(ip) {
  let r = loginAttempts.get(ip);
  if (!r) return;
  r.fails++;
  if (r.fails >= MAX_FAILS) {
    r.lockCycles++;
    if (r.lockCycles >= 2) {
      r.ban = true;
      console.log('[安全] IP已永久封禁:', ip);
    } else {
      r.lockedUntil = Date.now() + LOCK_MINUTES * 60000;
      console.log('[安全] IP锁定15分钟:', ip);
    }
  }
  console.log('[安全] IP登录失败:', ip, '累计:', r.fails, '轮次:', r.lockCycles);
}

function resetLoginAttempts(ip) {
  loginAttempts.delete(ip);
}

// ── 默认配置（请修改为你自己的设备信息）────────────────
let CFG = {
  encKey:      null,
  esp32Url:    'http://192.168.1.100:80',
  esp32User:   'admin',
  esp32Pass:   'admin',
  mqttUrl:     'mqtt://192.168.1.100:1883',
  mqttUser:    'mqtt',
  mqttPass:    'your_mqtt_password',
  interval:    3000,
  haPrefix:    'homeassistant',
  stateTopic:  'mppt/status',
  adminHash:   null,
  energyTotal: 0,
};

// 从 config.json 读取配置
try {
  const saved = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  const allowed = ['encKey','esp32Url','esp32User','esp32Pass','mqttUrl','mqttUser','mqttPass','interval','haPrefix','stateTopic','adminHash','energyTotal'];
  allowed.forEach(k => { if (saved[k] !== undefined) CFG[k] = saved[k]; });
  console.log('[配置] 已加载 config.json');
} catch { console.log('[配置] 使用默认配置'); }

// 初始化加密密钥
ENC_KEY = CFG.encKey ? Buffer.from(CFG.encKey, 'hex') : crypto.randomBytes(32);
CFG.encKey = ENC_KEY.toString('hex');

// 解密存储的密码
CFG.esp32Pass = decrypt(CFG.esp32Pass);
CFG.mqttPass  = decrypt(CFG.mqttPass);

// 初始化管理员密码
ADMIN_HASH = CFG.adminHash || hashPassword(DEFAULT_PASS);

// 保存配置（密码加密后存储）
function saveConfig() {
  const saveData = { ...CFG };
  saveData.adminHash = ADMIN_HASH;
  saveData.encKey = ENC_KEY.toString('hex');
  // 加密存储密码
  if (saveData.esp32Pass && !saveData.esp32Pass.includes(':')) {
    saveData.esp32Pass = encrypt(saveData.esp32Pass);
  }
  if (saveData.mqttPass && !saveData.mqttPass.includes(':')) {
    saveData.mqttPass = encrypt(saveData.mqttPass);
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(saveData, null, 2), 'utf8');
}

// ── CSV 字段定义 ──────────────────────────────────────
const SENSORS = [
  { key:'time',      name:'时间',            icon:'mdi:clock-outline' },
  { key:'elapsed',   name:'运行时长',         icon:'mdi:timer-outline' },
  { key:'cpu_temp',  name:'CPU温度',          unit:'°C', icon:'mdi:thermometer',       cls:'temperature' },
  { key:'err',       name:'错误码',           icon:'mdi:alert-circle-outline' },
  { key:'err_msg',   name:'错误信息',         icon:'mdi:alert' },
  { key:'reset',     name:'重启原因',         icon:'mdi:restart' },
  { key:'chg',       name:'充电状态',         icon:'mdi:battery-charging' },
  { key:'bypass',    name:'旁路',            icon:'mdi:pipe' },
  { key:'buck',      name:'Buck状态',        icon:'mdi:power-plug' },
  { key:'fan',       name:'风扇',            icon:'mdi:fan' },
  { key:'eff',       name:'效率',   unit:'%', icon:'mdi:percent',                    cls:'measurement' },
  { key:'wh',        name:'本次电量', unit:'Wh',icon:'mdi:lightning-bolt',           cls:'energy' },
  { key:'twh',       name:'累计电量', unit:'Wh',icon:'mdi:lightning-bolt-outline',   cls:'energy' },
  { key:'temp',      name:'温度',   unit:'°C', icon:'mdi:thermometer',               cls:'temperature' },
  { key:'mppt_log',  name:'MPPT日志',         icon:'mdi:message-text-outline' },
  { key:'pwm',       name:'PWM',    unit:'',   icon:'mdi:sine-wave',                  cls:'measurement' },
  { key:'ppwm',      name:'PPWM',   unit:'',   icon:'mdi:sine-wave',                  cls:'measurement' },
  { key:'pwm_d',     name:'PWM_D',  unit:'',   icon:'mdi:sine-wave',                  cls:'measurement' },
  { key:'pwm_c',     name:'PWMC',   unit:'',   icon:'mdi:sine-wave',                  cls:'measurement' },
  { key:'vin_max',   name:'最大输入电压', unit:'V', icon:'mdi:flash',                 cls:'voltage' },
  { key:'pin',       name:'输入功率', unit:'W', icon:'mdi:flash-outline',             cls:'power' },
  { key:'vin',       name:'输入电压', unit:'V', icon:'mdi:flash',                     cls:'voltage' },
  { key:'iin',       name:'输入电流', unit:'A', icon:'mdi:current-ac',                cls:'current' },
  { key:'pout',      name:'输出功率', unit:'W', icon:'mdi:flash-outline',             cls:'power' },
  { key:'vout',      name:'输出电压', unit:'V', icon:'mdi:battery',                   cls:'voltage' },
  { key:'iout',      name:'输出电流', unit:'A', icon:'mdi:current-ac',                cls:'current' },
  { key:'loop',      name:'循环耗时', unit:'ms',icon:'mdi:timer-sand',                cls:'measurement' },
  { key:'energy_daily',  name:'每日发电量', unit:'kWh', icon:'mdi:solar-power',        cls:'energy' },
  { key:'energy_total',  name:'累计发电量', unit:'kWh', icon:'mdi:solar-power',        cls:'energy' },
];

// ── MQTT 管理 ─────────────────────────────────────────
let mqttClient = null;
let mqttReady = false;

function connectMQTT() {
  if (mqttClient) {
    try { mqttClient.end(true); } catch {}
    mqttClient = null;
  }
  mqttReady = false;
  mqttClient = mqtt.connect(CFG.mqttUrl, {
    username: CFG.mqttUser,
    password: CFG.mqttPass,
    will: { topic: `${CFG.stateTopic}/online`, payload: 'offline', retain: true },
  });
  mqttClient.on('connect', () => {
    console.log('[MQTT] 已连接', CFG.mqttUrl);
    mqttReady = true;
    mqttClient.publish(`${CFG.stateTopic}/online`, 'online', { retain: true });
    publishDiscovery();
  });
  mqttClient.on('error', e => console.error('[MQTT] 错误:', e.message));
  mqttClient.on('close', () => { mqttReady = false; });
}

// ── HA 自动发现 ──────────────────────────────────────
function publishDiscovery() {
  if (!mqttReady) return;
  SENSORS.forEach(s => {
    if (!s.unit) return;
    const uid = `mppt_${s.key}`;
    mqttClient.publish(`${CFG.haPrefix}/sensor/${uid}/config`, JSON.stringify({
      name: `MPPT ${s.name}`,
      state_topic: CFG.stateTopic,
      unit_of_measurement: s.unit,
      value_template: `{{ value_json.${s.key} }}`,
      unique_id: uid, device_class: s.cls, icon: s.icon,
      device: { identifiers: ['esp32_mppt'], name: 'ESP32 MPPT 控制器', model: 'MPPT V2.1', manufacturer: 'ESP32 MPPT' },
    }), { retain: true });
  });
  ['chg','bypass','buck','fan'].forEach(k => {
    const uid = `mppt_${k}`;
    const names = { chg:'充电状态', bypass:'旁路', buck:'Buck运行', fan:'风扇' };
    mqttClient.publish(`${CFG.haPrefix}/binary_sensor/${uid}/config`, JSON.stringify({
      name: `MPPT ${names[k]}`, state_topic: CFG.stateTopic,
      value_template: `{{ value_json.${k} }}`, unique_id: uid,
      payload_on: '1', payload_off: '0',
      device_class: k==='fan'?'running': k==='chg'?'battery_charging':'power',
      device: { identifiers: ['esp32_mppt'], name:'ESP32 MPPT 控制器' },
    }), { retain: true });
  });
  console.log('[MQTT] HA 自动发现已发布');
}

// ── 解析 CSV ─────────────────────────────────────────
function parseCSV(text) {
  const a = text.split(',');
  if (a.length < 14) return null;
  const g = (i) => a[i] !== undefined ? a[i] : '0';
  return {
    time: g(0), elapsed: g(1), cpu_temp: parseFloat(g(2)),
    err: parseInt(g(3)), err_msg: g(4).trim(), reset: g(5).trim(),
    chg: parseInt(g(6)), bypass: parseInt(g(7)), buck: parseInt(g(8)), fan: parseInt(g(9)),
    eff: g(10)==='inf'||g(10)==='nan' ? null : parseFloat(g(10)),
    wh: parseFloat(g(11)), twh: parseFloat(g(12)), temp: parseFloat(g(13)),
    mppt_log: g(14).trim(), pwm: parseFloat(g(15)), ppwm: parseFloat(g(16)),
    pwm_d: parseFloat(g(17)), pwm_c: parseFloat(g(18)), vin_max: parseFloat(g(19)),
    pin: parseFloat(g(20)), vin: parseFloat(g(21)), iin: parseFloat(g(22)),
    pout: parseFloat(g(23)), vout: parseFloat(g(24)), iout: parseFloat(g(25)),
    loop: parseFloat(g(26)),
  };
}

// ── ESP32 轮询 ───────────────────────────────────────
// ── ESP32 轮询 ───────────────────────────────────────
let latestData = {};
let pollTimer = null;
let esp32Online = false;
let energyDaily = 0;
let energyTotal = CFG.energyTotal || 0;
let lastDay = new Date().getDate();
let energySaveTimer = null;

function checkDayReset() {
  const now = new Date();
  if (now.getDate() !== lastDay) {
    energyDaily = 0;
    lastDay = now.getDate();
    console.log('[电量] 新的一天，重置每日发电量');
  }
}

async function fetchESP32() {
  const auth = Buffer.from(`${CFG.esp32User}:${CFG.esp32Pass}`).toString('base64');
  try {
    const res = await fetch(`${CFG.esp32Url}/update`, {
      headers: { Authorization: `Basic ${auth}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const data = parseCSV(text);
    if (!data) throw new Error('解析失败');
    
    checkDayReset();
    const pout = data.pout || 0;
    if (pout > 0) {
      const dt_h = CFG.interval / 3600000.0;
      energyDaily += pout * dt_h;
      energyTotal += pout * dt_h;
    }
    data.energy_daily = parseFloat((energyDaily / 1000).toFixed(6));
    data.energy_total = parseFloat((energyTotal / 1000).toFixed(6));
    
    latestData = data;
    esp32Online = true;
    if (mqttReady) mqttClient.publish(CFG.stateTopic, JSON.stringify(data));
    notifyClients(data);
  } catch (e) {
    esp32Online = false;
    console.error('[ESP32] 获取失败:', e.message);
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  fetchESP32();
  pollTimer = setInterval(fetchESP32, CFG.interval);
  if (energySaveTimer) clearInterval(energySaveTimer);
  energySaveTimer = setInterval(() => {
    CFG.energyTotal = energyTotal;
    saveConfig();
  }, 300000);
}

// ── SSE ──────────────────────────────────────────────
const sseClients = new Set();
function notifyClients(data) {
  const msg = JSON.stringify({ ...data, _esp32Online: esp32Online, _mqttReady: mqttReady });
  sseClients.forEach(res => res.write(`data: ${msg}\n\n`));
}

// ── Web 服务器 ──────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.static('public'));
app.get('/favicon.ico', (req, res) => res.redirect('/icon.ico'));

// 认证中间件
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ') || !verifyToken(auth.slice(7))) {
    return res.status(401).json({ error: '未登录' });
  }
  next();
}

// ── 登录 ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const limit = checkRateLimit(ip);
  if (!limit.allowed) {
    const msg = limit.locked ? '密码错误次数过多，请在' + limit.waitMinutes + '分钟后重试' : '登录尝试过多';
    return res.status(429).json({ success: false, error: msg, locked: true, waitMinutes: limit.waitMinutes });
  }
  const { password } = req.body;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ success: false, error: '请输入密码', remaining: limit.remaining });
  }
  if (verifyPassword(password, ADMIN_HASH)) {
    resetLoginAttempts(ip);
    res.json({ success: true, token: createToken() });
  } else {
    recordLoginFail(ip);
    const r = loginAttempts.get(ip);
    if (r.ban) {
      res.status(429).json({ success: false, error: '该IP已被永久封禁', locked: true, banned: true });
    } else if (r.lockedUntil > Date.now()) {
      const wait = Math.ceil((r.lockedUntil - Date.now()) / 60000);
      res.status(429).json({ success: false, error: '密码错误次数过多，请在' + wait + '分钟后重试', locked: true, waitMinutes: wait });
    } else {
      const remaining = MAX_FAILS - r.fails;
      res.status(403).json({ success: false, error: '密码错误，剩余尝试次数: ' + remaining, remaining: remaining });
    }
  }
});

app.get('/api/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache',
    Connection: 'keep-alive', 'Access-Control-Allow-Origin': '*',
  });
  res.write(`data: ${JSON.stringify({ ...latestData, _esp32Online: esp32Online, _mqttReady: mqttReady })}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

app.get('/api/data', (req, res) => res.json(latestData));

// ── 设置接口（需登录）─────────────────────────────────
app.get('/api/settings', requireAuth, (req, res) => {
  res.json({
    esp32Url: CFG.esp32Url,
    esp32User: CFG.esp32User,
    esp32Pass: '****',
    mqttUrl: CFG.mqttUrl,
    mqttUser: CFG.mqttUser,
    mqttPass: '****',
    interval: CFG.interval,
    stateTopic: CFG.stateTopic,
    _esp32Online: esp32Online,
    _mqttReady: mqttReady,
  });
});

app.post('/api/settings', requireAuth, (req, res) => {
  const body = req.body;
  let changed = false;

  if (body.adminPassword && body.adminPassword !== '****') {
    if (body.adminPassword.length < 6) return res.status(400).json({ success: false, message: '密码至少6位' });
    ADMIN_HASH = hashPassword(body.adminPassword);
    changed = true;
  }
  if (body.esp32Url && typeof body.esp32Url === 'string' && body.esp32Url !== CFG.esp32Url) { CFG.esp32Url = body.esp32Url.replace(/\/+$/, ''); changed = true; }
  if (body.esp32User && typeof body.esp32User === 'string' && body.esp32User !== CFG.esp32User) { CFG.esp32User = body.esp32User; changed = true; }
  if (body.esp32Pass && typeof body.esp32Pass === 'string' && body.esp32Pass !== '****') { CFG.esp32Pass = body.esp32Pass; changed = true; }

  const mqttChanged = body.mqttUrl && typeof body.mqttUrl === 'string' && body.mqttUrl !== CFG.mqttUrl;
  if (body.mqttUrl && typeof body.mqttUrl === 'string' && body.mqttUrl !== CFG.mqttUrl) { 
    if (!body.mqttUrl.startsWith('mqtt://') && !body.mqttUrl.startsWith('mqtts://')) 
      return res.status(400).json({ success: false, message: 'MQTT地址格式错误' });
    CFG.mqttUrl = body.mqttUrl; changed = true; 
  }
  if (body.mqttUser && typeof body.mqttUser === 'string' && body.mqttUser !== CFG.mqttUser) { CFG.mqttUser = body.mqttUser; changed = true; }
  if (body.mqttPass && typeof body.mqttPass === 'string' && body.mqttPass !== '****') { CFG.mqttPass = body.mqttPass; changed = true; }

  if (body.interval && parseInt(body.interval) >= 1000) { CFG.interval = parseInt(body.interval); changed = true; }
  if (body.stateTopic && typeof body.stateTopic === 'string') { CFG.stateTopic = body.stateTopic; changed = true; }

  if (!changed) return res.json({ success: true, message: '无变更' });

  saveConfig();
  console.log('[配置] 已更新，重新连接...');

  // 重启 ESP32 轮询
  startPolling();

  // 如果 MQTT 配置变了，重连
  if (mqttChanged || body.mqttUser || (body.mqttPass && body.mqttPass !== '****')) {
    setTimeout(() => connectMQTT(), 500);
  } else {
    // 只重新发布发现
    publishDiscovery();
  }

  res.json({ success: true, message: '配置已更新' });
});

// ── 测试连接（需登录）─────────────────────────────────
app.post('/api/test-esp32', requireAuth, async (req, res) => {
  const { url, user, pass } = req.body;
  const auth = Buffer.from(`${user||CFG.esp32User}:${pass||CFG.esp32Pass}`).toString('base64');
  try {
    const r = await fetch(`${url||CFG.esp32Url}/update`, {
      headers: { Authorization: `Basic ${auth}` },
      signal: AbortSignal.timeout(5000),
    });
    const text = await r.text();
    const data = parseCSV(text);
    res.json({ success: !!data, data: data ? { vin: data.vin, vout: data.vout, pin: data.pin } : null, raw: text.substring(0, 100) });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

app.post('/api/test-mqtt', requireAuth, (req, res) => {
  const { url, user, pass } = req.body;
  const testClient = mqtt.connect(url || CFG.mqttUrl, {
    username: user || CFG.mqttUser,
    password: pass || CFG.mqttPass,
  });
  const timer = setTimeout(() => {
    testClient.end(true);
    res.json({ success: false, error: '连接超时' });
  }, 5000);
  testClient.on('connect', () => {
    clearTimeout(timer);
    testClient.end(true);
    res.json({ success: true });
  });
  testClient.on('error', e => {
    clearTimeout(timer);
    testClient.end(true);
    res.json({ success: false, error: e.message });
  });
});

// ── ESP32 控制命令（需登录）───────────────────────────
app.post('/api/control', requireAuth, async (req, res) => {
  const { type, index, operation } = req.body;
  if (type === undefined || operation === undefined) {
    return res.status(400).json({ success: false, error: '缺少参数' });
  }
  const auth = Buffer.from(`${CFG.esp32User}:${CFG.esp32Pass}`).toString('base64');
  const url = `${CFG.esp32Url}/Control?Type=${type}&Index=${index||0}&Operation=${operation}`;
  try {
    const r = await fetch(url, {
      headers: { Authorization: `Basic ${auth}` },
      signal: AbortSignal.timeout(5000),
    });
    const text = await r.text();
    res.json({ success: r.ok, response: text.substring(0, 200) });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// ── 启动 ─────────────────────────────────────────────
connectMQTT();
startPolling();

function startServer(port) {
  const srv = app.listen(port);
  srv.on('listening', () => {
    console.log(`\n=== MPPT MQTT Bridge ===`);
    console.log(`Web 面板: http://localhost:${port}`);
    console.log(`MQTT: ${CFG.mqttUrl} -> ${CFG.stateTopic}`);
    console.log(`ESP32: ${CFG.esp32Url}\n`);
  });
  srv.on('error', (err) => {
    if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
      const guess = port + 1;
      console.log(`[端口] ${port} 不可用，尝试 ${guess}...`);
      if (guess - PORT > 100) {
        console.error('[端口] 无法找到可用端口，请用 set PORT=xxx 指定端口后重试');
        return;
      }
      startServer(guess);
    } else {
      console.error('[启动失败]', err.message);
    }
  });
}

startServer(PORT);