// ============================================================================
// MPPT 太阳能控制器 - MQTT 桥接服务 (完美稳定版 + 年度账单)
// ============================================================================
//Edit by Aurelius1688 晴若晓溪 
process.env.TZ = process.env.TZ || 'Asia/Shanghai';

const express = require('express');
const mqtt = require('mqtt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ── 运行路径 ──
const isPkg = typeof process.pkg !== 'undefined';
const EXE_DIR = isPkg ? path.dirname(process.execPath) : __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(EXE_DIR, 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const KEY_PATH = path.join(DATA_DIR, 'enc.key');
const MONTHLY_PATH = path.join(DATA_DIR, 'monthly_stats.json'); // [新增] 月度账本
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT) || 18080;
const BUILD_ID = '2026-11-13-stable';

// ── 版本指纹 ──
const UI_META_RE = /<meta\s+name=["']mppt-ui-build["']\s+content=["']([^"']+)["']/;
function readUiBuild() {
  try {
    const m = UI_META_RE.exec(fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8'));
    return m ? m[1] : 'unknown';
  } catch { return 'missing'; }
}
const UI_BUILD = readUiBuild();
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}

// ── 加密工具 ──
let ENC_KEY = null;
const ENC_RE = /^[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/;
function encrypt(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + cipher.getAuthTag().toString('hex') + ':' + enc.toString('hex');
}
function decrypt(text) {
  if (!text || typeof text !== 'string' || !ENC_RE.test(text)) return text;
  try {
    const parts = text.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(parts[0], 'hex'));
    decipher.setAuthTag(Buffer.from(parts[1], 'hex'));
    return decipher.update(Buffer.from(parts[2], 'hex')) + decipher.final();
  } catch { return text; }
}

// ── 密码与安全 ──
let ADMIN_HASH = null;
const LEGACY_PASSES = ['admin', 'change-this-now', 'admin123'];
function generateRandomPassword() { return crypto.randomBytes(12).toString('base64url'); }
function hashPassword(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pass, salt, 64).toString('hex');
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a ?? '')), bb = Buffer.from(String(b ?? ''));
  if (ba.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ba, bb); } catch { return false; }
}
function verifyPassword(pass, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, key] = stored.split(':');
  return safeEqual(key, crypto.scryptSync(pass, salt, 64).toString('hex'));
}
function createToken() {
  const payload = JSON.stringify({ t: Date.now() });
  return Buffer.from(payload).toString('base64url') + '.' + crypto.createHmac('sha256', ENC_KEY).update(payload).digest('hex');
}
function verifyToken(token) {
  try {
    const [b64, hmac] = token.split('.');
    if (safeEqual(hmac, crypto.createHmac('sha256', ENC_KEY).update(Buffer.from(b64, 'base64url').toString()).digest('hex'))) {
      return (Date.now() - JSON.parse(Buffer.from(b64, 'base64url').toString()).t) < 86400000;
    }
  } catch { return false; }
  return false;
}

const loginAttempts = new Map();
const controlLast = new Map();
function checkRateLimit(ip) {
  const now = Date.now(); let r = loginAttempts.get(ip) || { fails: 0, lockedUntil: 0, ban: false, lastSeen: now };
  r.lastSeen = now; loginAttempts.set(ip, r);
  if (r.ban) return { allowed: false, locked: true, banned: true };
  if (r.lockedUntil > now) return { allowed: false, locked: true, waitMinutes: Math.ceil((r.lockedUntil - now) / 60000) };
  return { allowed: true, remaining: 5 - r.fails };
}
function recordLoginFail(ip) {
  let r = loginAttempts.get(ip); if (!r) return;
  r.fails++;
  if (r.fails >= 5) { r.ban = true; console.log('[安全] IP已永久封禁:', ip); }
}
function resetLoginAttempts(ip) { loginAttempts.delete(ip); }

const cleanMapTimer = setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginAttempts) if (!r.ban && r.fails === 0 && now - (r.lastSeen || 0) > 3600000) loginAttempts.delete(ip);
  for (const [ip, t] of controlLast) if (now - t > 3600000) controlLast.delete(ip);
}, 1800000);
cleanMapTimer.unref();

// ── 默认配置 ──
let CFG = {
  encKey: null, esp32Url: 'http://192.168.1.100', esp32User: 'admin', esp32Pass: 'admin',
  mqttUrl: 'mqtt://192.168.1.100:1883', mqttUser: 'mqtt', mqttPass: '',
  interval: 1000, haPrefix: 'homeassistant', stateTopic: 'mppt/status', cmdTopic: 'mppt/cmd/' + crypto.randomBytes(4).toString('hex'),
  restartPayload: crypto.randomBytes(8).toString('hex'), weatherCity: '', csvFormat: 'auto', adminHash: null,
  
  energyTotalWh: 0,
  energyDailyWh: 0,
  energyYesterdayWh: 0,
  energyDate: ''
};

function todayStr() { return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10); }

function loadOrCreateKey() {
  if (process.env.ENC_KEY && /^[0-9a-f]{64}$/i.test(process.env.ENC_KEY)) return Buffer.from(process.env.ENC_KEY, 'hex');
  try {
    const s = fs.readFileSync(KEY_PATH, 'utf8').trim();
    if (/^[0-9a-f]{64}$/i.test(s)) return Buffer.from(s, 'hex');
  } catch {}
  if (CFG.encKey && /^[0-9a-f]{64}$/i.test(CFG.encKey)) {
    try { fs.writeFileSync(KEY_PATH, CFG.encKey, { mode: 0o600 }); } catch {}
    return Buffer.from(CFG.encKey, 'hex');
  }
  const k = crypto.randomBytes(32);
  try { fs.writeFileSync(KEY_PATH, k.toString('hex'), { mode: 0o600 }); } catch {}
  return k;
}

let firstRun = false;
try {
  const saved = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  ['esp32Url','esp32User','esp32Pass','mqttUrl','mqttUser','mqttPass','interval','stateTopic','cmdTopic','restartPayload','adminHash','energyTotalWh','energyDailyWh','energyYesterdayWh','energyDate','weatherCity','csvFormat'].forEach(k => { if (saved[k] !== undefined) CFG[k] = saved[k]; });
} catch { firstRun = true; }

ENC_KEY = loadOrCreateKey();
CFG.esp32Pass = decrypt(CFG.esp32Pass);
CFG.mqttPass = decrypt(CFG.mqttPass);

if (!CFG.adminHash || LEGACY_PASSES.some(p => verifyPassword(p, CFG.adminHash))) {
  const p = process.env.ADMIN_PASSWORD || generateRandomPassword();
  CFG.adminHash = hashPassword(p);
  console.log('========================================');
  console.log('[安全] 管理员密码已重置为:', p);
  console.log('========================================');
  firstRun = true;
}
ADMIN_HASH = CFG.adminHash;

function saveConfig() {
  const saveData = { ...CFG, adminHash: ADMIN_HASH };
  delete saveData.encKey;
  if (saveData.esp32Pass && !ENC_RE.test(saveData.esp32Pass)) saveData.esp32Pass = encrypt(saveData.esp32Pass);
  if (saveData.mqttPass && !ENC_RE.test(saveData.mqttPass)) saveData.mqttPass = encrypt(saveData.mqttPass);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(saveData, null, 2), 'utf8');
}
if (firstRun) saveConfig();

// ── [新增] 年度账单数据加载 ──
let MONTHLY_STATS = {};
try {
  if (fs.existsSync(MONTHLY_PATH)) MONTHLY_STATS = JSON.parse(fs.readFileSync(MONTHLY_PATH, 'utf8'));
} catch (e) { console.error('[月度数据] 加载失败:', e.message); }
function saveMonthlyStats() {
  try { fs.writeFileSync(MONTHLY_PATH, JSON.stringify(MONTHLY_STATS, null, 2), 'utf8'); } catch (e) {}
}

// ── HA 自动发现配置 ──
const SENSORS = [
  { key:'cpu_temp',  name:'CPU温度', unit:'°C', icon:'mdi:thermometer', cls:'temperature' },
  { key:'temp',      name:'温度', unit:'°C', icon:'mdi:thermometer', cls:'temperature' },
  { key:'eff',       name:'效率', unit:'%', icon:'mdi:percent' },
  { key:'pin',       name:'输入功率', unit:'W', icon:'mdi:flash-outline', cls:'power' },
  { key:'vin',       name:'输入电压', unit:'V', icon:'mdi:flash', cls:'voltage' },
  { key:'iin',       name:'输入电流', unit:'A', icon:'mdi:current-ac', cls:'current' },
  { key:'pout',      name:'输出功率', unit:'W', icon:'mdi:flash-outline', cls:'power' },
  { key:'vout',      name:'输出电压', unit:'V', icon:'mdi:battery', cls:'voltage' },
  { key:'iout',      name:'输出电流', unit:'A', icon:'mdi:current-ac', cls:'current' },
  { key:'loop',      name:'循环耗时', unit:'ms', icon:'mdi:timer-sand' },
  { key:'vin_max',   name:'最大输入电压', unit:'V', icon:'mdi:flash', cls:'voltage' },
  { key:'pwm',       name:'PWM', unit:'', icon:'mdi:sine-wave' },
  { key:'ppwm',      name:'PPWM', unit:'', icon:'mdi:sine-wave' },
  { key:'wh',        name:'本次电量', unit:'Wh', icon:'mdi:lightning-bolt', cls:'energy' },
  { key:'twh',       name:'累计电量', unit:'Wh', icon:'mdi:lightning-bolt-outline', cls:'energy' },
  { key:'energy_daily',  name:'每日发电量', unit:'kWh', icon:'mdi:solar-power', cls:'energy', state_cls: 'total' },
  { key:'energy_yesterday', name:'昨日发电量', unit:'kWh', icon:'mdi:solar-power', cls:'energy', state_cls: 'total' },
  { key:'energy_total',  name:'累计发电量', unit:'kWh', icon:'mdi:solar-power', cls:'energy', state_cls: 'total_increasing' },
];

let mqttClient = null, mqttReady = false;
let lastRestartCmd = 0;

function connectMQTT() {
  if (mqttClient) try { mqttClient.end(true); } catch {}
  mqttReady = false;
  
  const clientId = 'mppt_bridge_' + crypto.randomBytes(4).toString('hex');
  
  mqttClient = mqtt.connect(CFG.mqttUrl, { 
    clientId: clientId,
    username: CFG.mqttUser, 
    password: CFG.mqttPass, 
    will: { topic: `${CFG.stateTopic}/online`, payload: 'offline', retain: true },
    connectTimeout: 5000,
    reconnectPeriod: 5000
  });
  
  mqttClient.on('connect', () => {
    console.log('[MQTT] 已连接', CFG.mqttUrl);
    mqttReady = true;
    mqttClient.publish(`${CFG.stateTopic}/online`, 'online', { retain: true });
    mqttClient.subscribe(`${CFG.cmdTopic}/restart`, { qos: 0 });
    publishDiscovery();
  });
  
  mqttClient.on('message', (topic, message) => {
    if (topic === `${CFG.cmdTopic}/restart` && message.toString().trim() === CFG.restartPayload) {
      if (Date.now() - lastRestartCmd < 5000) return;
      lastRestartCmd = Date.now();
      sendControl(9, 0, 2, 'Home Assistant');
    }
  });
  
  mqttClient.on('error', e => console.error('[MQTT] 错误:', e.message));
  mqttClient.on('close', () => { mqttReady = false; console.log('[MQTT] 连接已断开'); });
}

function publishDiscovery() {
  if (!mqttReady) return;
  const avail = { availability_topic: `${CFG.stateTopic}/online`, payload_available: 'online', payload_not_available: 'offline' };
  const dev = { identifiers: ['esp32_mppt'], name: 'ESP32 MPPT 控制器', model: 'MPPT V2.1', manufacturer: 'ESP32 MPPT' };
  
  SENSORS.forEach(s => {
    mqttClient.publish(`${CFG.haPrefix}/sensor/mppt_${s.key}/config`, JSON.stringify({
      name: `MPPT ${s.name}`, state_topic: CFG.stateTopic, unit_of_measurement: s.unit,
      value_template: `{{ value_json.${s.key} }}`, unique_id: `mppt_${s.key}`,
      ...(s.cls ? { device_class: s.cls } : {}),
      icon: s.icon, state_class: s.state_cls || 'measurement',
      ...avail, device: dev
    }), { retain: true });
  });
  
  ['chg','bypass','buck','fan'].forEach(k => {
    const names = { chg:'充电状态', bypass:'旁路', buck:'Buck运行', fan:'风扇' };
    mqttClient.publish(`${CFG.haPrefix}/binary_sensor/mppt_${k}/config`, JSON.stringify({
      name: `MPPT ${names[k]}`, state_topic: CFG.stateTopic, value_template: `{{ value_json.${k} }}`,
      unique_id: `mppt_${k}`, payload_on: '1', payload_off: '0',
      device_class: k==='fan'?'running': k==='chg'?'battery_charging':'power', ...avail, device: dev
    }), { retain: true });
  });
  
  mqttClient.publish(`${CFG.haPrefix}/button/mppt_restart_esp32/config`, JSON.stringify({
    name: 'MPPT 重启 ESP32', command_topic: `${CFG.cmdTopic}/restart`, payload_press: CFG.restartPayload,
    unique_id: 'mppt_restart_esp32', device_class: 'restart', icon: 'mdi:restart', ...avail, device: dev
  }), { retain: true });
  console.log('[MQTT] HA 自动发现已发布（全字段）');
}

// ── 解析 CSV ──
let csvFormatDetected = 'unknown';
function num(v) {
  const s = String(v === undefined || v === null ? '' : v).trim();
  if (!s || /^(inf|-inf|nan)$/i.test(s)) return null;
  const x = Number(s);
  return Number.isFinite(x) ? x : null;
}
function intVal(v) { const x = num(v); return x === null ? null : Math.trunc(x); }

function parseCSV(text, forceFormat) {
  const a = String(text || '').trim().split(',').map(s => s.trim());
  while (a.length && a[a.length - 1] === '') a.pop();
  if (a.length < 14) return null;
  const fmt = (forceFormat === 'standard' || forceFormat === 'qingcai') ? forceFormat : (a.length >= 27 ? 'standard' : a.length === 26 ? 'qingcai' : 'standard');
  csvFormatDetected = fmt + '/' + a.length;
  const g = (i) => a[i] !== undefined ? a[i] : '0';

  if (fmt === 'qingcai') {
    return {
      time: g(0), elapsed: g(1), cpu_temp: num(g(2)),
      err: intVal(g(3)), err_msg: g(4), reset: '',
      chg: intVal(g(5)), bypass: intVal(g(6)), buck: intVal(g(7)), fan: intVal(g(8)),
      eff: num(g(9)), wh: num(g(10)), twh: num(g(11)), temp: num(g(12)),
      mppt_log: g(13), pwm: num(g(14)), ppwm: num(g(15)),
      pwm_d: num(g(16)), pwm_c: num(g(17)), vin_max: num(g(18)),
      pin: num(g(19)), vin: num(g(20)), iin: num(g(21)),
      pout: num(g(22)), vout: num(g(23)), iout: num(g(24)), loop: num(g(25)),
    };
  }
  return {
    time: g(0), elapsed: g(1), cpu_temp: num(g(2)),
    err: intVal(g(3)), err_msg: g(4), reset: g(5),
    chg: intVal(g(6)), bypass: intVal(g(7)), buck: intVal(g(8)), fan: intVal(g(9)),
    eff: num(g(10)), wh: num(g(11)), twh: num(g(12)), temp: num(g(13)),
    mppt_log: g(14), pwm: num(g(15)), ppwm: num(g(16)),
    pwm_d: num(g(17)), pwm_c: num(g(18)), vin_max: num(g(19)),
    pin: num(g(20)), vin: num(g(21)), iin: num(g(22)),
    pout: num(g(23)), vout: num(g(24)), iout: num(g(25)), loop: num(g(26)),
  };
}

// ── 历史记录 ──
const HISTORY_DIR = path.join(DATA_DIR, 'history');
const HISTORY_BUCKET = 60 * 1000;
const HISTORY_KEYS = ['pin','pout','iin','iout','vin','vout','eff','temp'];
try { fs.mkdirSync(HISTORY_DIR, { recursive: true }); } catch (e) {}

function historyPath(day) { return path.join(HISTORY_DIR, day + '.json'); }
function loadHistory(day) { try { const o = JSON.parse(fs.readFileSync(historyPath(day), 'utf8')); return Array.isArray(o.points) ? o.points : []; } catch { return []; } }
function bucketStart(ts) { return Math.floor(ts / HISTORY_BUCKET) * HISTORY_BUCKET; }
function clockUTC8(ts) { return new Date(ts + 8 * 3600 * 1000).toISOString().slice(11, 16); }
function historyPeak(points, key) {
  let best = null;
  for (const p of points) { const raw = p && (p[key + 'Max'] !== undefined ? p[key + 'Max'] : p[key]); const v = Number(raw); if (Number.isFinite(v) && (!best || v > best.value)) best = { value: v, at: p.t }; }
  return best;
}

let historyDay = todayStr();
let historyPoints = loadHistory(historyDay);
let historyDirty = false;
let historyLastFlush = 0;

function recordHistory(data, ts) {
  const day = todayStr();
  if (day !== historyDay) { flushHistory(true); historyDay = day; historyPoints = loadHistory(day); }
  const t = bucketStart(ts);
  let b = historyPoints[historyPoints.length - 1];
  if (!b || b.t !== t) { b = { t, n: 0, ms: 0 }; HISTORY_KEYS.forEach(k => { b[k] = 0; b[k + 'Max'] = 0; }); historyPoints.push(b); }
  b.n++;
  b.ms = (b.ms || 0) + (CFG.interval || 1000);
  HISTORY_KEYS.forEach(k => {
    const v = Number(data[k]); if (!Number.isFinite(v)) return;
    if (b.n === 1) { b[k] = v; b[k + 'Max'] = v; } else { b[k] = (b[k] * (b.n - 1) + v) / b.n; b[k + 'Max'] = Math.max(b[k + 'Max'], v); }
  });
  historyDirty = true;
  const now = Date.now();
  if (now - historyLastFlush >= 2000) { flushHistory(true); historyLastFlush = now; }
}
function flushHistory(force) {
  if (!historyDirty && !force) return;
  try { fs.writeFileSync(historyPath(historyDay), JSON.stringify({ date: historyDay, points: historyPoints })); historyDirty = false; } catch {}
}
const HISTORY_KEEP_DAYS = 30;
function pruneHistory() {
  try {
    const cutoff = new Date(Date.now() + 8 * 3600 * 1000 - HISTORY_KEEP_DAYS * 86400000).toISOString().slice(0, 10);
    for (const f of fs.readdirSync(HISTORY_DIR)) if (f.match(/^\d{4}-\d{2}-\d{2}\.json$/) && f.slice(0, 10) < cutoff) fs.unlinkSync(path.join(HISTORY_DIR, f));
  } catch {}
}
pruneHistory();

const pruneTimer = setInterval(pruneHistory, 3600000);
pruneTimer.unref();

const DAILY_MIN_W = 20;
function summarizeDay(points) {
  let energyKwh = 0, effMs = 0, samples = 0, peak = null;
  for (const p of points) {
    const ms = Number(p.ms) || HISTORY_BUCKET, out = Number(p.pout);
    if (Number.isFinite(out)) { energyKwh += out * ms / 3600000 / 1000; if (out >= DAILY_MIN_W) effMs += ms; }
    const pv = Number(p.pinMax !== undefined ? p.pinMax : p.pin); if (Number.isFinite(pv) && (!peak || pv > peak.value)) peak = { value: pv, at: p.t };
    samples += Number(p.n) || 0;
  }
  return { energyKwh: parseFloat(energyKwh.toFixed(4)), peakW: peak ? parseFloat(peak.value.toFixed(1)) : null, peakAt: peak ? clockUTC8(peak.at) : null, hours: parseFloat((effMs / 3600000).toFixed(2)), samples };
}
function dailyRows(days) {
  const span = Math.max(1, Math.min(HISTORY_KEEP_DAYS, parseInt(days, 10) || HISTORY_KEEP_DAYS));
  const base = Date.now() + 8 * 3600 * 1000, rows = [];
  for (let i = span - 1; i >= 0; i--) {
    const day = new Date(base - i * 86400000).toISOString().slice(0, 10);
    const row = day === historyDay ? summarizeDay(historyPoints) : summarizeDay(loadHistory(day));
    rows.push(row && row.samples ? { date: day, ...row, empty: false } : { date: day, energyKwh: 0, peakW: null, peakAt: null, hours: 0, samples: 0, empty: true });
  }
  return rows;
}
function dailyStats(rows) {
  const live = rows.filter(r => !r.empty), totalKwh = live.reduce((a, r) => a + r.energyKwh, 0);
  let best = null; for (const r of live) if (!best || r.energyKwh > best.energyKwh) best = r;
  return { keepDays: HISTORY_KEEP_DAYS, rangeDays: rows.length, daysWithData: live.length, totalKwh: parseFloat(totalKwh.toFixed(3)), avgKwh: parseFloat((live.length ? totalKwh / live.length : 0).toFixed(3)), bestDate: best ? best.date : null, bestKwh: best ? best.energyKwh : 0, peakW: live.reduce((a, r) => Math.max(a, r.peakW || 0), 0) };
}

// ── 核心：ESP32 轮询与后端积分统计 ──
let latestData = {};
let lastUpdate = 0, lastPollTime = 0, pollTimer = null, esp32Online = false, energySaveTimer = null;

function checkDayReset() {
  const d = todayStr();
  if (CFG.energyDate && CFG.energyDate !== d) {
    console.log(`[电量] 跨天结算: ${CFG.energyDate} -> ${d}`);
    
    // [新增] 将昨天的电量存入月账本 (取昨天的年月，防止月初第一天算错)
    const yMonth = CFG.energyDate.slice(0, 7);
    MONTHLY_STATS[yMonth] = (MONTHLY_STATS[yMonth] || 0) + (CFG.energyDailyWh / 1000);
    saveMonthlyStats();
    
    CFG.energyYesterdayWh = CFG.energyDailyWh;
    CFG.energyDailyWh = 0;
    CFG.energyDate = d;
    saveConfig();
  } else if (!CFG.energyDate) {
    CFG.energyDate = d;
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
    const data = parseCSV(text, CFG.csvFormat);
    if (!data) throw new Error('解析失败');
    
    checkDayReset();
    
    const now = Date.now();
    const pout = data.pout || 0;
    
    if (pout > 0) {
      let dt_sec = lastPollTime ? (now - lastPollTime) / 1000 : CFG.interval / 1000;
      dt_sec = Math.min(dt_sec, 60);
      
      const addedWh = pout * (dt_sec / 3600);
      CFG.energyDailyWh += addedWh;
      CFG.energyTotalWh += addedWh;
    }
    lastPollTime = now;

    data.energy_daily = parseFloat((CFG.energyDailyWh / 1000).toFixed(3));
    data.energy_yesterday = parseFloat((CFG.energyYesterdayWh / 1000).toFixed(3));
    data.energy_total = parseFloat((CFG.energyTotalWh / 1000).toFixed(3));
    data._esp32Url = CFG.esp32Url;

    recordHistory(data, now);
    latestData = data;
    lastUpdate = now;
    esp32Online = true;
    
    if (mqttReady) mqttClient.publish(CFG.stateTopic, JSON.stringify(data));
    notifyClients(data);
  } catch (e) {
    esp32Online = false;
    lastPollTime = 0; 
    if (!e.message.includes('fetch failed') && !e.message.includes('timeout')) {
      console.error('[ESP32] 获取失败:', e.message);
    }
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  lastPollTime = 0;
  fetchESP32();
  pollTimer = setInterval(fetchESP32, CFG.interval);
  if (energySaveTimer) clearInterval(energySaveTimer);
  energySaveTimer = setInterval(() => { saveConfig(); flushHistory(false); }, 60000);
}

// ── SSE ──
const sseClients = new Set();
function notifyClients(data) {
  const msg = JSON.stringify({ ...data, _esp32Online: esp32Online, _mqttReady: mqttReady, _weather: weatherData });
  sseClients.forEach(res => { try { res.write(`data: ${msg}\n\n`); } catch {} });
}
const sseTimer = setInterval(() => sseClients.forEach(res => { try { res.write(': ping\n\n'); } catch {} }), 15000);
sseTimer.unref();

// ── 天气 ──
const WEATHER_INTERVAL = 10 * 60 * 1000;
let weatherData = null, weatherTimer = null;
async function fetchWeather() {
  if (!CFG.weatherCity) { weatherData = null; return; }
  try {
    const res = await fetch('https://d1.weather.com.cn/sk_2d/' + CFG.weatherCity + '.html', { headers: { Referer: 'http://www.weather.com.cn/', 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(8000) });
    const m = (await res.text()).match(/dataSK=(\{.*\})/);
    if (!m) throw new Error('解析失败');
    const d = JSON.parse(m[1].replace(/;\s*$/, ''));
    weatherData = { temp: parseFloat(d.temp), weather: d.weather, windDir: d.WD, windLevel: d.WS, humidity: d.SD, time: d.time, date: d.date };
    const msg = JSON.stringify({ _weather: weatherData });
    sseClients.forEach(res2 => { try { res2.write(`data: ${msg}\n\n`); } catch {} });
  } catch {}
}
function startWeather() { if (weatherTimer) clearInterval(weatherTimer); fetchWeather(); weatherTimer = setInterval(fetchWeather, WEATHER_INTERVAL); }

// ── SSRF 防护 ──
function isAllowedTargetUrl(input, current) {
  if (!input) return true;
  const norm = s => { try { const u = new URL(s); return u.protocol + '//' + u.host; } catch { return String(s || '').replace(/\/+$/, ''); } };
  if (norm(input) === norm(current)) return true;
  try {
    const u = new URL(input);
    if (!['http:', 'https:', 'mqtt:', 'mqtts:'].includes(u.protocol)) return false;
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') return true;
    const m = u.hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) { const x = parseInt(m[1]), y = parseInt(m[2]); return x === 10 || (x === 172 && y >= 16 && y <= 31) || (x === 192 && y === 168); }
  } catch { return false; }
  return false;
}

// ── Web 服务器 ──
const app = express();
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); next(); });
app.use(express.json({ limit: '100kb' }));
app.use(express.static(PUBLIC_DIR, { dotfiles: 'deny' }));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'icon.ico')));

app.get('/api/health', (req, res) => res.json({ ok: true, uptime: Math.round(process.uptime()), esp32Online, mqttReady, build: BUILD_ID, uiBuild: UI_BUILD }));
app.get('/api/diagnostics', requireAuth, (req, res) => res.json({ esp32Online, mqttReady, lastUpdate, esp32Url: CFG.esp32Url, mqttUrl: CFG.mqttUrl, dataDir: DATA_DIR, build: BUILD_ID }));

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ') || !verifyToken(auth.slice(7))) return res.status(401).json({ error: '未登录' });
  next();
}

app.post('/api/login', (req, res) => {
  const ip = req.ip || 'unknown', limit = checkRateLimit(ip);
  if (!limit.allowed) return res.status(429).json({ success: false, error: '尝试过多', locked: true, waitMinutes: limit.waitMinutes });
  const { password } = req.body;
  if (!password) return res.status(400).json({ success: false, error: '请输入密码' });
  if (verifyPassword(password, ADMIN_HASH)) { resetLoginAttempts(ip); res.json({ success: true, token: createToken() }); }
  else { recordLoginFail(ip); res.status(403).json({ success: false, error: '密码错误' }); }
});

app.get('/api/stream', (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'Access-Control-Allow-Origin': '*' });
  res.write(`data: ${JSON.stringify({ ...latestData, _esp32Online: esp32Online, _mqttReady: mqttReady, _weather: weatherData })}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

app.get('/api/data', (req, res) => res.json(latestData));
app.get('/api/history', (req, res) => {
  const q = String(req.query.date || ''), day = /^\d{4}-\d{2}-\d{2}$/.test(q) ? q : todayStr();
  const points = day === historyDay ? historyPoints.slice() : loadHistory(day);
  const peaks = {}; HISTORY_KEYS.forEach(k => { const p = historyPeak(points, k); if (p) peaks[k] = { value: p.value, at: clockUTC8(p.at) }; });
  let energyKwh = 0; for (const p of points) { const v = Number(p && p.pout), ms = Number(p && p.ms) || HISTORY_BUCKET; if (Number.isFinite(v)) energyKwh += v * ms / 3600000 / 1000; }
  if (day === historyDay) flushHistory(true);
  res.json({ ok: true, date: day, metrics: HISTORY_KEYS, points, peaks, energyKwh: parseFloat(energyKwh.toFixed(6)) });
});
app.get('/api/weather', (req, res) => res.json(weatherData || { error: '暂无数据' }));

// [新增] 返回月账本数据，同时把今天未结算的电量加进去，保证前端实时图表正确
app.get('/api/monthly', (req, res) => {
  const days = Math.max(1, Math.min(HISTORY_KEEP_DAYS, parseInt(req.query.days, 10) || HISTORY_KEEP_DAYS));
  const rows = dailyRows(days); flushHistory(false);
  
  const displayLongTerm = { ...MONTHLY_STATS };
  const currentMonth = todayStr().slice(0, 7);
  displayLongTerm[currentMonth] = (displayLongTerm[currentMonth] || 0) + (CFG.energyDailyWh / 1000);
  
  res.json({ ok: true, days: rows, stats: dailyStats(rows), longTerm: displayLongTerm });
});

app.get('/api/settings', requireAuth, (req, res) => res.json({
  esp32Url: CFG.esp32Url, esp32User: CFG.esp32User, esp32Pass: '****', mqttUrl: CFG.mqttUrl, mqttUser: CFG.mqttUser, mqttPass: '****',
  interval: CFG.interval, stateTopic: CFG.stateTopic, weatherCity: CFG.weatherCity, csvFormat: CFG.csvFormat, _esp32Online: esp32Online, _mqttReady: mqttReady
}));

app.post('/api/settings', requireAuth, (req, res) => {
  const body = req.body; let changed = false;
  if (body.adminPassword && body.adminPassword !== '****' && body.adminPassword.length >= 6) { ADMIN_HASH = hashPassword(body.adminPassword); changed = true; }
  if (body.esp32Url && body.esp32Url !== CFG.esp32Url) { CFG.esp32Url = body.esp32Url.replace(/\/+$/, ''); changed = true; }
  if (body.esp32User && body.esp32User !== CFG.esp32User) { CFG.esp32User = body.esp32User; changed = true; }
  if (body.esp32Pass && body.esp32Pass !== '****') { CFG.esp32Pass = body.esp32Pass; changed = true; }
  const mqttChanged = body.mqttUrl && body.mqttUrl !== CFG.mqttUrl;
  if (mqttChanged) { CFG.mqttUrl = body.mqttUrl; changed = true; }
  if (body.mqttUser && body.mqttUser !== CFG.mqttUser) { CFG.mqttUser = body.mqttUser; changed = true; }
  if (body.mqttPass && body.mqttPass !== '****') { CFG.mqttPass = body.mqttPass; changed = true; }
  if (body.interval && parseInt(body.interval) >= 500) { CFG.interval = parseInt(body.interval); changed = true; }
  if (body.stateTopic && body.stateTopic !== CFG.stateTopic) { CFG.stateTopic = body.stateTopic; changed = true; }
  if (body.weatherCity !== undefined && body.weatherCity !== CFG.weatherCity) { CFG.weatherCity = body.weatherCity.trim(); changed = true; startWeather(); }
  if (body.csvFormat !== undefined && body.csvFormat !== CFG.csvFormat) { CFG.csvFormat = body.csvFormat; changed = true; }
  
  if (!changed) return res.json({ success: true, message: '无变更' });
  saveConfig(); startPolling();
  if (mqttChanged || body.mqttUser || (body.mqttPass && body.mqttPass !== '****')) setTimeout(() => connectMQTT(), 500);
  else publishDiscovery();
  res.json({ success: true, message: '配置已更新' });
});

app.post('/api/test-esp32', requireAuth, async (req, res) => {
  const { url, user, pass } = req.body;
  if (url && !isAllowedTargetUrl(url, CFG.esp32Url)) return res.json({ success: false, error: '目标地址不允许' });
  try {
    const r = await fetch(`${url||CFG.esp32Url}/update`, { headers: { Authorization: `Basic ${Buffer.from(`${user||CFG.esp32User}:${pass||CFG.esp32Pass}`).toString('base64')}` }, signal: AbortSignal.timeout(5000) });
    const data = parseCSV(await r.text(), CFG.csvFormat);
    res.json({ success: !!data, data: data ? { vin: data.vin, vout: data.vout, pin: data.pin } : null });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/test-mqtt', requireAuth, (req, res) => {
  const { url, user, pass } = req.body;
  if (url && !isAllowedTargetUrl(url, CFG.mqttUrl)) return res.json({ success: false, error: '目标地址不允许' });
  const testClient = mqtt.connect(url || CFG.mqttUrl, { username: user || CFG.mqttUser, password: pass || CFG.mqttPass });
  const timer = setTimeout(() => { testClient.end(true); res.json({ success: false, error: '连接超时' }); }, 5000);
  testClient.on('connect', () => { clearTimeout(timer); testClient.end(true); res.json({ success: true }); });
  testClient.on('error', e => { clearTimeout(timer); testClient.end(true); res.json({ success: false, error: e.message }); });
});

async function sendControl(type, index, operation, source) {
  try {
    const r = await fetch(`${CFG.esp32Url}/Control?Type=${type}&Index=${index||0}&Operation=${operation}`, { headers: { Authorization: `Basic ${Buffer.from(`${CFG.esp32User}:${CFG.esp32Pass}`).toString('base64')}` }, signal: AbortSignal.timeout(5000) });
    return { success: !!r.ok, response: (await r.text()).substring(0, 200) };
  } catch (e) { return { success: false, error: e.message }; }
}
app.post('/api/control', requireAuth, async (req, res) => {
  const now = Date.now(); if (now - (controlLast.get(req.ip) || 0) < 1000) return res.status(429).json({ success: false, error: '操作频繁' });
  controlLast.set(req.ip, now); res.json(await sendControl(req.body.type, req.body.index, req.body.operation, 'Web'));
});

// ── 优雅退出与防崩溃机制 ──
function shutdown(signal) {
  console.log(`\n[退出] 收到 ${signal}，正在清理退出...`);
  if (pollTimer) clearInterval(pollTimer);
  if (energySaveTimer) clearInterval(energySaveTimer);
  if (weatherTimer) clearInterval(weatherTimer);
  
  try { saveConfig(); flushHistory(true); } catch {}
  
  if (mqttClient) {
    console.log('[退出] 断开 MQTT...');
    if (mqttReady) {
      mqttClient.publish(`${CFG.stateTopic}/online`, 'offline', { retain: true }, () => {
        mqttClient.end(true, () => process.exit(0));
      });
    } else {
      mqttClient.end(true, () => process.exit(0));
    }
  } else {
    process.exit(0);
  }
  
  setTimeout(() => {
    console.log('[退出] 强制终止进程');
    process.exit(0);
  }, 1000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  console.error('[崩溃] 发生未捕获异常:', err);
  shutdown('uncaughtException');
});

// ── 启动 ──
connectMQTT();
startPolling();
startWeather();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[版本] 服务端 ${BUILD_ID} / 面板 ${UI_BUILD}`);
  console.log(`\n=== MPPT MQTT Bridge（完美稳定版 + 年度账单）===`);
  console.log(`Web 面板: http://localhost:${PORT}`);
  console.log(`MQTT:     ${CFG.mqttUrl} -> ${CFG.stateTopic}`);
  console.log(`ESP32:    ${CFG.esp32Url}  轮询 ${CFG.interval}ms`);
  console.log(`电量统计: 前端图表采用后端积分，电能统计明细读取硬件原生\n`);
});
