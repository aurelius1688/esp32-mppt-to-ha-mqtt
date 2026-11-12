// 容器 / NAS 内默认无时区设置，先固定为北京时间，保证「每日发电量」在 0 点归零。
process.env.TZ = process.env.TZ || 'Asia/Shanghai';

const express = require('express');
const mqtt = require('mqtt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// [安全] 已删除 Blynk 硬件协议依赖：const net = require('net'); const tls = require('tls');

// ── 运行路径（飞牛部署时通过卷挂载 /app/data 持久化）──
const PORT = Number(process.env.PORT) || 4088;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const KEY_PATH = path.join(DATA_DIR, 'enc.key');   // [安全] 密钥独立文件，权限 0600
const PUBLIC_DIR = path.join(__dirname, 'public');
// ── 版本指纹（判定容器跑的到底是哪份代码）──────────────────
const BUILD_ID = '2026-11-12-sec1';   // [安全] 加固版
const UI_META_RE = /<meta\s+name=["']mppt-ui-build["']\s+content=["']([^"']+)["']/;
function readUiBuild() {
  try {
    const m = UI_META_RE.exec(fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8'));
    return m ? m[1] : 'unknown';
  } catch { return 'missing'; }
}
const UI_BUILD = readUiBuild();
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {
  console.error('[配置] 无法创建数据目录', DATA_DIR, e.message);
}

// ── 加密工具（AES-256-GCM）────────────────────────────
let ENC_KEY = null;
const ENC_RE = /^[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/;

function encrypt(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}

function decrypt(text) {
  if (!text || typeof text !== 'string' || !ENC_RE.test(text)) return text;
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

// [安全] 密钥加载/生成：环境变量 > data/enc.key > 旧 config.json.encKey（迁移后写入独立文件）
function loadOrCreateKey() {
  if (process.env.ENC_KEY && /^[0-9a-f]{64}$/i.test(process.env.ENC_KEY)) {
    console.log('[配置] 使用环境变量 ENC_KEY');
    return Buffer.from(process.env.ENC_KEY, 'hex');
  }
  try {
    const s = fs.readFileSync(KEY_PATH, 'utf8').trim();
    if (/^[0-9a-f]{64}$/i.test(s)) return Buffer.from(s, 'hex');
  } catch {}
  if (CFG.encKey && /^[0-9a-f]{64}$/i.test(CFG.encKey)) {
    try {
      fs.writeFileSync(KEY_PATH, CFG.encKey, { mode: 0o600 });
      console.log('[安全] 已将 encKey 从 config.json 迁移到', KEY_PATH);
    } catch (e) { console.error('[安全] 无法写入密钥文件:', e.message); }
    return Buffer.from(CFG.encKey, 'hex');
  }
  const k = crypto.randomBytes(32);
  try {
    fs.writeFileSync(KEY_PATH, k.toString('hex'), { mode: 0o600 });
    console.log('[安全] 已生成新密钥文件', KEY_PATH);
  } catch (e) { console.error('[安全] 无法写入密钥文件:', e.message); }
  return k;
}

// ── 密码管理 ──────────────────────────────────────────
let ADMIN_HASH = null;
// [安全] 不再使用固定默认密码；首次启动随机生成并打印，旧默认密码自动迁移为随机密码
const LEGACY_PASSES = ['admin', 'change-this-now', 'admin123'];

function generateRandomPassword() {
  return crypto.randomBytes(12).toString('base64url');
}

function hashPassword(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = crypto.scryptSync(pass, salt, 64).toString('hex');
  return salt + ':' + key;
}

// [安全] 时序安全比较，防时序侧信道
function safeEqual(a, b) {
  const ba = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  if (ba.length !== bb.length) {
    try { crypto.timingSafeEqual(ba, ba); } catch {}
    return false;
  }
  try { return crypto.timingSafeEqual(ba, bb); } catch { return false; }
}

function verifyPassword(pass, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, key] = stored.split(':');
  if (!salt || !key) return false;
  const hash = crypto.scryptSync(pass, salt, 64).toString('hex');
  return safeEqual(key, hash);
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
    if (!safeEqual(hmac, expected)) return false;   // [安全] timing-safe
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
    r = { fails: 0, lockedUntil: 0, ban: false, lockCycles: 0, lastSeen: now };
    loginAttempts.set(ip, r);
  }
  r.lastSeen = now;   // [安全] 用于定期清理
  if (r.ban) return { allowed: false, locked: true, banned: true, remaining: 0 };
  if (r.lockedUntil > now) return { allowed: false, locked: true, remaining: 0, waitMinutes: Math.ceil((r.lockedUntil - now) / 60000) };
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

// [安全] 定期清理登录限流 / 控制限流的 Map，防止内存泄漏
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginAttempts) {
    if (r.ban) continue;
    if (r.fails === 0 && now - (r.lastSeen || 0) > 3600000) loginAttempts.delete(ip);
  }
  for (const [ip, t] of controlLast) {
    if (now - t > 3600000) controlLast.delete(ip);
  }
}, 1800000).unref();

// ── 默认配置（已脱敏，上传 GitHub 用）─────────────────────
function envStr(k, def) {
  return (process.env[k] !== undefined && process.env[k] !== '') ? process.env[k] : def;
}
function envInt(k, def) {
  const n = parseInt(process.env[k], 10);
  return Number.isFinite(n) && n >= 500 ? n : def;
}

let CFG = {
  encKey:      null,
  esp32Url:    envStr('ESP32_URL', 'http://192.168.1.100').replace(/\/+$/, ''),
  esp32User:   envStr('ESP32_USER', 'admin'),
  esp32Pass:   envStr('ESP32_PASS', 'admin'),
  mqttUrl:     envStr('MQTT_URL', 'mqtt://192.168.1.100:1883'),
  mqttUser:    envStr('MQTT_USER', 'mqtt'),
  mqttPass:    envStr('MQTT_PASS', ''),    // [脱敏] 默认空密码，由用户自己配
  interval:    envInt('POLL_INTERVAL', 1000),
  haPrefix:    envStr('HA_PREFIX', 'homeassistant'),
  stateTopic:  envStr('STATE_TOPIC', 'mppt/status'),
  // [安全] cmdTopic 首次启动随机后缀，避免默认 mppt/cmd 被猜中
  cmdTopic:    envStr('CMD_TOPIC', 'mppt/cmd/' + crypto.randomBytes(6).toString('hex')),
  // [安全] HA 按钮 payload 随机化，光知道 topic 也发不了重启命令
  restartPayload: envStr('RESTART_PAYLOAD', crypto.randomBytes(8).toString('hex')),
  weatherCity: envStr('WEATHER_CITY', ''),
  csvFormat:   envStr('CSV_FORMAT', 'auto'),
  adminHash:   null,
  energyTotal: 0,
  energyDaily: 0,
  energyDate:  '',
};

let firstRun = false;
try {
  const saved = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  const allowed = ['encKey','esp32Url','esp32User','esp32Pass','mqttUrl','mqttUser','mqttPass','interval','haPrefix','stateTopic','cmdTopic','restartPayload','adminHash','energyTotal','energyDaily','energyDate','weatherCity','csvFormat'];
  allowed.forEach(k => { if (saved[k] !== undefined) CFG[k] = saved[k]; });
  console.log('[配置] 已加载', CONFIG_PATH, '（如需改环境变量，请先删除此文件）');
} catch {
  firstRun = true;
  if (process.env.ADMIN_PASSWORD) CFG.adminHash = hashPassword(process.env.ADMIN_PASSWORD);
  console.log('[配置] 首次启动，用环境变量生成', CONFIG_PATH);
}

// 初始化加密密钥
ENC_KEY = loadOrCreateKey();
CFG.encKey = null;   // [安全] 不再写入 config.json

// 解密存储的密码
CFG.esp32Pass = decrypt(CFG.esp32Pass);
CFG.mqttPass  = decrypt(CFG.mqttPass);

// [安全] 密码初始化：首次启动 / 旧默认密码一律迁移为随机密码并打印一次
if (!CFG.adminHash) {
  const p = process.env.ADMIN_PASSWORD || generateRandomPassword();
  CFG.adminHash = hashPassword(p);
  console.log('========================================');
  console.log('[安全] 首次启动，管理员密码:', p);
  console.log('[安全] 请登录后立即在「设置」中修改');
  console.log('========================================');
}
let passMigrated = false;
if (LEGACY_PASSES.some(p => verifyPassword(p, CFG.adminHash))) {
  const np = process.env.ADMIN_PASSWORD || generateRandomPassword();
  CFG.adminHash = hashPassword(np);
  passMigrated = true;
  console.log('========================================');
  console.log('[安全] 检测到旧默认密码，已重置为:', np);
  console.log('[安全] 请登录后立即在「设置」中修改');
  console.log('========================================');
}
ADMIN_HASH = CFG.adminHash;

// 保存配置（密码加密后存储；encKey 不再落盘）
function saveConfig() {
  const saveData = { ...CFG };
  saveData.adminHash = ADMIN_HASH;
  delete saveData.encKey;   // [安全] 密钥独立文件，不写 config
  ['esp32Pass', 'mqttPass'].forEach(k => {
    if (saveData[k] && !ENC_RE.test(saveData[k])) saveData[k] = encrypt(saveData[k]);
  });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(saveData, null, 2), 'utf8');
}

if (firstRun || passMigrated) saveConfig();

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
function restartTopic() { return `${CFG.cmdTopic}/restart`; }
let lastRestartCmd = 0;

async function sendControl(type, index, operation, source) {
  const auth = Buffer.from(`${CFG.esp32User}:${CFG.esp32Pass}`).toString('base64');
  const url = `${CFG.esp32Url}/Control?Type=${encodeURIComponent(type)}&Index=${encodeURIComponent(index || 0)}&Operation=${encodeURIComponent(operation)}`;
  let result;
  try {
    const r = await fetch(url, {
      headers: { Authorization: `Basic ${auth}` },
      signal: AbortSignal.timeout(5000),
    });
    const text = await r.text();
    result = { success: !!r.ok, response: text.substring(0, 200),
      ...(r.ok ? {} : { error: `控制器返回 HTTP ${r.status}` }) };
  } catch (e) {
    result = { success: false, error: e.message };
  }
  console.log(`[控制] ${source} ${result.success ? '重启命令已发送' : '重启失败: ' + result.error}`);
  if (mqttReady && mqttClient) {
    mqttClient.publish(`${CFG.cmdTopic}/restart/result`, JSON.stringify({
      ok: result.success, source,
      time: new Date().toLocaleString('zh-CN', { hour12: false }),
      text: result.success ? '重启命令已发送' : ('失败：' + (result.error || '未知错误')),
    }), { retain: true });
  }
  return result;
}

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
    mqttClient.subscribe(restartTopic(), { qos: 0 }, err => {
      if (err) console.error('[MQTT] 重启按钮订阅失败:', err.message);
      else console.log('[MQTT] 已监听 HA 重启按钮 ->', restartTopic());
    });
    publishDiscovery();
  });
  mqttClient.on('message', (topic, message) => {
    // [安全] 校验随机 payload，光知道 topic 不够；仍需 MQTT broker ACL 限制该用户只能 publish 状态主题
    if (topic !== restartTopic() || message.toString().trim() !== CFG.restartPayload) return;
    const now = Date.now();
    if (now - lastRestartCmd < 5000) {
      console.log('[控制] 5 秒内的重复重启命令已忽略');
      return;
    }
    lastRestartCmd = now;
    sendControl(9, 0, 2, 'Home Assistant');
  });
  mqttClient.on('error', e => console.error('[MQTT] 错误:', e.message));
  mqttClient.on('close', () => { mqttReady = false; });
}

// ── HA 自动发现 ──────────────────────────────────────
function publishDiscovery() {
  if (!mqttReady) return;
  const availability = {
    availability_topic: `${CFG.stateTopic}/online`,
    payload_available: 'online',
    payload_not_available: 'offline',
  };
  const device = {
    identifiers: ['esp32_mppt'],
    name: 'ESP32 MPPT 控制器',
    model: 'MPPT V2.1',
    manufacturer: 'ESP32 MPPT',
    configuration_url: `http://${CFG.esp32Url.replace(/^https?:\/\//, '').replace(/\/.*$/, '')}`,
  };
  const energyKeys = ['wh', 'twh', 'energy_daily', 'energy_total'];

  SENSORS.forEach(s => {
    if (!s.unit) return;
    const uid = `mppt_${s.key}`;
    mqttClient.publish(`${CFG.haPrefix}/sensor/${uid}/config`, JSON.stringify({
      name: `MPPT ${s.name}`,
      state_topic: CFG.stateTopic,
      unit_of_measurement: s.unit,
      value_template: `{{ value_json.${s.key} }}`,
      unique_id: uid, device_class: s.cls, icon: s.icon,
      state_class: energyKeys.includes(s.key) ? 'total_increasing' : 'measurement',
      ...availability,
      device,
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
      ...availability,
      device,
    }), { retain: true });
  });
  const restartUid = 'mppt_restart_esp32';
  mqttClient.publish(`${CFG.haPrefix}/button/${restartUid}/config`, JSON.stringify({
    name: 'MPPT 重启 ESP32',
    command_topic: restartTopic(),
    payload_press: CFG.restartPayload,   // [安全] 随机 payload
    unique_id: restartUid,
    device_class: 'restart',
    icon: 'mdi:restart',
    ...availability,
    device,
  }), { retain: true });
  const resultTopic = `${CFG.cmdTopic}/restart/result`;
  mqttClient.publish(`${CFG.haPrefix}/sensor/mppt_restart_result/config`, JSON.stringify({
    name: 'MPPT 最近一次重启命令',
    state_topic: resultTopic,
    value_template: '{{ value_json.text }}',
    json_attributes_topic: resultTopic,
    unique_id: 'mppt_restart_result',
    icon: 'mdi:information-outline',
    ...availability,
    device,
  }), { retain: true });
  console.log('[MQTT] HA 自动发现已发布（含重启 ESP32 按钮）');
}

// ── 解析 CSV（兼容两种固件格式）──────────────────────
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
  const fmt = (forceFormat === 'standard' || forceFormat === 'qingcai')
    ? forceFormat
    : (a.length >= 27 ? 'standard' : a.length === 26 ? 'qingcai' : 'standard');
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

// ── 今日趋势历史（UTC+8 自然日，按分钟聚合后落盘）────────
const HISTORY_DIR = path.join(DATA_DIR, 'history');
const HISTORY_BUCKET = 60 * 1000;
const HISTORY_KEYS = ['pin','pout','iin','iout','vin','vout','eff','temp'];
try { fs.mkdirSync(HISTORY_DIR, { recursive: true }); } catch (e) {
  console.error('[历史] 无法创建目录', HISTORY_DIR, e.message);
}
function historyPath(day) { return path.join(HISTORY_DIR, day + '.json'); }
function loadHistory(day) {
  try {
    const o = JSON.parse(fs.readFileSync(historyPath(day), 'utf8'));
    return Array.isArray(o.points) ? o.points : [];
  } catch { return []; }
}
function bucketStart(ts) { return Math.floor(ts / HISTORY_BUCKET) * HISTORY_BUCKET; }
function clockUTC8(ts) { return new Date(ts + 8 * 3600 * 1000).toISOString().slice(11, 16); }
function historyPeak(points, key) {
  let best = null;
  for (const p of points) {
    const raw = p && (p[key + 'Max'] !== undefined ? p[key + 'Max'] : p[key]);
    const v = Number(raw);
    if (Number.isFinite(v) && (!best || v > best.value)) best = { value: v, at: p.t };
  }
  return best;
}
function todayStr() { return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10); }
let historyDay = todayStr();
let historyPoints = loadHistory(historyDay);
let historyDirty = false;
let historySaveTimer = null;
let historyLastFlush = 0;
function recordHistory(data, ts) {
  const day = todayStr();
  if (day !== historyDay) {
    flushHistory(true);
    historyDay = day;
    historyPoints = loadHistory(day);
    pruneHistory();
  }
  const t = bucketStart(ts);
  let b = historyPoints[historyPoints.length - 1];
  if (!b || b.t !== t) {
    b = { t, n: 0, ms: 0 };
    HISTORY_KEYS.forEach(k => { b[k] = 0; b[k + 'Max'] = 0; });
    historyPoints.push(b);
  }
  b.n++;
  b.ms = (b.ms || 0) + (CFG.interval || 1000);
  HISTORY_KEYS.forEach(k => {
    const v = Number(data[k]);
    if (!Number.isFinite(v)) return;
    if (b.n === 1) { b[k] = v; b[k + 'Max'] = v; }
    else { b[k] = (b[k] * (b.n - 1) + v) / b.n; b[k + 'Max'] = Math.max(b[k + 'Max'], v); }
  });
  historyDirty = true;
  const now = Date.now();
  if (now - historyLastFlush >= 2000) { flushHistory(true); historyLastFlush = now; }
}
function flushHistory(force) {
  if (!historyDirty && !force) return;
  try {
    fs.writeFileSync(historyPath(historyDay), JSON.stringify({
      date: historyDay, bucketMs: HISTORY_BUCKET, timezone: 'UTC+8',
      metrics: HISTORY_KEYS, points: historyPoints,
    }));
    historyDirty = false;
  } catch (e) { console.error('[历史] 写盘失败:', e.message); }
}

const HISTORY_KEEP_DAYS = 30;
function pruneHistory() {
  try {
    const cutoff = new Date(Date.now() + 8 * 3600 * 1000 - HISTORY_KEEP_DAYS * 86400000)
      .toISOString().slice(0, 10);
    let removed = 0;
    for (const f of fs.readdirSync(HISTORY_DIR)) {
      if (!/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) continue;
      if (f.slice(0, 10) < cutoff) {
        try { fs.unlinkSync(path.join(HISTORY_DIR, f)); removed++; } catch (e) {}
      }
    }
    if (removed) console.log('[历史] 清理 ' + removed + ' 个超过 ' + HISTORY_KEEP_DAYS + ' 天的文件（保留 ' + cutoff + ' 起）');
  } catch (e) { console.error('[历史] 清理失败:', e.message); }
}
pruneHistory();
const historyPruneTimer = setInterval(pruneHistory, 3600 * 1000);
if (historyPruneTimer.unref) historyPruneTimer.unref();

// ── 每日发电量汇总（近 30 天柱状图）────────────────────
const DAILY_MIN_W = 20;
const dailyCache = new Map();
function summarizeDay(points) {
  let energyKwh = 0, effMs = 0, samples = 0, peak = null;
  for (const p of points) {
    if (!p) continue;
    const ms = Number(p.ms) || HISTORY_BUCKET;
    const out = Number(p.pout);
    if (Number.isFinite(out)) {
      energyKwh += out * ms / 3600000 / 1000;
      if (out >= DAILY_MIN_W) effMs += ms;
    }
    const raw = p.pinMax !== undefined ? p.pinMax : p.pin;
    const pv = Number(raw);
    if (Number.isFinite(pv) && (!peak || pv > peak.value)) peak = { value: pv, at: p.t };
    samples += Number(p.n) || 0;
  }
  return {
    energyKwh: parseFloat(energyKwh.toFixed(4)),
    peakW: peak ? parseFloat(peak.value.toFixed(1)) : null,
    peakAt: peak ? clockUTC8(peak.at) : null,
    hours: parseFloat((effMs / 3600000).toFixed(2)),
    samples,
  };
}
function dailyRows(days) {
  const span = Math.max(1, Math.min(HISTORY_KEEP_DAYS, parseInt(days, 10) || HISTORY_KEEP_DAYS));
  const base = Date.now() + 8 * 3600 * 1000;
  const rows = [];
  for (let i = span - 1; i >= 0; i--) {
    const day = new Date(base - i * 86400000).toISOString().slice(0, 10);
    let row = null;
    if (day === historyDay) {
      row = summarizeDay(historyPoints);
    } else {
      const fp = historyPath(day);
      let st = null;
      try { st = fs.statSync(fp); } catch (e) { st = null; }
      if (st) {
        const hit = dailyCache.get(day);
        if (hit && hit.mtimeMs === st.mtimeMs) row = hit.row;
        else {
          row = summarizeDay(loadHistory(day));
          dailyCache.set(day, { mtimeMs: st.mtimeMs, row });
        }
      }
    }
    rows.push(row && row.samples
      ? { date: day, ...row, empty: false }
      : { date: day, energyKwh: 0, peakW: null, peakAt: null, hours: 0, samples: 0, empty: true });
  }
  const keepFrom = new Date(Date.now() + 8 * 3600 * 1000 - HISTORY_KEEP_DAYS * 86400000)
    .toISOString().slice(0, 10);
  for (const k of dailyCache.keys()) if (k < keepFrom) dailyCache.delete(k);
  return rows;
}
function dailyStats(rows) {
  const live = rows.filter(r => !r.empty);
  const totalKwh = live.reduce((a, r) => a + r.energyKwh, 0);
  const avgKwh = live.length ? totalKwh / live.length : 0;
  let best = null;
  for (const r of live) if (!best || r.energyKwh > best.energyKwh) best = r;
  return {
    keepDays: HISTORY_KEEP_DAYS,
    rangeDays: rows.length,
    daysWithData: live.length,
    totalKwh: parseFloat(totalKwh.toFixed(3)),
    avgKwh: parseFloat(avgKwh.toFixed(3)),
    bestDate: best ? best.date : null,
    bestKwh: best ? best.energyKwh : 0,
    peakW: live.reduce((a, r) => Math.max(a, r.peakW || 0), 0),
  };
}

// ── ESP32 轮询 ───────────────────────────────────────
let latestData = {};
let lastUpdate = 0;
let pollTimer = null;
let esp32Online = false;
let energyDaily = (CFG.energyDate === todayStr()) ? (CFG.energyDaily || 0) : 0;
let energyTotal = CFG.energyTotal || 0;
let lastDay = todayStr();
let energySaveTimer = null;

function checkDayReset() {
  const d = todayStr();
  if (d !== lastDay) {
    energyDaily = 0;
    lastDay = d;
    CFG.energyDaily = 0;
    CFG.energyDate = d;
    saveConfig();
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
    const data = parseCSV(text, CFG.csvFormat);
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
    data._esp32Url = CFG.esp32Url;   // 前端信息卡片「设备地址」用

    CFG.energyTotal = energyTotal;
    CFG.energyDaily = energyDaily;
    CFG.energyDate = todayStr();

    recordHistory(data, Date.now());
    latestData = data;
    lastUpdate = Date.now();
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
    CFG.energyDaily = energyDaily;
    CFG.energyDate = todayStr();
    saveConfig();
  }, 300000);
  if (historySaveTimer) clearInterval(historySaveTimer);
  historySaveTimer = setInterval(() => flushHistory(false), 60000);
}

process.on('exit', () => {
  try {
    CFG.energyTotal = energyTotal;
    CFG.energyDaily = energyDaily;
    CFG.energyDate = todayStr();
    saveConfig();
    flushHistory(true);
  } catch {}
});

// ── SSE ──────────────────────────────────────────────
const sseClients = new Set();
function notifyClients(data) {
  const msg = JSON.stringify({ ...data, _esp32Online: esp32Online, _mqttReady: mqttReady, _weather: weatherData });
  // [安全] 单个客户端写失败不能拖垮循环
  sseClients.forEach(res => { try { res.write(`data: ${msg}\n\n`); } catch {} });
}
setInterval(() => {
  sseClients.forEach(res => { try { res.write(': ping\n\n'); } catch {} });
}, 15000).unref();

// ── 天气 ──────────────────────────────────────────────
const WEATHER_INTERVAL = 10 * 60 * 1000;
let weatherData = null;
let weatherTimer = null;

async function fetchWeather() {
  if (!CFG.weatherCity) { weatherData = null; return; }
  try {
    const res = await fetch('https://d1.weather.com.cn/sk_2d/' + CFG.weatherCity + '.html', {
      headers: {
        'Referer': 'http://www.weather.com.cn/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const text = await res.text();
    const m = text.match(/dataSK=(\{.*\})/);
    if (!m) throw new Error('解析失败');
    const d = JSON.parse(m[1].replace(/;\s*$/, ''));
    weatherData = {
      temp: parseFloat(d.temp),
      weather: d.weather || '',
      windDir: d.WD || '',
      windLevel: d.WS || '',
      humidity: d.SD || '',
      time: d.time || '',
      date: d.date || '',
    };
    console.log('[天气] 已更新:', weatherData.weather, weatherData.temp + '°C');
    const msg = JSON.stringify({ _weather: weatherData });
    sseClients.forEach(res2 => { try { res2.write(`data: ${msg}\n\n`); } catch {} });
  } catch (e) {
    console.error('[天气] 获取失败:', e.message);
  }
}

function startWeather() {
  if (weatherTimer) clearInterval(weatherTimer);
  fetchWeather();
  weatherTimer = setInterval(fetchWeather, WEATHER_INTERVAL);
}

// ── [安全] SSRF 防护：测试接口的 URL 只允许当前配置或私网地址 ──
function normUrl(s) {
  try {
    const u = new URL(s);
    return u.protocol + '//' + u.host;
  } catch { return String(s || '').replace(/\/+$/, ''); }
}
function isAllowedTargetUrl(input, current) {
  if (!input) return true;
  const a = normUrl(input), b = normUrl(current);
  if (b && a === b) return true;
  try {
    const u = new URL(input);
    if (!['http:', 'https:', 'mqtt:', 'mqtts:'].includes(u.protocol)) return false;
    const host = u.hostname;
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;
    const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) {
      const [x, y] = [parseInt(m[1]), parseInt(m[2])];
      if (x === 10) return true;
      if (x === 172 && y >= 16 && y <= 31) return true;
      if (x === 192 && y === 168) return true;
      if (x === 169 && y === 254) return true;
      if (x === 127) return true;
      return false;
    }
    return false;
  } catch { return false; }
}

// ── [安全] 控制接口限流 ────────────────────────────────
const controlLast = new Map();

// ── Web 服务器 ──────────────────────────────────────
const app = express();
// [安全] 安全响应头
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.json({ limit: '100kb' }));   // [安全] 请求体大小限制
app.use(express.static(PUBLIC_DIR, { dotfiles: 'deny' }));   // [安全] 拒绝隐藏文件
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'icon.ico')));

// [安全] 健康检查只返回状态布尔值和版本，不暴露内网地址/主题/路径
app.get('/api/health', (req, res) => res.json({
  ok: true,
  uptime: Math.round(process.uptime()),
  esp32Online, mqttReady,
  build: BUILD_ID, uiBuild: UI_BUILD, uiMatch: UI_BUILD === BUILD_ID,
}));

// [安全] 排障信息需要登录
app.get('/api/diagnostics', requireAuth, (req, res) => {
  res.json({
    ok: true, uptime: Math.round(process.uptime()),
    esp32Online, mqttReady,
    lastUpdate: lastUpdate ? new Date(lastUpdate).toISOString() : null,
    esp32Url: CFG.esp32Url, mqttUrl: CFG.mqttUrl, stateTopic: CFG.stateTopic,
    restartTopic: restartTopic(),
    csvFormat: CFG.csvFormat, csvDetected: csvFormatDetected,
    history: { date: historyDay, points: historyPoints.length, dir: 'data/history' },
    build: BUILD_ID, uiBuild: UI_BUILD, uiMatch: UI_BUILD === BUILD_ID,
    dataDir: DATA_DIR, publicDir: PUBLIC_DIR,
  });
});

app.get('/api/version', (req, res) => {
  const files = {};
  for (const f of ['server.js', 'public/index.html', 'VERSION.txt']) {
    try { files[f] = crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, f))).digest('hex'); }   // [安全] SHA-256
    catch { files[f] = 'missing'; }
  }
  res.json({ build: BUILD_ID, uiBuild: readUiBuild(), uiMatch: readUiBuild() === BUILD_ID,
             startedAt: new Date().toISOString(), files });
});

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

// [安全] 数据接口保持公开（按需求），但不含控制元信息
app.get('/api/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache',
    Connection: 'keep-alive', 'Access-Control-Allow-Origin': '*',
  });
  res.write(`data: ${JSON.stringify({ ...latestData, _esp32Online: esp32Online, _mqttReady: mqttReady, _weather: weatherData })}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

app.get('/api/data', (req, res) => res.json(latestData));

app.get('/api/history', (req, res) => {
  const q = String(req.query.date || '');
  const day = /^\d{4}-\d{2}-\d{2}$/.test(q) ? q : todayStr();
  const points = day === historyDay ? historyPoints.slice() : loadHistory(day);
  const peaks = {};
  HISTORY_KEYS.forEach(k => {
    const p = historyPeak(points, k);
    if (p) peaks[k] = { value: p.value, at: clockUTC8(p.at) };
  });
  let energyKwh = 0;
  for (const p of points) {
    const v = Number(p && p.pout);
    const ms = Number(p && p.ms) || HISTORY_BUCKET;
    if (Number.isFinite(v)) energyKwh += v * ms / 3600000 / 1000;
  }
  if (day === historyDay) flushHistory(true);
  res.json({
    ok: true, date: day, timezone: 'UTC+8', bucketMs: HISTORY_BUCKET,
    metrics: HISTORY_KEYS, count: points.length, points, peaks,
    energyKwh: parseFloat(energyKwh.toFixed(6)),
  });
});

app.get('/api/weather', (req, res) => res.json(weatherData || { error: '暂无数据' }));

app.get('/api/monthly', (req, res) => {
  try {
    const days = Math.max(1, Math.min(HISTORY_KEEP_DAYS, parseInt(req.query.days, 10) || HISTORY_KEEP_DAYS));
    const rows = dailyRows(days);
    flushHistory(false);
    res.json({
      ok: true, timezone: 'UTC+8', bucketMs: HISTORY_BUCKET,
      days: rows, rangeDays: days, stats: dailyStats(rows),
    });
  } catch (e) {
    console.error('[月统计] 生成失败:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

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
    weatherCity: CFG.weatherCity,
    csvFormat: CFG.csvFormat,
    _esp32Online: esp32Online,
    _mqttReady: mqttReady,
    _csvDetected: csvFormatDetected,
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

  if (body.interval && parseInt(body.interval) >= 500) { CFG.interval = parseInt(body.interval); changed = true; }
  if (body.stateTopic && typeof body.stateTopic === 'string') { CFG.stateTopic = body.stateTopic; changed = true; }
  if (body.weatherCity !== undefined) {
    const wc = String(body.weatherCity).trim();
    if (wc !== '' && !/^\d{9}$/.test(wc)) return res.status(400).json({ success: false, message: '天气城市代码格式错误（9位数字，留空则关闭天气）' });
    if (wc !== CFG.weatherCity) { CFG.weatherCity = wc; changed = true; }
  }
  if (body.csvFormat !== undefined) {
    const f = String(body.csvFormat);
    if (!['auto', 'standard', 'qingcai'].includes(f))
      return res.status(400).json({ success: false, message: 'CSV 格式参数错误' });
    if (f !== CFG.csvFormat) { CFG.csvFormat = f; changed = true; }
  }

  if (!changed) return res.json({ success: true, message: '无变更' });

  saveConfig();
  console.log('[配置] 已更新，重新连接...');

  startPolling();
  if (body.weatherCity !== undefined) startWeather();

  if (mqttChanged || body.mqttUser || (body.mqttPass && body.mqttPass !== '****')) {
    setTimeout(() => connectMQTT(), 500);
  } else {
    publishDiscovery();
  }

  res.json({ success: true, message: '配置已更新' });
});

// ── 测试连接（需登录）─────────────────────────────────
app.post('/api/test-esp32', requireAuth, async (req, res) => {
  const { url, user, pass } = req.body;
  if (url && !isAllowedTargetUrl(url, CFG.esp32Url)) {
    return res.json({ success: false, error: '目标地址不允许（仅允许当前配置或内网地址）' });
  }
  const targetUrl = (url || CFG.esp32Url).replace(/\/+$/, '');
  const auth = Buffer.from(`${user||CFG.esp32User}:${pass||CFG.esp32Pass}`).toString('base64');
  try {
    const r = await fetch(`${targetUrl}/update`, {
      headers: { Authorization: `Basic ${auth}` },
      signal: AbortSignal.timeout(5000),
    });
    const text = await r.text();
    const data = parseCSV(text, CFG.csvFormat);
    res.json({ success: !!data, data: data ? { vin: data.vin, vout: data.vout, pin: data.pin } : null,
      csvDetected: csvFormatDetected, raw: text.substring(0, 100) });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

app.post('/api/test-mqtt', requireAuth, (req, res) => {
  const { url, user, pass } = req.body;
  if (url && !isAllowedTargetUrl(url, CFG.mqttUrl)) {
    return res.json({ success: false, error: '目标地址不允许（仅允许当前配置或内网地址）' });
  }
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

// ── ESP32 控制命令（需登录 + 限流）─────────────────────
app.post('/api/control', requireAuth, async (req, res) => {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const last = controlLast.get(ip) || 0;
  if (now - last < 1000) return res.status(429).json({ success: false, error: '操作过于频繁' });
  controlLast.set(ip, now);
  const { type, index, operation } = req.body;
  if (type === undefined || operation === undefined) {
    return res.status(400).json({ success: false, error: '缺少参数' });
  }
  res.json(await sendControl(type, index, operation, 'Web 面板'));
});

// ── 启动 ─────────────────────────────────────────────
connectMQTT();
startPolling();
startWeather();

function shutdown(signal) {
  console.log(`[退出] 收到 ${signal}，保存数据...`);
  try {
    CFG.energyTotal = energyTotal;
    CFG.energyDaily = energyDaily;
    CFG.energyDate = todayStr();
    saveConfig();
  } catch {}
  try {
    if (mqttClient && mqttReady) {
      mqttClient.publish(`${CFG.stateTopic}/online`, 'offline', { retain: true }, () => process.exit(0));
    } else {
      process.exit(0);
    }
  } catch { process.exit(0); }
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

const srv = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[版本] 服务端 ${BUILD_ID} / 面板 ${UI_BUILD} / 匹配=${UI_BUILD === BUILD_ID}`);
  console.log(`\n=== MPPT MQTT Bridge（飞牛 / Linux 版 · 安全加固）===`);
  console.log(`Web 面板: http://<飞牛IP>:${PORT}`);
  console.log(`MQTT:     ${CFG.mqttUrl} -> ${CFG.stateTopic}`);
  console.log(`ESP32:    ${CFG.esp32Url}  轮询 ${CFG.interval}ms  CSV格式 ${CFG.csvFormat}`);
  console.log(`配置目录: ${DATA_DIR}`);
  console.log(`时区:     ${process.env.TZ}\n`);
});
srv.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[启动失败] 端口 ${PORT} 已被占用：请改 docker-compose.yml 的 ports，或设置 PORT 环境变量`);
  } else if (err.code === 'EACCES') {
    console.error(`[启动失败] 无权限绑定端口 ${PORT}`);
  } else {
    console.error('[启动失败]', err.message);
  }
  process.exit(1);
});
