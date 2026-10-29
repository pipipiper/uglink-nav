import LG_SOURCE from './liquidglass.txt';
import { ICON_180, ICON_512 } from './icons.js';

const DISCOVERY = [
  'https://api-zh.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias',
  'https://api-us.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias',
  'https://api-eur.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias',
  'https://api-aar.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias',
];
const COOKIE = 'ugnav';
const SESSION_SECONDS = 7 * 24 * 3600;
const rate = new Map();
let discoveryCache = { origin: null, at: 0 };

const enc = new TextEncoder();

function md5Hex(value) {
  const bytes = enc.encode(value);
  const shift = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i += 1) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
  const length = bytes.length;
  const total = (((length + 9 + 63) >> 6) << 6);
  const buffer = new Uint8Array(total);
  buffer.set(bytes);
  buffer[length] = 0x80;
  const view = new DataView(buffer.buffer);
  const bitLength = length * 8;
  view.setUint32(total - 8, bitLength >>> 0, true);
  view.setUint32(total - 4, Math.floor(bitLength / 4294967296), true);
  let a = 0x67452301;
  let b = 0xefcdab89;
  let c = 0x98badcfe;
  let d = 0x10325476;
  const M = new Uint32Array(16);
  for (let offset = 0; offset < total; offset += 64) {
    for (let i = 0; i < 16; i += 1) M[i] = view.getUint32(offset + i * 4, true);
    let A = a;
    let B = b;
    let C = c;
    let D = d;
    for (let i = 0; i < 64; i += 1) {
      let F;
      let g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      const prevD = D;
      D = C;
      C = B;
      const sum = (A + F + K[i] + M[g]) >>> 0;
      B = (B + ((sum << shift[i]) | (sum >>> (32 - shift[i])))) >>> 0;
      A = prevD;
    }
    a = (a + A) >>> 0;
    b = (b + B) >>> 0;
    c = (c + C) >>> 0;
    d = (d + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, a, true);
  outView.setUint32(4, b, true);
  outView.setUint32(8, c, true);
  outView.setUint32(12, d, true);
  return [...out].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function b64ToBytes(b64) {
  const bin = atob(b64.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function bytesToBigInt(bytes) {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex ? BigInt('0x' + hex) : 0n;
}

function bigIntToBytes(value, length) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  if (out.length === length) return out;
  if (out.length > length) return out.subarray(out.length - length);
  const padded = new Uint8Array(length);
  padded.set(out, length - out.length);
  return padded;
}

function readTLV(bytes, offset) {
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let cursor = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i += 1) length = (length << 8) | bytes[cursor + i];
    cursor += count;
  }
  return { tag, length, start: cursor, end: cursor + length };
}

function parseRsaPublicKey(base64Pem) {
  const raw = b64ToBytes(base64Pem);
  const text = new TextDecoder().decode(raw);
  const der = text.includes('-----BEGIN') ? b64ToBytes(text.replace(/-----(BEGIN|END)[^-]+-----/g, '')) : raw;
  const outer = readTLV(der, 0);
  const algorithm = readTLV(der, outer.start);
  const bitString = readTLV(der, algorithm.end);
  const inner = readTLV(der, bitString.start + 1);
  const modulus = readTLV(der, inner.start);
  const exponent = readTLV(der, modulus.end);
  return {
    n: bytesToBigInt(der.subarray(modulus.start, modulus.end)),
    e: bytesToBigInt(der.subarray(exponent.start, exponent.end)),
  };
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function rsaEncryptPKCS1(message, key) {
  const msg = enc.encode(message);
  const size = (key.n.toString(2).length + 7) >> 3;
  const paddingLength = size - 3 - msg.length;
  if (paddingLength < 8) throw new Error('RSA 输入过长');
  const em = new Uint8Array(size);
  em[0] = 0;
  em[1] = 2;
  const random = crypto.getRandomValues(new Uint8Array(paddingLength));
  for (let i = 0; i < paddingLength; i += 1) random[i] = random[i] || 1;
  em.set(random, 2);
  em[2 + paddingLength] = 0;
  em.set(msg, 3 + paddingLength);
  return bigIntToBytes(modPow(bytesToBigInt(em), key.e, key.n), size);
}

function absorbCookies(jar, response) {
  let list = [];
  if (typeof response.headers.getSetCookie === 'function') list = response.headers.getSetCookie();
  if (!list.length) {
    const raw = response.headers.get('set-cookie');
    if (raw) list = raw.split(/,(?=\s*[^;=\s]+=)/);
  }
  for (const raw of list) {
    const pair = raw.split(';')[0];
    const index = pair.indexOf('=');
    if (index > 0) jar.set(pair.slice(0, index), pair.slice(index + 1));
  }
}

async function resolveOrigin(alias) {
  if (discoveryCache.origin && Date.now() - discoveryCache.at < 300000) return discoveryCache.origin;
  for (const endpoint of DISCOVERY) {
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          Accept: 'application/json, text/plain, */*',
          'Content-Type': 'application/json',
          Origin: 'https://www.ug.link',
          Referer: 'https://www.ug.link/',
          lang: 'zh-CN',
        },
        body: JSON.stringify({ alias }),
        signal: AbortSignal.timeout(8000),
      });
      const json = await response.json();
      const relayDomain = json?.data?.relayDomain;
      if (json?.code === 200 && typeof relayDomain === 'string') {
        const origin = `https://${alias}.${relayDomain.trim().toLowerCase().replace(/\.$/, '')}`;
        discoveryCache = { origin, at: Date.now() };
        return origin;
      }
    } catch {}
  }
  throw new Error('UGREENlink 发现失败：检查 ID 或远程访问状态');
}

async function mint(config, port) {
  const jar = new Map();
  const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const origin = await resolveOrigin(config.alias);

  let numberVersion = '78471';
  let shortVersion = '1.19.0';
  try {
    const page = await fetch(`${origin}/desktop/`, { headers: { Accept: 'text/html' }, signal: AbortSignal.timeout(8000) });
    absorbCookies(jar, page);
    const html = await page.text();
    numberVersion = html.match(/clientNumberVersion\s*=\s*(?:window\.clientNumberVersion\s*=\s*)?(\d{1,10})/)?.[1] ?? numberVersion;
    shortVersion = html.match(/clientShowVersion\s*=\s*(?:window\.clientShowVersion\s*=\s*)?["'](\d+\.\d+\.\d+)/)?.[1] ?? shortVersion;
  } catch {}

  const ctx = { Origin: origin, Referer: `${origin}/desktop/` };
  const common = {
    Accept: 'application/json, text/plain, */*',
    'Cache-Control': 'no-cache',
    'Client-Id': `${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}WEB`,
    'Client-Version': numberVersion,
    'Client-Version-Str': shortVersion,
    'UG-Agent': 'PC/WEB',
    'X-Specify-Language': 'zh-CN',
    ...ctx,
  };

  const check = await fetch(`${origin}/ugreen/v1/verify/check`, {
    method: 'POST',
    headers: { Accept: '*/*', 'Content-Type': 'text/plain;charset=UTF-8', ...ctx },
    body: JSON.stringify({ username: config.username }),
    signal: AbortSignal.timeout(15000),
  });
  absorbCookies(jar, check);
  const rsaToken = check.headers.get('x-rsa-token');
  if (!rsaToken) throw new Error(`check 失败（HTTP ${check.status}）`);
  const rsaKey = parseRsaPublicKey(rsaToken);

  const login = await fetch(`${origin}/ugreen/v1/verify/login`, {
    method: 'POST',
    headers: {
      ...common,
      'Content-Type': 'application/json',
      'UG-Client-Id': md5Hex(`uglink-worker:${config.alias}:Chrome`),
      ...(cookieHeader() ? { Cookie: cookieHeader() } : {}),
    },
    body: JSON.stringify({
      username: config.username,
      password: bytesToB64(rsaEncryptPKCS1(config.password, rsaKey)),
      keepalive: false,
      otp: true,
      is_simple: true,
    }),
    signal: AbortSignal.timeout(15000),
  });
  absorbCookies(jar, login);
  const loginJson = await login.json();
  const data = loginJson?.data ?? {};
  if (loginJson?.code !== 200) throw new Error(`登录失败（code ${loginJson?.code ?? 'unknown'}）`);
  if (data.enable_otp && !data.token) throw new Error('该账号要求二次验证，签发模式无法处理');

  const token = data.token;
  const url = new URL(`${origin}/ugreen/v1/gateway/proxy/dockerToken`);
  url.searchParams.set('port', String(port));
  const headers = { ...common, 'X-Ugreen-Security-Key': md5Hex(token) };
  if ((data.auth_type ?? 'url') === 'header') {
    headers['X-Ugreen-Token'] = bytesToB64(rsaEncryptPKCS1(token, parseRsaPublicKey(data.public_key)));
  } else {
    url.searchParams.set('token', token);
  }
  if (cookieHeader()) headers.Cookie = cookieHeader();

  const dt = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
  absorbCookies(jar, dt);
  const dtJson = await dt.json();
  const redirectUrl = dtJson?.data?.redirect_url;
  if (dtJson?.code !== 200 || typeof redirectUrl !== 'string') {
    throw new Error(`签发失败（code ${dtJson?.code ?? 'unknown'}）`);
  }
  if (!redirectUrl.startsWith('https://')) throw new Error('签发返回了非 HTTPS 地址');
  return redirectUrl;
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(value));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function authVersion(env) {
  return (await env.CONFIG.get('auth-version')) || '0';
}

async function isAuthed(request, secret, version = '0') {
  const header = request.headers.get('Cookie') ?? '';
  const match = header.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!match) return false;
  const [exp, sig, cookieVersion = '0'] = match[1].split('.');
  if (!exp || !sig || cookieVersion !== version) return false;
  if (Number(exp) < Math.floor(Date.now() / 1000)) return false;
  return (await sign(`${exp}:${version}`, secret)) === sig;
}

function cookieFor(exp, sig, version = '0') {
  return `${COOKIE}=${exp}.${sig}.${version}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`;
}

function passwordBytes(value) {
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, salt, iterations = 100000) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(salt), iterations }, key, 256);
  return { salt, iterations, hash: passwordBytes(bits), algorithm: 'PBKDF2-SHA256' };
}

async function verifyPassword(password, env) {
  const custom = await env.CONFIG.get('auth-password', 'json');
  if (custom?.hash && custom?.salt) {
    const candidate = await hashPassword(password, custom.salt, custom.iterations);
    return candidate.hash === custom.hash;
  }
  return password === env.ADMIN_KEY;
}

const STYLE = `
:root{color-scheme:dark;--ink:#f4f6fb;--muted:rgba(235,240,255,.55);--line:rgba(255,255,255,.14)}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;min-height:100%;overflow-x:hidden}
body{background:#05060a;color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;-webkit-font-smoothing:antialiased;overflow-x:hidden}
a{color:inherit}
#root{position:relative;min-height:100vh;min-height:100dvh;display:grid;grid-template-rows:auto auto;align-content:start;gap:14px;padding:16px;max-width:980px;margin:0 auto}
.bg{position:fixed;inset:0;z-index:0;overflow:hidden;background:
  radial-gradient(46% 42% at 28% 28%,rgba(82,130,255,.62),transparent 66%),
  radial-gradient(38% 36% at 76% 20%,rgba(123,224,199,.42),transparent 64%),
  radial-gradient(52% 46% at 62% 88%,rgba(172,92,255,.5),transparent 66%),
  radial-gradient(30% 30% at 12% 82%,rgba(255,138,120,.22),transparent 62%),
  linear-gradient(160deg,#0b1020 0%,#05060a 58%,#0a0a16 100%)}
.bg::after{content:"";position:absolute;inset:0;background:radial-gradient(120% 100% at 50% 0%,transparent 52%,rgba(0,0,0,.5) 100%)}
.glass{position:relative;border-radius:26px;border:1px solid var(--line);background:rgba(255,255,255,.055);box-shadow:0 24px 60px rgba(0,0,0,.35),inset 0 1px 0 rgba(255,255,255,.16);backdrop-filter:blur(22px) saturate(150%);-webkit-backdrop-filter:blur(22px) saturate(150%)}
.lg-ready .glass{backdrop-filter:none;-webkit-backdrop-filter:none;background:rgba(255,255,255,.02)}
.glass > .inner{position:relative;z-index:1}
.bar{border-radius:22px}
.bar > .inner{display:flex;align-items:center;gap:10px;padding:12px 18px;min-height:58px}
.brand{font-weight:700;letter-spacing:.18em;font-size:12px;color:rgba(255,255,255,.72)}
.spacer{flex:1}
.act{display:inline-flex;align-items:center;gap:6px;padding:7px 13px;border-radius:999px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:rgba(255,255,255,.82);text-decoration:none;font-size:13px;transition:background .18s ease,border-color .18s ease}
.act:hover{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.24)}
.panel > .inner{padding:22px}
h1{font-size:18px;margin:0 0 4px;font-weight:650}
.sub{margin:0 0 18px;color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:14px}
.tile{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;min-height:120px;padding:18px 12px;border-radius:20px;text-decoration:none;color:var(--ink);background:linear-gradient(160deg,rgba(255,255,255,.09),rgba(255,255,255,.03));border:1px solid rgba(255,255,255,.12);box-shadow:inset 0 1px 0 rgba(255,255,255,.18),0 10px 26px rgba(0,0,0,.22);transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease}
.tile:hover{transform:translateY(-2px);border-color:rgba(255,255,255,.24);box-shadow:inset 0 1px 0 rgba(255,255,255,.24),0 16px 32px rgba(0,0,0,.3)}
.tile .ico{font-size:30px;line-height:1;filter:drop-shadow(0 2px 6px rgba(0,0,0,.35))}
.tile .nm{font-size:13px;text-align:center;color:rgba(255,255,255,.86);word-break:break-all}
label{display:block;font-size:12px;color:var(--muted);margin:14px 0 6px;letter-spacing:.02em}
input{width:100%;padding:12px 13px;border-radius:14px;border:1px solid rgba(255,255,255,.14);background:rgba(6,8,14,.5);color:var(--ink);font-size:15px;outline:none;transition:border-color .18s ease,box-shadow .18s ease}
input:focus{border-color:rgba(91,140,255,.9);box-shadow:0 0 0 3px rgba(91,140,255,.22)}
button{font:inherit}
.btn{padding:12px 18px;border:0;border-radius:14px;background:linear-gradient(180deg,#6d9bff,#4a7bf0);color:#fff;font-weight:650;font-size:14px;cursor:pointer;box-shadow:0 10px 24px rgba(74,123,240,.32),inset 0 1px 0 rgba(255,255,255,.28);transition:transform .16s ease,filter .16s ease}
.btn:hover{filter:brightness(1.07);transform:translateY(-1px)}
.btn:disabled{opacity:.55;cursor:default;transform:none;filter:none}
.btn.ghost{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);box-shadow:inset 0 1px 0 rgba(255,255,255,.14);color:rgba(255,255,255,.86)}
.row{display:grid;grid-template-columns:60px 1fr 110px 42px;gap:10px;align-items:center;margin-bottom:10px}
.row input{margin:0}
.icon-btn{height:42px;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:rgba(255,255,255,.7);cursor:pointer;font-size:18px}
.icon-btn:hover{background:rgba(255,255,255,.12)}
#msg{min-height:22px;font-size:13px;margin-top:12px;color:var(--muted)}
.err{color:#ff8f8f}
.ok{color:#7be0c7}
.empty{padding:26px 6px;color:var(--muted);font-size:14px;text-align:center}
.panel.narrow{width:min(100%,420px);margin:0 auto;align-self:center}
.overview{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:22px}
.overview h2{font-size:26px;line-height:1.25;margin:0 0 7px;font-weight:650;letter-spacing:-.02em}
.overview .sub{margin:0}
.count{font-size:12px;color:var(--muted);white-space:nowrap}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:18px}
.search{position:relative;flex:1;min-width:0}
.search::before{content:"";position:absolute;width:13px;height:13px;border:1.6px solid rgba(255,255,255,.5);border-radius:50%;left:15px;top:13px;pointer-events:none}
.search::after{content:"";position:absolute;width:6px;height:1.6px;background:rgba(255,255,255,.5);transform:rotate(45deg);left:27px;top:29px;pointer-events:none}
.search input{padding:10px 14px 10px 40px;background:rgba(6,8,14,.3)}
.filters{display:flex;gap:8px;overflow-x:auto;padding:2px 0 14px;margin-bottom:2px;scrollbar-width:none}
.filters::-webkit-scrollbar{display:none}
.filter{flex:none;border:1px solid transparent;border-radius:999px;padding:6px 13px;background:transparent;color:var(--muted);font-size:13px;cursor:pointer}
.filter:hover{color:var(--ink);background:rgba(255,255,255,.06)}
.filter.active{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.15);color:var(--ink)}
.app-item{position:relative;min-width:0}
.app-item .tile{height:100%;width:100%}
.app-item[hidden]{display:none}
.tile .ico{display:flex;align-items:center;justify-content:center;width:48px;height:48px;font-size:30px;object-fit:contain}
img.ico{border-radius:12px}
.tile .port{font-size:11px;line-height:1;color:rgba(235,240,255,.38)}
.card-menu{position:absolute;z-index:2;right:7px;top:7px}
.menu-toggle{display:flex;align-items:center;justify-content:center;width:28px;height:28px;padding:0;border:0;border-radius:9px;background:transparent;color:rgba(255,255,255,.48);font-size:20px;line-height:1;cursor:pointer;opacity:0;transition:opacity .16s ease,background .16s ease}
.app-item:hover .menu-toggle,.menu-toggle:focus,.menu-toggle[aria-expanded="true"]{opacity:1}
.menu-toggle:hover{background:rgba(255,255,255,.12);color:var(--ink)}
.menu-popover{display:none;position:absolute;right:0;top:32px;width:112px;padding:5px;border:1px solid rgba(255,255,255,.15);border-radius:13px;background:#171b28;box-shadow:0 14px 32px rgba(0,0,0,.4)}
.card-menu.open .menu-popover{display:block}
.menu-popover button{display:block;width:100%;padding:7px 10px;border:0;border-radius:8px;background:none;color:var(--ink);font-size:12px;text-align:left;cursor:pointer}
.menu-popover button:hover{background:rgba(255,255,255,.08)}
.menu-popover .danger{color:#ff9e9e}
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:270px;padding:32px 12px;text-align:center}
.empty-symbol{display:flex;align-items:center;justify-content:center;width:58px;height:58px;margin-bottom:15px;border:1px solid rgba(255,255,255,.12);border-radius:18px;background:rgba(255,255,255,.055);font-size:26px;color:rgba(255,255,255,.55)}
.empty h3{font-size:16px;margin:0 0 5px;font-weight:600}
.empty p{margin:0 0 18px;font-size:13px}
#no-results{display:none}
.modal{border:1px solid rgba(255,255,255,.16);border-radius:24px;padding:0;background:rgba(15,19,30,.97);color:var(--ink);width:min(460px,calc(100% - 28px));max-height:calc(100dvh - 32px);box-shadow:0 30px 100px rgba(0,0,0,.6)}
.modal::backdrop{background:rgba(1,3,9,.72);backdrop-filter:blur(8px)}
.modal-head{display:flex;align-items:center;justify-content:space-between;padding:20px 22px 4px}
.modal-head h2{font-size:19px;margin:0}
.modal-close{width:30px;height:30px;border:0;border-radius:9px;background:rgba(255,255,255,.06);color:var(--muted);font-size:21px;cursor:pointer}
.modal form{padding:0 22px 22px}
.modal label{margin-top:12px}
.modal input{margin:0}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-hint{margin:6px 0 0;color:var(--muted);font-size:11px;line-height:1.5}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}
.modal-body{padding:12px 22px 22px}
.mint-description{margin:0;color:rgba(255,255,255,.86);font-size:14px;line-height:1.8}
.mint-warning{margin:12px 0 0;color:var(--muted);font-size:12px;line-height:1.7}
.mint-progress{padding:24px 0 14px;text-align:center}
.mint-spinner{display:block;width:34px;height:34px;margin:0 auto 16px;border:3px solid rgba(255,255,255,.12);border-top-color:#83a8ff;border-radius:50%;animation:mint-spin .8s linear infinite}
.mint-progress h3,.mint-result h3{margin:0 0 7px;font-size:17px;font-weight:600}
.mint-progress p,.mint-result p{margin:0;color:var(--muted);font-size:12px}
.mint-result{padding-top:4px}
.mint-result h3{color:#7fe0c1}
.mint-link{margin-top:6px!important;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px!important;line-height:1.5;user-select:all}
#mint-copy-status{min-height:20px;margin-top:8px;font-size:12px}
@keyframes mint-spin{to{transform:rotate(360deg)}}
#app-msg{min-height:20px;margin:10px 0 -8px;font-size:12px}
.settings-section{border-top:1px solid var(--line);margin-top:24px;padding-top:5px}
.section-title{font-size:14px;margin:18px 0 2px;font-weight:600}
@media (max-width:520px){
  #root{padding:12px;padding-top:max(12px,env(safe-area-inset-top));padding-bottom:max(20px,env(safe-area-inset-bottom));gap:12px}
  .bar > .inner{gap:8px;padding:10px 12px;min-height:56px}
  .brand{font-size:11px;letter-spacing:.12em}
  .bar h1{font-size:14px!important}
  .act{min-height:36px;padding:7px 11px}
  .panel{border-radius:22px}
  .panel > .inner{padding:18px 16px}
  .grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
  .tile{min-height:132px;padding:20px 12px 16px;border-radius:18px;gap:9px}
  .tile .nm{width:100%;font-size:14px;line-height:1.4;overflow-wrap:anywhere;word-break:normal}
  .row{grid-template-columns:48px 1fr 84px 40px;gap:8px}
  .overview{gap:10px;margin-bottom:18px}
  .overview h2{font-size:23px}
  .overview .sub{font-size:12px;line-height:1.5}
  .overview .btn{flex:none;min-height:42px;padding:10px 12px;font-size:13px}
  .toolbar{flex-wrap:wrap;gap:7px;margin-bottom:12px}
  .search{flex-basis:100%}
  .search input{min-height:44px;font-size:16px}
  .count{margin-left:auto}
  .filter{min-height:36px;padding:7px 14px}
  .tile .port{display:none}
  .menu-toggle{width:34px;height:34px;opacity:1}
  .menu-popover{top:36px}
  .modal{max-height:calc(100dvh - 24px);overflow-y:auto}
  .form-grid{grid-template-columns:1fr;gap:0}
  .modal input{font-size:16px}
}
@media (max-width:360px){.overview{align-items:stretch;flex-direction:column}.overview .btn{align-self:flex-start}.bar .brand{display:none}}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
`;

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const BAR_CONFIG = '{"cornerRadius":22,"zRadius":18,"blurAmount":0.42,"refraction":0.65,"chromAberration":0.06,"edgeHighlight":0.12,"specular":0.32,"fresnel":0.95,"saturation":0.08,"tintStrength":0.16,"shadowOpacity":0.24}';
const PANEL_CONFIG = '{"cornerRadius":26,"zRadius":34,"blurAmount":0.5,"refraction":0.78,"chromAberration":0.09,"edgeHighlight":0.14,"specular":0.4,"fresnel":1,"saturation":0.12,"tintStrength":0.2,"shadowOpacity":0.3}';
const MANIFEST = JSON.stringify({
  name: 'UGLINK 导航',
  short_name: '导航',
  start_url: '/',
  display: 'standalone',
  background_color: '#05060a',
  theme_color: '#05060a',
  icons: [
    { src: '/icon-180.png?v=3', sizes: '180x180', type: 'image/png' },
    { src: '/icon-512.png?v=3', sizes: '512x512', type: 'image/png' }
  ]
});

function binaryFromB64(b64, type) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return new Response(bytes, { headers: { 'Content-Type': type, 'Cache-Control': 'public, max-age=604800' } });
}

const FAVICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="bg" x1="8" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse"><stop stop-color="#243A78"/><stop offset="1" stop-color="#101D48"/></linearGradient><linearGradient id="mark" x1="20" y1="18" x2="45" y2="46" gradientUnits="userSpaceOnUse"><stop stop-color="#FFFFFF"/><stop offset="1" stop-color="#DCE8FF"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#bg)"/><path d="M19 17.625V33C19 41.25 24.25 45.875 32 45.875C39.75 45.875 45 41.25 45 33V17.625" fill="none" stroke="url(#mark)" stroke-width="7" stroke-linecap="round"/><circle cx="45" cy="17.625" r="4.875" fill="#7FE0C1"/><path d="M42.75 17.625L44.25 19.125L47.375 15.875" fill="none" stroke="#102043" stroke-width="1.375" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

const INIT_SCRIPT = `<script type="module">
const root = document.getElementById('root');
const glasses = Array.from(root.children).filter((el) => el.classList && el.classList.contains('glass'));
try {
  const mod = await import('/liquidglass.js');
  await mod.LiquidGlass.init({ root, glassElements: glasses });
  root.classList.add('lg-ready');
} catch (error) {
  console.warn('liquid glass unavailable:', error);
}
</script>`;

function layout(title, bodyHtml, actions = '') {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#05060a"><meta name="application-name" content="UGLINK"><link rel="icon" href="/favicon.svg?v=2" type="image/svg+xml"><link rel="icon" type="image/png" sizes="180x180" href="/icon-180.png?v=3"><link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=3"><link rel="manifest" href="/manifest.webmanifest?v=2"><meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="导航"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"><title>UGLINK · ${title}</title><style>${STYLE}</style></head>
<body><div id="root">
<div class="bg"></div>
<header class="glass bar" data-config='${BAR_CONFIG}'><div class="inner"><span class="brand">UGLINK</span><h1 style="font-size:15px;margin:0 0 0 2px;font-weight:600">${title}</h1><span class="spacer"></span>${actions}</div></header>
<main class="glass panel" data-config='${PANEL_CONFIG}'><div class="inner">${bodyHtml}</div></main>
</div>${INIT_SCRIPT}</body></html>`;
}

function goPage(app) {
  const name = escapeHtml(app.name);
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#080d1b"><link rel="icon" href="/favicon.svg?v=2" type="image/svg+xml"><title>正在打开 ${name} · UGLINK</title>
<style>
*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 30% 20%,#1b3262,transparent 48%),radial-gradient(circle at 80% 80%,#153c3a,transparent 42%),#080d1b;color:#f4f6fb;font:15px/1.7 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}.card{width:min(420px,100%);padding:38px 30px;text-align:center;border:1px solid rgba(255,255,255,.14);border-radius:26px;background:rgba(18,25,43,.88);box-shadow:0 28px 80px rgba(0,0,0,.35)}.brand{margin-bottom:28px;color:#9ca9c0;font-size:12px;font-weight:700;letter-spacing:.2em}.spinner{display:block;width:38px;height:38px;margin:0 auto 20px;border:3px solid rgba(255,255,255,.12);border-top-color:#83a8ff;border-radius:50%;animation:spin .8s linear infinite}h1{margin:0 0 8px;font-size:22px;font-weight:650}p{margin:0;color:#9ca9c0;font-size:13px}.error{margin-top:16px;color:#ff9e9e}.actions{display:flex;justify-content:center;gap:10px;margin-top:24px}.btn{display:inline-block;padding:10px 18px;border:0;border-radius:12px;background:#5b8cff;color:#fff;font:inherit;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer}.btn.ghost{border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.07)}@keyframes spin{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.spinner{animation-duration:1.6s}}
</style></head><body><main class="card"><div class="brand">UGLINK</div><span class="spinner" id="spinner" aria-hidden="true"></span><h1>正在打开 ${name}</h1><p id="status" role="status" aria-live="polite">正在签发一次性登录凭据，完成后将自动跳转…</p><p class="error" id="error" role="alert" hidden></p><div class="actions" id="actions" hidden><button class="btn" id="retry" type="button">重试</button><a class="btn ghost" href="/">返回导航</a></div><noscript><p class="error">请启用 JavaScript 以完成登录跳转。</p></noscript></main>
<script>
const appId = ${clientData(app.id)};
const status = document.getElementById('status');
const error = document.getElementById('error');
async function openApp() {
  document.getElementById('spinner').hidden = false;
  document.getElementById('actions').hidden = true;
  error.hidden = true;
  status.textContent = '正在签发一次性登录凭据，完成后将自动跳转…';
  try {
    const response = await fetch('/api/mint?app=' + encodeURIComponent(appId));
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.url) throw new Error(data.error || '登录链接签发失败');
    status.textContent = '签发完成，正在跳转…';
    location.replace(data.url);
  } catch (reason) {
    document.getElementById('spinner').hidden = true;
    status.textContent = '暂时无法打开应用';
    error.textContent = reason.message || '登录链接签发失败，请稍后重试。';
    error.hidden = false;
    document.getElementById('actions').hidden = false;
  }
}
document.getElementById('retry').addEventListener('click', openApp);
openApp();
</script></body></html>`;
}

function loginPage() {
  return layout('登录', `<p class="sub" style="margin-top:0">请输入访问口令进入导航。</p>
<form method="POST" action="/login"><label>访问口令</label><input type="password" name="key" autofocus autocomplete="current-password"><button class="btn" style="margin-top:18px;width:100%">进入</button></form>`)
    .replace('<main class="glass panel"', '<main class="glass panel narrow"');
}

function iconHtml(app) {
  const icon = String(app.icon || '').trim();
  if (/^https:\/\/[^\s]+$/i.test(icon) || /^data:image\/svg\+xml,(?:%3c|<)svg(?:%20|\s)/i.test(icon)) {
    return `<img class="ico" src="${escapeHtml(icon)}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.replaceWith(document.createTextNode('📦'))">`;
  }
  return `<span class="ico" aria-hidden="true">${escapeHtml(icon || '📦')}</span>`;
}

function appDialog() {
  return `<dialog class="modal" id="app-dialog">
<div class="modal-head"><h2 id="dialog-title">新增应用</h2><button class="modal-close" id="dialog-close" type="button" aria-label="关闭">×</button></div>
<form id="app-form">
<input id="app-id" type="hidden">
<label for="app-name">应用名称</label><input id="app-name" maxlength="40" placeholder="例如：Jellyfin" required autofocus>
<div class="form-grid"><div><label for="app-port">NAS 端口</label><input id="app-port" type="number" min="1" max="65535" step="1" inputmode="numeric" placeholder="例如：8096" required></div>
<div><label for="app-category">分类</label><input id="app-category" list="category-list" maxlength="20" placeholder="默认分类"><datalist id="category-list"></datalist></div></div>
<label for="app-icon">图标</label><input id="app-icon" maxlength="16000" placeholder="Emoji、HTTPS 图片地址或 SVG Data URL（选填）">
<p class="form-hint">端口填写 NAS 实际提供服务的端口，不是容器映射端口。</p>
<p id="app-msg" role="status"></p>
<div class="modal-actions"><button class="btn ghost" id="dialog-cancel" type="button">取消</button><button class="btn" id="app-submit" type="submit">保存应用</button></div>
</form></dialog>`;
}

function mintDialog() {
  return `<dialog class="modal" id="mint-dialog" aria-labelledby="mint-title">
<div class="modal-head"><h2 id="mint-title">签发一次性登录链接</h2><button class="modal-close" id="mint-close" type="button" aria-label="关闭">×</button></div>
<div class="modal-body">
<div id="mint-confirm"><p class="mint-description" id="mint-description"></p><p class="mint-warning">链接包含临时登录凭据，任何获得链接的人都可能登录该应用。链接打开后失效，请勿分享给不信任的人。</p></div>
<div class="mint-progress" id="mint-progress" role="status" aria-live="polite" hidden><span class="mint-spinner" aria-hidden="true"></span><h3>正在签发…</h3><p>正在通过 UGREENlink 获取一次性登录凭据，请稍候。</p></div>
<div class="mint-result" id="mint-result" hidden><h3>签发完成</h3><p>一次性登录链接已生成，请妥善保管。</p><label for="mint-url">登录链接</label><input class="mint-link" id="mint-url" type="text" readonly autocomplete="off" spellcheck="false"><p id="mint-copy-status" role="status" aria-live="polite"></p></div>
<p class="err" id="mint-error" role="alert" hidden></p>
<div class="modal-actions"><button class="btn ghost" id="mint-cancel" type="button">取消</button><button class="btn" id="mint-primary" type="button">确定签发</button></div>
</div></dialog>`;
}

function clientData(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

function navPage(config) {
  const apps = config?.apps ?? [];
  const categories = [...new Set(apps.map((app) => app.category || '默认分类'))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
  const filters = ['全部', ...categories].map((category, index) => `<button class="filter${index === 0 ? ' active' : ''}" type="button" data-category="${escapeHtml(index === 0 ? '' : category)}">${escapeHtml(category)}</button>`).join('');
  const tiles = apps.map((app) => `<article class="app-item" data-id="${escapeHtml(app.id)}" data-name="${escapeHtml(String(app.name).toLowerCase())}" data-category="${escapeHtml(app.category || '默认分类')}">
<a class="tile" href="/go?app=${encodeURIComponent(app.id)}" target="_blank" rel="noopener noreferrer" title="在新标签页打开 ${escapeHtml(app.name)}">${iconHtml(app)}<span class="nm">${escapeHtml(app.name)}</span><span class="port">:${escapeHtml(app.port)}</span></a>
<div class="card-menu"><button class="menu-toggle" type="button" aria-label="管理 ${escapeHtml(app.name)}" aria-expanded="false">···</button><div class="menu-popover"><button type="button" data-action="copy">复制登录链接</button><button type="button" data-action="edit">编辑应用</button><button class="danger" type="button" data-action="delete">删除应用</button></div></div>
</article>`).join('');
  const empty = apps.length ? '' : `<div class="empty" id="empty-apps"><div class="empty-symbol">＋</div><h3>添加你的第一个应用</h3><p class="sub">集中管理 NAS 上的服务，点击即可安全登录。</p><button class="btn" type="button" data-open-app>新增应用</button></div>`;
  const body = `<div class="overview"><div><h2>我的应用</h2><p class="sub">你的 NAS 服务，从这里一键抵达。</p></div><button class="btn" type="button" data-open-app>＋ 新增应用</button></div>
<div class="toolbar"><div class="search"><input id="app-search" type="search" placeholder="搜索应用" aria-label="搜索应用"></div><span class="count" id="app-count">${apps.length} 个应用</span></div>
<nav class="filters" id="app-filters" aria-label="应用分类"${apps.length ? '' : ' hidden'}>${filters}</nav>
<div class="grid" id="app-grid"${apps.length ? '' : ' hidden'}>${tiles}</div>${empty}
<div class="empty" id="no-results"><div class="empty-symbol">⌕</div><h3>没有找到应用</h3><p class="sub">试试其他名称或分类。</p></div>
<p id="nav-notice" role="status" aria-live="polite" style="min-height:22px;margin:14px 0 0;font-size:13px;text-align:center"></p>
${appDialog().replace('<datalist id="category-list"></datalist>', `<datalist id="category-list">${categories.map((item) => `<option value="${escapeHtml(item)}"></option>`).join('')}</datalist>`)}
${mintDialog()}
<script>
const apps = ${clientData(apps)};
const dialog = document.getElementById('app-dialog');
const mintDialog = document.getElementById('mint-dialog');
const form = document.getElementById('app-form');
const search = document.getElementById('app-search');
const count = document.getElementById('app-count');
let category = '';
let mintApp = null;
let mintBusy = false;
let mintState = 'confirm';
let mintedUrl = '';
function notify(message, error = false) {
  const notice = document.getElementById('nav-notice');
  notice.textContent = message;
  notice.className = error ? 'err' : 'ok';
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const field = document.createElement('textarea');
    field.value = text;
    field.style.cssText = 'position:fixed;left:-9999px;top:0';
    document.body.append(field);
    field.select();
    const copied = document.execCommand('copy');
    field.remove();
    if (!copied) throw new Error('浏览器未允许复制，请检查剪贴板权限');
  }
}
function setMintState(state, message = '') {
  mintState = state;
  document.getElementById('mint-confirm').hidden = state !== 'confirm';
  document.getElementById('mint-progress').hidden = state !== 'busy';
  document.getElementById('mint-result').hidden = state !== 'done';
  document.getElementById('mint-error').hidden = state !== 'error';
  document.getElementById('mint-title').textContent = state === 'done' ? '一次性登录链接已签发' : state === 'error' ? '签发失败' : '签发一次性登录链接';
  document.getElementById('mint-close').disabled = state === 'busy';
  document.getElementById('mint-cancel').disabled = state === 'busy';
  const primary = document.getElementById('mint-primary');
  primary.hidden = state === 'busy';
  primary.disabled = state === 'busy';
  primary.textContent = state === 'done' ? '复制链接' : state === 'error' ? '重新签发' : '确定签发';
  document.getElementById('mint-cancel').textContent = state === 'done' ? '关闭' : '取消';
  document.getElementById('mint-error').textContent = message;
}
function openMintDialog(app) {
  mintApp = app;
  mintedUrl = '';
  document.getElementById('mint-description').textContent = '将为“' + app.name + '”签发一次性登录链接。';
  document.getElementById('mint-url').value = '';
  document.getElementById('mint-copy-status').textContent = '';
  setMintState('confirm');
  mintDialog.showModal();
}
async function issueMintLink() {
  if (!mintApp || mintBusy) return;
  mintBusy = true;
  setMintState('busy');
  try {
    const response = await fetch('/api/mint?app=' + encodeURIComponent(mintApp.id));
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.url) throw new Error(data.error || '登录链接签发失败');
    mintedUrl = data.url;
    const field = document.getElementById('mint-url');
    field.value = mintedUrl;
    setMintState('done');
    const status = document.getElementById('mint-copy-status');
    try {
      await copyText(mintedUrl);
      status.className = 'ok';
      status.textContent = '已自动复制，也可以手动复制。';
    } catch {
      field.focus();
      field.select();
      status.className = '';
      status.textContent = '浏览器未允许自动复制，请点击“复制链接”或手动选择复制。';
    }
  } catch (error) {
    setMintState('error', error.message || '登录链接签发失败');
  } finally {
    mintBusy = false;
  }
}
document.getElementById('mint-primary').addEventListener('click', async () => {
  if (mintState !== 'done') return issueMintLink();
  const status = document.getElementById('mint-copy-status');
  try {
    await copyText(mintedUrl);
    status.className = 'ok';
    status.textContent = '链接已复制。';
    document.getElementById('mint-primary').textContent = '已复制';
  } catch (error) {
    const field = document.getElementById('mint-url');
    field.focus();
    field.select();
    status.className = 'err';
    status.textContent = error.message || '复制失败，请手动选择链接复制。';
  }
});
document.getElementById('mint-url').addEventListener('focus', (event) => event.target.select());
document.getElementById('mint-close').onclick = () => mintDialog.close();
document.getElementById('mint-cancel').onclick = () => mintDialog.close();
mintDialog.addEventListener('click', (event) => { if (event.target === mintDialog && !mintBusy) mintDialog.close(); });
mintDialog.addEventListener('cancel', (event) => { if (mintBusy) event.preventDefault(); });
function openDialog(app) {
  document.getElementById('dialog-title').textContent = app ? '编辑应用' : '新增应用';
  document.getElementById('app-id').value = app?.id || '';
  document.getElementById('app-name').value = app?.name || '';
  document.getElementById('app-port').value = app?.port || '';
  document.getElementById('app-category').value = app?.category || '';
  document.getElementById('app-icon').value = app?.icon || '';
  document.getElementById('app-msg').textContent = '';
  dialog.showModal();
  document.getElementById('app-name').focus();
}
function filterApps() {
  const query = search.value.trim().toLowerCase();
  let visible = 0;
  document.querySelectorAll('.app-item').forEach((item) => {
    const matches = (!query || item.dataset.name.includes(query)) && (!category || item.dataset.category === category);
    item.hidden = !matches;
    if (matches) visible += 1;
  });
  count.textContent = visible + ' / ' + apps.length + ' 个应用';
  document.getElementById('no-results').style.display = apps.length && !visible ? 'flex' : 'none';
  document.getElementById('app-grid').hidden = !visible;
}
document.querySelectorAll('[data-open-app]').forEach((button) => button.addEventListener('click', () => openDialog()));
search.addEventListener('input', filterApps);
document.querySelectorAll('.filter').forEach((button) => button.addEventListener('click', () => {
  document.querySelector('.filter.active')?.classList.remove('active');
  button.classList.add('active');
  category = button.dataset.category;
  filterApps();
}));
document.querySelectorAll('.menu-toggle').forEach((button) => button.addEventListener('click', () => {
  const menu = button.parentElement;
  const opening = !menu.classList.contains('open');
  document.querySelectorAll('.card-menu.open').forEach((el) => { el.classList.remove('open'); el.querySelector('button').setAttribute('aria-expanded', 'false'); });
  menu.classList.toggle('open', opening);
  button.setAttribute('aria-expanded', String(opening));
}));
document.addEventListener('click', (event) => {
  if (!event.target.closest('.card-menu')) document.querySelectorAll('.card-menu.open').forEach((el) => { el.classList.remove('open'); el.querySelector('button').setAttribute('aria-expanded', 'false'); });
});
document.querySelectorAll('[data-action]').forEach((button) => button.addEventListener('click', async () => {
  const id = button.closest('.app-item').dataset.id;
  const app = apps.find((item) => item.id === id);
  if (button.dataset.action === 'edit') return openDialog(app);
  if (button.dataset.action === 'copy') {
    openMintDialog(app);
    return;
  }
  if (!confirm('确定删除“' + app.name + '”吗？此操作不会影响 NAS 上的应用。')) return;
  button.disabled = true;
  const response = await fetch('/api/apps/' + encodeURIComponent(id), { method: 'DELETE' });
  const data = await response.json().catch(() => ({}));
  if (response.ok) location.reload();
  else { alert(data.error || '删除失败'); button.disabled = false; }
}));
document.getElementById('dialog-close').onclick = () => dialog.close();
document.getElementById('dialog-cancel').onclick = () => dialog.close();
dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = document.getElementById('app-id').value;
  const submit = document.getElementById('app-submit');
  const message = document.getElementById('app-msg');
  submit.disabled = true;
  message.className = '';
  message.textContent = '正在保存…';
  const body = {
    name: document.getElementById('app-name').value.trim(),
    port: Number(document.getElementById('app-port').value),
    category: document.getElementById('app-category').value.trim(),
    icon: document.getElementById('app-icon').value.trim(),
  };
  try {
    const response = await fetch(id ? '/api/apps/' + encodeURIComponent(id) : '/api/apps', { method: id ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || '保存失败');
    location.reload();
  } catch (error) {
    message.className = 'err';
    message.textContent = error.message;
    submit.disabled = false;
  }
});
</script>`;
  return layout('导航', body, '<a class="act" href="/settings">设置</a><a class="act" href="/logout">退出</a>');
}

function settingsPage(config) {
  return layout('设置', `<div>
<label>UGREENlink ID</label><input id="alias" value="${escapeHtml(config?.alias ?? '')}" placeholder="你的 UGREENlink ID">
<label>NAS 用户名</label><input id="username" value="${escapeHtml(config?.username ?? '')}">
<label>NAS 密码</label><input id="password" type="password" placeholder="${config?.password ? '已保存，留空则不修改' : '未设置'}">
<button class="btn" id="save" style="margin-top:18px">保存配置</button>
<p id="msg"></p>
</div>
<div class="settings-section"><h2 class="section-title">修改访问口令</h2><p class="sub">新口令至少 8 个字符。修改成功后，其他设备的登录态都会失效。</p>
<form id="password-form">
<label for="current-key">原口令</label><input id="current-key" type="password" autocomplete="current-password" required>
<label for="new-key">新口令</label><input id="new-key" type="password" autocomplete="new-password" minlength="8" required>
<label for="confirm-key">确认新口令</label><input id="confirm-key" type="password" autocomplete="new-password" minlength="8" required>
<button class="btn ghost" id="change-key" type="submit" style="margin-top:18px">更新口令</button><p id="key-msg"></p>
</form></div>
<script>
document.getElementById('save').onclick = async () => {
  const body = {
    alias: document.getElementById('alias').value.trim(),
    username: document.getElementById('username').value.trim(),
    password: document.getElementById('password').value,
  };
  const res = await fetch('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  const msg = document.getElementById('msg');
  msg.className = res.ok ? 'ok' : 'err';
  msg.textContent = res.ok ? '已保存' : (data.error || '保存失败');
};
document.getElementById('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const currentKey = document.getElementById('current-key').value;
  const newKey = document.getElementById('new-key').value;
  const confirmKey = document.getElementById('confirm-key').value;
  const msg = document.getElementById('key-msg');
  if (newKey !== confirmKey) { msg.className = 'err'; msg.textContent = '两次输入的新口令不一致'; return; }
  const button = document.getElementById('change-key');
  button.disabled = true;
  msg.className = '';
  msg.textContent = '正在更新…';
  try {
    const res = await fetch('/api/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ currentKey, newKey, confirmKey }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || '口令修改失败');
    msg.className = 'ok';
    msg.textContent = '口令已更新，即将退出登录';
    setTimeout(() => { location.href = '/logout'; }, 900);
  } catch (error) {
    msg.className = 'err';
    msg.textContent = error.message;
    button.disabled = false;
  }
});
</script>`, '<a class="act" href="/">返回导航</a><a class="act" href="/logout">退出</a>');
}

function limited(ip) {
  const now = Date.now();
  const list = (rate.get(ip) ?? []).filter((t) => now - t < 60000);
  if (list.length >= 10) return true;
  list.push(now);
  rate.set(ip, list);
  return false;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function readAppInput(body) {
  const name = String(body?.name ?? '').trim();
  const icon = String(body?.icon ?? '').trim();
  const category = String(body?.category ?? '').trim();
  const port = Number(body?.port);
  if (!name) return { error: '应用名称不能为空' };
  if (name.length > 40) return { error: '应用名称不能超过 40 个字符' };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: '端口必须是 1–65535 之间的整数' };
  if (category.length > 20) return { error: '分类不能超过 20 个字符' };
  if (icon.length > 16000) return { error: '图标地址不能超过 16000 个字符' };
  if (icon.includes(':') && !/^https:\/\/[^\s]+$/i.test(icon) && !/^data:image\/svg\+xml,(?:%3c|<)svg(?:%20|\s)/i.test(icon)) return { error: '图标图片仅支持 HTTPS 地址或 SVG Data URL' };
  return { app: { name, icon, category, port } };
}

async function saveConfig(env, config) {
  await env.CONFIG.put('config', JSON.stringify(config));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/health') return new Response('ok');
    if (url.pathname === '/favicon.svg' || url.pathname === '/favicon.ico') {
      return new Response(FAVICON, { headers: { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } });
    }
    if (url.pathname === '/liquidglass.js') {
      return new Response(LG_SOURCE, { headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'public, max-age=86400' } });
    }
    if (url.pathname === '/apple-touch-icon.png' || url.pathname === '/icon-180.png') {
      return binaryFromB64(ICON_180, 'image/png');
    }
    if (url.pathname === '/icon-512.png') {
      return binaryFromB64(ICON_512, 'image/png');
    }
    if (url.pathname === '/manifest.webmanifest') {
      return new Response(MANIFEST, { headers: { 'Content-Type': 'application/manifest+json; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
    }

    if (url.pathname === '/login' && request.method === 'POST') {
      const form = await request.formData();
      const key = String(form.get('key') ?? '');
      if (!(await verifyPassword(key, env))) return new Response(loginPage(), { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      const version = await authVersion(env);
      const exp = String(Math.floor(Date.now() / 1000) + SESSION_SECONDS);
      const sig = await sign(`${exp}:${version}`, env.ADMIN_KEY);
      return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': cookieFor(exp, sig, version) } });
    }
    if (url.pathname === '/logout') {
      return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` } });
    }
    const version = await authVersion(env);
    if (!(await isAuthed(request, env.ADMIN_KEY, version))) {
      return new Response(loginPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }

    const config = await env.CONFIG.get('config', 'json');

    if (url.pathname === '/') {
      return new Response(navPage(config), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/settings') {
      return new Response(settingsPage(config), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/api/config' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: '请求格式无效' }, 400);
      }
      const alias = String(body.alias ?? '').trim();
      const username = String(body.username ?? '').trim();
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(alias)) return json({ error: 'UGREENlink ID 格式不正确' }, 400);
      if (!username) return json({ error: '用户名不能为空' }, 400);
      const password = typeof body.password === 'string' && body.password.length ? body.password : config?.password;
      if (!password) return json({ error: '首次配置需要填写密码' }, 400);
      await saveConfig(env, { ...config, alias, username, password, apps: config?.apps ?? [] });
      return json({ ok: true });
    }
    if (url.pathname === '/api/password' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: '请求格式无效' }, 400); }
      const currentKey = typeof body.currentKey === 'string' ? body.currentKey : '';
      const newKey = typeof body.newKey === 'string' ? body.newKey : '';
      const confirmKey = typeof body.confirmKey === 'string' ? body.confirmKey : '';
      if (!(await verifyPassword(currentKey, env))) return json({ error: '原口令不正确' }, 403);
      if (newKey.length < 8 || newKey.length > 128) return json({ error: '新口令长度需为 8–128 个字符' }, 400);
      if (newKey !== confirmKey) return json({ error: '两次输入的新口令不一致' }, 400);
      if (newKey === currentKey) return json({ error: '新口令不能与原口令相同' }, 400);
      const salt = bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
      const record = await hashPassword(newKey, salt);
      await env.CONFIG.put('auth-password', JSON.stringify(record));
      await env.CONFIG.put('auth-version', crypto.randomUUID());
      return json({ ok: true });
    }
    if (url.pathname === '/api/apps' && request.method === 'POST') {
      if ((config?.apps?.length ?? 0) >= 50) return json({ error: '最多可添加 50 个应用' }, 400);
      let body;
      try { body = await request.json(); } catch { return json({ error: '请求格式无效' }, 400); }
      const result = readAppInput(body);
      if (result.error) return json({ error: result.error }, 400);
      const app = { id: crypto.randomUUID(), ...result.app };
      const next = { ...config, apps: [...(config?.apps ?? []), app] };
      await saveConfig(env, next);
      return json({ ok: true, app }, 201);
    }
    const appMatch = url.pathname.match(/^\/api\/apps\/([^/]+)$/);
    if (appMatch && request.method === 'PUT') {
      let id;
      try { id = decodeURIComponent(appMatch[1]); } catch { return json({ error: '应用 ID 无效' }, 400); }
      const index = (config?.apps ?? []).findIndex((app) => app.id === id);
      if (index < 0) return json({ error: '应用不存在' }, 404);
      let body;
      try { body = await request.json(); } catch { return json({ error: '请求格式无效' }, 400); }
      const result = readAppInput(body);
      if (result.error) return json({ error: result.error }, 400);
      const apps = [...config.apps];
      apps[index] = { ...apps[index], ...result.app };
      await saveConfig(env, { ...config, apps });
      return json({ ok: true, app: apps[index] });
    }
    if (appMatch && request.method === 'DELETE') {
      let id;
      try { id = decodeURIComponent(appMatch[1]); } catch { return json({ error: '应用 ID 无效' }, 400); }
      const apps = config?.apps ?? [];
      if (!apps.some((app) => app.id === id)) return json({ error: '应用不存在' }, 404);
      await saveConfig(env, { ...config, apps: apps.filter((app) => app.id !== id) });
      return json({ ok: true });
    }
    if (url.pathname === '/api/mint') {
      if (!config) return json({ error: '尚未配置' }, 400);
      const app = (config.apps ?? []).find((a) => a.id === url.searchParams.get('app'));
      if (!app) return json({ error: '应用不存在' }, 404);
      if (limited(request.headers.get('CF-Connecting-IP') ?? 'unknown')) return json({ error: '签发过于频繁' }, 429);
      try {
        return json({ url: await mint(config, app.port) });
      } catch (error) {
        return json({ error: error.message || '签发失败' }, 502);
      }
    }
    if (url.pathname === '/go') {
      if (!config) return new Response('尚未配置', { status: 400 });
      const app = (config.apps ?? []).find((a) => a.id === url.searchParams.get('app'));
      if (!app) return new Response('应用不存在', { status: 404 });
      return new Response(goPage(app), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    return new Response('not found', { status: 404 });
  },
};

export { md5Hex, parseRsaPublicKey, rsaEncryptPKCS1, bytesToB64 };
