'use strict';

/* ============================================================
   CyberGuard — سایبرگارد
   طراحی و توسعه: یوسف پرورش
   منطق همهٔ ابزارها — تمام پردازش‌ها به‌صورت محلی انجام می‌شود
   ============================================================ */

/* ---------- ابزارهای کمکی ---------- */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

const FA_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];

function toFa(value) {
  return String(value).replace(/[0-9]/g, (d) => FA_DIGITS[Number(d)]);
}

let toastTimer = null;
function showToast(message) {
  const toast = $('#toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2400);
}

function escapeHTML(str) {
  return String(str).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

function copyText(text, successMsg) {
  const msg = successMsg || 'در حافظه کپی شد ✅';
  const fallbackCopy = () => {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '-1000px';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) { showToast(msg); return; }
      showToast('کپی خودکار ممکن نشد؛ لطفاً دستی کپی کنید');
    } catch (err) {
      showToast('کپی خودکار ممکن نشد؛ لطفاً دستی کپی کنید');
    }
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast(msg)).catch(fallbackCopy);
  } else {
    fallbackCopy();
  }
}

function bindEnter(inputEl, btnEl) {
  if (!inputEl || !btnEl) return;
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); btnEl.click(); }
  });
}

/* ============================================================
   هش SHA-256 — پیاده‌سازی داخلی و مستقل (بدون نیاز به اینترنت)
   ============================================================ */
const SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function rotr32(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha256FromBytes(bytes) {
  const H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];
  const bitLength = bytes.length * 8;
  const padded = bytes.slice();
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0x00);
  const hi = Math.floor(bitLength / 0x100000000);
  const lo = bitLength >>> 0;
  padded.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
  padded.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

  const w = new Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const b0 = padded[offset + i * 4];
      const b1 = padded[offset + i * 4 + 1];
      const b2 = padded[offset + i * 4 + 2];
      const b3 = padded[offset + i * 4 + 3];
      w[i] = (((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) | 0);
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3)) | 0;
      const s1 = (rotr32(y, 17) ^ rotr32(y, 19) ^ (y >>> 10)) | 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3];
    let e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) | 0;
      const ch = ((e & f) ^ (~e & g)) | 0;
      const temp1 = (h + S1 + ch + SHA_K[i] + w[i]) | 0;
      const S0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) | 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) | 0;
      const temp2 = (S0 + maj) | 0;
      h = g; g = f; f = e;
      e = (d + temp1) | 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0;
    H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  let hex = '';
  for (let i = 0; i < 8; i++) {
    hex += ('00000000' + ((H[i] >>> 0).toString(16))).slice(-8);
  }
  return hex;
}

function utf8Bytes(text) {
  if (typeof TextEncoder !== 'undefined') {
    return Array.from(new TextEncoder().encode(text));
  }
  const bin = unescape(encodeURIComponent(text));
  const out = [];
  for (let i = 0; i < bin.length; i++) out.push(bin.charCodeAt(i) & 0xff);
  return out;
}

function sha256Hex(text) {
  return sha256FromBytes(utf8Bytes(String(text)));
}

/* ============================================================
   ابزار ۱: بررسی تقریبی قدرت رمز عبور
   ============================================================ */
const COMMON_PASSWORDS = [
  '123456', 'password', '123456789', '12345678', '12345', 'qwerty', 'abc123',
  '111111', '123123', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
  'iloveyou', 'football', 'princess', 'sunshine', 'master', '1234',
  '1234567', '1234567890', 'passw0rd', 'password1', 'qwe123', '1q2w3e4r',
  'a123456', '654321', '555555', 'google', 'qwerty123', '000000', 'asdfgh', 'password123'
];

const SEQUENCES = [
  'abcdefghijklmnopqrstuvwxyz', '0123456789',
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '!@#$%^&*()'
];

function hasSequence(pw) {
  const low = pw.toLowerCase();
  for (const seq of SEQUENCES) {
    for (let i = 0; i + 4 <= seq.length; i++) {
      const part = seq.slice(i, i + 4);
      if (low.indexOf(part) !== -1) return true;
      const rev = part.split('').reverse().join('');
      if (low.indexOf(rev) !== -1) return true;
    }
  }
  return false;
}

function formatCrackTime(seconds) {
  if (!isFinite(seconds) || seconds < 1) return 'کمتر از ۱ ثانیه';
  if (seconds < 60) return toFa(Math.ceil(seconds)) + ' ثانیه';
  const minutes = seconds / 60;
  if (minutes < 60) return toFa(Math.ceil(minutes)) + ' دقیقه';
  const hours = minutes / 60;
  if (hours < 24) return toFa(Math.ceil(hours)) + ' ساعت';
  const days = hours / 24;
  if (days < 30) return toFa(Math.ceil(days)) + ' روز';
  const months = days / 30;
  if (months < 12) return toFa(Math.ceil(months)) + ' ماه';
  const years = days / 365;
  if (years < 1000) return toFa(Math.round(years)) + ' سال';
  if (years < 1e6) return toFa(Math.round(years / 1000)) + ' هزار سال';
  if (years < 1e9) return toFa(Math.round(years / 1e6)) + ' میلیون سال';
  return 'میلیاردها سال';
}

function analyzePassword(pw) {
  const len = pw.length;
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);

  const checks = [
    { ok: len >= 8, text: 'حداقل ۸ کاراکتر (اکنون: ' + toFa(len) + ' کاراکتر)' },
    { ok: hasLower, text: 'شامل حروف کوچک انگلیسی (a-z)' },
    { ok: hasUpper, text: 'شامل حروف بزرگ انگلیسی (A-Z)' },
    { ok: hasDigit, text: 'شامل اعداد (0-9)' },
    { ok: hasSymbol, text: 'شامل نمادها (!@#$...)' }
  ];

  let score = 0;
  if (len >= 16) score += 35;
  else if (len >= 12) score += 28;
  else if (len >= 8) score += 18;
  else score += 5;
  if (hasLower) score += 10;
  if (hasUpper) score += 12;
  if (hasDigit) score += 12;
  if (hasSymbol) score += 15;
  if (hasLower && hasUpper && hasDigit && hasSymbol) score += 8;
  if (len >= 20) score += 6;

  const warnings = [];
  if (COMMON_PASSWORDS.indexOf(pw.toLowerCase()) !== -1) {
    score = Math.min(score, 8);
    warnings.push('این رمز در فهرست رایج‌ترین رمزهای عبور جهان قرار دارد!');
  }
  if (hasSequence(pw)) {
    score -= 15;
    warnings.push('شامل دنبالهٔ متوالی حروف یا اعداد است (مانند abc یا 1234).');
  }
  if (/(.)\1{2,}/.test(pw)) {
    score -= 12;
    warnings.push('کاراکترهای تکراری پشت سر هم دارد (مانند aaa یا 111).');
  }

  score = Math.max(0, Math.min(100, score));

  let charset = 0;
  if (hasLower) charset += 26;
  if (hasUpper) charset += 26;
  if (hasDigit) charset += 10;
  if (hasSymbol) charset += 33;
  if (charset === 0) charset = 26;
  const entropy = len * (Math.log(charset) / Math.LN2);
  const seconds = Math.pow(2, entropy) / 2 / 1e10;

  const levels = [
    [25, 'خیلی ضعیف', '#ff5d73'],
    [45, 'ضعیف', '#ff8a4c'],
    [65, 'متوسط', '#ffb454'],
    [82, 'خوب', '#a3e635'],
    [101, 'خیلی قوی', '#34d399']
  ];
  let label = 'خیلی ضعیف';
  let color = '#ff5d73';
  for (const lv of levels) {
    if (score < lv[0]) { label = lv[1]; color = lv[2]; break; }
  }

  return { score: score, label: label, color: color, checks: checks, warnings: warnings, crackText: formatCrackTime(seconds) };
}

function renderStrength(pw) {
  const box = $('#pwResult');
  if (!box) return;
  if (!pw) { box.hidden = true; return; }
  const res = analyzePassword(pw);
  const fill = $('#pwFill');
  if (fill) {
    fill.style.width = res.score + '%';
    fill.style.background = res.color;
  }
  const labelEl = $('#pwLabel');
  if (labelEl) { labelEl.textContent = res.label; labelEl.style.color = res.color; }
  const scoreEl = $('#pwScore');
  if (scoreEl) scoreEl.textContent = toFa(res.score) + '٪';
  const checksEl = $('#pwChecks');
  if (checksEl) {
    checksEl.innerHTML = res.checks.map((c) =>
      '<li class="' + (c.ok ? 'ok' : 'no') + '">' + (c.ok ? '✅' : '⬜') + ' ' + c.text + '</li>'
    ).join('');
  }
  const warnEl = $('#pwWarn');
  if (warnEl) {
    if (res.warnings.length) {
      warnEl.innerHTML = res.warnings.map((t) => '⚠️ ' + escapeHTML(t)).join('<br>');
      warnEl.hidden = false;
    } else {
      warnEl.hidden = true;
    }
  }
  const crackEl = $('#pwCrack');
  if (crackEl) crackEl.textContent = '⏳ زمان تقریبی شکستن با حملهٔ brute-force: ' + res.crackText;
  box.hidden = false;
}

function initStrengthTool() {
  const input = $('#pwInput');
  if (!input) return;
  const btn = $('#pwCheckBtn');
  const toggle = $('#pwToggle');
  if (btn) {
    btn.addEventListener('click', () => {
      if (!input.value) { showToast('لطفاً اول یک رمز عبور وارد کنید'); input.focus(); return; }
      renderStrength(input.value);
    });
  }
  if (toggle) {
    toggle.addEventListener('click', () => {
      const isPass = input.type === 'password';
      input.type = isPass ? 'text' : 'password';
      toggle.textContent = isPass ? '🙈' : '👁️';
    });
  }
}

/* ============================================================
   ابزار ۲: تولید رمزهای تصادفی
   ============================================================ */
const CHARSETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digit: '0123456789',
  symbol: '!@#$%^&*()-_=+[]{};:,.?/~'
};

function secureRandomInt(max) {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const arr = new Uint32Array(1);
    const limit = Math.floor(4294967296 / max) * max;
    let x;
    do { crypto.getRandomValues(arr); x = arr[0]; } while (x >= limit);
    return x % max;
  }
  return Math.floor(Math.random() * max);
}

function generatePassword(length, options) {
  const groups = [];
  let pool = '';
  if (options.upper) { groups.push(CHARSETS.upper); pool += CHARSETS.upper; }
  if (options.lower) { groups.push(CHARSETS.lower); pool += CHARSETS.lower; }
  if (options.digit) { groups.push(CHARSETS.digit); pool += CHARSETS.digit; }
  if (options.symbol) { groups.push(CHARSETS.symbol); pool += CHARSETS.symbol; }
  if (!pool) return null;
  const chars = [];
  for (const g of groups) chars.push(g.charAt(secureRandomInt(g.length)));
  while (chars.length < length) chars.push(pool.charAt(secureRandomInt(pool.length)));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    const t = chars[i]; chars[i] = chars[j]; chars[j] = t;
  }
  return chars.slice(0, length).join('');
}

function initGeneratorTool() {
  const btn = $('#genBtn');
  if (!btn) return;
  const lengthInput = $('#genLength');
  const lenVal = $('#genLenVal');
  const output = $('#genOutput');
  const copyBtn = $('#genCopy');
  const result = $('#genResult');

  if (lengthInput && lenVal) {
    lengthInput.addEventListener('input', () => { lenVal.textContent = toFa(lengthInput.value); });
  }

  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      if (!output || !output.value) { showToast('اول یک رمز تولید کنید'); return; }
      copyText(output.value, 'رمز عبور کپی شد ✅');
    });
  }

  btn.addEventListener('click', () => {
    const options = {
      upper: !!($('#genUpper') && $('#genUpper').checked),
      lower: !!($('#genLower') && $('#genLower').checked),
      digit: !!($('#genDigit') && $('#genDigit').checked),
      symbol: !!($('#genSymbol') && $('#genSymbol').checked)
    };
    if (!options.upper && !options.lower && !options.digit && !options.symbol) {
      if (result) {
        result.hidden = false;
        result.innerHTML = '<div class="verdict verdict-warn">⚠️ حداقل یک نوع کاراکتر را انتخاب کنید</div>';
      }
      return;
    }
    const length = lengthInput ? Math.max(8, Math.min(64, parseInt(lengthInput.value, 10) || 16)) : 16;
    const pw = generatePassword(length, options);
    if (!pw) return;
    if (output) output.value = pw;
    const res = analyzePassword(pw);
    if (result) {
      result.hidden = false;
      result.innerHTML =
        '<div class="verdict verdict-ok">✅ رمز تولید شد — طول: ' + toFa(length) + ' کاراکتر</div>' +
        '<div class="note">قدرت تقریبی: <b style="color:' + res.color + '">' + res.label + '</b>' +
        ' — از این رمز در چند حساب مختلف استفاده نکنید.</div>';
    }
  });
}

/* ============================================================
   ابزار ۳: بررسی اولیه نشانه‌های مشکوک لینک‌ها
   ============================================================ */
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'tiny.cc', 'rebrand.ly', 'ow.ly', 'buff.ly', 'shorturl.at', 'rb.gy'];
const RISKY_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'buzz', 'click', 'work', 'icu', 'cam', 'rest', 'fit'];
const PHISH_WORDS = ['login', 'signin', 'sign-in', 'log-in', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'wallet', 'webscr', 'password', 'billing', 'invoice', 'payment', 'gift'];

function checkLink(raw) {
  const input = String(raw || '').trim();
  if (!input) return { error: 'لطفاً یک لینک وارد کنید.' };
  let url;
  const hadScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input);
  try {
    url = new URL(hadScheme ? input : 'https://' + input);
  } catch (e) {
    return { error: 'لینک واردشده معتبر به نظر نمی‌رسد؛ دوباره بررسی کنید.' };
  }

  const items = [];
  let danger = 0;
  let warn = 0;
  const add = (level, text) => {
    items.push({ level: level, text: text });
    if (level === 'danger') danger++;
    else if (level === 'warn') warn++;
  };

  const proto = url.protocol.replace(':', '').toLowerCase();
  if (proto === 'https') add('ok', 'از پروتکل امن HTTPS استفاده می‌کند.');
  else if (proto === 'http') add('warn', 'بدون رمزنگاری (HTTP) است؛ اطلاعات این لینک قابل شنود است.');
  else add('danger', 'پروتکل غیرمعمول یا ناامن: «' + proto + '»');

  const host = url.hostname.toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add('warn', 'به‌جای نام دامنه، مستقیماً از IP استفاده شده است.');
  if (url.username) add('danger', 'از کاراکتر @ برای پنهان‌کردن مقصد واقعی استفاده شده است.');
  if (host.indexOf('xn--') !== -1) add('warn', 'دامنه با کدگذاری Punycode است؛ ممکن است تقلیدی از دامنه‌ای معروف باشد.');

  const parts = host.split('.').filter(Boolean);
  const tld = parts.length ? parts[parts.length - 1] : '';
  if (RISKY_TLDS.indexOf(tld) !== -1) add('warn', 'پسوند دامنه (.' + tld + ') ارزان است و در بسیاری از سایت‌های فیشینگ استفاده می‌شود.');

  const isShortener = SHORTENERS.some((s) => host === s || host.endsWith('.' + s));
  if (isShortener) add('warn', 'این یک لینک کوتاه‌شده است و مقصد واقعی آن پنهان است.');
  if (url.href.length > 100) add('warn', 'لینک بسیار طولانی است؛ تکنیکی رایج برای پنهان‌کردن مقصد.');
  if (parts.length >= 4 && !isShortener) add('warn', 'زیردامنه‌های زیادی دارد؛ ممکن است برای جلب اعتماد شما ساخته شده باشد.');
  if ((host.match(/-/g) || []).length >= 3) add('warn', 'در دامنه از خط تیرهٔ زیادی استفاده شده است.');

  const fullPath = (url.pathname + ' ' + url.search + ' ' + url.hash).toLowerCase();
  const found = PHISH_WORDS.filter((w) => fullPath.indexOf(w) !== -1 || host.indexOf(w) !== -1);
  if (found.length) add('warn', 'کلیدواژه‌های حساس فیشینگ در لینک دیده می‌شود: ' + found.slice(0, 3).join('، '));

  if (/\.(exe|msi|bat|cmd|scr|apk|zip|rar)(\?|#|$)/i.test(url.pathname)) {
    add('danger', 'این لینک مستقیماً به یک فایل احتمالاً مخرب اشاره می‌کند.');
  }

  let level;
  let title;
  if (danger > 0) { level = 'danger'; title = '⛔ خطرناک — به این لینک اعتماد نکنید'; }
  else if (warn >= 2) { level = 'danger'; title = '🚨 پرخطر — چند نشانهٔ مشکوک پیدا شد'; }
  else if (warn === 1) { level = 'warn'; title = '⚠️ نیازمند احتیاط — یک نشانهٔ مشکوک پیدا شد'; }
  else { level = 'ok'; title = '✅ در بررسی اولیه، نشانهٔ مشکوکی پیدا نشد'; }

  return {
    level: level,
    title: title,
    items: items,
    note: 'این بررسی صرفاً اولیه و تقریبی است؛ هرگز اطلاعات حساس خود را در لینک‌های ناشناس وارد نکنید.'
  };
}

function renderVerdict(container, v) {
  if (!container) return;
  container.hidden = false;
  if (v.error) {
    container.innerHTML = '<div class="verdict verdict-bad">' + v.error + '</div>';
    return;
  }
  let html = '<div class="verdict verdict-' + v.level + '">' + v.title + '</div>';
  if (v.items && v.items.length) {
    html += '<ul class="check-list">' + v.items.map((it) => {
      const icon = it.level === 'ok' ? '✅' : (it.level === 'warn' ? '⚠️' : '⛔');
      return '<li class="' + it.level + '">' + icon + ' ' + escapeHTML(it.text) + '</li>';
    }).join('') + '</ul>';
  }
  if (v.note) html += '<div class="note warn">⚠️ ' + v.note + '</div>';
  container.innerHTML = html;
}

function initLinkTool() {
  const input = $('#linkInput');
  if (!input) return;
  const btn = $('#linkBtn');
  const result = $('#linkResult');
  const run = () => renderVerdict(result, checkLink(input.value));
  if (btn) btn.addEventListener('click', run);
  bindEnter(input, btn);
}

/* ============================================================
   ابزار ۴: بررسی قالب ایمیل و نشانه‌های مشکوک
   ============================================================ */
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

const LOOKALIKE = {
  'gmai1.com': 'gmail.com', 'gmial.com': 'gmail.com', 'gmai.com': 'gmail.com',
  'gnail.com': 'gmail.com', 'gmail.co': 'gmail.com', 'gmail.cm': 'gmail.com',
  'yaho.com': 'yahoo.com', 'yaho0.com': 'yahoo.com', 'yahooo.com': 'yahoo.com',
  'hotmial.com': 'hotmail.com', 'hotmai1.com': 'hotmail.com', 'hotmall.com': 'hotmail.com',
  'outlook.co': 'outlook.com', 'outlok.com': 'outlook.com',
  'iclod.com': 'icloud.com', 'icoud.com': 'icloud.com'
};

const DISPOSABLE = ['mailinator.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com'];

function checkEmail(raw) {
  const email = String(raw || '').trim();
  if (!email) return { error: 'لطفاً یک ایمیل وارد کنید.' };
  const valid = EMAIL_RE.test(email);
  if (!valid) {
    const items = [];
    if (email.indexOf('@') === -1) items.push({ level: 'danger', text: 'کاراکتر @ در ایمیل وجود ندارد.' });
    else if ((email.match(/@/g) || []).length > 1) items.push({ level: 'danger', text: 'بیش از یک کاراکتر @ وجود دارد.' });
    else if (/\s/.test(email)) items.push({ level: 'danger', text: 'ایمیل نباید فاصله (space) داشته باشد.' });
    else if (!/\.[a-zA-Z]{2,}$/.test(email)) items.push({ level: 'danger', text: 'دامنه فاقد پسوند معتبر است (مانند .com یا .org).' });
    else items.push({ level: 'danger', text: 'قالب ایمیل استاندارد نیست (کاراکترهای غیرمجاز یا چیدمان نادرست).' });
    return { level: 'bad', title: '❌ قالب ایمیل نامعتبر است', items: items, note: 'نمونهٔ قالب درست: name@example.com' };
  }

  const at = email.indexOf('@');
  const local = email.slice(0, at);
  const domain = email.slice(at + 1).toLowerCase();

  const items = [{ level: 'ok', text: 'قالب کلی ایمیل معتبر است.' }];
  let danger = 0;
  let warn = 0;
  const add = (level, text) => {
    items.push({ level: level, text: text });
    if (level === 'danger') danger++;
    else if (level === 'warn') warn++;
  };

  if (email.indexOf('..') !== -1) add('warn', 'نقطه‌های پشت سر هم دارد؛ الگویی غیرمعمول و مشکوک است.');
  if (/^[.\-_]/.test(local) || /[.\-_]$/.test(local)) add('warn', 'بخش نام کاربری با نقطه یا خط تیره شروع یا پایان می‌یابد؛ در فیشینگ رایج است.');
  if (LOOKALIKE[domain]) add('danger', 'دامنه شبیه‌سازی‌شده است! احتمالاً منظور «' + LOOKALIKE[domain] + '» بوده — احتمال فیشینگ بالاست.');
  if (DISPOSABLE.some((d) => domain === d || domain.endsWith('.' + d))) add('warn', 'این یک سرویس ایمیل موقتی است؛ برای حساب‌های مهم مناسب نیست.');
  if (local.indexOf('+') !== -1) add('ok', 'شامل برچسب (+tag) است؛ برخی سرویس‌ها آن را به همان صندوق اصلی تحویل می‌دهند.');
  if (local.length > 40) add('warn', 'نام کاربری بسیار طولانی است؛ الگوی غیرمعمول.');

  let level;
  let title;
  if (danger > 0) { level = 'danger'; title = '⛔ قالب معتبر است اما نشانهٔ جدی فیشینگ پیدا شد'; }
  else if (warn > 0) { level = 'warn'; title = '⚠️ قالب معتبر است اما نشانه‌های مشکوکی دارد'; }
  else { level = 'ok'; title = '✅ قالب معتبر و بدون نشانهٔ مشکوک'; }

  return {
    level: level,
    title: title,
    items: items,
    note: 'این بررسی صرفاً قالب و نشانه‌های ظاهری است؛ معتبر بودن قالب به معنی وجود واقعی آن ایمیل نیست.'
  };
}

function initEmailTool() {
  const input = $('#emailInput');
  if (!input) return;
  const btn = $('#emailBtn');
  const result = $('#emailResult');
  const run = () => renderVerdict(result, checkEmail(input.value));
  if (btn) btn.addEventListener('click', run);
  bindEnter(input, btn);
}

/* ============================================================
   ابزار ۵: محاسبه هش SHA-256
   ============================================================ */
function initHashTool() {
  const input = $('#hashInput');
  if (!input) return;
  const btn = $('#hashBtn');
  const result = $('#hashResult');
  const output = $('#hashOutput');
  const copyBtn = $('#hashCopy');

  const compute = () => {
    const text = input.value;
    if (!text) {
      if (result) result.hidden = true;
      showToast('لطفاً متنی برای محاسبه هش وارد کنید');
      input.focus();
      return;
    }
    try {
      if (output) output.textContent = sha256Hex(text);
      if (result) result.hidden = false;
    } catch (e) {
      showToast('خطایی در محاسبه هش رخ داد');
    }
  };

  if (btn) btn.addEventListener('click', compute);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); compute(); }
  });

  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      if (!output || !output.textContent) { showToast('اول هش را محاسبه کنید'); return; }
      copyText(output.textContent, 'هش کپی شد ✅');
    });
  }
}

/* ============================================================
   هدر، منو و بخش‌های عمومی
   ============================================================ */
function initHeader() {
  const menuBtn = $('#menuBtn');
  const nav = $('#nav');
  if (menuBtn && nav) {
    menuBtn.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      menuBtn.classList.toggle('open', open);
      menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    nav.addEventListener('click', (e) => {
      if (e.target && e.target.tagName === 'A') {
        nav.classList.remove('open');
        menuBtn.classList.remove('open');
        menuBtn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  const toTop = $('#toTop');
  const header = $('.site-header');
  window.addEventListener('scroll', () => {
    const y = window.scrollY || 0;
    if (header) header.classList.toggle('scrolled', y > 10);
    if (toTop) toTop.classList.toggle('show', y > 500);
  }, { passive: true });

  if (toTop) {
    toTop.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }
}

function initReveal() {
  const els = $$('.reveal');
  if (!els.length) return;
  if (typeof IntersectionObserver === 'undefined') {
    els.forEach((el) => el.classList.add('visible'));
    return;
  }
  const io = new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (en.isIntersecting) {
        en.target.classList.add('visible');
        io.unobserve(en.target);
      }
    });
  }, { threshold: 0.1 });
  els.forEach((el) => io.observe(el));
}

function initMisc() {
  const year = $('#year');
  if (year) {
    try {
      year.textContent = new Intl.DateTimeFormat('fa-IR', { year: 'numeric' }).format(new Date());
    } catch (e) {
      year.textContent = toFa(new Date().getFullYear());
    }
  }
}

/* ---------- راه‌اندازی ---------- */
function init() {
  initHeader();
  initStrengthTool();
  initGeneratorTool();
  initLinkTool();
  initEmailTool();
  initHashTool();
  initReveal();
  initMisc();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
