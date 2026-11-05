/* ============================================================
 * LockAuth — общие утилиты аутентификации LockBox (демо)
 *
 * - TOTP по RFC 6238 (SHA-1, 6 цифр, период 30 с) — коды полностью
 *   совместимы с Google Authenticator и другими TOTP-приложениями.
 * - SHA-1/HMAC реализованы на чистом JS: работают даже без HTTPS,
 *   где Web Crypto (crypto.subtle) недоступен.
 * - Маскировка email/телефона для показа адресата кода.
 * - Работа с localStorage-аккаунтами (lockbox_users).
 * ============================================================ */
(function (root) {
  'use strict';

  var LS_USERS = 'lockbox_users';
  var LS_SESSION = 'lockbox_session';

  // ---- Аккаунты (localStorage) ----
  function getUsers() {
    try { return JSON.parse(localStorage.getItem(LS_USERS)) || {}; } catch (e) { return {}; }
  }
  function saveUsers(u) { localStorage.setItem(LS_USERS, JSON.stringify(u)); }

  // ---- SHA-1 (чистый JS) ----
  function sha1(msgBytes) {
    var len = msgBytes.length;
    var bitLen = len * 8;
    var blocks = ((len + 8) >> 6) + 1;
    var words = new Uint32Array(blocks * 16);
    var i;
    for (i = 0; i < len; i++) words[i >> 2] |= msgBytes[i] << (24 - (i % 4) * 8);
    words[len >> 2] |= 0x80 << (24 - (len % 4) * 8);
    words[blocks * 16 - 1] = bitLen >>> 0;

    var H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    var w = new Uint32Array(80);
    for (var b = 0; b < blocks; b++) {
      for (i = 0; i < 16; i++) w[i] = words[b * 16 + i];
      for (i = 16; i < 80; i++) {
        var x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (x << 1) | (x >>> 31);
      }
      var a = H[0], bb = H[1], c = H[2], d = H[3], e = H[4];
      for (i = 0; i < 80; i++) {
        var f, k;
        if (i < 20)      { f = (bb & c) | (~bb & d);          k = 0x5A827999; }
        else if (i < 40) { f = bb ^ c ^ d;                    k = 0x6ED9EBA1; }
        else if (i < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = bb ^ c ^ d;                    k = 0xCA62C1D6; }
        var t = (((a << 5) | (a >>> 27)) + e + f + k + w[i]) >>> 0;
        e = d; d = c; c = (bb << 30) | (bb >>> 2); bb = a; a = t;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + bb) >>> 0; H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0; H[4] = (H[4] + e) >>> 0;
    }
    var out = new Uint8Array(20);
    for (i = 0; i < 5; i++) {
      out[i * 4]     = H[i] >>> 24;
      out[i * 4 + 1] = (H[i] >>> 16) & 255;
      out[i * 4 + 2] = (H[i] >>> 8) & 255;
      out[i * 4 + 3] = H[i] & 255;
    }
    return out;
  }

  // ---- HMAC-SHA1 (RFC 2104) ----
  function hmacSha1(keyBytes, msgBytes) {
    var BLOCK = 64;
    var k = keyBytes.length > BLOCK ? sha1(keyBytes) : keyBytes;
    var ipad = new Uint8Array(BLOCK), opad = new Uint8Array(BLOCK);
    ipad.fill(0x36); opad.fill(0x5c);
    for (var i = 0; i < k.length; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    var inner = new Uint8Array(BLOCK + msgBytes.length);
    inner.set(ipad); inner.set(msgBytes, BLOCK);
    var innerHash = sha1(inner);
    var outer = new Uint8Array(BLOCK + 20);
    outer.set(opad); outer.set(innerHash, BLOCK);
    return sha1(outer);
  }

  // ---- Base32 (RFC 4648, без паддинга) ----
  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function base32Encode(bytes) {
    var out = '', bits = 0, val = 0;
    for (var i = 0; i < bytes.length; i++) {
      val = (val << 8) | bytes[i]; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    return out;
  }
  function base32Decode(str) {
    var clean = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
    var bits = 0, val = 0, out = [];
    for (var i = 0; i < clean.length; i++) {
      val = (val << 5) | B32.indexOf(clean[i]); bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  // ---- Секрет для TOTP: 20 случайных байт = 32 символа Base32 ----
  function randomBytes(n) {
    var b = new Uint8Array(n);
    if (root.crypto && root.crypto.getRandomValues) root.crypto.getRandomValues(b);
    else for (var i = 0; i < n; i++) b[i] = Math.floor(Math.random() * 256);
    return b;
  }
  function genSecret() { return base32Encode(randomBytes(20)); }

  // ---- TOTP (RFC 6238): SHA-1, 6 цифр, шаг 30 с ----
  function totpAt(secretB32, counter) {
    var key = base32Decode(secretB32);
    var msg = new Uint8Array(8);
    var c = counter;
    for (var i = 7; i >= 0; i--) { msg[i] = c & 255; c = Math.floor(c / 256); }
    var h = hmacSha1(key, msg);
    var off = h[19] & 15;
    var bin = (((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) >>> 0;
    return ('000000' + (bin % 1000000)).slice(-6);
  }
  function currentCounter() { return Math.floor(Date.now() / 1000 / 30); }
  function secondsRemaining() { return 30 - (Math.floor(Date.now() / 1000) % 30); }
  // Проверка кода с допуском ±1 шаг (рассинхрон часов)
  function verifyTotp(secretB32, code) {
    var clean = String(code || '').replace(/\D/g, '');
    if (clean.length !== 6) return false;
    var cnt = currentCounter();
    for (var i = -1; i <= 1; i++) {
      if (totpAt(secretB32, cnt + i) === clean) return true;
    }
    return false;
  }

  // ---- Маскировка получателей кода ----
  function maskEmail(e) {
    var parts = String(e || '').split('@');
    if (parts.length !== 2 || !parts[1]) return e;
    var loc = parts[0];
    var vis = loc.slice(0, Math.min(2, loc.length));
    return vis + '***@' + parts[1];
  }
  function maskPhone(p) {
    var d = (String(p || '').match(/\d/g) || []).join('');
    if (d.length >= 10) {
      var cc = d.length > 10 ? '+' + d.slice(0, d.length - 10) : '+7';
      var n = d.slice(-10);
      return cc + ' \u2022\u2022\u2022 \u2022\u2022\u2022 ' + n.slice(6, 8) + ' ' + n.slice(8);
    }
    return '\u2022'.repeat(Math.max(d.length - 4, 0)) + d.slice(-4);
  }

  // ---- otpauth:// URI и QR ----
  function otpauthUri(secret, label) {
    return 'otpauth://totp/LockBox:' + encodeURIComponent(label) +
           '?secret=' + secret + '&issuer=LockBox';
  }
  function renderQr(el, secret, label) {
    if (!el) return;
    if (typeof root.qrcode !== 'function') {
      el.textContent = 'QR недоступен — введите ключ вручную';
      return;
    }
    try {
      var qr = root.qrcode(0, 'M');
      qr.addData(otpauthUri(secret, label));
      qr.make();
      el.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0 });
    } catch (e) {
      el.textContent = 'Не удалось построить QR — введите ключ вручную';
    }
  }

  var LockAuth = {
    LS_USERS: LS_USERS, LS_SESSION: LS_SESSION,
    getUsers: getUsers, saveUsers: saveUsers,
    sha1: sha1, hmacSha1: hmacSha1,
    base32Encode: base32Encode, base32Decode: base32Decode,
    genSecret: genSecret, totpAt: totpAt,
    currentCounter: currentCounter, secondsRemaining: secondsRemaining,
    verifyTotp: verifyTotp,
    maskEmail: maskEmail, maskPhone: maskPhone,
    otpauthUri: otpauthUri, renderQr: renderQr
  };

  root.LockAuth = LockAuth;
  if (typeof module !== 'undefined' && module.exports) module.exports = LockAuth;
})(typeof window !== 'undefined' ? window : globalThis);
