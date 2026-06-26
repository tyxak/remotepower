/*
 * wg-access.js — RemotePower "WG Access" (WireGuard VPN) client helpers (v5.2.0)
 * ---------------------------------------------------------------------------
 * WHAT THIS IS
 *   Client-side helpers for the "create WireGuard client" flow:
 *     - WGAccess.genKeypair()       : generate a Curve25519/X25519 keypair
 *                                     (WireGuard base64 format, 44 chars, '='-padded)
 *     - WGAccess.buildClientConf()  : assemble a standard [Interface]/[Peer] .conf
 *     - WGAccess.renderQR(el, text) : draw a QR of the conf into a <canvas>
 *     - WGAccess.downloadConf()     : download the .conf as a file
 *     - WGAccess.publicFromPrivate(): derive the public key from a base64 private
 *                                     key (used for verification / re-derivation)
 *
 * CSP RATIONALE (production serves `script-src 'self'; style-src 'self'`, NO
 * unsafe-inline):
 *   - This is an EXTERNAL /static/js file loaded via <script src>, so the file
 *     itself is allowed.
 *   - It NEVER injects inline event handlers (on*=) or inline style="..."
 *     strings via innerHTML. Styles are set with element.style.x; events (none
 *     are needed here, but if added) must use addEventListener. The QR is
 *     rendered to a <canvas> 2d context with fillRect() — no SVG/innerHTML/style
 *     strings. The download anchor is built with document.createElement and
 *     properties set programmatically.
 *   - Exposed on the global `window.WGAccess` namespace (NOT an ES module — the
 *     project concatenates/serves plain scripts).
 *
 * VENDORED CODE + LICENSES (self-contained, no external deps):
 *   - Curve25519 / X25519 scalar multiplication (crypto_scalarmult_base and the
 *     supporting field arithmetic) is adapted from TweetNaCl.js
 *     (https://github.com/dchest/tweetnacl-js), which is released into the
 *     PUBLIC DOMAIN (The Unlicense). The big-multiply (M) is written in the
 *     loop form rather than TweetNaCl's hand-unrolled form for compactness; it
 *     computes the same result. WebCrypto does not portably expose raw X25519
 *     public-key derivation from a raw private scalar, hence the pure-JS impl.
 *   - QR Code generator (Reed-Solomon ECC, byte-mode segment encoding, mask
 *     selection, module drawing) is a JavaScript port of Nayuki's "QR Code
 *     generator library" (https://www.nayuki.io/page/qr-code-generator-library),
 *     Copyright (c) Project Nayuki, MIT License.
 */

(function (global) {
  'use strict';

  /* ===================================================================== *
   * Base64 (raw bytes <-> standard base64). Self-contained so we do not
   * depend on btoa/atob being present (e.g. under Node for testing).
   * ===================================================================== */
  var B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function base64Encode(bytes) {
    var out = '';
    var i;
    for (i = 0; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] +
             B64_CHARS[(n >> 6) & 63] + B64_CHARS[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) {
      var n1 = bytes[i] << 16;
      out += B64_CHARS[(n1 >> 18) & 63] + B64_CHARS[(n1 >> 12) & 63] + '==';
    } else if (rem === 2) {
      var n2 = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += B64_CHARS[(n2 >> 18) & 63] + B64_CHARS[(n2 >> 12) & 63] +
             B64_CHARS[(n2 >> 6) & 63] + '=';
    }
    return out;
  }

  function base64Decode(str) {
    var lookup = {};
    for (var j = 0; j < B64_CHARS.length; j++) lookup[B64_CHARS[j]] = j;
    var bytes = [];
    var buffer = 0, bits = 0;
    for (var i = 0; i < str.length; i++) {
      var c = lookup[str[i]];
      if (c === undefined) continue; // skip '=' and whitespace
      buffer = (buffer << 6) | c;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((buffer >> bits) & 0xff);
      }
    }
    return new Uint8Array(bytes);
  }

  /* ===================================================================== *
   * Curve25519 / X25519 — adapted from TweetNaCl.js (public domain).
   * Field elements are 16-limb (16-bit) representations in Float64Array(16).
   * ===================================================================== */
  function gf(init) {
    var i, r = new Float64Array(16);
    if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  }

  var _121665 = gf([0xdb41, 1]); // 121665

  function car25519(o) {
    var i, v, c = 1;
    for (i = 0; i < 16; i++) {
      v = o[i] + c + 65535;
      c = Math.floor(v / 65536);
      o[i] = v - c * 65536;
    }
    o[0] += c - 1 + 37 * (c - 1);
  }

  function sel25519(p, q, b) {
    var t, c = ~(b - 1);
    for (var i = 0; i < 16; i++) {
      t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }

  function pack25519(o, n) {
    var i, j, b;
    var m = gf(), t = gf();
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (m[15] >> 16) & 1;
      m[14] &= 0xffff;
      sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = t[i] >> 8;
    }
  }

  function unpack25519(o, n) {
    var i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
  }

  function A(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
  function Z(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

  // Multiply mod 2^255 - 19 (loop form of TweetNaCl's unrolled M()).
  function M(o, a, b) {
    var t = new Float64Array(31);
    var i, j;
    for (i = 0; i < 16; i++) {
      for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    }
    // 2^256 ≡ 38 (mod 2^255-19): fold high limbs t[16..30] into t[0..14]
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
  }

  function S(o, a) { M(o, a, a); }

  function inv25519(o, i) {
    var c = gf();
    var a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
      S(c, c);
      if (a !== 2 && a !== 4) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
  }

  // q = scalarmult(n, p): the X25519 Montgomery ladder.
  function crypto_scalarmult(q, n, p) {
    var z = new Uint8Array(32);
    var x = new Float64Array(80);
    var r, i;
    var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf();
    for (i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64; // WireGuard/X25519 standard clamping
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; i++) {
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
      r = (z[i >>> 3] >>> (i & 7)) & 1;
      sel25519(a, b, r);
      sel25519(c, d, r);
      A(e, a, c);
      Z(a, a, c);
      A(c, b, d);
      Z(b, b, d);
      S(d, e);
      S(f, a);
      M(a, c, a);
      M(c, b, e);
      A(e, a, c);
      Z(a, a, c);
      S(b, a);
      Z(c, d, f);
      M(a, c, _121665);
      A(a, a, d);
      M(c, c, a);
      M(a, d, f);
      M(d, b, x);
      S(b, e);
      sel25519(a, b, r);
      sel25519(c, d, r);
    }
    for (i = 0; i < 16; i++) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }
    var x32 = x.subarray(32);
    var x16 = x.subarray(16);
    inv25519(x32, x32);
    M(x16, x16, x32);
    pack25519(q, x16);
    return 0;
  }

  var _BASE9 = new Uint8Array(32);
  _BASE9[0] = 9;

  function crypto_scalarmult_base(q, n) {
    return crypto_scalarmult(q, n, _BASE9);
  }

  /* ===================================================================== *
   * QR Code generator — JS port of Nayuki's QR Code generator (MIT).
   * Byte mode, ECC level configurable (default M), automatic version + mask.
   * ===================================================================== */

  // Error-correction levels: ordinal indexes the ECC tables; formatBits is the
  // 2-bit format-info value used when drawing the format bits.
  var ECL = {
    L: { ordinal: 0, formatBits: 1 },
    M: { ordinal: 1, formatBits: 0 },
    Q: { ordinal: 2, formatBits: 3 },
    H: { ordinal: 3, formatBits: 2 }
  };

  // Index 0 is illegal padding; versions 1..40 follow.
  var ECC_CODEWORDS_PER_BLOCK = [
    [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // L
    [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28], // M
    [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // Q
    [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]  // H
  ];
  var NUM_ERROR_CORRECTION_BLOCKS = [
    [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25], // L
    [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49], // M
    [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68], // Q
    [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]  // H
  ];

  function getBit(x, i) { return ((x >>> i) & 1) !== 0; }

  function reedSolomonMultiply(x, y) {
    var z = 0;
    for (var i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xff;
  }

  function reedSolomonComputeDivisor(degree) {
    var result = [];
    for (var i = 0; i < degree - 1; i++) result.push(0);
    result.push(1);
    var root = 1;
    for (i = 0; i < degree; i++) {
      for (var j = 0; j < result.length; j++) {
        result[j] = reedSolomonMultiply(result[j], root);
        if (j + 1 < result.length) result[j] ^= result[j + 1];
      }
      root = reedSolomonMultiply(root, 0x02);
    }
    return result;
  }

  function reedSolomonComputeRemainder(data, divisor) {
    var result = divisor.map(function () { return 0; });
    for (var bi = 0; bi < data.length; bi++) {
      var factor = data[bi] ^ result.shift();
      result.push(0);
      for (var i = 0; i < result.length; i++) {
        result[i] ^= reedSolomonMultiply(divisor[i], factor);
      }
    }
    return result;
  }

  function getNumRawDataModules(ver) {
    var result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      var numAlign = Math.floor(ver / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (ver >= 7) result -= 36;
    }
    return result;
  }

  function getNumDataCodewords(ver, eclOrdinal) {
    return Math.floor(getNumRawDataModules(ver) / 8) -
      ECC_CODEWORDS_PER_BLOCK[eclOrdinal][ver] *
      NUM_ERROR_CORRECTION_BLOCKS[eclOrdinal][ver];
  }

  function addEccAndInterleave(data, ver, eclOrdinal) {
    var numBlocks = NUM_ERROR_CORRECTION_BLOCKS[eclOrdinal][ver];
    var blockEccLen = ECC_CODEWORDS_PER_BLOCK[eclOrdinal][ver];
    var rawCodewords = Math.floor(getNumRawDataModules(ver) / 8);
    var numShortBlocks = numBlocks - rawCodewords % numBlocks;
    var shortBlockLen = Math.floor(rawCodewords / numBlocks);
    var blocks = [];
    var rsDiv = reedSolomonComputeDivisor(blockEccLen);
    for (var i = 0, k = 0; i < numBlocks; i++) {
      var datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
      var dat = data.slice(k, k + datLen);
      k += dat.length;
      var ecc = reedSolomonComputeRemainder(dat, rsDiv);
      if (i < numShortBlocks) dat.push(0); // pad cell to align interleaving
      blocks.push(dat.concat(ecc));
    }
    var result = [];
    for (var col = 0; col < blocks[0].length; col++) {
      for (var b = 0; b < blocks.length; b++) {
        // skip the padding cell that short blocks carry in the data region
        if (col !== shortBlockLen - blockEccLen || b >= numShortBlocks) {
          result.push(blocks[b][col]);
        }
      }
    }
    return result;
  }

  // QrCode object: holds the module grid; constructor draws everything.
  function QrCode(version, eclObj, dataCodewords, mask) {
    this.version = version;
    this.size = version * 4 + 17;
    this.eclOrdinal = eclObj.ordinal;
    this.eclFormatBits = eclObj.formatBits;
    this.modules = [];
    this.isFunction = [];
    for (var i = 0; i < this.size; i++) {
      var rowM = [], rowF = [];
      for (var j = 0; j < this.size; j++) { rowM.push(false); rowF.push(false); }
      this.modules.push(rowM);
      this.isFunction.push(rowF);
    }
    this.drawFunctionPatterns();
    var allCodewords = addEccAndInterleave(dataCodewords, version, this.eclOrdinal);
    this.drawCodewords(allCodewords);
    if (mask === -1) {
      var minPenalty = Infinity;
      for (var m = 0; m < 8; m++) {
        this.applyMask(m);
        this.drawFormatBits(m);
        var penalty = this.getPenaltyScore();
        if (penalty < minPenalty) { mask = m; minPenalty = penalty; }
        this.applyMask(m); // undo (XOR is its own inverse)
      }
    }
    this.mask = mask;
    this.applyMask(mask);
    this.drawFormatBits(mask);
  }

  QrCode.prototype.setFunctionModule = function (x, y, isDark) {
    this.modules[y][x] = isDark;
    this.isFunction[y][x] = true;
  };

  QrCode.prototype.drawFinderPattern = function (x, y) {
    for (var dy = -4; dy <= 4; dy++) {
      for (var dx = -4; dx <= 4; dx++) {
        var dist = Math.max(Math.abs(dx), Math.abs(dy));
        var xx = x + dx, yy = y + dy;
        if (0 <= xx && xx < this.size && 0 <= yy && yy < this.size) {
          this.setFunctionModule(xx, yy, dist !== 2 && dist !== 4);
        }
      }
    }
  };

  QrCode.prototype.drawAlignmentPattern = function (x, y) {
    for (var dy = -2; dy <= 2; dy++) {
      for (var dx = -2; dx <= 2; dx++) {
        this.setFunctionModule(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  };

  QrCode.prototype.getAlignmentPatternPositions = function () {
    if (this.version === 1) return [];
    var numAlign = Math.floor(this.version / 7) + 2;
    var step = (this.version === 32) ? 26 :
      Math.ceil((this.version * 4 + 4) / (numAlign * 2 - 2)) * 2;
    var result = [6];
    for (var pos = this.size - 7; result.length < numAlign; pos -= step) {
      result.splice(1, 0, pos);
    }
    return result;
  };

  QrCode.prototype.drawFunctionPatterns = function () {
    var i;
    for (i = 0; i < this.size; i++) {
      this.setFunctionModule(6, i, i % 2 === 0);
      this.setFunctionModule(i, 6, i % 2 === 0);
    }
    this.drawFinderPattern(3, 3);
    this.drawFinderPattern(this.size - 4, 3);
    this.drawFinderPattern(3, this.size - 4);
    var alignPos = this.getAlignmentPatternPositions();
    var n = alignPos.length;
    for (i = 0; i < n; i++) {
      for (var j = 0; j < n; j++) {
        if (!((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0))) {
          this.drawAlignmentPattern(alignPos[i], alignPos[j]);
        }
      }
    }
    this.drawFormatBits(0); // dummy; rewritten with the real mask later
    this.drawVersion();
  };

  QrCode.prototype.drawFormatBits = function (mask) {
    var data = (this.eclFormatBits << 3) | mask;
    var rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var bits = ((data << 10) | rem) ^ 0x5412;
    for (i = 0; i <= 5; i++) this.setFunctionModule(8, i, getBit(bits, i));
    this.setFunctionModule(8, 7, getBit(bits, 6));
    this.setFunctionModule(8, 8, getBit(bits, 7));
    this.setFunctionModule(7, 8, getBit(bits, 8));
    for (i = 9; i < 15; i++) this.setFunctionModule(14 - i, 8, getBit(bits, i));
    for (i = 0; i < 8; i++) this.setFunctionModule(this.size - 1 - i, 8, getBit(bits, i));
    for (i = 8; i < 15; i++) this.setFunctionModule(8, this.size - 15 + i, getBit(bits, i));
    this.setFunctionModule(8, this.size - 8, true); // always dark
  };

  QrCode.prototype.drawVersion = function () {
    if (this.version < 7) return;
    var rem = this.version;
    for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    var bits = (this.version << 12) | rem;
    for (i = 0; i < 18; i++) {
      var bit = getBit(bits, i);
      var a = this.size - 11 + i % 3;
      var b = Math.floor(i / 3);
      this.setFunctionModule(a, b, bit);
      this.setFunctionModule(b, a, bit);
    }
  };

  QrCode.prototype.drawCodewords = function (data) {
    var i = 0; // bit index into data
    for (var right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < this.size; vert++) {
        for (var j = 0; j < 2; j++) {
          var x = right - j;
          var upward = ((right + 1) & 2) === 0;
          var y = upward ? this.size - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  };

  QrCode.prototype.applyMask = function (mask) {
    for (var y = 0; y < this.size; y++) {
      for (var x = 0; x < this.size; x++) {
        var invert;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = (x * y) % 2 + (x * y) % 3 === 0; break;
          case 6: invert = ((x * y) % 2 + (x * y) % 3) % 2 === 0; break;
          case 7: invert = ((x + y) % 2 + (x * y) % 3) % 2 === 0; break;
          default: invert = false;
        }
        if (!this.isFunction[y][x] && invert) {
          this.modules[y][x] = !this.modules[y][x];
        }
      }
    }
  };

  QrCode.prototype.finderPenaltyCountPatterns = function (runHistory) {
    var n = runHistory[1];
    var core = n > 0 && runHistory[2] === n && runHistory[3] === n * 3 &&
               runHistory[4] === n && runHistory[5] === n;
    return (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0) +
           (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0);
  };

  QrCode.prototype.finderPenaltyAddHistory = function (currentRunLength, runHistory) {
    if (runHistory[0] === 0) currentRunLength += this.size; // white border on first run
    runHistory.pop();
    runHistory.unshift(currentRunLength);
  };

  QrCode.prototype.finderPenaltyTerminateAndCount = function (currentRunColor, currentRunLength, runHistory) {
    if (currentRunColor) {
      this.finderPenaltyAddHistory(currentRunLength, runHistory);
      currentRunLength = 0;
    }
    currentRunLength += this.size;
    this.finderPenaltyAddHistory(currentRunLength, runHistory);
    return this.finderPenaltyCountPatterns(runHistory);
  };

  QrCode.prototype.getPenaltyScore = function () {
    var result = 0;
    var size = this.size;
    var modules = this.modules;
    var x, y, runColor, runLen, runHistory;

    // Rows
    for (y = 0; y < size; y++) {
      runColor = false; runLen = 0;
      runHistory = [0, 0, 0, 0, 0, 0, 0];
      for (x = 0; x < size; x++) {
        if (modules[y][x] === runColor) {
          runLen++;
          if (runLen === 5) result += 3;
          else if (runLen > 5) result++;
        } else {
          this.finderPenaltyAddHistory(runLen, runHistory);
          if (!runColor) result += this.finderPenaltyCountPatterns(runHistory) * 40;
          runColor = modules[y][x];
          runLen = 1;
        }
      }
      result += this.finderPenaltyTerminateAndCount(runColor, runLen, runHistory) * 40;
    }

    // Columns
    for (x = 0; x < size; x++) {
      runColor = false; runLen = 0;
      runHistory = [0, 0, 0, 0, 0, 0, 0];
      for (y = 0; y < size; y++) {
        if (modules[y][x] === runColor) {
          runLen++;
          if (runLen === 5) result += 3;
          else if (runLen > 5) result++;
        } else {
          this.finderPenaltyAddHistory(runLen, runHistory);
          if (!runColor) result += this.finderPenaltyCountPatterns(runHistory) * 40;
          runColor = modules[y][x];
          runLen = 1;
        }
      }
      result += this.finderPenaltyTerminateAndCount(runColor, runLen, runHistory) * 40;
    }

    // 2x2 blocks of the same color
    for (y = 0; y < size - 1; y++) {
      for (x = 0; x < size - 1; x++) {
        var color = modules[y][x];
        if (color === modules[y][x + 1] && color === modules[y + 1][x] &&
            color === modules[y + 1][x + 1]) {
          result += 3;
        }
      }
    }

    // Balance of dark/light
    var dark = 0;
    for (y = 0; y < size; y++) for (x = 0; x < size; x++) if (modules[y][x]) dark++;
    var total = size * size;
    var k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    result += k * 10;
    return result;
  };

  // Encode an array of byte values into a QrCode at the given ECC level.
  function encodeBytes(data, eclObj) {
    var version, ccBits, dataCapacityBits;
    for (version = 1; version <= 40; version++) {
      dataCapacityBits = getNumDataCodewords(version, eclObj.ordinal) * 8;
      ccBits = version <= 9 ? 8 : 16;
      var usedBits = 4 + ccBits + data.length * 8;
      if (usedBits <= dataCapacityBits) break;
    }
    if (version > 40) throw new Error('WGAccess.renderQR: data too long for a QR code');

    var bb = [];
    function appendBits(val, len) {
      for (var i = len - 1; i >= 0; i--) bb.push((val >>> i) & 1);
    }
    appendBits(0x4, 4);            // byte mode indicator
    appendBits(data.length, ccBits); // character count
    for (var i = 0; i < data.length; i++) appendBits(data[i] & 0xff, 8);

    // Terminator + bit padding + byte padding (0xEC / 0x11 alternating).
    appendBits(0, Math.min(4, dataCapacityBits - bb.length));
    appendBits(0, (8 - bb.length % 8) % 8);
    for (var pad = 0xec; bb.length < dataCapacityBits; pad ^= 0xec ^ 0x11) {
      appendBits(pad, 8);
    }

    var dataCodewords = [];
    for (i = 0; i < bb.length / 8; i++) dataCodewords.push(0);
    for (i = 0; i < bb.length; i++) {
      dataCodewords[i >>> 3] |= bb[i] << (7 - (i & 7));
    }
    return new QrCode(version, eclObj, dataCodewords, -1);
  }

  /* ===================================================================== *
   * Small utilities
   * ===================================================================== */
  function getCrypto() {
    var c = (global && (global.crypto || global.msCrypto)) ||
            (typeof crypto !== 'undefined' ? crypto : null);
    if (!c || typeof c.getRandomValues !== 'function') {
      throw new Error('WGAccess: secure random (crypto.getRandomValues) unavailable');
    }
    return c;
  }

  function utf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.prototype.slice.call(new TextEncoder().encode(str));
    }
    // Minimal UTF-8 fallback.
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) {
        out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        var c2 = str.charCodeAt(++i);
        var cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f),
                 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      } else {
        out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      }
    }
    return out;
  }

  function sanitizeFilename(name) {
    name = String(name == null ? 'wireguard' : name);
    // Strip path separators / control / reserved characters; collapse spaces.
    name = name.replace(/[\/\\]+/g, '_')
               .replace(/[\x00-\x1f<>:"|?*]+/g, '')
               .replace(/\s+/g, '_')
               .replace(/^\.+/, '')
               .replace(/_+/g, '_')
               .trim();
    if (!name) name = 'wireguard';
    if (!/\.conf$/i.test(name)) name += '.conf';
    return name.slice(0, 128);
  }

  /* ===================================================================== *
   * Public API
   * ===================================================================== */
  var WGAccess = {
    /**
     * Generate a WireGuard Curve25519 keypair.
     * @returns {{privateKey: string, publicKey: string}} base64 (44 chars, '='-padded)
     */
    genKeypair: function () {
      var priv = new Uint8Array(32);
      getCrypto().getRandomValues(priv);
      // WireGuard / X25519 standard clamping (matches `wg genkey`).
      priv[0] &= 248;
      priv[31] &= 127;
      priv[31] |= 64;
      var pub = new Uint8Array(32);
      crypto_scalarmult_base(pub, priv);
      return { privateKey: base64Encode(priv), publicKey: base64Encode(pub) };
    },

    /**
     * Derive the public key (base64) from a base64 private key.
     * @param {string} privB64
     * @returns {string} public key, base64
     */
    publicFromPrivate: function (privB64) {
      var priv = base64Decode(privB64);
      if (priv.length !== 32) throw new Error('WGAccess: private key must be 32 bytes');
      var pub = new Uint8Array(32);
      crypto_scalarmult_base(pub, priv);
      return base64Encode(pub);
    },

    /**
     * Build a standard WireGuard client .conf text.
     * @param {Object} o {privateKey, address, dns, hubPublicKey, endpoint, allowedIps, presharedKey}
     * @returns {string}
     */
    buildClientConf: function (o) {
      o = o || {};
      var lines = [];
      lines.push('[Interface]');
      lines.push('PrivateKey = ' + (o.privateKey || ''));
      lines.push('Address = ' + (o.address || ''));
      if (o.dns) lines.push('DNS = ' + o.dns);
      lines.push('');
      lines.push('[Peer]');
      lines.push('PublicKey = ' + (o.hubPublicKey || ''));
      if (o.presharedKey) lines.push('PresharedKey = ' + o.presharedKey);
      lines.push('Endpoint = ' + (o.endpoint || ''));
      lines.push('AllowedIPs = ' + (o.allowedIps || '0.0.0.0/0, ::/0'));
      lines.push('PersistentKeepalive = 25');
      return lines.join('\n') + '\n';
    },

    /**
     * Render a QR code of `text` into a <canvas> (or a container, in which case
     * a canvas is created and appended). CSP-safe: draws via the 2d context's
     * fillRect; no inline styles or innerHTML.
     * @param {HTMLElement} el  a <canvas> or a container element
     * @param {string} text
     * @param {Object} [opts] {ecl:'L'|'M'|'Q'|'H', size:px, border:modules, dark, light}
     * @returns {QrCode}
     */
    renderQR: function (el, text, opts) {
      if (!el) throw new Error('WGAccess.renderQR: target element required');
      opts = opts || {};
      var eclObj = ECL[opts.ecl] || ECL.M;
      var qr = encodeBytes(utf8Bytes(String(text)), eclObj);

      var canvas;
      var tag = el.tagName ? el.tagName.toLowerCase() : '';
      if (tag === 'canvas') {
        canvas = el;
      } else {
        // Container: clear it and create a canvas via DOM (no innerHTML strings).
        while (el.firstChild) el.removeChild(el.firstChild);
        canvas = (el.ownerDocument || document).createElement('canvas');
        el.appendChild(canvas);
      }

      var border = (opts.border != null) ? opts.border : 4;
      var targetPx = opts.size || 240;
      var moduleCount = qr.size + border * 2;
      var scale = Math.max(1, Math.floor(targetPx / moduleCount));
      var dim = moduleCount * scale;

      canvas.width = dim;
      canvas.height = dim;
      var ctx = canvas.getContext('2d');
      ctx.fillStyle = opts.light || '#ffffff';
      ctx.fillRect(0, 0, dim, dim);
      ctx.fillStyle = opts.dark || '#000000';
      for (var y = 0; y < qr.size; y++) {
        for (var x = 0; x < qr.size; x++) {
          if (qr.modules[y][x]) {
            ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
          }
        }
      }
      // Display sizing via element.style.* (allowed under CSP — not an inline attr).
      canvas.style.width = dim + 'px';
      canvas.style.height = dim + 'px';
      canvas.style.imageRendering = 'pixelated';
      return qr;
    },

    /**
     * Trigger a download of `confText` as a file. Builds an <a download> with an
     * object URL programmatically (no inline handlers/styles), clicks, revokes.
     * @param {string} filename
     * @param {string} confText
     */
    downloadConf: function (filename, confText) {
      var name = sanitizeFilename(filename);
      var blob = new Blob([confText], { type: 'text/plain;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.rel = 'noopener';
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 0);
      return name;
    }
  };

  global.WGAccess = WGAccess;

})(typeof window !== 'undefined' ? window
   : (typeof self !== 'undefined' ? self : globalThis));
