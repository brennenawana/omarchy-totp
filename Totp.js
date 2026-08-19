.pragma library

// RFC 4226 (HOTP) and RFC 6238 (TOTP) in plain JavaScript.
//
// Self-contained on purpose: no imports, no external process, no network. The
// alternative — shelling out to oathtool — would put the shared secret on a
// command line, where /proc/<pid>/cmdline exposes it to every process running
// as this user. Deriving the code in-process is both simpler and safer.
//
// JavaScript bitwise operators are 32-bit, so SHA-1/SHA-256 work on 32-bit
// words and SHA-512 emulates 64-bit words as [hi, lo] pairs throughout.
//
// Verified against the RFC 6238 Appendix B test vectors; see test/vectors.js.

// ---------------------------------------------------------------- constants

function unhex32(spec) {
  var parts = spec.split(" ")
  var out = []
  for (var i = 0; i < parts.length; i++) out.push(parseInt(parts[i], 16) >>> 0)
  return out
}

function unhex64(spec) {
  var parts = spec.split(" ")
  var out = []
  for (var i = 0; i < parts.length; i++) {
    out.push([parseInt(parts[i].substring(0, 8), 16) >>> 0,
              parseInt(parts[i].substring(8, 16), 16) >>> 0])
  }
  return out
}

var K256 = unhex32(
  "428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 " +
  "d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 " +
  "e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da " +
  "983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 " +
  "27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 " +
  "a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 " +
  "19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 " +
  "748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2")

var H256 = unhex32(
  "6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19")

var K512 = unhex64(
  "428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc " +
  "3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 " +
  "d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2 " +
  "72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694 " +
  "e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65 " +
  "2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 " +
  "983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 " +
  "c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70 " +
  "27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df " +
  "650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b " +
  "a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 " +
  "d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8 " +
  "19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 " +
  "391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3 " +
  "748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec " +
  "90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b " +
  "ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 " +
  "06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b " +
  "28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c " +
  "4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817")

var H512 = unhex64(
  "6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1 " +
  "510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179")

// ------------------------------------------------------------ byte plumbing

function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0 }
function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0 }

// Big-endian padding: 0x80, zeros, then the message length in bits as a
// `lengthBytes`-wide big-endian integer filling the tail of the final block.
function pad(bytes, blockSize, lengthBytes) {
  var out = bytes.slice(0)
  out.push(0x80)
  while ((out.length + lengthBytes) % blockSize !== 0) out.push(0)
  var bits = bytes.length * 8
  for (var i = lengthBytes - 1; i >= 0; i--) {
    out.push(i < 6 ? Math.floor(bits / Math.pow(2, 8 * i)) & 0xff : 0)
  }
  return out
}

function beWord(bytes, i) {
  return ((bytes[i] << 24) | (bytes[i + 1] << 16) |
          (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0
}

function words32ToBytes(words) {
  var out = []
  for (var i = 0; i < words.length; i++) {
    out.push((words[i] >>> 24) & 0xff, (words[i] >>> 16) & 0xff,
             (words[i] >>> 8) & 0xff, words[i] & 0xff)
  }
  return out
}

function words64ToBytes(words) {
  var out = []
  for (var i = 0; i < words.length; i++) {
    out.push((words[i][0] >>> 24) & 0xff, (words[i][0] >>> 16) & 0xff,
             (words[i][0] >>> 8) & 0xff, words[i][0] & 0xff,
             (words[i][1] >>> 24) & 0xff, (words[i][1] >>> 16) & 0xff,
             (words[i][1] >>> 8) & 0xff, words[i][1] & 0xff)
  }
  return out
}

function bytesFromAscii(s) {
  var out = []
  for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff)
  return out
}

// --------------------------------------------------------------------- SHA-1

function sha1(bytes) {
  var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
  var msg = pad(bytes, 64, 8)
  var w = new Array(80)

  for (var off = 0; off < msg.length; off += 64) {
    var t
    for (t = 0; t < 16; t++) w[t] = beWord(msg, off + 4 * t)
    for (t = 16; t < 80; t++) {
      w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
    }

    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4]
    for (t = 0; t < 80; t++) {
      var f, k
      if (t < 20) { f = (b & c) | (~b & d); k = 0x5a827999 }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1 }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc }
      else { f = b ^ c ^ d; k = 0xca62c1d6 }
      var tmp = (rotl32(a, 5) + (f >>> 0) + e + k + w[t]) >>> 0
      e = d; d = c; c = rotl32(b, 30); b = a; a = tmp
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0
    h[3] = (h[3] + d) >>> 0; h[4] = (h[4] + e) >>> 0
  }
  return words32ToBytes(h)
}

// ------------------------------------------------------------------- SHA-256

function sha256(bytes) {
  var h = H256.slice(0)
  var msg = pad(bytes, 64, 8)
  var w = new Array(64)

  for (var off = 0; off < msg.length; off += 64) {
    var t
    for (t = 0; t < 16; t++) w[t] = beWord(msg, off + 4 * t)
    for (t = 16; t < 64; t++) {
      var s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ (w[t - 15] >>> 3)
      var s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ (w[t - 2] >>> 10)
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0
    }

    var a = h[0], b = h[1], c = h[2], d = h[3]
    var e = h[4], f = h[5], g = h[6], hh = h[7]
    for (t = 0; t < 64; t++) {
      var S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      var ch = (e & f) ^ (~e & g)
      var t1 = (hh + S1 + (ch >>> 0) + K256[t] + w[t]) >>> 0
      var S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
      var maj = (a & b) ^ (a & c) ^ (b & c)
      var t2 = (S0 + (maj >>> 0)) >>> 0
      hh = g; g = f; f = e; e = (d + t1) >>> 0
      d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0
  }
  return words32ToBytes(h)
}

// ------------------------------------------------- SHA-512 (64-bit as hi/lo)

function add64(a, b) {
  var lo = (a[1] >>> 0) + (b[1] >>> 0)
  var hi = (a[0] + b[0] + (lo >= 0x100000000 ? 1 : 0)) >>> 0
  return [hi, lo >>> 0]
}

function xor64(a, b) { return [(a[0] ^ b[0]) >>> 0, (a[1] ^ b[1]) >>> 0] }
function and64(a, b) { return [(a[0] & b[0]) >>> 0, (a[1] & b[1]) >>> 0] }
function not64(a) { return [~a[0] >>> 0, ~a[1] >>> 0] }

function rotr64(a, n) {
  if (n === 0) return [a[0], a[1]]
  if (n === 32) return [a[1], a[0]]
  if (n < 32) {
    return [((a[0] >>> n) | (a[1] << (32 - n))) >>> 0,
            ((a[1] >>> n) | (a[0] << (32 - n))) >>> 0]
  }
  var m = n - 32
  return [((a[1] >>> m) | (a[0] << (32 - m))) >>> 0,
          ((a[0] >>> m) | (a[1] << (32 - m))) >>> 0]
}

function shr64(a, n) {
  if (n < 32) {
    return [a[0] >>> n, ((a[1] >>> n) | (a[0] << (32 - n))) >>> 0]
  }
  return [0, a[0] >>> (n - 32)]
}

function sha512(bytes) {
  var h = []
  for (var i = 0; i < 8; i++) h.push([H512[i][0], H512[i][1]])
  var msg = pad(bytes, 128, 16)
  var w = new Array(80)

  for (var off = 0; off < msg.length; off += 128) {
    var t
    for (t = 0; t < 16; t++) {
      w[t] = [beWord(msg, off + 8 * t), beWord(msg, off + 8 * t + 4)]
    }
    for (t = 16; t < 80; t++) {
      var x = w[t - 15]
      var s0 = xor64(xor64(rotr64(x, 1), rotr64(x, 8)), shr64(x, 7))
      var y = w[t - 2]
      var s1 = xor64(xor64(rotr64(y, 19), rotr64(y, 61)), shr64(y, 6))
      w[t] = add64(add64(add64(w[t - 16], s0), w[t - 7]), s1)
    }

    var a = h[0], b = h[1], c = h[2], d = h[3]
    var e = h[4], f = h[5], g = h[6], hh = h[7]
    for (t = 0; t < 80; t++) {
      var S1 = xor64(xor64(rotr64(e, 14), rotr64(e, 18)), rotr64(e, 41))
      var ch = xor64(and64(e, f), and64(not64(e), g))
      var t1 = add64(add64(add64(add64(hh, S1), ch), K512[t]), w[t])
      var S0 = xor64(xor64(rotr64(a, 28), rotr64(a, 34)), rotr64(a, 39))
      var maj = xor64(xor64(and64(a, b), and64(a, c)), and64(b, c))
      var t2 = add64(S0, maj)
      hh = g; g = f; f = e; e = add64(d, t1)
      d = c; c = b; b = a; a = add64(t1, t2)
    }
    var next = [a, b, c, d, e, f, g, hh]
    for (i = 0; i < 8; i++) h[i] = add64(h[i], next[i])
  }
  return words64ToBytes(h)
}

// ---------------------------------------------------------------------- HMAC

var HASHES = {
  "SHA1": { fn: sha1, block: 64 },
  "SHA256": { fn: sha256, block: 64 },
  "SHA512": { fn: sha512, block: 128 }
}

function normalizeAlgorithm(name) {
  var key = String(name || "SHA1").toUpperCase().replace(/[^A-Z0-9]/g, "")
  if (key === "SHA") key = "SHA1"
  return HASHES.hasOwnProperty(key) ? key : null
}

// RFC 2104. Keys longer than the block size are hashed down first; shorter
// ones are zero-padded up.
function hmac(algorithm, keyBytes, msgBytes) {
  var algo = normalizeAlgorithm(algorithm)
  if (!algo) throw new Error("unsupported algorithm: " + algorithm)
  var spec = HASHES[algo]

  var key = keyBytes.slice(0)
  if (key.length > spec.block) key = spec.fn(key)
  while (key.length < spec.block) key.push(0)

  var inner = [], outer = []
  for (var i = 0; i < spec.block; i++) {
    inner.push(key[i] ^ 0x36)
    outer.push(key[i] ^ 0x5c)
  }
  return spec.fn(outer.concat(spec.fn(inner.concat(msgBytes))))
}

// -------------------------------------------------------------------- base32

var B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// RFC 4648 base32, forgiving about how issuers actually present secrets:
// lowercase, grouped with spaces or dashes, and with the padding left off.
// Throws on any character that is not base32 at all — a silent skip would
// turn a mistyped secret into a plausible-looking wrong code.
function base32Decode(input) {
  var s = String(input || "").replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase()
  if (s.length === 0) throw new Error("secret is empty")

  var bits = 0, value = 0, out = []
  for (var i = 0; i < s.length; i++) {
    var idx = B32_ALPHABET.indexOf(s.charAt(i))
    if (idx < 0) throw new Error("secret is not valid base32")
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  if (out.length === 0) throw new Error("secret is too short")
  return out
}

// ----------------------------------------------------------------- HOTP/TOTP

function counterBytes(counter) {
  var hi = Math.floor(counter / 0x100000000)
  var lo = counter >>> 0
  return [(hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
          (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff]
}

// RFC 4226 §5.3 dynamic truncation.
function hotp(algorithm, keyBytes, counter, digits) {
  var mac = hmac(algorithm, keyBytes, counterBytes(counter))
  var offset = mac[mac.length - 1] & 0x0f
  var binary = ((mac[offset] & 0x7f) << 24) | ((mac[offset + 1] & 0xff) << 16) |
               ((mac[offset + 2] & 0xff) << 8) | (mac[offset + 3] & 0xff)
  var code = String(binary % Math.pow(10, digits))
  while (code.length < digits) code = "0" + code
  return code
}

// Options: {digits, period, algorithm, t}. `t` is unix seconds and defaults to
// now, so callers under test can pin it.
function totp(secretBase32, options) {
  var opts = options || {}
  var digits = opts.digits || 6
  var period = opts.period || 30
  var t = opts.t === undefined ? Math.floor(Date.now() / 1000) : opts.t
  return hotp(opts.algorithm || "SHA1", base32Decode(secretBase32),
              Math.floor(t / period), digits)
}

// Seconds until the current code expires, for the countdown ring.
function secondsRemaining(period, t) {
  var p = period || 30
  var now = t === undefined ? Math.floor(Date.now() / 1000) : t
  return p - (now % p)
}
