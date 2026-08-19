// Standalone test harness for Totp.js. Run with: node test/vectors.js
//
// Totp.js is a QML JS library, so it starts with `.pragma library` and has no
// module exports. Both are stripped here and the body is evaluated directly,
// which keeps the shipped file free of any test-only scaffolding.

const fs = require("fs")
const path = require("path")

const source = fs
  .readFileSync(path.join(__dirname, "..", "Totp.js"), "utf8")
  .replace(/^\.pragma library\s*/, "")

const T = {}
new Function("exports", source + "\n;Object.assign(exports, {" +
  "sha1, sha256, sha512, hmac, base32Decode, hotp, totp, secondsRemaining," +
  "bytesFromAscii, normalizeAlgorithm});")(T)

let failures = 0

function check(name, actual, expected) {
  const ok = String(actual) === String(expected)
  if (!ok) failures++
  console.log(`${ok ? "  ok  " : "FAIL  "}${name}` +
    (ok ? "" : `\n        expected ${expected}\n        actual   ${actual}`))
}

function hex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("")
}

// --- raw digests, so a broken hash is not diagnosed as a broken TOTP -------

console.log("\nDigests (FIPS 180-4 examples)")
const abc = T.bytesFromAscii("abc")
check("sha1('abc')", hex(T.sha1(abc)),
  "a9993e364706816aba3e25717850c26c9cd0d89d")
check("sha256('abc')", hex(T.sha256(abc)),
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("sha512('abc')", hex(T.sha512(abc)),
  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")

// Multi-block input exercises the message schedule across block boundaries.
const long = T.bytesFromAscii("a".repeat(1000))
check("sha1(1000*'a')", hex(T.sha1(long)),
  "291e9a6c66994949b57ba5e650361e98fc36b1ba")
check("sha512(1000*'a')", hex(T.sha512(long)),
  "67ba5535a46e3f86dbfbed8cbbaf0125c76ed549ff8b0b9e03e0c88cf90fa634" +
  "fa7b12b47d77b694de488ace8d9a65967dc96df599727d3292a8d9d447709c97")

// --- HMAC (RFC 4231 case 1) ------------------------------------------------

console.log("\nHMAC (RFC 4231)")
const key20 = new Array(20).fill(0x0b)
const hi = T.bytesFromAscii("Hi There")
check("hmac-sha256", hex(T.hmac("SHA256", key20, hi)),
  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
check("hmac-sha512", hex(T.hmac("SHA512", key20, hi)),
  "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
  "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")

// --- base32 ----------------------------------------------------------------

console.log("\nbase32 (RFC 4648)")
check("decode 'MZXW6==='", hex(T.base32Decode("MZXW6===")), "666f6f")
check("lowercase and spaces", hex(T.base32Decode("mz xw 6")), "666f6f")
check("dashes", hex(T.base32Decode("MZXW-6")), "666f6f")

function rejects(name, fn) {
  let threw = false
  try { fn() } catch (e) { threw = true }
  check(name, threw ? "rejected" : "accepted", "rejected")
}
rejects("rejects '1' (not in alphabet)", () => T.base32Decode("MZXW1"))
rejects("rejects '!'", () => T.base32Decode("MZXW6!"))
rejects("rejects empty", () => T.base32Decode(""))

// --- RFC 6238 Appendix B ---------------------------------------------------

const SEEDS = {
  SHA1: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
  SHA256: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====",
  SHA512: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
          "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
}

// [unix time, SHA1, SHA256, SHA512] — all 8-digit, 30-second period.
const VECTORS = [
  [59, "94287082", "46119246", "90693936"],
  [1111111109, "07081804", "68084774", "25091201"],
  [1111111111, "14050471", "67062674", "99943326"],
  [1234567890, "89005924", "91819424", "93441116"],
  [2000000000, "69279037", "90698825", "38618901"],
  [20000000000, "65353130", "77737706", "47863826"]
]

console.log("\nTOTP (RFC 6238 Appendix B)")
for (const [t, ...expected] of VECTORS) {
  ;["SHA1", "SHA256", "SHA512"].forEach((algo, i) => {
    check(`t=${t} ${algo}`,
      T.totp(SEEDS[algo], { t, digits: 8, period: 30, algorithm: algo }),
      expected[i])
  })
}

// t=20000000000 is past 2^31 seconds, so the counter needs the full 64-bit
// path rather than a 32-bit truncation. Covered above; asserted here directly.
check("counter exceeds 32 bits",
  T.totp(SEEDS.SHA1, { t: 20000000000, digits: 8, period: 30 }), "65353130")

// --- defaults and shape ----------------------------------------------------

console.log("\nDefaults")
check("defaults to 6 digits",
  T.totp(SEEDS.SHA1, { t: 59 }).length, 6)
check("6-digit code is the 8-digit tail",
  T.totp(SEEDS.SHA1, { t: 59 }), "287082")
check("algorithm defaults to SHA1",
  T.totp(SEEDS.SHA1, { t: 59, digits: 8 }), "94287082")
check("algorithm name is normalized",
  T.totp(SEEDS.SHA1, { t: 59, digits: 8, algorithm: "sha-1" }), "94287082")
check("unknown algorithm is rejected", T.normalizeAlgorithm("md5"), "null")

// A code whose truncated value happens to be short must still be zero-padded.
check("zero padding", T.hotp("SHA1", T.base32Decode("GEZDGNBVGY3TQOJQ"), 0, 8).length, 8)

console.log("\nCountdown")
check("secondsRemaining at period start", T.secondsRemaining(30, 0), 30)
check("secondsRemaining mid-window", T.secondsRemaining(30, 1111111109), 1)
check("secondsRemaining honours period", T.secondsRemaining(60, 59), 1)

console.log(failures === 0
  ? "\nAll checks passed.\n"
  : `\n${failures} check(s) FAILED.\n`)
process.exit(failures === 0 ? 0 : 1)
