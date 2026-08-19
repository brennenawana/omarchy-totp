.pragma library
.import "Totp.js" as Totp

// Parsing, validation, and on-disk shape for 2FA accounts.
//
// Everything that reaches this file is untrusted: otpauth:// URIs decoded from
// a QR code someone put on a web page, text pasted from a clipboard, and the
// index file itself (which a previous version, or a text editor, may have left
// malformed). Nothing here trusts its input, and nothing here ever handles the
// shared secret's storage — that belongs to the keyring, via Vault.qml.

var MAX_TEXT = 128
var VALID_DIGITS = [6, 7, 8]
var MIN_PERIOD = 1
var MAX_PERIOD = 300

// Control characters have no place in a display label. They are stripped
// rather than rejected: a stray one should not block an otherwise valid
// enrolment, and they carry no meaning worth preserving. Everything else is
// kept verbatim — including anything that looks like markup, which the UI
// renders literally by using Text.PlainText everywhere.
function cleanText(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/[\x00-\x1f\x7f]/g, "")
    .trim()
    .substring(0, MAX_TEXT)
}

function isBlank(value) {
  return cleanText(value).length === 0
}

// --------------------------------------------------------------- otpauth://

// Splits "scheme://type/label?query" without relying on a URL parser, which
// QML's JS environment does not provide. Returns {type, label, params}.
function splitUri(uri) {
  var text = String(uri || "").trim()
  var match = text.match(/^otpauth:\/\/([^\/?#]+)\/?([^?#]*)(?:\?([^#]*))?/i)
  if (!match) throw new Error("Not an otpauth:// link")

  var params = {}
  var query = match[3] || ""
  if (query.length > 0) {
    var pairs = query.split("&")
    for (var i = 0; i < pairs.length; i++) {
      if (pairs[i].length === 0) continue
      var eq = pairs[i].indexOf("=")
      var rawKey = eq < 0 ? pairs[i] : pairs[i].substring(0, eq)
      var rawValue = eq < 0 ? "" : pairs[i].substring(eq + 1)
      // A malformed percent-escape throws out of decodeURIComponent; treat the
      // segment as literal rather than failing the whole enrolment.
      var key, value
      try { key = decodeURIComponent(rawKey) } catch (e) { key = rawKey }
      try { value = decodeURIComponent(rawValue) } catch (e2) { value = rawValue }
      params[key.toLowerCase()] = value
    }
  }

  // The label is returned still encoded. Splitting it into issuer and account
  // has to happen before decoding: the separator is a literal colon in the
  // path, while a colon *inside* either half arrives as %3A. Decode first and
  // the two become indistinguishable, so "<img src=\"http://x\">" would split
  // at the colon in "http:" instead of being one name.
  return { type: match[1].toLowerCase(), label: match[2] || "", params: params }
}

function decodeOrRaw(text) {
  try { return decodeURIComponent(text) } catch (e) { return text }
}

// The label is "issuer:account" or just "account", per the Key Uri Format.
// The issuer= parameter wins over the label prefix when they disagree, which
// is what every other authenticator does.
//
// A literal colon is the separator. Some producers encode it as %3A instead,
// so that is accepted too — but only when there is no literal colon anywhere
// in the label. The two spellings are genuinely ambiguous: an issuer that
// itself contains a colon also arrives as %3A, and treating that as the
// separator splits "Iss:uer:account" in the wrong place. Preferring the
// literal form resolves it, because a name's own colon is always encoded
// while the separator this plugin writes never is.
function splitLabel(rawLabel) {
  var text = String(rawLabel || "")
  var separator = text.indexOf(":") >= 0 ? /^([^:]*):\s*(?:%20)*(.*)$/
                                         : /^(.*?)%3a\s*(?:%20)*(.*)$/i
  var match = text.match(separator)
  if (!match) return { issuer: "", account: decodeOrRaw(text) }
  return {
    issuer: decodeOrRaw(match[1]),
    account: decodeOrRaw(match[2]).replace(/^\s+/, "")
  }
}

// Parses an otpauth:// URI into an account record. Throws with a message meant
// to be shown to the user.
function parseOtpauth(uri) {
  var parts = splitUri(uri)

  if (parts.type === "hotp") {
    throw new Error("Counter-based (HOTP) codes are not supported")
  }
  if (parts.type !== "totp") {
    throw new Error("Unsupported otpauth type: " + cleanText(parts.type))
  }

  var named = splitLabel(parts.label)
  var issuer = cleanText(parts.params.issuer || named.issuer)
  var account = cleanText(named.account)

  return normalizeAccount({
    label: account.length > 0 ? account : issuer,
    issuer: issuer,
    secret: parts.params.secret || "",
    digits: parts.params.digits,
    period: parts.params.period,
    algorithm: parts.params.algorithm
  })
}

// ------------------------------------------------------------- normalisation

// Applies defaults, coerces types, and rejects anything out of range. The
// caller gets back a record safe to store, or an exception explaining why not.
//
// `secret` is validated but is NOT part of the stored record — Vault.qml hands
// it to the keyring and drops it. Keeping it out of the index file is the
// whole point of the split.
function normalizeAccount(input) {
  var raw = input || {}

  var label = cleanText(raw.label)
  var issuer = cleanText(raw.issuer)
  if (label.length === 0) label = issuer
  if (label.length === 0) throw new Error("A name is required")

  var digits = raw.digits === undefined || raw.digits === null || raw.digits === ""
    ? 6 : parseInt(raw.digits, 10)
  if (VALID_DIGITS.indexOf(digits) < 0) {
    throw new Error("Digits must be 6, 7, or 8")
  }

  var period = raw.period === undefined || raw.period === null || raw.period === ""
    ? 30 : parseInt(raw.period, 10)
  if (!isFinite(period) || period < MIN_PERIOD || period > MAX_PERIOD) {
    throw new Error("Period must be between " + MIN_PERIOD + " and " + MAX_PERIOD + " seconds")
  }

  var algorithm = Totp.normalizeAlgorithm(raw.algorithm)
  if (!algorithm) {
    throw new Error("Unsupported algorithm: " + cleanText(raw.algorithm))
  }

  var secret = String(raw.secret || "").replace(/[\s-]/g, "")
  if (secret.length === 0) throw new Error("A secret is required")

  // Decode the secret and actually generate a code. A secret that only fails
  // at sign-in time — when the account is already locked behind it — is the
  // worst bug this plugin could ship, so it fails here instead.
  try {
    Totp.totp(secret, { digits: digits, period: period, algorithm: algorithm, t: 0 })
  } catch (e) {
    throw new Error("That secret is not valid base32")
  }

  return {
    label: label,
    issuer: issuer,
    digits: digits,
    period: period,
    algorithm: algorithm,
    secret: secret
  }
}

// ------------------------------------------------------------- index records

// Ids only need to be unique and stable — they key the keyring lookup and
// never authenticate anything, so a timestamp plus randomness is enough. The
// caller passes the ids already in use so a collision cannot silently
// overwrite another account's secret.
function newId(existingIds) {
  var taken = {}
  var list = existingIds || []
  for (var i = 0; i < list.length; i++) taken[list[i]] = true

  for (var attempt = 0; attempt < 1000; attempt++) {
    var id = Date.now().toString(36) + "-" +
      Math.floor(Math.random() * 0x100000000).toString(36) +
      Math.floor(Math.random() * 0x100000000).toString(36)
    if (!taken[id]) return id
  }
  throw new Error("Could not allocate an account id")
}

// Strips an account down to what may be written to disk. The secret is absent
// by construction: this function names every field it copies, so a secret
// cannot reach the index file by being added to the record upstream.
function toRecord(id, account) {
  return {
    id: id,
    label: account.label,
    issuer: account.issuer,
    digits: account.digits,
    period: account.period,
    algorithm: account.algorithm
  }
}

// Reads the index file. Anything unparseable or structurally wrong yields an
// empty list rather than an exception — a corrupt index must not stop the
// panel from opening, and the accounts it describes are recoverable from the
// keyring entries that outlive it.
function parseIndex(text) {
  var parsed
  try {
    parsed = JSON.parse(String(text || ""))
  } catch (e) {
    return []
  }
  if (!parsed || !parsed.accounts || parsed.accounts.length === undefined) return []

  var out = []
  var seen = {}
  for (var i = 0; i < parsed.accounts.length; i++) {
    var row = parsed.accounts[i]
    if (!row || typeof row !== "object") continue

    var id = cleanText(row.id)
    // Ids address keyring items, so keep them to a conservative shape and
    // never let a duplicate shadow an earlier entry.
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(id) || seen[id]) continue
    seen[id] = true

    var digits = parseInt(row.digits, 10)
    var period = parseInt(row.period, 10)
    var algorithm = Totp.normalizeAlgorithm(row.algorithm)

    out.push({
      id: id,
      label: cleanText(row.label) || id,
      issuer: cleanText(row.issuer),
      digits: VALID_DIGITS.indexOf(digits) >= 0 ? digits : 6,
      period: isFinite(period) && period >= MIN_PERIOD && period <= MAX_PERIOD ? period : 30,
      algorithm: algorithm || "SHA1"
    })
  }
  return out
}

function serializeIndex(records) {
  var rows = []
  for (var i = 0; i < records.length; i++) {
    rows.push(toRecord(records[i].id, records[i]))
  }
  return JSON.stringify({ version: 1, accounts: rows }, null, 2) + "\n"
}

// ------------------------------------------------------------------- export

// Renders an account back into the otpauth:// form every authenticator
// understands, so an export is a migration path rather than a snapshot only
// this plugin can read.
//
// Both halves of the label are percent-encoded, which is what keeps the
// issuer/account separator unambiguous: a colon inside either name becomes
// %3A and cannot be mistaken for the separator when the link is read back.
function toOtpauth(record, secret) {
  var label = encodeURIComponent(record.label)
  if (record.issuer.length > 0) {
    label = encodeURIComponent(record.issuer) + ":" + label
  }

  var params = ["secret=" + encodeURIComponent(secret)]
  if (record.issuer.length > 0) {
    params.push("issuer=" + encodeURIComponent(record.issuer))
  }
  params.push("algorithm=" + record.algorithm)
  params.push("digits=" + record.digits)
  params.push("period=" + record.period)

  return "otpauth://totp/" + label + "?" + params.join("&")
}

// The export is a plain list of otpauth:// links with a short header. Comment
// lines are ignored on the way back in, so the header can explain itself
// without breaking a restore.
function buildExport(records, secretFor) {
  var lines = [
    "# Omarchy 2FA export",
    "# One otpauth:// link per account. Any authenticator can read these.",
    "# Anyone holding this file can generate your codes — keep it encrypted.",
    ""
  ]
  var missing = 0
  for (var i = 0; i < records.length; i++) {
    var secret = secretFor(records[i].id)
    if (!secret || secret.length === 0) { missing++; continue }
    lines.push(toOtpauth(records[i], secret))
  }
  return { text: lines.join("\n") + "\n", exported: lines.length - 4, missing: missing }
}

// Reads an export back. Blank lines and comments are skipped; every other line
// must parse, and a line that does not is reported rather than silently
// dropped — a restore that quietly loses an account is worse than one that
// fails loudly.
function parseExport(text) {
  var lines = String(text || "").split("\n")
  var accounts = []
  var errors = []
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line.length === 0 || line.charAt(0) === "#") continue
    try {
      accounts.push(parseOtpauth(line))
    } catch (e) {
      errors.push("line " + (i + 1) + ": " + e.message)
    }
  }
  return { accounts: accounts, errors: errors }
}

// ------------------------------------------------------------------ display

// Case-insensitive substring match over the name and issuer, for the filter
// field. Kept here so the panel does no string logic of its own.
function matches(record, query) {
  var q = String(query || "").trim().toLowerCase()
  if (q.length === 0) return true
  return (record.label + " " + record.issuer).toLowerCase().indexOf(q) >= 0
}

// Codes are read aloud and typed in groups; every authenticator splits them.
function groupCode(code) {
  var text = String(code || "")
  if (text.length === 6) return text.substring(0, 3) + " " + text.substring(3)
  if (text.length === 8) return text.substring(0, 4) + " " + text.substring(4)
  if (text.length === 7) return text.substring(0, 4) + " " + text.substring(4)
  return text
}
