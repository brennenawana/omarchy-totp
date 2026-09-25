import QtQuick
import Quickshell
import Quickshell.Io
import "YubiKey.js" as Yk

// Optional source of one-time codes from OATH accounts on a YubiKey.
//
// The applet on the key is write-only — a secret goes in and never comes back
// out — so nothing here can import. It is a *source*: list the accounts on an
// inserted key and read their codes through `ykman`. Nothing is stored, on the
// key or here.
//
// The whole item is inert unless the "yubikey" setting is on. Every process
// below is started only from a function that checks `enabled` first, so a
// switch that is off means no ykman invocation at all.
Item {
  id: root

  property bool enabled: false

  // Parsed records in the same shape as vault records, so the panel can render
  // them without knowing where they came from.
  property var accounts: []
  // id -> current code.
  property var codes: ({})
  // "off" | "missing" | "no-key" | "loading" | "ready" | "error"
  property string status: "off"
  property string error: ""

  readonly property bool showing: enabled && status === "ready" && accounts.length > 0

  function codeFor(record) {
    return codes.hasOwnProperty(record.id) ? codes[record.id] : ""
  }

  // Drops everything read from the key. Called when the popup closes, for the
  // same reason the vault drops its secrets: nothing outlives the panel.
  function forget() {
    accounts = []
    codes = ({})
    if (enabled) status = "loading"
  }

  // Re-reads the key. Cheap and idempotent; the panel calls it on open.
  function refresh() {
    if (!enabled) return
    status = "loading"
    error = ""
    probe.token = ""
    probe.running = true
  }

  // One account's code, for a credential that needs a touch before it will
  // answer — a bulk read cannot produce those.
  function fetchCode(name) {
    if (!enabled) return
    single.name = name
    single.token = ""
    single.command = ["ykman", "oath", "accounts", "code", "-s", name]
    single.running = true
  }

  onEnabledChanged: {
    if (enabled) {
      refresh()
    } else {
      // Stop anything mid-flight and blank the state. A Process left running
      // would still be talking to the key after the feature was switched off.
      probe.running = false
      lister.running = false
      bulk.running = false
      single.running = false
      accounts = []
      codes = ({})
      status = "off"
      error = ""
    }
  }

  // 1. Is ykman installed, and is a key plugged in? One call answers both and
  //    prints a single token, so no exit code has to be guessed at.
  Process {
    id: probe
    property string token: ""
    command: ["sh", "-c",
      "if ! command -v ykman >/dev/null 2>&1; then echo YKMAN_MISSING; exit 0; fi\n" +
      "if [ -z \"$(ykman list 2>/dev/null)\" ]; then echo YKMAN_NOKEY; exit 0; fi\n" +
      "echo YKMAN_OK"]

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: probe.token = String(text || "").trim()
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      if (!root.enabled) return
      var token = probe.token
      probe.token = ""
      if (token === "YKMAN_MISSING") { root.status = "missing"; return }
      if (token === "YKMAN_NOKEY") { root.status = "no-key"; return }
      if (code !== 0 || token !== "YKMAN_OK") {
        root.status = "error"
        root.error = "The key could not be read."
        return
      }
      lister.running = true
    }
  }

  // 2. Account names, with their OATH type so HOTP accounts can be left alone.
  Process {
    id: lister
    property string result: ""
    command: ["ykman", "oath", "accounts", "list", "-o"]

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: lister.result = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      if (!root.enabled) return
      var text = lister.result
      lister.result = ""
      if (code !== 0) {
        root.status = "error"
        root.error = "The key's OATH application could not be read."
        return
      }
      root.accounts = Yk.parseAccountList(text)
      if (root.accounts.length === 0) { root.status = "ready"; return }
      bulk.running = true
    }
  }

  // 3. Every code in one pass. A credential that requires a touch comes back
  //    without one, and its row offers the on-demand fetch instead.
  Process {
    id: bulk
    property string result: ""
    command: ["ykman", "oath", "accounts", "code"]

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: bulk.result = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      if (!root.enabled) return
      var text = bulk.result
      bulk.result = ""
      // A short or failed bulk read is not a failure of the source: the
      // accounts still list, and each row can produce its own code.
      root.codes = code === 0 ? Yk.parseCodes(text) : {}
      root.status = "ready"
    }
  }

  // 4. A single account, on demand.
  Process {
    id: single
    property string name: ""
    property string result: ""
    command: []

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: single.result = text
    }
    stderr: StdioCollector { waitForEnd: true }

    onExited: function(code) {
      if (!root.enabled) return
      var text = single.result
      single.result = ""
      var name = single.name
      if (code !== 0) {
        root.error = "No code for " + name + "."
        return
      }
      var value = Yk.parseSingleCode(text)
      if (value.length === 0) return
      var merged = {}
      for (var key in root.codes) merged[key] = root.codes[key]
      merged[Yk.accountId(name)] = value
      root.codes = merged
    }
  }
}
