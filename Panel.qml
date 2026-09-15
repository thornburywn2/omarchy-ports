// Ports: what is listening on this machine, who owns it, and how far it
// reaches.
//
// Button and popup live together on Ui/Panel, the same shape as the other
// dev.reuk widgets, so open/close/opened belong to the panel itself and the
// bar's panel navigation (SUPER + CTRL + <n>, Tab between panels) just works.
//
// Nothing here writes to `bar`. Third-party widgets are handed a facade whose
// presentation state is read-only, and a failed assignment throws out of
// whatever handler made it -- inside close(), that is a panel that never
// closes.
//
// Discovery and every action live in bin/ports.py. This file runs it on a
// timer, sorts what comes back into sections, and asks it to act.

import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "dev.reuk.ports"
  ipcTarget: "dev.reuk.ports"
  // The shell already routes summon/hide/toggle to bar widgets, and one
  // handler per monitor would only collide on a single target.
  manageIpc: false

  readonly property color ink: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(ink, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string home: Quickshell.env("HOME") || ""

  readonly property int refreshSec: Math.max(2, Math.min(120, Number(setting("refreshIntervalSec", 5)) || 5))
  readonly property bool includeDocker: flag("includeDocker", true)
  readonly property bool includeUdp: flag("includeUdp", false)
  readonly property string ignoredPorts: String(setting("ignoredPorts", "53,631,5353"))

  // When the icon turns the urgent colour: "Network" (something is reachable
  // beyond this machine), "Network and VPN" (also sockets bound only to a VPN
  // address), or "Never", for an icon that always matches the rest of the bar.
  readonly property string iconAlert: {
    var value = String(setting("iconAlert", "Network"))
    return ["Network", "Network and VPN", "Never"].indexOf(value) !== -1 ? value : "Network"
  }
  readonly property bool showSystem: flag("showSystem", true)
  readonly property bool showGuesses: flag("showGuesses", true)
  readonly property bool confirmActions: flag("confirmActions", true)
  // Lower-cased names to leave out of the list, the counts and the icon alert.
  readonly property var hiddenNames: String(setting("hiddenNames", "")).split(",")
    .map(function(name) { return name.trim().toLowerCase() })
    .filter(function(name) { return name !== "" })

  // A setting written from the command line without --json arrives as the
  // string "false", which a plain `!== false` would read as on.
  function flag(name, fallback) {
    var value = setting(name, fallback)
    if (typeof value === "string") {
      var text = value.trim().toLowerCase()
      return !(text === "false" || text === "off" || text === "no" || text === "0")
    }
    return value !== false && value !== 0
  }
  readonly property string helper: decodeURIComponent(String(Qt.resolvedUrl("bin/ports.py")).replace(/^file:\/\//, ""))

  // The helper runs as /usr/bin/python3 in isolated mode with an emptied
  // environment. The interpreter is never looked up on PATH (a version
  // manager's shim would otherwise decide what runs), no PYTHON* variables or
  // user site directory apply, and ss and docker resolve from /usr/bin and
  // /bin only. DOCKER_HOST is the one variable passed through, for rootless
  // Docker.
  readonly property var helperEnvironment: {
    var environment = { PATH: "/usr/bin:/bin", LC_ALL: "C" }
    var dockerHost = Quickshell.env("DOCKER_HOST")
    if (dockerHost) environment.DOCKER_HOST = String(dockerHost)
    return environment
  }

  // The helper bounds its own output well below this and times out its own
  // children; these only catch the helper itself misbehaving. The deadlines
  // sit above its slowest paths: a full scan with Docker, and docker stop.
  readonly property int maxHelperChars: 2 * 1024 * 1024
  readonly property int scanDeadlineMs: 35000
  readonly property int actionDeadlineMs: 45000

  // Codepoints rather than pasted glyphs, so each one can be looked up.
  readonly property var glyphs: ({
    radar: String.fromCodePoint(0xF0437),
    open: String.fromCodePoint(0xF03CC),
    copy: String.fromCodePoint(0xF018F),
    stop: String.fromCodePoint(0xF04DB),
    terminate: String.fromCodePoint(0xF04DB),
    kill: String.fromCodePoint(0xF068C)
  })

  // ------------------------------------------------------------------ scan

  property var listeners: []
  property var warnings: []
  property string scanError: ""
  property bool scanned: false
  // The last listener list, as text. A refresh that finds the same sockets
  // leaves `listeners` untouched, so the rows are not rebuilt under the
  // pointer -- which would drop the hover, the tooltip and the cursor.
  property string listenersText: ""
  // Set just before a runaway scan is killed, so the handler reports why
  // instead of trying to parse whatever partial output arrived.
  property string scanAbort: ""

  // Listeners after the hiding settings and before the filter box: what the
  // counts, the icon alert and the sections all start from.
  readonly property var shown: root.listeners.filter(function(l) { return root.isShown(l) })
  readonly property int networkCount: countScope(root.shown, "network")
  readonly property int vpnCount: countScope(root.shown, "overlay")
  readonly property bool alerting: root.iconAlert !== "Never"
    && (root.networkCount > 0 || (root.iconAlert === "Network and VPN" && root.vpnCount > 0))

  function countScope(rows, scope) {
    var n = 0
    for (var i = 0; i < rows.length; i++) if (rows[i].scope === scope) n++
    return n
  }

  function scanCommand() {
    var command = ["/usr/bin/python3", "-I", root.helper, "scan", "--ignore", root.ignoredPorts]
    if (root.includeUdp) command.push("--udp")
    if (!root.includeDocker) command.push("--no-docker")
    return command
  }

  function refresh() {
    if (scanner.running) return
    root.scanAbort = ""
    scanner.command = root.scanCommand()
    scanner.running = true
    scanDeadline.restart()
  }

  function abortScan(reason) {
    if (!scanner.running) return
    root.scanAbort = reason
    scanner.signal(9)
  }

  function applyScan(text) {
    scanDeadline.stop()
    if (root.scanAbort !== "") {
      root.scanned = true
      root.scanError = root.scanAbort
      root.scanAbort = ""
      return
    }
    var payload = null
    try { payload = JSON.parse(String(text || "")) } catch (e) { payload = null }
    root.scanned = true
    if (!payload || !Array.isArray(payload.listeners)) {
      root.scanError = payload && payload.error
        ? String(payload.error)
        : "Scan failed. Run bin/ports.py scan to see why."
      return
    }
    root.scanError = ""
    root.warnings = Array.isArray(payload.warnings) ? payload.warnings : []
    var next = JSON.stringify(payload.listeners)
    if (next !== root.listenersText) {
      root.listenersText = next
      root.listeners = payload.listeners
    }
  }

  // -------------------------------------------------------------- sections

  property string query: ""
  readonly property var visibleListeners: filtered(root.shown, root.query)
  readonly property var yours: visibleListeners.filter(function(l) {
    return root.isYours(l)
  })
  readonly property var containers: visibleListeners.filter(function(l) {
    return l.owner.kind === "container"
  })
  readonly property var others: visibleListeners.filter(function(l) {
    return !(l.owner.kind === "container" || root.isYours(l))
  })
  // Keyboard order is reading order: down through each section in turn.
  readonly property var ordered: yours.concat(containers, others)

  function isYours(l) {
    return l.owner.kind === "process" && l.owner.owned
  }

  function isShown(l) {
    var o = l.owner || {}
    if (!root.showSystem && !(o.kind === "container" || root.isYours(l))) return false
    if (root.hiddenNames.length === 0) return true
    var names = [o.name, o.service, root.showGuesses ? o.guess : ""]
    for (var i = 0; i < names.length; i++) {
      if (names[i] && root.hiddenNames.indexOf(String(names[i]).toLowerCase()) !== -1) return false
    }
    return true
  }

  function filtered(rows, text) {
    var needle = String(text || "").trim().toLowerCase()
    if (needle === "") return rows
    return rows.filter(function(l) {
      var o = l.owner || {}
      var fields = [l.port, l.proto, (l.addresses || []).join(" "), o.name, root.showGuesses ? o.guess : "", o.pid,
                    o.command, o.cwd, o.image, o.project, o.service]
      return fields.filter(function(v) { return v !== undefined && v !== null && v !== "" })
        .join(" ").toLowerCase().indexOf(needle) !== -1
    })
  }

  function shortPath(path) {
    var p = String(path || "")
    if (root.home !== "" && (p === root.home || p.indexOf(root.home + "/") === 0))
      return "~" + p.slice(root.home.length)
    return p
  }

  // A socket the scanner could not attribute keeps its well-known name only
  // as a question: "Redis?" is honest, "Redis" would be a claim.
  function title(l) {
    var o = l.owner || {}
    if (o.kind === "unknown") return root.showGuesses && o.guess ? o.guess + "?" : "Unknown"
    return String(o.name || "Unknown")
  }

  function meta(l) {
    var o = l.owner || {}
    var parts = []
    if (l.proto !== "tcp") parts.push(String(l.proto).toUpperCase())
    if (o.kind === "process") {
      if (o.cwd && o.cwd !== "/") parts.push(root.shortPath(o.cwd))
      parts.push("PID " + o.pid)
      if (!o.owned) parts.push("read-only")
    } else if (o.kind === "container") {
      parts.push(o.project && o.service ? o.project + "/" + o.service : String(o.image || ""))
      if (o.containerPort && o.containerPort !== l.port) parts.push("→ :" + o.containerPort)
    } else {
      parts.push("owner hidden")
      parts.push((l.addresses || []).join(", "))
    }
    return parts.filter(function(p) { return p !== "" }).join("  ·  ")
  }

  function reachTag(scope) {
    if (scope === "network") return "LAN"
    if (scope === "overlay") return "VPN"
    return ""
  }

  function reachSentence(scope) {
    if (scope === "network") return "reachable from the network"
    if (scope === "overlay") return "reachable from VPN peers"
    return "this machine only"
  }

  // The row carries a name and one line; everything else waits in here.
  function detail(l) {
    var o = l.owner || {}
    var lines = []
    if (o.kind === "process") {
      if (o.command) lines.push(o.command)
      if (!o.owned) lines.push("Owned by another user, so it is read-only.")
    } else if (o.kind === "container") {
      lines.push(String(o.image || ""))
      lines.push("Host :" + l.port + " → container :" + o.containerPort)
    } else {
      lines.push("Owned by root or another user, so the process is hidden.")
      if (root.showGuesses && o.guess) lines.push("Port " + l.port + " is usually " + o.guess + ".")
    }
    lines.push((l.addresses || []).join(", ") + "  ·  " + root.reachSentence(l.scope))
    return lines.filter(function(s) { return s !== "" }).join("\n")
  }

  function actionLabel(l, action) {
    if (action === "open") return "Open " + l.url
    if (action === "copy") return "Copy " + l.url
    if (action === "stop") return "Stop container"
    if (action === "kill") return "Force kill (SIGKILL)"
    return "Terminate (SIGTERM)"
  }

  function heroMeta() {
    if (!root.scanned) return "Scanning"
    if (root.shown.length === 0) return root.listeners.length === 0 ? "Nothing listening" : "All hidden by settings"
    var parts = []
    if (root.networkCount > 0) parts.push(root.networkCount + " on the network")
    if (root.vpnCount > 0) parts.push(root.vpnCount + " VPN only")
    return parts.length > 0 ? parts.join(" · ") : "All local"
  }

  function barTooltip() {
    if (root.scanError !== "") return "Ports · " + root.scanError
    if (!root.scanned) return "Ports"
    var text = "Ports · " + root.shown.length + " listening"
    if (root.networkCount > 0) text += " · " + root.networkCount + " on the network"
    return text
  }

  // ---------------------------------------------------------------- cursor

  // The cursor follows a listener, not a slot: a refresh that adds a row
  // above it would otherwise slide the highlight onto a different port.
  property string cursorKey: ""
  property bool cursorActive: false
  property bool cursorFromKeyboard: false
  readonly property int cursorIndex: {
    for (var i = 0; i < ordered.length; i++) if (ordered[i].key === cursorKey) return i
    return -1
  }
  readonly property var cursorListener: cursorIndex >= 0 ? ordered[cursorIndex] : null

  function moveCursor(dy) {
    if (root.ordered.length === 0) return
    var next = root.cursorIndex < 0
      ? (dy > 0 ? 0 : root.ordered.length - 1)
      : Math.max(0, Math.min(root.ordered.length - 1, root.cursorIndex + dy))
    root.cursorFromKeyboard = true
    root.cursorActive = true
    root.cursorKey = root.ordered[next].key
  }

  function pointAt(key) {
    root.cursorFromKeyboard = false
    root.cursorActive = true
    root.cursorKey = key
  }

  // Only a keyboard move scrolls; a row under the mouse is already in view.
  function reveal(item) {
    if (!root.cursorFromKeyboard || !item) return
    var pad = Style.space(6)
    var top = item.mapToItem(listColumn, 0, 0).y
    var bottom = top + item.height
    var maxY = Math.max(0, flick.contentHeight - flick.height)
    if (top - pad < flick.contentY) flick.contentY = Math.max(0, top - pad)
    else if (bottom + pad > flick.contentY + flick.height)
      flick.contentY = Math.min(maxY, bottom + pad - flick.height)
  }

  // --------------------------------------------------------------- actions

  property var pending: null
  property string actionAbort: ""
  property string busyKey: ""
  property string doneText: ""
  property string notice: ""
  property bool noticeIsError: false

  function has(l, action) {
    return !!l && (l.actions || []).indexOf(action) !== -1
  }

  // URLs come from the helper, built from a numeric address and a port. They
  // are checked again here because this is where they leave for the browser.
  function safeUrl(url) {
    return /^http:\/\/(localhost|\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d{1,5}$/.test(String(url || ""))
  }

  function perform(l, action) {
    if (!root.has(l, action) || root.busyKey !== "") return
    if ((action === "open" || action === "copy") && !root.safeUrl(l.url)) return
    if (action === "open") {
      Quickshell.execDetached(["/usr/bin/xdg-open", l.url])
      root.close()
    } else if (action === "copy") {
      Quickshell.execDetached(["/usr/bin/wl-copy", l.url])
      root.say("Copied " + l.url, false)
    } else if (!root.confirmActions) {
      root.pending = { listener: l, action: action }
      root.runPending()
    } else {
      root.pending = { listener: l, action: action }
      confirm.message = root.confirmMessage(l, action)
      confirm.confirmText = action === "stop" ? "Stop" : (action === "kill" ? "Kill" : "Terminate")
      // Destructive, so the safe answer is the one already selected.
      confirm.selectedIndex = 0
      confirm.opened = true
    }
  }

  function confirmMessage(l, action) {
    var o = l.owner
    if (action === "stop") return "Stop container " + o.name + "? It stops serving :" + l.port + "."
    if (action === "kill") return "Force kill " + o.name + " (PID " + o.pid + ")? It gets no chance to clean up."
    return "Terminate " + o.name + " (PID " + o.pid + ") on :" + l.port + "?"
  }

  function cancelPending() {
    confirm.opened = false
    root.pending = null
    keyCatcher.forceActiveFocus()
  }

  function runPending() {
    var p = root.pending
    confirm.opened = false
    root.pending = null
    keyCatcher.forceActiveFocus()
    if (!p || actor.running) return
    var l = p.listener
    var o = l.owner
    if (p.action === "stop") {
      if (!/^[0-9a-f]{12,64}$/.test(String(o.id))) {
        root.say("Refusing an unexpected container id.", true)
        return
      }
      actor.command = ["/usr/bin/python3", "-I", root.helper, "stop", "--container", String(o.id)]
      root.doneText = "Stopped " + o.name
    } else {
      if (!(Number.isInteger(o.pid) && o.pid > 1 && Number.isInteger(o.start) && o.start > 0)) {
        root.say("Refusing an unexpected process identity.", true)
        return
      }
      var kill = p.action === "kill"
      actor.command = ["/usr/bin/python3", "-I", root.helper, "signal", "--pid", String(o.pid),
                       "--start", String(o.start), "--signal", kill ? "kill" : "term"]
      root.doneText = "Sent " + (kill ? "SIGKILL" : "SIGTERM") + " to " + o.name + " (PID " + o.pid + ")"
    }
    root.busyKey = l.key
    root.actionAbort = ""
    actor.running = true
    actionDeadline.restart()
  }

  function abortAction(reason) {
    if (!actor.running) return
    root.actionAbort = reason
    actor.signal(9)
  }

  function finishAction(text) {
    actionDeadline.stop()
    if (root.actionAbort !== "") {
      root.busyKey = ""
      root.say(root.actionAbort, true)
      root.actionAbort = ""
      return
    }
    var payload = null
    try { payload = JSON.parse(String(text || "")) } catch (e) { payload = null }
    root.busyKey = ""
    if (payload && payload.ok === true) {
      root.say(root.doneText, false)
      settle.restart()
    } else {
      root.say(payload && payload.error ? String(payload.error) : "That did not work.", true)
    }
  }

  function say(text, isError) {
    root.notice = text
    root.noticeIsError = isError
    noticeTimer.restart()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onSettingsChanged: root.refresh()
  onOpenedChanged: {
    if (opened) {
      root.cursorActive = false
      root.cursorKey = ""
      root.refresh()
      if (flick) flick.contentY = 0
    } else {
      confirm.opened = false
      root.pending = null
      search.text = ""
    }
  }

  Process {
    id: scanner
    clearEnvironment: true
    environment: root.helperEnvironment
    stdout: StdioCollector {
      id: scanOutput
      waitForEnd: true
      onDataChanged: if (scanOutput.text.length > root.maxHelperChars)
        root.abortScan("The scan printed too much output, so it was stopped.")
      // Through the id on purpose: a bare `text` here would resolve to
      // whichever `text` is in scope, not the collector's own.
      onStreamFinished: root.applyScan(scanOutput.text)
    }
  }

  Process {
    id: actor
    clearEnvironment: true
    environment: root.helperEnvironment
    stdout: StdioCollector {
      id: actorOutput
      waitForEnd: true
      onDataChanged: if (actorOutput.text.length > root.maxHelperChars)
        root.abortAction("The action printed too much output, so it was stopped.")
      onStreamFinished: root.finishAction(actorOutput.text)
    }
  }

  // The icon's colour depends on the scan, so it keeps running while the
  // panel is closed; opening forces a fresh one.
  Timer {
    interval: root.refreshSec * 1000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  // A signalled process takes a moment to let go of its socket; rescanning
  // straight away would still find it there.
  Timer {
    id: settle
    interval: 700
    onTriggered: root.refresh()
  }

  Timer {
    id: noticeTimer
    interval: 5000
    onTriggered: root.notice = ""
  }

  Timer {
    id: scanDeadline
    interval: root.scanDeadlineMs
    onTriggered: root.abortScan("The scan took too long, so it was stopped.")
  }

  Timer {
    id: actionDeadline
    interval: root.actionDeadlineMs
    onTriggered: root.abortAction("That took too long, so it was stopped.")
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.glyphs.radar
    // Lit per the iconAlert setting: by default while anything is reachable
    // from the network, the one state worth noticing without opening the panel.
    active: root.alerting
    tooltipText: root.barTooltip()
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) root.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(layout.implicitHeight, Style.space(680))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: search.activeFocus && !confirm.opened

      onCloseRequested: {
        if (confirm.opened) root.cancelPending()
        else if (search.text !== "") search.text = ""
        else root.close()
      }
      onTabRequested: function(direction) {
        if (confirm.opened) confirm.selectedIndex = confirm.selectedIndex === 0 ? 1 : 0
        else root.switchPanel(direction)
      }
      onMoveRequested: function(dx, dy) {
        if (confirm.opened) {
          if (dx !== 0) confirm.selectedIndex = confirm.selectedIndex === 0 ? 1 : 0
          return
        }
        if (dy !== 0) root.moveCursor(dy)
      }
      onActivateRequested: {
        if (confirm.opened) {
          if (confirm.selectedIndex === 0) root.cancelPending()
          else root.runPending()
          return
        }
        root.perform(root.cursorListener, "open")
      }
      onDeleteRequested: {
        if (confirm.opened) return
        var l = root.cursorListener
        root.perform(l, root.has(l, "stop") ? "stop" : "terminate")
      }
      // Letters are commands, so only digits (ports are what gets searched
      // for most) and "/" hand the keyboard over to the filter.
      onTextKey: function(t) {
        if (confirm.opened) return
        if (t === "r" || t === "R") root.refresh()
        else if (t === "c") root.perform(root.cursorListener, "copy")
        else if (t === "K") root.perform(root.cursorListener, "kill")
        else if (t === "/" || /^[0-9]$/.test(t)) {
          search.forceActiveFocus()
          if (t !== "/") search.insert(search.cursorPosition, t)
        }
      }

      Column {
        id: layout
        width: parent.width
        spacing: Style.space(12)

        PanelHero {
          width: parent.width
          title: "Ports"
          meta: root.heroMeta()
          foreground: root.ink
          fontFamily: root.fontFamily

          iconComponent: Text {
            text: root.glyphs.radar
            color: root.alerting ? root.urgent : root.ink
            font.family: root.fontFamily
            font.pixelSize: Style.font.display
            Behavior on color { ColorAnimation { duration: 240 } }
          }

          trailingControl: Text {
            text: root.scanned ? String(root.shown.length) : ""
            color: root.ink
            font.family: root.fontFamily
            font.pixelSize: Style.font.displayLarge
            font.bold: true
          }
        }

        TextField {
          id: search
          width: parent.width
          placeholderText: "Filter by port, name, project or image"
          foreground: root.ink
          font.family: root.fontFamily
          onTextChanged: root.query = text
          Keys.onEscapePressed: function(event) {
            text = ""
            keyCatcher.forceActiveFocus()
            event.accepted = true
          }
          Keys.onDownPressed: function(event) {
            keyCatcher.forceActiveFocus()
            root.moveCursor(1)
            event.accepted = true
          }
          Keys.onReturnPressed: function(event) {
            keyCatcher.forceActiveFocus()
            root.moveCursor(1)
            event.accepted = true
          }
        }

        BorderSurface {
          visible: root.scanError !== ""
          width: parent.width
          implicitHeight: errorText.implicitHeight + Style.spacing.xl * 2
          color: Util.alpha(root.urgent, 0.10)
          borderSpec: Border.flat(Util.alpha(root.urgent, 0.35), 1)
          radius: Style.cornerRadius

          Text {
            id: errorText
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Style.space(12)
            anchors.rightMargin: Style.space(12)
            text: root.scanError
            color: root.ink
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }
        }

        Text {
          width: parent.width
          visible: text !== ""
          text: root.notice !== ""
            ? root.notice
            : (root.warnings.length > 0 ? String(root.warnings[0]) : "")
          color: root.notice !== "" && root.noticeIsError ? root.urgent : root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        Text {
          width: parent.width
          visible: root.scanError === "" && root.ordered.length === 0
          topPadding: Style.space(8)
          bottomPadding: Style.space(8)
          horizontalAlignment: Text.AlignHCenter
          text: !root.scanned
            ? "Scanning…"
            : (root.query.trim() !== ""
              ? "Nothing matches “" + root.query.trim() + "”."
              : (root.listeners.length > 0 ? "Everything listening is hidden by your settings." : "Nothing is listening."))
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          wrapMode: Text.WordWrap
        }

        // The hero and filter stay put; only the listeners scroll.
        Flickable {
          id: flick
          visible: root.ordered.length > 0
          width: parent.width
          height: Math.min(listColumn.implicitHeight, Style.space(430))
          contentWidth: width
          contentHeight: listColumn.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          interactive: contentHeight > height
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: listColumn
            width: flick.width
            spacing: Style.space(10)

            Section { title: "YOUR PROCESSES"; rows: root.yours }
            Section { title: "CONTAINERS"; rows: root.containers }
            Section { title: "SYSTEM"; rows: root.others }
          }
        }

        Text {
          width: parent.width
          visible: root.ordered.length > 0
          horizontalAlignment: Text.AlignHCenter
          text: "↵ open   c copy   x stop   K kill   / filter   r refresh"
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      ConfirmDialog {
        id: confirm
        anchors.fill: parent
        z: 10
        background: Color.popups.background
        foreground: root.ink
        selectedText: Color.accent
        fontFamily: root.fontFamily
        onCanceled: root.cancelPending()
        onConfirmed: root.runPending()
      }
    }
  }

  // One owner group: a rule, a small-caps title with its count, the rows.
  component Section: Column {
    id: section
    property string title: ""
    property var rows: []

    visible: rows.length > 0
    width: parent ? parent.width : 0
    spacing: Style.space(4)

    PanelSeparator { foreground: root.ink }

    Item { width: 1; height: Style.space(4) }

    SectionHead {
      title: section.title
      value: String(section.rows.length)
    }

    Repeater {
      model: section.rows

      ListenerRow {
        required property var modelData
        listener: modelData
      }
    }
  }

  component SectionHead: Item {
    id: head
    property string title: ""
    property string value: ""

    width: parent ? parent.width : 0
    implicitHeight: Math.max(headLabel.implicitHeight, headValue.implicitHeight)

    PanelSectionHeader {
      id: headLabel
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      text: head.title
      foreground: root.ink
      fontFamily: root.fontFamily
    }

    Text {
      id: headValue
      anchors.right: parent.right
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      text: head.value
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }
  }

  // Reach dot, port, owner and one line of context. The trailing slot shows
  // how far the port reaches, and swaps to the actions while the row holds
  // the cursor -- a fixed width either way, so titles never reflow on hover.
  component ListenerRow: CursorSurface {
    id: row
    property var listener: null
    property int buttonsHovered: 0

    readonly property var owner: listener ? listener.owner : ({})
    readonly property bool guessed: owner.kind === "unknown"
    readonly property bool busy: !!listener && root.busyKey === listener.key

    width: parent ? parent.width : 0
    implicitHeight: Math.max(Style.space(40), texts.implicitHeight + Style.space(12))
    hasCursor: !!listener && root.cursorActive && root.cursorKey === listener.key
    foreground: root.ink
    opacity: busy ? 0.45 : 1

    onHasCursorChanged: if (hasCursor) root.reveal(row)

    // Declared first so the action buttons sit above it and keep their clicks.
    MouseArea {
      id: rowMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: root.has(row.listener, "open") ? Qt.PointingHandCursor : Qt.ArrowCursor
      onEntered: if (row.listener) root.pointAt(row.listener.key)
      onClicked: root.perform(row.listener, "open")
    }

    Rectangle {
      id: reachDot
      width: Style.space(6)
      height: width
      radius: width / 2
      anchors.left: parent.left
      anchors.leftMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      color: !row.listener || row.listener.scope === "local"
        ? "transparent"
        : (row.listener.scope === "network" ? root.urgent : Util.alpha(root.ink, 0.5))
    }

    Text {
      id: portText
      anchors.left: reachDot.right
      anchors.leftMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      width: Style.space(56)
      text: row.listener ? ":" + row.listener.port : ""
      color: root.ink
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
      font.bold: true
    }

    Column {
      id: texts
      anchors.left: portText.right
      anchors.leftMargin: Style.space(6)
      anchors.right: trailing.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(2)

      Text {
        width: parent.width
        text: row.listener ? root.title(row.listener) : ""
        color: row.guessed ? root.dim : root.ink
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: !row.guessed
        elide: Text.ElideRight
      }

      Text {
        width: parent.width
        visible: text !== ""
        text: row.listener ? root.meta(row.listener) : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        elide: Text.ElideMiddle
      }
    }

    Item {
      id: trailing
      anchors.right: parent.right
      anchors.rightMargin: Style.space(4)
      anchors.verticalCenter: parent.verticalCenter
      width: Style.space(98)
      height: Style.space(24)

      Text {
        anchors.right: parent.right
        anchors.rightMargin: Style.space(6)
        anchors.verticalCenter: parent.verticalCenter
        visible: !row.hasCursor
        text: row.listener ? root.reachTag(row.listener.scope) : ""
        color: row.listener && row.listener.scope === "network" ? root.urgent : root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 1.2
      }

      Row {
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(2)
        visible: row.hasCursor && !row.busy

        Repeater {
          model: row.listener ? row.listener.actions : []

          PanelActionButton {
            required property string modelData
            iconText: root.glyphs[modelData] || ""
            tooltipText: root.actionLabel(row.listener, modelData)
            foreground: root.ink
            hoverColor: modelData === "open" || modelData === "copy" ? root.ink : root.urgent
            fontFamily: root.fontFamily
            onClicked: root.perform(row.listener, modelData)
            onHovered: function(isHovered) {
              row.buttonsHovered = Math.max(0, row.buttonsHovered + (isHovered ? 1 : -1))
            }
          }
        }
      }
    }

    // Suppressed over the action buttons, which carry tooltips of their own.
    PanelToolTip {
      visible: rowMouse.containsMouse && row.buttonsHovered === 0
      text: row.listener ? root.detail(row.listener) : ""
      fontFamily: root.fontFamily
    }
  }
}
