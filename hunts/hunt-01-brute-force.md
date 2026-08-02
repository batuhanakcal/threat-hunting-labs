# Hunt #01  Brute-Force Authentication Attempts

**Type:** Hypothesis-driven (PEAK)
**Environment:** Splunk BOTS v3 (Frothly), all-time
**Threat Hunter:** Batuhan Akcal
**Status:** Closed - hypothesis disproved

---

## Hypothesis

> An attacker may be attempting to gain access to Frothly systems through brute-force
> authentication - repeated failed login attempts, potentially followed by a success.

**Refinement:** "Is there brute-force?" is not huntable. Narrowed to: *repeated failed
authentication attempts against Frothly's login surfaces (web application and VPN),
within the BOTS v3 dataset timeframe.*

## ABLE

| | |
|---|---|
| **Actor** | Unspecified, any external or internal attacker. No specific threat actor. |
| **Behavior** | High volume of failed authentication attempts against one target, optionally followed by a success (MITRE **T1110 — Brute Force**). |
| **Location** | Authentication surfaces: web application login (`access_combined`) and VPN/firewall (`cisco:asa`). |
| **Evidence** | Repeated POST requests to login endpoints; failed-auth log messages; abnormal request volume from a single source. |

**Scope/stop condition:** Check both web and VPN authentication layers. If neither shows
failed-auth volume, close the hunt rather than expanding indefinitely.

---

## Recon - how does authentication appear in this data?

Before hunting, I had to learn what login looks like here. Evidence can't be invented - it has to be discovered.

**Finding 1 - the web login surface is `member.php`:**
```
index=botsv3 sourcetype=access_combined uri_path="/member.php" | stats count by uri_query, status | sort - count
```
![member.php actions and status](../hunt-01-bruteforce-images/hunt-01-bruteforce-1.png)

Result: 102 events total. `action=register` (22), `action=login` (11), `action=lostpw` (11),the 
rest are profile views. **Every single event returned HTTP 200.**

**Key lesson:** status code does not separate success from failure on this app - the server
returns 200 whether or not the credentials were valid. A common trap.

---

## Execute

### Step 1 - Are there any login *attempts* (POST) on the web app?

```
index=botsv3 sourcetype=access_combined uri_path="/member.php" | stats count by method, uri_query
```
![member.php by method - all GET](../hunt-01-bruteforce-images/hunt-01-bruteforce-2.png)

**Result: 100% GET, zero POST.**

Credential submission always happens via POST (the form body carries username/password).
GET requests only *display* the login page. So the 11 `action=login` events are 11 people
**viewing** the login form, not 11 password attempts. **No brute-force traffic on member.php.**

### Step 2 - Is there any other login surface on the web app?

```
index=botsv3 sourcetype=access_combined uri_path="*login*" | stats count by uri_path, method | sort - count
```
![sitewide login path search](../hunt-01-bruteforce-images/hunt-01-bruteforce-3.png)

**Result: a single `/login.cgi` GET request.** No other login endpoints, no POST volume.
The web layer is clean.

### Step 3 - Pivot to the VPN layer (cisco:asa)

Web being clean doesn't mean brute-force doesn't exist; it may just be the wrong layer.
`cisco:asa` (80,192 events) is the firewall/VPN, a classic brute-force target.

New data source → discover its fields first (its schema is nothing like web logs):
```
index=botsv3 sourcetype=cisco:asa | fieldsummary | table field count
```
![cisco asa fieldsummary](../hunt-01-bruteforce-images/hunt-01-bruteforce-4.png)

**Key observation:** most fields appear in all 80,192 events (generic metadata), but
`Group`, `IP`, and `Username` appear in **only 4 events**. Authentication events are the ones
carrying a username, so this environment contains just 4 user-authentication records.

### Step 4 - Examine those 4 authentication events

```
index=botsv3 sourcetype=cisco:asa Username=* | table _time, Username, IP, _raw
```
![VPN authentication events](../hunt-01-bruteforce-images/hunt-01-bruteforce-5.png)

All four are `%ASA-4-113019` - **VPN session disconnected** events, not login attempts:

| User | Duration | Reason |
|------|----------|--------|
| bstoll | 6h 26m | User Requested |
| bstoll | 49m | User Requested |
| abungstein | 1d 3h 55m | Idle Timeout |
| pcerf | 6h 17m | User Requested |

**Verdict on these:** legitimate users. The durations are decisive - brute-force sessions
last milliseconds (try/reject/retry), not hours. These are multi-hour work sessions
transferring megabytes of data. No failed attempts among them.

### Step 5 - Visibility check: are failed logins even logged?

Before declaring "no brute-force," confirm we *could* see it. (Absence of evidence is only
evidence of absence if the data source is actually collecting it.)

```
index=botsv3 sourcetype=cisco:asa (113005 OR "authentication rejected" OR "AAA user authentication Rejected") | stats count
```
![auth-specific search returns zero](../hunt-01-bruteforce-images/hunt-01-bruteforce-6.png)

**Result: 0 events.** No failed-authentication records at all.

A broader search (`Rejected OR denied OR "authentication failed" OR 113005`) returned
**20,747 events** - alarming at first glance. But breaking it down by Cisco message code:

```
index=botsv3 sourcetype=cisco:asa (Rejected OR denied OR "authentication failed" OR 113005)
| rex field=_raw "%ASA-\d+-(?<msg_code>\d+)"
| stats count by msg_code | sort - count
```
![message code breakdown](../hunt-01-bruteforce-images/hunt-01-bruteforce-7.png)

| msg_code | count | meaning |
|----------|-------|---------|
| 106001 | 20,479 | Inbound TCP connection denied - routine firewall filtering |
| 710003 | 268 | Management access denied |
| **113005** | **0** | **Failed authentication - none** |

**Note:** a big number is not a finding. Broad OR searches sweep up unrelated noise;
98% of those "denied" events were the firewall doing its normal job at the *connection*
layer, not the *authentication* layer.

---

## Verdict

**Hypothesis disproved for the layers examined.** No evidence of brute-force authentication on the web or VPN authentication surfaces,
confirmed across three independent checks:

1. **Web login:** zero POST requests to any login endpoint; only 11 login-page views and a single `/login.cgi` GET.
2. **VPN:** only 4 authentication-related records, all legitimate multi-hour user sessions (verified by session duration and byte counts).
3. **Failed-auth search:** zero `113005` events; the 20,747 "denied" events were connection-level firewall denials, not login failures.

## Visibility gap (the real finding)

## Scope & limitations

This hunt covered **two authentication surfaces**: the web application (`access_combined`)
and the VPN/firewall (`cisco:asa`). The verdict applies to those layers only.

**Not examined in this hunt** - authentication may also occur in:

| Sourcetype | Why it could matter |
|---|---|
| `aws:cloudtrail` | AWS console logins (`ConsoleLogin` events carry success/failure) |
| `aws:rds:audit` | Database authentication attempts (~35k events) |
| `stream:http` | Richer HTTP detail than access logs, incl. POST bodies |
| Windows/endpoint auth logs | RDP / SMB / local logon attempts |

These were left out deliberately to keep the hunt scoped and closeable (per PEAK: define a
stop condition rather than hunting indefinitely). They are logged as candidates for a
follow-up hunt: *"Brute-force, part 2 - cloud and database authentication."*

**Honest statement of the finding:** *No brute-force activity was found on the web or VPN
authentication surfaces. Other authentication layers remain unexamined.*

## Detection idea (deferred)

A brute-force detection cannot be built on this data because the required signal (failed auth
events) isn't collected. Once AAA logging is enabled, the rule would be:
*alert when a single source produces N failed authentications within a short window, especially
if followed by a success from the same source.*

## Important Notes

- **Status codes lie on login pages.** 200 means "request processed," not "login succeeded."
- **GET vs POST is the real discriminator** for credential submission on web apps.
- **Every sourcetype has its own schema.** `status`/`method` don't exist in `cisco:asa`; its
  success/failure lives inside the raw message and its Cisco message code.
- **Prove visibility before declaring absence.** "No evidence" only means something if the
  data source collects that evidence.
- **Big numbers aren't findings.** Break them down (here: `rex` on message codes) before reacting.
- **A disproved hypothesis is a successful hunt** especially when it surfaces a logging gap.
