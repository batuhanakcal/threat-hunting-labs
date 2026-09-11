# Hunt #01  Brute-Force Authentication Attempts

**Type:** Hypothesis-driven (PEAK)
**Environment:** Splunk BOTS v3 (Frothly), all-time
**Threat Hunter:** Batuhan Akcal
**Status:** Analysis complete — no supporting pattern observed; visibility limited

## Executive assessment

The searches below did not establish a brute-force pattern across the six examined surfaces.
This is a negative result within the available data, not proof that brute-force did not occur.
VPN failure visibility and CloudTrail field extraction need verification before relying on
automated detections. Low event counts and long sessions do not establish benign intent.

**Time scope:** Original discovery searches used **All time** on BOTS v3. Exact per-source
start/end times and the search display timezone were not recorded in this report.
**Confidence:** The listed counts describe the saved searches; confidence in environment-wide
absence is limited. [Rerun requirements](../validation-notes.md) record the remaining checks.

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
| **Behavior** | High volume of failed authentication attempts against one target, optionally followed by a success (MITRE **T1110 Brute Force**). |
| **Location** | Authentication surfaces: web application login (`access_combined`) and VPN/firewall (`cisco:asa`). |
| **Evidence** | Repeated POST requests to login endpoints; failed-auth log messages; abnormal request volume from a single source. |

**Scope/stop condition:** Start with web and VPN authentication, then record the subsequent
cloud, database, Windows, and network HTTP checks below. Stop after the defined checks and
report unresolved coverage gaps; zero results do not by themselves disprove the hypothesis.

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

**Key lesson:** HTTP 200 on these requests does not establish authentication success or failure.
The saved results contain no verified failed credential submission from which to infer the
application's failure response. Confirm the form behavior and application auth logs first.

---

## Execute

### Step 1 - Are there any login *attempts* (POST) on the web app?

```
index=botsv3 sourcetype=access_combined uri_path="/member.php" | stats count by method, uri_query
```
![member.php by method - all GET](../hunt-01-bruteforce-images/hunt-01-bruteforce-2.png)

**Result: 100% GET, zero POST.**

No POST submissions were observed on this path. The 11 `action=login` GETs are consistent with
login-page requests, but are neither 11 verified password attempts nor 11 distinct people.
Authentication can use other methods, endpoints, or headers; validate this application's
behavior before treating method alone as a credential-submission discriminator.

### Step 2 - Is there any other login surface on the web app?

```
index=botsv3 sourcetype=access_combined uri_path="*login*" | stats count by uri_path, method | sort - count
```
![sitewide login path search](../hunt-01-bruteforce-images/hunt-01-bruteforce-3.png)

**Result: a single `/login.cgi` GET request.** This name-based search found no POST volume on
matching paths. It does not enumerate endpoints whose names lack `login`, or prove the web
layer is free of authentication abuse.

### Step 3 - Pivot to the VPN layer (cisco:asa)

The absence of a web pattern does not rule out activity on another authentication layer.
`cisco:asa` (80,192 events) is the firewall/VPN, a classic brute-force target.

New data source → discover its fields first (its schema is nothing like web logs):
```
index=botsv3 sourcetype=cisco:asa | fieldsummary | table field count
```
![cisco asa fieldsummary](../hunt-01-bruteforce-images/hunt-01-bruteforce-4.png)

**Key observation:** most fields appear in all 80,192 events (generic metadata), but
`Group`, `IP`, and `Username` appear in **only 4 events**. These are the four records with those
extracted fields; other authentication records could use different fields or remain unparsed.

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

**Verdict on these:** session-disconnect records, with no failed login attempts among them.
The durations and byte counts are compatible with normal work sessions. They do not establish
legitimate ownership of the account or exclude earlier failed attempts or account compromise.

### Step 5 - Visibility check: are failed logins even logged?

Before declaring "no brute-force," confirm we *could* see it. (Absence of evidence is only
evidence of absence if the data source is actually collecting it.)

```
index=botsv3 sourcetype=cisco:asa (113005 OR "authentication rejected" OR "AAA user authentication Rejected") | stats count
```
![auth-specific search returns zero](../hunt-01-bruteforce-images/hunt-01-bruteforce-6.png)

**Result: 0 events matching these failure indicators in the searched ASA data.**

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

**No supporting brute-force pattern observed in the initial web/VPN checks.**

1. **Web login:** zero POST requests on the examined paths; 11 `action=login` GETs and a single `/login.cgi` GET.
2. **VPN:** four extracted user-associated records, all session disconnects; user legitimacy is not established by session duration.
3. **Failed-auth search:** zero `113005` events; the 20,747 "denied" events were connection-level firewall denials, not login failures.

## Visibility gap (the real finding)

The searches found **no ASA failed-authentication records**. Possible explanations include:

- there genuinely were no failed logins, or
- AAA logging is disabled or filtered, records were not forwarded/retained, or the searches
  did not cover the relevant event format or time range.

The actionable output is **unverified failure visibility**. Check ASA logging configuration,
message IDs, forwarding, and retention. In an authorized test environment, generate a failed
and successful login and verify both reach Splunk. The saved searches do not identify which
of these collection or search conditions caused the missing signal.

## Detection idea (deferred)

A brute-force rule cannot be validated from these ASA results alone. Once failure/success
telemetry is verified, a candidate would be:
*alert when a single source produces N failed authentications within a short window, especially
if followed by a success from the same source.*

## Important Notes

- **Status codes lie on login pages.** 200 means "request processed," not "login succeeded."
- **Validate application semantics.** Method and status alone do not prove a credential submission or its outcome.
- **Every sourcetype has its own schema.** `status`/`method` don't exist in `cisco:asa`; its
  success/failure lives inside the raw message and its Cisco message code.
- **Prove visibility before declaring absence.** "No evidence" only means something if the
  data source collects that evidence.
- **Big numbers aren't findings.** Break them down (here: `rex` on message codes) before reacting.
- **A negative or inconclusive result can be useful** when its coverage limits and next actions are explicit.


---

# Part 2 - Closing the Scope Gap: Cloud & Database Layers

The original hunt covered web and VPN authentication and explicitly listed cloud and database
layers as unexamined. This section closes that gap, testing the same hypothesis against
`aws:cloudtrail` and `aws:rds:audit`.

## Recon - authentication in two new sources

**CloudTrail:** 113 distinct API actions across 6,571 events. Authentication = `eventName=ConsoleLogin`.

![CloudTrail eventName inventory](../hunt-01-bruteforce-images/hunt-01-bruteforce-8.png)

A field-parsing problem appeared immediately: `stats count by userName` returned **0 rows despite
4 matching events**. CloudTrail is nested JSON and the AWS TA isn't installed, so the values exist
in raw text but aren't queryable as fields. Workaround: read raw events directly.

![4 events but 0 stats rows](../hunt-01-bruteforce-images/hunt-01-bruteforce-9.png)

**RDS audit:** CSV-like format, not JSON:
```
20180820 14:54:02,ip-10-2-1-63,rdsadmin,localhost,35209,908272,QUERY,mysql,'SELECT ...',0
```
Fields: `timestamp | server | user | source host | connection id | query id | operation | database | query | result_code`

Database authentication = the `CONNECT` operation; success/failure lives in the final
`result_code` (**0 = success, non-zero = failure**).

![RDS audit raw format](../hunt-01-bruteforce-images/hunt-01-bruteforce-10.png)

## Layer 3 - AWS Console logins

```
index=botsv3 sourcetype=aws:cloudtrail eventName=ConsoleLogin | table _time, _raw
```
![ConsoleLogin raw events](../hunt-01-bruteforce-images/hunt-01-bruteforce-11.png)

Only **4 ConsoleLogin events** in the entire dataset. All four: user `bstoll` (the same user seen
in the VPN sessions above), `"ConsoleLogin": "Success"` zero failures, Chrome/Edge user agents,
from `107.77.212.175` (×3, matching his VPN IP) and `157.97.121.132` (×1). Also: `"MFAUsed": "No"`.

These four events show successful console logins without recorded MFA use. They do not show
a brute-force pattern or establish that every relevant authentication event was collected.

## Layer 4 - Database connections

```
index=botsv3 sourcetype=aws:rds:audit CONNECT | stats count by _raw | sort - count | head 20
```
![RDS CONNECT pattern](../hunt-01-bruteforce-images/hunt-01-bruteforce-12.png)

**2,579 CONNECT events were reported in the search.** The displayed sample contains
`result_code = 0`. Because the query ends in `head 20`, it does not establish the result codes
of all 2,579 events. A full aggregation is needed before claiming zero failures.

The raw pattern explains itself: user `frothlyadmin` connecting from internal IPs `172.16.0.127`
and `172.16.0.13` at rigid 30-second intervals (09:04:13, 09:04:43, 09:05:13, 09:05:43…).
The regularity is consistent with an application connection pool, but scheduled malicious
activity can also be regular. Confirm the application/account ownership before assigning intent.

**Proposed full-count check — not yet run in this revision:**

```spl
index=botsv3 sourcetype=aws:rds:audit
| rex field=_raw "^(?:[^,]*,){6}(?<audit_operation>[^,]+),"
| rex field=_raw ",(?<result_code>-?\d+)\s*$"
| where audit_operation="CONNECT"
| eval result_code=coalesce(result_code,"UNPARSED")
| stats count by result_code
```

Check the parser against raw rows, include `UNPARSED` results, and reconcile the total with
the operation inventory. Nonzero codes require interpretation; not every connection error is
a bad-password attempt.

## Final verdict - all four authentication surfaces

| Layer | Sourcetype | Result |
|---|---|---|
| Web application | `access_combined` | No POST on examined paths; application auth behavior not fully validated |
| VPN / firewall | `cisco:asa` | 4 session disconnects; no matching failed-auth records, coverage unverified |
| AWS Console | `aws:cloudtrail` | 4 successful logins, zero failures |
| Database | `aws:rds:audit` | 2,579 CONNECT matches reported; displayed sample successful, full result-code count pending |

**These four checks did not establish a brute-force pattern.** They do not exhaust all
authentication evidence; the Windows and network HTTP checks below extend the investigation.

## Additional security observations

1. **No MFA recorded for the four examined IAM console logins** — `"MFAUsed": "No"`.
   *Recommendation: review and enforce the appropriate MFA policy.* Other access controls were not assessed.
2. **Two source IPs for one user, same day** not suspicious in isolation, but worth an
   "impossible travel" detection while MFA stays off.
3. **Second visibility gap AWS TA missing.** CloudTrail's nested JSON isn't field-extracted, so
   field-based queries silently return nothing. Combined with the ASA failed-auth gap above, this
   environment has **two significant authentication blind spots**.

## Detection idea (database layer)

A database rule is a candidate once the parser and failed-login telemetry are validated:
*alert when a single source produces N `CONNECT` events with non-zero `result_code` in a short
window, especially if followed by a `result_code=0` from the same source.*

## Additional lessons

- **Every data source encodes "login" differently.** Web = POST to a login endpoint; VPN = ASA
  message codes; CloudTrail = `eventName=ConsoleLogin` + `responseElements`; database = `CONNECT`
  + `result_code`. Same hypothesis, four translations. Learning each source's own language *is* the job.
- **Events > 0 but stats = 0 can indicate missing grouping fields.** Inspect raw JSON and its
  field paths; nested fields may need `spath` or corrected add-on configuration.
- **Rhythm suggests automation, not intent.** Confirm ownership and purpose of regular activity.
- **Samples and totals answer different questions.** Use full aggregation to make claims about
  every event; retain samples to explain the format.


## Layers 5 & 6 - Windows and network-level HTTP (closing the last gaps)

The scope section originally listed two unexamined surfaces. Both were subsequently checked.

**Windows authentication** the environment *does* collect Windows security logs
(`wineventlog:security`, 46,469 events; plus `winhostmon` and Sysmon):

```
index=botsv3 sourcetype=wineventlog:security (EventCode=4625 OR EventCode=4624) | stats count by EventCode
```

| EventCode | Meaning | Count |
|---|---|---|
| 4624 | Successful logon | 427 |
| 4625 | **Failed logon** | **3** |

![Windows logon success vs failure](../hunt-01-bruteforce-images/hunt-01-bruteforce-13.png)

Three failed logons were found in this search. That count alone does not establish brute-force
or ordinary user typos. Inspect target accounts, source addresses, logon types, failure codes,
and timestamps. Their presence confirms some failure telemetry, not complete Windows coverage.

**Network-level HTTP POSTs** - `stream:http` does contain POSTs that `access_combined` didn't show:

```
index=botsv3 sourcetype=stream:http | stats count by http_method
```
GET 9,908 · POST 261 · HEAD 43 · PROPFIND 2

![stream:http method distribution](../hunt-01-bruteforce-images/hunt-01-bruteforce-14.png)

Reviewing where those 261 POSTs go (`stats count by site, uri_path`), they are ordinary web
activity: forum posting (`newthread.php`), form submissions, third-party sites. No concentration
of POSTs against a login endpoint.

**Six surfaces were examined without establishing a brute-force pattern.** Coverage and
outcome-verification limits remain.

## Scope & limitations (full hunt)

This report covers web application, VPN, AWS Console, database, Windows, and network-level HTTP
checks. It does not prove exhaustive endpoint discovery, complete collection, or the absence of
low-volume/distributed password attacks. Other sources may supply corroborating evidence.
The revised RDS query and deferred detections require a rerun with explicit time bounds and
recorded field-extraction coverage. No new search results are claimed here.
