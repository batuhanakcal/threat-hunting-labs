# Hunt #03 DNS Baseline Hunt: Investigating Suspected C2

**Type:** Baseline hunt (PEAK) → suspected incident for investigation
**Environment:** Splunk BOTS v3 (Frothly), all-time
**Threat Hunter:** Batuhan Akcal
**Status:** Suspected C2 identified; compromise mechanism and exfiltration unconfirmed

## Executive assessment

Combining domain-label length, suffix-group cardinality, and rarity reduced 5,063 domains to
15 candidates. DNS and HTTP pivots linked one candidate to suspicious traffic on `PCERF-L`.
The domain name, OAuth-like paths, and outbound byte counts support a high-priority C2
investigation. They do not independently establish an exploit, a C2 framework, or stolen data.

**Confidence:** Suspicious network activity is documented; C2 is an analytic assessment.
The proposed drive-by chain and exfiltration require corroboration.
**Time scope:** Original discovery used **All time**. The working timeline concerns
2018-08-20, approximately 11:00–11:18 in the original Splunk display timezone, which was not
recorded for this hunt. Exact source coverage and UTC normalization remain to be captured.
**Validation:** Original screenshots are retained. Revised queries below are proposed and
have not been rerun against BOTS v3. See the [validation record](../validation-notes.md).

---

## Why a baseline hunt

Hunts #01 and #02 were hypothesis-driven: I started with a threat technique or a specific
observation and tested it. This hunt used PEAK's second type, **baseline hunting**, where you
start with no target at all. You characterize what "normal" looks like in a dataset, then hunt
whatever fails to fit.

DNS was chosen deliberately:
- **High volume** (218,456 events) enough data for statistics to mean something
- **Useful coverage** many applications resolve names, making DNS a valuable source of leads
- **Known limits** direct-IP connections, cached answers, alternative resolvers, and encrypted
  DNS can bypass the collected DNS view; absence from these logs does not rule out C2

No IOC list, no threat intel feed, no alert. Just: *what is normal here, and what isn't?*

---

## Phase 1: Data dictionary

```
index=botsv3 sourcetype=stream:dns | fieldsummary | table field count
```

![stream:dns fieldsummary](../hunt-03-dns-images/hunt-03-dns-1.png)

46 fields across 218,456 events. The ones that matter for hunting:

| Field | Meaning | Why it matters |
|---|---|---|
| `src_ip` | Querying host | Primary baseline dimension |
| `query{}` | Domain requested | The core artifact |
| `query_type{}` | Record type (A, AAAA, TXT…) | Record-type distribution can provide leads |
| `reply_code` | NoError / NXDOMAIN | Repeated failures merit review; DGA and benign misconfiguration are possible explanations |
| `bytes`, `bytes_in/out` | Byte counters | Validate collection semantics before interpreting size or direction |

Note: fields ending in `{}` are **multi-value** a single DNS event can carry several
queries/answers, stored as an array.

## Phase 2: Establish normal

**Host distribution** (16 hosts, two natural groups):

| Group | Hosts | Query volume |
|---|---|---|
| Servers | mars, gacrux×4, matar, hoth, ip-172-16-0-109 | 5,000–32,000 |
| User laptops | BSTOLL-L, BTUN-L, PCERF-L, MKRAEUS-L, JWORTOS-L, ABUNGST-L, FYODOR-L | 7,000–15,000 |
| Outlier | **ntesla** | **1** |

![DNS volume by host](../hunt-03-dns-images/hunt-03-dns-2.png)

These groups motivate separate baselines; 30,000 queries alone does not establish normal or
abnormal behavior for either group. Normalize by collection duration and host role.
(`ntesla` with a single query was noted and parked; its coverage remains unverified.)

**Domain distribution** 5,063 unique domains, 176,831 queries. A classic long tail:

```
splunk.froth.ly                    130,946   ← 74% of all traffic
polaris...rds.amazonaws.com          4,704
sv5dc01.splunk.local                 2,304
wpad.localdomain                     1,683
_ldap._tcp...splunk.local            1,664
```

The dominant names are consistent with infrastructure services such as Splunk, AD/LDAP, WPAD,
and AWS. They establish context, not a certified clean baseline. The difference between
218,456 events and 176,831 queries in the saved distribution also needs reconciliation of
filters, nulls, and multivalue handling before those counts are treated as interchangeable.

## Phase 3: Hunt the anomaly

Three angles were applied to the same data. The first two did not identify a convincing
tunneling lead; the third produced a candidate for further investigation.

**a) Domain length** DNS tunneling encodes data into subdomains, inflating name length.
Median 25 chars, max 75. The longest entries were `ip6.arpa` reverse lookups and mDNS printer
names, all legitimate. **No tunneling signature.**

**b) Subdomain cardinality** tunneling's second signature: hundreds of random subdomains under
one registered domain.

| Registered domain | Distinct subdomains |
|---|---|
| in-addr.arpa | 2,731 (reverse DNS normal) |
| outlook.com | 161 |
| froth.ly | 70 |

No convincing tunneling pattern emerged from this summary. Low-volume tunneling is not ruled out.

**c) Rare, isolated long subdomains** This is what produced the finding. Sorting by rarity alone
wasn't enough: the tail is dominated by hundreds of single-occurrence reverse-DNS and CDN names,
and the candidate sat several hundred rows down. Three weak signals had to be combined, none of
which is suspicious on its own:

- **A long subdomain label** (≥20 characters). Random or machine-generated names are long;
  legitimate hostnames tend to be short and readable.
- **An isolated registered domain** (≤3 distinct subdomains observed). Real CDNs, analytics
  platforms and cloud services produce dozens or hundreds of subdomains. A long random label
  under a domain that appears almost nowhere else is a different shape entirely.
- **Low query volume** (<10). This focuses on the rare tail; both legitimate services and
  malicious activity can be rare or frequent.

```
index=botsv3 sourcetype=stream:dns
| stats count by query{}
| rename query{} as domain
| where NOT match(domain,"(arpa|local)$")
| rex field=domain "^(?<label>[^.]+)\."
| rex field=domain "(?<regdom>[^.]+\.[^.]+)$"
| eventstats dc(domain) as sub_count by regdom
| where len(label)>=20 AND sub_count<=3 AND count<10
| sort count
| table domain, count, sub_count
```

The first `rex` extracts the first label. The second extracts the last two labels
(`igg.biz` here), used as an approximate suffix group. Despite its name, `regdom` is **not a
general registered-domain parser**: for example, `co.uk` needs public-suffix-aware handling.
`eventstats` attaches the distinct-name count within each group in the searched data.
That count depends on coverage and is a prioritization feature, not proof of service legitimacy.

The recorded thresholds were label length ≥20, ≤3 distinct names per suffix group, and <10
queries. The saved result documents 15 candidates; it does not document a threshold sweep,
recall measurement, or independent validation. Record those before claiming that tuning kept
all relevant candidates. This query does not calculate entropy.

**5,063 domains reduced to 15 rows:**

![rare isolated long subdomains](../hunt-03-dns-images/hunt-03-dns-3.png)

Most of the 15 are explainable: Shopify storefronts, Firebase instances, WPEngine CDN nodes,
moatpixel ad infrastructure. One is not:

```
microsoftexchangeservervwu2g8sj20.igg.biz     3 queries
```

Suspicious on two independent grounds:
1. **Brand-like naming** `microsoftexchangeserver` followed by a random-looking suffix,
   consistent with an attempt to resemble Microsoft infrastructure.
2. **Unexpected suffix** the name is under `igg.biz`, rather than a domain established as
   approved Microsoft infrastructure in this analysis. Provider cost or registration identity
   requirements were not verified and are not used as evidence of maliciousness.

And only **3 queries** out of 176,831. No blocklist was involved; the domain surfaced purely
because its *shape* and *rarity* didn't fit the environment.

## Phase 4: Validate the anomaly

```
index=botsv3 sourcetype=stream:dns "igg.biz" | table _time, src_ip, query{}, reply_code, dest_ip
```

![suspicious domain DNS resolution](../hunt-03-dns-images/hunt-03-dns-4.png)

| Attribute | Value |
|---|---|
| Source | **172.16.197.137** (host `PCERF-L`, a user laptop) |
| Resolved to | **31.22.4.67 / 31.22.4.68** |
| Name servers | `ns1.byethost15.org`, `ns2.byethost15.org` |
| Reply code | **NoError** recorded in the historical lookup; this does not establish current availability |

The branding and hosting-related names make this a useful review candidate. Validate the
response's answer records: `dest_ip` can identify the DNS resolver rather than the IP returned
for the queried name. The saved report records two resolved addresses; preserve the raw answers
when rerunning this check.

## Phase 5: Eliminate the false positive

Pivoting to `PCERF-L` surfaced Symantec endpoint data: 419 behavior events, **18 marked
"Blocked"**, including:

```
[AC7-2.1] Block scripts - Caller MD5=bf01cb424cafaf985bcca2a26aa48cd4
```

A blocked script on the same host as a suspicious C2 lookup looks like a smoking gun. It wasn't.
Searching the hash across the whole index:

```
index=botsv3 "bf01cb424cafaf985bcca2a26aa48cd4"
```

The hash belongs to **`splunkd.exe`**, and the "blocked scripts" were Splunk's own collectors:
`win_installed_apps.bat`, `win_listening_ports.bat`, `perfmon.cmd`, `winEventLog.cmd`. 1,543
occurrences. This also explained the `wmic os get LocalDateTime` / `reg query …Uninstall` volume
in Sysmon Splunk_TA_windows inventory scripts, not reconnaissance.

**Verdict on this lead: operational noise, not an attack.** Symantec's script-blocking policy is
interfering with Splunk's data collection a real operational finding, but a separate one.

> **Lesson:** "Blocked" is not a synonym for "threat stopped." Escalating on a status label
> without identifying *what* was blocked is a classic triage failure.

## Phase 6: Move to the HTTP layer

DNS shows what was *asked for*; HTTP shows what was *done*. This is where the hunt broke open.

```
index=botsv3 host=PCERF-L sourcetype=stream:http (igg.biz OR 31.22.4.67)
| table _time, site, uri_path, http_method, bytes_out, bytes_in | sort _time
```

![C2 HTTP session](../hunt-03-dns-images/hunt-03-dns-5.png)

```
11:09:43  GET  /                                             563 out
11:09:47  GET  /cgi-bin/                                     561 out
11:09:49  GET  /favicon.ico                                  552 out
11:09:50  GET  /.well-known/                                 570 out
11:09:53  GET  /oauth/                                       672 out
11:09:55  GET  /oauth/RequestVerificationToken=pmiXqCa…   15,249 out
11:10:18  POST /oauth/RequestVerificationToken=pmiXqCa…   12,280 out
11:10:18  GET  /oauth/RequestVerificationToken=pmiXqCa…   24,669 out
11:10:24  GET  /oauth/RequestVerificationToken=pmiXqCa…      276 out
```

Three observations supporting investigation:

1. **Rapid requests to several paths**, including `/cgi-bin/`, `/.well-known/`, `/oauth/`,
   and `/favicon.ico`. This may reflect automated requests, but browsers also fetch paths
   automatically. The sequence is not a validated C2-framework fingerprint.
2. **OAuth-like paths** containing `RequestVerificationToken=` and opaque strings on the
   suspicious domain. These justify inspecting request/response content and application context.
3. **24,669 reported outbound bytes on a GET.** This is an anomaly worth inspecting. Large
   URLs, headers/cookies, sensor accounting, and payload behavior are alternative explanations.

The table is a selected excerpt from the screenshot, not a complete transfer accounting.
The original ~53 KB total is not retained as a measured finding: the listed rows and broader
screenshot need reconciliation. Byte counters alone do not identify stolen content or prove
exfiltration. Inspect raw records, direction semantics, duplicates, and missing counters first.

## Phase 7: Scope and attribution

**Scope** the saved indicator-based search points to one endpoint:

```
index=botsv3 (31.22.4.67 OR "igg.biz" OR 172.81.134.220 OR lightbodyfatburn)
| stats count by host, sourcetype
```

| Host | Sourcetype | Count |
|---|---|---|
| PCERF-L | stream:http / dns / tcp / ip | 75 |
| SEPM | symantec:ep:packet:file | 46 (log relay for PCERF-L) |
| splunkhwf.froth.ly | syslog | 8 (log relay) |

`SEPM` and `splunkhwf` are collectors reporting about `PCERF-L`. Splunk's `host` field can
identify the relay rather than the origin. This IOC search does not rule out lateral movement,
other infrastructure, uncollected hosts, or connections to the second resolved IP `31.22.4.68`.

**Process attribution** Sysmon should answer "which program made this connection" (EventID 3):

The original notes report no matching connection attribution, but also five EventID 3 records
among 744 Sysmon events. Those counts do not establish that network logging was disabled.
Filtering, collection time, extraction, and query scope need review. The original abbreviated
sourcetype contained an ellipsis and should not be copied as an exact match.

**Proposed source/field discovery — not yet run:**

```spl
index=botsv3 host=PCERF-L (source="*Sysmon*" OR sourcetype="*Sysmon*")
| stats count by source sourcetype
```

Inspect raw XML and the actual event-ID field before narrowing to EventID 3 and the destination
IPs. Check collection/configuration in the relevant period. Sysmon EventID 3 is configurable
and disabled by default; the observed counts alone do not establish this host's configuration.
[Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

Symantec filled the gap instead:
```
Remote: 172.81.134.220, lightbodyfatburn.net, 443, Outbound,
Application: C:/Windows/SystemApps/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/MicrosoftEdge…
```

![Symantec traffic log showing process](../hunt-03-dns-images/hunt-03-dns-6.png)

The shown Symantec record associates the connection to `172.81.134.220` with
**`MicrosoftEdge.exe`** and records **Allowed**. This helps attribute that connection; it does
not automatically attribute every `igg.biz` request to the same process. An allowed connection
is not proof that the product recognized C2 and failed to enforce a block. Review policy mode,
detection evidence, and process/time correlation before assigning a control failure.

> **Lesson:** different sources give different visibility. Sysmon was blind here; Symantec wasn't.
> Never rely on a single telemetry source to answer a single question.

## Phase 8: Reconstruct the chain (referrers)

The `http_referrer` field can suggest how requests are related. Ordering suspicious traffic
produced a working hypothesis for the browsing sequence; absent referrers and temporal proximity
do not prove a redirect or exploit. The original narrow-window query was:

```
index=botsv3 host=PCERF-L sourcetype=stream:http
(mans-alliance OR lightbodyfatburn OR igg.biz OR platinum-casino)
earliest="08/20/2018:11:07:00" latest="08/20/2018:11:11:00"
| table _time, site, uri_path, http_referrer | sort _time
```

The 11:07–11:11 query covers the initial pivot only. The table below also contains earlier and
later observations from the investigation notes, so it cannot be reproduced by that query
alone. A revised full-window query follows the table. Confirm the original display timezone
before using these literal search times.

![referrer chain - compromise window](../hunt-03-dns-images/hunt-03-dns-7.png)

| Time | Site | Path | Referrer |
|---|---|---|---|
| 11:00:42 | schuetze-consult.de | /images, /right.gif | - (ordinary browsing) |
| 11:07:39 | www.mans-alliance.com | /store/index.php | **bing.com** (legitimate search) |
| **11:08:35** | **www.mans-alliance.com** | **/vorcnrid/yp1mn.ya6** | mans-alliance.com/store |
| **11:08:35** | **lightbodyfatburn.net** | / | - |
| 11:09:43 | igg.biz | / → /cgi-bin/ → /oauth/ | - |
| 11:10:18 | igg.biz | /oauth/RequestVerificationToken=… | Not recorded in this summary |
| 11:13:20 | lightbodyfatburn.net | / | Not recorded in this summary |
| 11:14:06 | platinum-casino.ru | **/zver/sysfiles/bo** | - |
| 11:15:22 | igg.biz | /oauth/RequestVerificationToken=… | Not recorded in this summary |
| 11:17:31 | platinum-casino.ru | /sver.sysfiles/bo | - |

The site label `igg.biz` abbreviates the full suspicious hostname in this table. Referrer cells
describe what the notes retained; labels such as "beacon" or "C2" are interpretations and
must not be inserted as if they were literal referrer values.

**Proposed full-window query — not yet run:**

```spl
index=botsv3 host=PCERF-L sourcetype=stream:http
(mans-alliance OR lightbodyfatburn OR igg.biz OR platinum-casino OR schuetze-consult.de)
earliest="08/20/2018:11:00:00" latest="08/20/2018:11:18:00"
| table _time site uri_path http_referrer http_method bytes_out bytes_in
| sort 0 _time
```

**11:08:35 is a transition of interest, not a proven compromise timestamp.** The notes show
a Bing referrer leading to `mans-alliance.com`, a request to `/vorcnrid/yp1mn.ya6`, and contact
with `lightbodyfatburn.net` in the same second. Benign page resources and redirects must also
be considered; the path's appearance alone does not establish exploitation.

The sequence is **consistent with a possible drive-by chain**. The saved evidence does not
include the alleged injected script, exploit payload, or process execution that would confirm
the mechanism. The `platinum-casino.ru` paths are additional investigation leads; folder names
do not establish malware family, stage, or actor attribution.

The `piwik.alesco-concepts.com` request is compatible with analytics. No malicious role for it
is established in this report.

---

## Verdict

**Suspected C2 activity on `PCERF-L` warrants investigation.**

The DNS candidate, HTTP path sequence, and unusually large outbound counters make this a
high-priority lead. The proposed drive-by entry path is plausible, but the available evidence
does not confirm an exploit, the exact compromise time, or the content and volume of exfiltrated
data. Requests to the suspicious infrastructure recur later in the session.

The indicator-based search links the activity to one endpoint. It is not a lateral-movement
assessment. The shown Symantec record supplies process attribution for one related connection
and an Allowed disposition; policy enforcement effectiveness still needs assessment.

## MITRE ATT&CK mapping

| Technique | Assessment | Additional evidence needed |
|---|---|---|
| [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189/) | Possible entry mechanism | Redirect/script content, exploit evidence, or correlated execution |
| [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | Candidate mapping for suspected HTTP C2 | Request/response or endpoint evidence establishing command/control use |
| [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Unconfirmed hypothesis | Evidence that data was stolen and transferred over the C2 channel |

T1568.002 (DGA) is not assigned: one random-looking suffix does not establish algorithmic
domain generation. See the [MITRE definition](https://attack.mitre.org/techniques/T1568/002/).

## Findings summary

| Finding | Assessment / priority |
|---|---|
| Suspicious DNS/HTTP activity on PCERF-L | High investigation priority; C2 assessment requires corroboration |
| Large outbound counters, including 24,669 bytes on a GET | Inspect content and counter semantics; exfiltration amount unconfirmed |
| Related Symantec connection marked Allowed | Policy and connection correlation review; detection failure not established |
| Missing Sysmon attribution for connections of interest | Verify query, fields, coverage, and configuration |
| Blocked collector-related scripts | Investigate effect on collection; 1,543 hash matches are not 1,543 confirmed blocks |

## Recommendations

For a live incident with equivalent evidence, escalate promptly and consider containment under
the organization's response procedure while preserving evidence. This report concerns a
historical lab dataset.

1. Correlate exact process instances, HTTP records, DNS answers, and endpoint artifacts.
2. Inspect response content, browser/process activity, and redirect evidence to test the
   proposed drive-by mechanism before assigning a precise compromise timestamp.
3. Validate byte direction, missing values, and duplicate accounting; inspect content before
   reporting exfiltration or a stolen-data total.
4. Review matching Symantec policy and alerts, including whether the connection was recognized
   as malicious. An Allowed network record alone does not answer that question.
5. Verify Sysmon network-event configuration, filtering, forwarding, and extraction. Tune
   EventID 3 collection to investigation needs and volume; other telemetry can also attribute
   network activity to processes.
6. Review the Splunk collector blocks with the endpoint-policy owner. Confirm collector
   integrity before making narrow policy changes.
7. Scope all observed addresses and domains, including `31.22.4.68`, then examine host behavior
   beyond those indicators. Review business impact and present-day ownership before blocking
   shared infrastructure or an entire DNS suffix.

## Candidate detections — revised queries pending validation

These queries produce review leads. No production false-positive rate or detection coverage is
claimed. Record the time range, field coverage, result count, inspected benign examples, and
known-positive matches using the [validation record](../validation-notes.md).

### Rule 1: Brand-like label under a reviewed DNS suffix

This rule is derived from the investigation. The initial discovery query in Phase 3 used
length, cardinality, and rarity instead of known brand strings.

```spl
index=botsv3 sourcetype=stream:dns
| mvexpand query{}
| eval domain=lower(rtrim('query{}',"."))
| rex field=domain "^(?<label>[^.]+)\.(?<suffix>.+)$"
| where match(label,"(microsoft|exchange|office|outlook|windows|google|amazon)")
  AND suffix="igg.biz"
| stats count as expanded_rows values(src_ip) as source_ips by domain
```

The suffix is deliberately scoped to this lab lead. Maintain an explicitly reviewed list if
generalizing it. Name shape alone does not establish an attack. After `mvexpand`, row counts
are not necessarily unique DNS transaction counts.

### Rule 2: Outbound-heavy GET requests

```spl
index=botsv3 sourcetype=stream:http http_method=GET
| eval outbound=tonumber(bytes_out), inbound=tonumber(bytes_in)
| where isnotnull(outbound) AND isnotnull(inbound)
| eval ratio=outbound/(inbound+1)
| where outbound>5000 AND ratio>3
| stats count as matching_records sum(outbound) as recorded_outbound_bytes
  values(uri_path) as paths by src_ip site
```

The `+1` is a denominator guard, not a protocol model. Confirm direction semantics, quantify
missing counters separately, and inspect URLs/headers/cookies and normal application traffic.
Summed sensor counters must not be labeled stolen-data volume. The thresholds are starting
points, not measured operating characteristics.

### Rule 3: Distinct-path review lead

```spl
index=botsv3 sourcetype=stream:http
| bin _time span=1m
| stats dc(uri_path) as distinct_paths values(uri_path) as paths by src_ip site _time
| where distinct_paths>=5
```

One ordinary page load can fetch five or more paths through CSS, JavaScript, images, and API
requests. This threshold is **not a standalone automation or C2 detector**. Inspect paths,
request outcomes, application behavior, and session context before escalation. Compare a
benign browsing sample and the suspicious sequence, then document any filtering/tuning.

## Important Notes

- Combining weak features made a large domain list manageable; none of the features establishes
  maliciousness on its own.
- Preserve failed leads and their resolution. The collector investigation helped avoid
  treating every Blocked event as a stopped threat.
- Distinguish a domain-resolution event, a network connection, a process attribution, and proof
  of compromise. A link at one layer does not automatically establish all the others.
- A referrer can support a sequence, but missing values and nearby timestamps do not prove
  an exploit chain.
- Candidate rules and historical observations have different validation status. Revised SPL
  needs a rerun before its outputs or effectiveness can be claimed.
