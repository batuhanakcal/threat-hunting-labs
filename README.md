# Threat Hunting Labs

Threat hunting on the Splunk **Boss of the SOC v3 (BOTS v3)** dataset, documented using the
**PEAK** framework. Each report records the question, queries, observations, alternative
explanations, and the reasoning behind the next pivot. Findings include suspicious activity,
telemetry limitations, and candidate detections.

**Author:** Batuhan Akcal · Cyber Security Engineer

**Environment:** Splunk Enterprise (local), BOTS v3 dataset ~2M events, 100+ sourcetypes

**Methodology:** [PEAK](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html)
(Prepare · Execute · Act with Knowledge) + ABLE scoping

## Hunts

### [Hunt #01 Brute-Force Authentication](hunts/hunt-01-brute-force.md)

**Type:** Hypothesis-driven · **Result:** No supporting pattern observed; visibility limited

Examined six authentication surfaces: web application, VPN, AWS Console, database, Windows,
and network-level HTTP. Each source encodes authentication differently, so the investigation
starts by identifying its fields and success/failure semantics.

The searches did not establish a brute-force pattern. No ASA failed-authentication records
were found, which leaves VPN failure visibility unverified. CloudTrail also exposed a field
extraction problem. These limitations prevent treating the negative result as proof that no
attack occurred. The four examined IAM console logins recorded no MFA use.

### [Hunt #02 Public S3 Bucket Exposure](hunts/hunt-02-s3-public-bucket-exposure.md)

**Type:** Pivot-led · **Result:** Public ACL grants observed; access impact needs validation

A command in `bash_history` led to a filename pivot across 19 sourcetypes. S3 access logs
contained 17 object GET requests, seven with an anonymous requester. Six of those seven came
from IPs also seen using a Frothly EC2 role; anonymous identity alone does not establish an
external actor or a successful download.

CloudTrail recorded public `READ` and `WRITE` bucket ACL grants and their removal
**56 minutes 8 seconds** later. Bucket `READ` permits listing; object download permissions
need separate verification. The report distinguishes the confirmed ACL change from unresolved
questions about successful access, the `OPEN_BUCKET_PLEASE_FIX.txt` key, and possible changes
to deployment artifacts. It includes follow-up queries for that validation.

### [Hunt #03 DNS Baseline Suspected C2](hunts/hunt-03-dns-baseline-c2-discovery.md)

**Type:** Baseline · **Result:** Suspected C2 requiring investigation · **Priority:** High

Started with 218,456 DNS events and the question: "What is normal here?" Combining label
length, low subdomain cardinality, and low query count reduced 5,063 domains to 15 candidates.
One candidate, `microsoftexchangeservervwu2g8sj20.igg.biz`, appeared in three queries.

DNS, HTTP, and endpoint pivots linked suspicious browser traffic to `PCERF-L`. HTTP records
showed unusually large outbound byte counts and OAuth-like paths. Those observations support
a C2 investigation; they do not establish the content or amount of stolen data. The referrer
timeline suggests a possible drive-by chain, with the exact compromise mechanism unconfirmed.

The investigation also separated Splunk collector activity from a misleading endpoint alert
and documented limited Sysmon process attribution for the connections of interest.

## Engineer detections

These are investigation queries and detection proposals. Production scheduling, independent
validation, and measured false-positive rates are not yet documented. Newly revised queries
are marked as pending validation in the reports.

| Engineer | Source | Signal and qualification |
|---|---|---|
| Repeated authentication failures | Hunt #01 | Deferred until failure logging and field extraction are verified |
| Public bucket ACL grant | Hunt #02 | Successful `PutBucketAcl` with an `AllUsers` grant; policy changes require a separate review |
| Successful anonymous object access | Hunt #02 | Anonymous requester plus object operation and successful HTTP response |
| Brand-like label under a reviewed DNS suffix | Hunt #03 | Review lead; domain shape alone does not establish maliciousness |
| Outbound-heavy GET | Hunt #03 | Byte-volume and direction anomaly; inspect headers, payload, and normal application behavior |
| Distinct paths within a minute | Hunt #03 | Exploratory lead; ordinary page assets can also meet the threshold |

## Reading and reproducing the work

The reports preserve the original query outputs and screenshots. Most discovery searches used
the Splunk **All time** picker against historical BOTS v3 data. Exact per-source coverage and
the Splunk/add-on versions were not captured in the original notes; these remain reproduction
gaps. Each report states its time and evidence limitations, and a [validation checklist](validation-notes.md)
records what a rerun needs to capture. No new Splunk results are claimed for revised queries.

## Reference notes

- **[spl-notes.md](spl-notes.md)** — personal SPL reference: what each query does and when to use it.
- **[stats-family-explained.md](stats-family-explained.md)** — grouping, fixed baselines, and running baselines.
- **[peak-framework-notes.md](peak-framework-notes.md)** — hunt types, ABLE scoping, and methodology notes.
- **[endpoint-lab-notes.md](endpoint-lab-notes.md)** — endpoint pipeline setup and preliminary validation notes for future hunts; a separate Hunt #04 report has not yet been written.
