# Threat Hunting Labs

Hypothesis-driven threat hunting on the Splunk **Boss of the SOC v3 (BOTS v3)** dataset,
documented end-to-end using the **PEAK** framework.

Each hunt starts from a question, not an alert, not an IOC list, and is written up with the
queries, the evidence, the false leads, and the reasoning behind every decision. Negative results
are documented as thoroughly as positive ones, because in real hunting most hypotheses don't pan
out, and knowing *why* they didn't is the point.

**Author:** Batuhan Akcal · Cyber Security Engineer
**Environment:** Splunk Enterprise (local), BOTS v3 dataset ~2M events, 100+ sourcetypes
**Methodology:** [PEAK](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html) (Prepare · Execute · Act with Knowledge) + ABLE scoping

---

## Hunts

### [Hunt #01 Brute-Force Authentication](hunts/hunt-01-brute-force.md)
**Type:** Hypothesis-driven · **Result:** Hypothesis disproved · **Finding:** visibility gaps

Tested for brute-force activity across **six authentication surfaces**: web application, VPN,
AWS Console, database, Windows, and network-level HTTP. Each source encodes "login" differently
(POST requests, ASA message codes, `ConsoleLogin` events, `CONNECT` + result codes, EventID
4624/4625), so each required learning its own semantics before it could be hunted.

No brute-force found. The value came from what the elimination exposed: **failed authentication
is not logged at all on the ASA**, and CloudTrail's nested JSON isn't field-extracted (AWS TA
missing), two blind spots that would hide a real attack. Also flagged: no MFA on IAM console
logins.

---

### [Hunt #02 Public S3 Bucket Exposure](hunts/hunt-02-s3-public-bucket-exposure.md)
**Type:** Pivot-led · **Result:** Confirmed finding · **Severity:** integrity risk

Started from a single command in `bash_history,` an archive was being pushed to S3. Pivoting on the
*filename* (rather than an IP) across 19 sourcetypes led to the S3 access logs, where **7 of 17
downloads had no authenticated identity**.

CloudTrail supplied the cause: an IAM user granted `AllUsers` the public internet both **READ
and WRITE** on the bucket, from an MFA-unauthenticated session, and revoked it 56 minutes later.
Inside that window, someone outside the organization wrote a file into the bucket named
**`OPEN_BUCKET_PLEASE_FIX.txt`**, proving the write grant was exploitable.

The severity here is integrity, not confidentiality: write access to a deployment bucket is a
supply chain risk: the web archive could have been replaced with a malicious version.

---

### [Hunt #03 DNS Baseline → C2 Discovery](hunts/hunt-03-dns-baseline-c2-discovery.md)
**Type:** Baseline · **Result:** Malicious activity confirmed · **Severity:** High

No target, no IOCs, just 218,456 DNS events and the question: "What is normal here?"* After
profiling host volumes and domain distribution, three anomaly techniques were applied: domain
length, subdomain cardinality, and **entropy**. The first two came back clean. Entropy surfaced a
single domain seen **3 times out of 176,831 queries**:

```
microsoftexchangeservervwu2g8sj20.igg.biz
```

A Microsoft-impersonating name on free dynamic DNS. Following it through HTTP revealed an active
**C2 channel disguised as OAuth token exchange**, with ~53 KB exfiltrated, including 24 KB
outbound on a single GET request. Referrer analysis reconstructed the full chain back to the
moment of compromise: a **drive-by** from a legitimate e-commerce site reached via Bing search.

Symantec saw the C2 sessions and logged them as **Allowed**. Sysmon couldn't attribute the
process because network logging (EventID 3) was effectively disabled.

---

## Detections developed

Hunts produce detections, not just reports. Rules built and threshold-tested against real data:

| Rule | Source | Signal |
|---|---|---|
| Auth-surface enumeration | Hunt #01 | High distinct-parameter count on login pages from one actor, non-browser UA. Tuned across four iterations (v1→v4) with TP/FP analysis at each step. |
| Public bucket grant | Hunt #02 | `PutBucketAcl` / `PutBucketPolicy` containing `AllUsers` near-zero false positives |
| Anonymous S3 object access | Hunt #02 | Empty requester field on corporate buckets |
| Brand impersonation on disposable DNS | Hunt #03 | Known brand string + free dynamic-DNS TLD |
| Outbound-heavy GET | Hunt #03 | `bytes_out / bytes_in > 3` a GET should download, not upload |
| Path probing | Hunt #03 | ≥5 distinct paths on one site within a minute = automation |

---

## Reference notes

- **[spl-notes.md](spl-notes.md)** - personal SPL reference: each query with what it does and *when it should come to mind*
- **[stats-family-explained.md](stats-family-explained.md)** - `stats` vs `eventstats` vs `streamstats`: fixed vs flowing baselines
- **[peak-framework-notes.md](peak-framework-notes.md)** - PEAK's three hunt types, the ABLE scoping model, and how to fill it in
- **[endpoint-lab-notes.md](endpoint-lab-notes.md)** - Created endpoint labs for new hunts.
