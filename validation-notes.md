# Validation and reproduction notes

The revised reports distinguish original observations from proposed checks. This page records
what is still needed to reproduce or validate the queries. It does not report completed reruns.

## Environment and coverage record

Record the BOTS v3 distribution used, Splunk Enterprise version, relevant add-on names/versions,
index names, extraction configuration, and search timezone. The original notes do not supply
all of these. Preserve raw event timestamps alongside displayed times.

For a coverage inventory, set the intended time range explicitly and run:

```spl
index=botsv3
| stats count as events min(_time) as earliest_epoch max(_time) as latest_epoch by sourcetype
| eval earliest_display=strftime(earliest_epoch,"%Y-%m-%dT%H:%M:%S%z"),
       latest_display=strftime(latest_epoch,"%Y-%m-%dT%H:%M:%S%z")
| table sourcetype events earliest_epoch latest_epoch earliest_display latest_display
```

Keep epoch values for unambiguous comparison. Earliest/latest events show observed coverage,
not proof of uninterrupted collection. Examine gaps and compare raw timestamp offsets with
parsed `_time`; document any source-specific offset or parsing correction.

## Evidence and query status

| Item | Existing evidence | Required next validation |
|---|---|---|
| Hunt #01 authentication review | Saved counts and screenshots | Verify failure visibility, application semantics, and exact source coverage |
| Hunt #01 RDS result-code aggregation | Original query showed a top-20 sample | Run revised full aggregation, inspect unparsed rows, and reconcile counts |
| Hunt #02 public ACL changes | Raw CloudTrail screenshot with UTC eventTime | Verify effective permissions, event success, and changes outside the two shown events |
| Hunt #02 successful anonymous operations | Requester/operation counts, without response outcomes | Run response-aware parser; inspect status, bytes, raw timestamps, request IDs, ownership, and warning-file PUT |
| Hunt #02 ACL/policy detection candidates | Revised SPL only | Verify nested field extraction, failed API calls, approved public access, and policy condition handling |
| Hunt #03 rarity/shape discovery | Original 15-row candidate result | Record full candidate dispositions and threshold comparison; confirm suffix handling and denominator counts |
| Hunt #03 suspected C2 and browser sequence | Saved DNS/HTTP/Symantec evidence | Correlate exact processes, request/response content, counters, and full time window |
| Hunt #03 revised candidates | Revised SPL and explicit limitations | Measure benign matches, positive examples, missing-field coverage, and operational volume |
| SPL running-baseline examples | Historical 3.3x observation from old query | Rerun `current=f` example; account for warm-up rows, missing hours, and zero baselines |

## Record for each detection candidate

For each run, preserve:

1. Query text/version, dataset, earliest/latest bounds, timezone, and sampling settings.
2. Input event count and field/parser coverage, including null/unparsed rows.
3. Result count, inspected examples, and why each reviewed result is benign, suspicious, or unresolved.
4. Known-positive coverage and missed examples where labels exist. A small lab sample does not
   establish general recall or production effectiveness.
5. Candidate threshold, alternatives considered, and the effect of each change on results.
6. Proposed schedule/lookback, expected daily volume, deduplication, and triage action before
   promoting a query into a production alert.

Use a separate benign period or held-out examples where available. If no independent dataset
exists, state that limitation. Do not claim a false-positive rate without a defined denominator
and a reviewed/labeled sample.

## Useful checks for this revision

- **S3 parser:** compare parsed columns to raw lines; retain malformed rows; distinguish 200/206
  reads from 403/404 responses. Preserve `-` byte values as unknown, not confirmed zero bytes.
- **S3 identity:** map source IPs to assets separately from requester authentication. Count
  successful requests separately from distinct objects, complete copies, and external actors.
- **HTTP path rule:** include an ordinary page load with multiple assets as a benign test case.
- **HTTP volume rule:** review large URLs/cookies, zero or missing counters, and sensor direction.
- **Running baseline:** confirm the target row is excluded, at least five preceding rows exist,
  and decide whether missing hours should be absent or zero-filled.

No separate Hunt #04 report is added by this revision. Endpoint setup and preliminary
experiments remain in the existing endpoint notes.
