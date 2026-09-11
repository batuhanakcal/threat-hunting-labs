# The stats Family Explained: stats vs eventstats vs streamstats

Splunk's three aggregation commands look similar but differ in one thing:
**what they look at, and whether they change the row count.**

---

## Quick compass

| Command | What it looks at | Row count | Order-sensitive? |
|---------|------------------|-----------|------------------|
| `stats` | groups events, collapses them | **reduced** | no |
| `eventstats` | the **entire** result set | **kept** | no |
| `streamstats` | Rows seen so far, including current by default; `current=f` excludes it | **kept** | **yes** |

One-line rule: **need fewer rows → stats. Need a column added → eventstats (whole table) or streamstats (running).**

---

## 1. stats - summarize and forget

Groups events and replaces them with a summary. 3,907 events in → a handful of rows out. Powerful but destructive: the original events are gone.

```
index=botsv3 sourcetype=access_combined | stats count by clientip
```
→ one row per IP with its total. Use for "how many / who / what."

---

## 2. eventstats - the oracle (sees the whole table)

Calculates across the **entire** result set, then attaches the same result onto **every** row. Rows are preserved. Because it sees all rows at once, it is **not** order-sensitive.

Think of a teacher who reads every exam first, then writes "class average: 95" on all papers, the same number on each.

Example with values 100, 50, 200, 30:
```
100  → avg: 95
50   → avg: 95
200  → avg: 95
30   → avg: 95
```

**Use for a FIXED baseline** compare each entity to the global norm:
```
index=botsv3 sourcetype=access_combined
| stats count by clientip
| eventstats avg(count) as baseline
| where count > baseline
```
"Which IP is above the overall average?" The data sets its own threshold.

---

## 3. streamstats - running calculations in row order

Walks the rows **in order** and calculates using **only the rows seen so far**. Each row gets a different result. Because it depends on what came before, it **is** order-sensitive → always `sort _time` first.

The current row is included by default (`current=true`); use `current=f` to exclude it.
The example below includes the current row. Use `sort 0 _time` for the chronological examples
to retain all rows rather than imposing the default sort result limit.

Same values 100, 50, 200, 30:
```
100  → avg: 100      (only itself)
50   → avg: 75       (100, 50)
200  → avg: 116.6    (100, 50, 200)
30   → avg: 95       (all four)
```

### Two modes

**Without an explicit window**, calculates a running result. Applicable memory/event limits still matter; it is not unlimited history:
```
| sort 0 _time | streamstats count as running_count
```

**Windowed** (`current=f window=N`) — compares against the preceding N rows. This revised
example requires a full five-row baseline and a positive average; it has not been rerun on BOTS v3:
```
index=botsv3 sourcetype=access_combined
| bin _time span=1h
| stats count as hits by _time
| sort 0 _time
| streamstats current=f window=5 count(hits) as baseline_rows avg(hits) as moving_avg
| where baseline_rows=5 AND moving_avg>0
| eval spike = hits / moving_avg
| where spike > 3
```
"Is this hour a spike relative to the preceding five observed hourly buckets?" Missing hours
are absent from this `stats` output. Use a bounded, continuous `timechart` if the comparison
must represent five consecutive hours.

**Note:** the time granularity ("hourly") comes from `bin span=1h`, NOT from streamstats. Streamstats just flows over whatever rows it's given; change the span to change the granularity.

---

## Fixed vs flowing baseline: the key mental model

- **eventstats** = fixed baseline. "Above the *overall* norm?" Good for static comparison.
- **streamstats** = flowing baseline. "A sudden jump vs *recent* behavior?" Good for time-series anomalies.

Attacks are often sudden jumps, so streamstats catches things a fixed baseline smooths over. Best hunters use both and cross-check: if two independent methods flag the same entity/time window, confidence goes up.

The original exploratory notes recorded a 3.3× spike with the earlier query that included the
current row. That historical value is not a result of the corrected `current=f` query. A new
run is required before claiming its output or detection effectiveness.

Reference: [Splunk streamstats documentation](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.0/search-commands/streamstats).
