# The stats Family Explained — stats vs eventstats vs streamstats

Splunk's three aggregation commands look similar but differ in one thing:
**what they look at, and whether they change the row count.**

---

## Quick compass

| Command | What it looks at | Row count | Order-sensitive? |
|---------|------------------|-----------|------------------|
| `stats` | groups events, collapses them | **reduced** | no |
| `eventstats` | the **entire** result set | **kept** | no |
| `streamstats` | **only the preceding rows** | **kept** | **yes** — `sort` first |

One-line rule: **need fewer rows → stats. Need a column added → eventstats (whole table) or streamstats (running).**

---

## 1. stats — summarize and forget

Groups events and replaces them with a summary. 3,907 events in → a handful of rows out. Powerful but destructive: the original events are gone.

```
index=botsv3 sourcetype=access_combined | stats count by clientip
```
→ one row per IP with its total. Use for "how many / who / what."

---

## 2. eventstats — the oracle (sees the whole table)

Calculates across the **entire** result set, then attaches the same result onto **every** row. Rows are preserved. Because it sees all rows at once, it is **not** order-sensitive.

Think of a teacher who reads every exam first, then writes "class average: 95" on all papers — same number on each.

Example with values 100, 50, 200, 30:
```
100  → avg: 95
50   → avg: 95
200  → avg: 95
30   → avg: 95
```

**Use for a FIXED baseline** — compare each entity to the global norm:
```
index=botsv3 sourcetype=access_combined
| stats count by clientip
| eventstats avg(count) as baseline
| where count > baseline
```
"Which IP is above the overall average?" The data sets its own threshold.

---

## 3. streamstats — real-time (sees only the past)

Walks the rows **in order** and calculates using **only the rows seen so far**. Each row gets a different result. Because it depends on what came before, it **is** order-sensitive → always `sort _time` first.

Think of a teacher who grades papers as they arrive and writes the running average on each — first paper knows only itself, last paper knows them all.

Same values 100, 50, 200, 30:
```
100  → avg: 100      (only itself)
50   → avg: 75       (100, 50)
200  → avg: 116.6    (100, 50, 200)
30   → avg: 95       (all four)
```

### Two modes

**Windowless** — accumulates from the very start (running total/count):
```
| sort _time | streamstats count as running_count
```

**Windowed** (`window=N`) — looks back only at the last N rows (moving average). This is what catches sudden spikes:
```
index=botsv3 sourcetype=access_combined
| bin _time span=1h
| stats count as hits by _time
| sort _time
| streamstats window=5 avg(hits) as moving_avg
| eval spike = hits / moving_avg
| where spike > 3
```
"Is this hour a spike vs the last 5 hours?" A fixed baseline can miss this; a flowing one catches it.

**Note:** the time granularity ("hourly") comes from `bin span=1h`, NOT from streamstats. streamstats just flows over whatever rows it's given — change the span to change the granularity.

---

## Fixed vs flowing baseline — the key mental model

- **eventstats** = fixed baseline. "Above the *overall* norm?" Good for static comparison.
- **streamstats** = flowing baseline. "A sudden jump vs *recent* behavior?" Good for time-series anomalies.

Attacks are often sudden jumps, so streamstats catches things a fixed baseline smooths over. Best hunters use both and cross-check: if two independent methods flag the same entity/time window, confidence goes up.

*(In BOTS v3, streamstats independently flagged the 09:00 traffic spike (3.3×) — the same hour the hypothesis-driven hunt found the __main__/0.2 forum crawler. Two methods, one time window = stronger finding.)*
