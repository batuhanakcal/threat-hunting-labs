# SPL Notes

Personal SPL reference — every query I learn goes here.
Format: the query, what it does, and when it should come to mind.

---

## Data discovery

### Count events by sourcetype

```
index=botsv3 | stats count by sourcetype
```

**What:** Shows which data sources exist in an index and how noisy each one is.
**When:** First thing to run in any new/unfamiliar environment.

### Count events by host

```
index=botsv3 | stats count by host | sort - count
```

**What:** Lists all machines sending logs, in loudest-first order.
**When:** Mapping out an environment — how many systems, which ones matter.

### Verify data exists (ignores time range)

```
| eventcount summarize=false index=botsv3
```

**What:** Asks the index metadata for the total event count — not affected by the time picker.
**When:** Search returns 0, and I need to know whether the data is missing or my search is wrong.

---

## Gotchas

- BOTS data is from 2018 → **always set time range to All time**, or searches return 0.
## Web log hunting

### Top talkers by IP
```
index=botsv3 sourcetype=access_combined | stats count by clientip | sort - count
```
**What:** Who sends the most requests to the web server.
**When:** Starting point of any web log hunt — but beware: behind an ELB/proxy, clientip may hide the real source.

### Most requested URIs
```
index=botsv3 sourcetype=access_combined | stats count by uri | sort - count
```
**What:** The server's "greatest hits" — what normal demand looks like.
**When:** Building a baseline of normal before hunting deviations.

### Error-focused recon hunt
```
index=botsv3 sourcetype=access_combined status>=400 | stats count by uri, status | sort - count
```
**What:** URIs generating client/server errors.
**When:** Scanners probing non-existent pages leave a 404 trail. (Note: favicon.ico 404s are noise.)

### Tool hunting via user-agent
```
index=botsv3 sourcetype=access_combined | stats count by useragent | sort - count
```
**What:** Self-identification of requesting software; attack tools often stand out (Hakai, python scripts, blank UAs).
**When:** Fast way to spot non-browser activity in web logs.

### Suspicious UA deep-dive
```
index=botsv3 sourcetype=access_combined useragent="__main__/0.2" | stats count by method, uri_path, uri_query | sort - count
```
**What:** What a suspicious agent actually did — method, pages, parameters.
**When:** After flagging a UA; separates crawling vs exploitation vs web shell chatter.

### Entity pivot across sourcetypes
```
index=botsv3 clientip=1.2.3.4 OR src_ip=1.2.3.4 OR src=1.2.3.4 | stats count by sourcetype
```
**What:** Every data layer where an entity appears (field names differ per sourcetype, hence the ORs).
**When:** Core hunting move — one behavior in one layer means little; combine layers around the entity.

### Who does this host talk to (TCP map)
```
index=botsv3 sourcetype=stream:tcp src_ip=172.16.0.149 | stats count by dest_ip, dest_port | sort - count
```
**What:** All TCP destinations + ports for a host.
**When:** "Is this machine doing anything besides X?" — C2/lateral movement check after spotting odd behavior.
### List all distinct values of fields for an entity
```
index=botsv3 src_ip=172.16.0.149 | stats values(src_mac) values(host) by src_ip
```
**What:** values() collects every distinct value — identity gathering, not counting.
**When:** "Who IS this machine?" — MAC + hostname identification after behavioral findings.

### Field-blind check
```
index=botsv3 sourcetype=stream:dns 172.16.0.149
```
**What:** Bare string search — matches anywhere in raw events, no field assumptions.
**When:** Before declaring "no trace in X data", when unsure of field names.

### Verify a data source exists before claiming absence
```
index=botsv3 sourcetype=stream:dns | stats count
```
**What:** Total event count for a source.
**When:** "No DNS record for host" only counts as evidence if DNS is actually collected. Absence of evidence ≠ evidence of absence — check visibility first.

## Gotchas (additions)
- MAC vendor lookup is useless in cloud/VM environments — `02:` prefix = locally-administered (virtual) MAC.
- Hostnames like `name.i-0abc123...` = AWS EC2 instance IDs → you're looking at cloud infrastructure.

## Detection engineering

### Time-windowed behavior counting (detection skeleton)
```
index=botsv3 sourcetype=access_combined uri_path IN ("/member.php", "/login*")
| bin _time span=30m
| stats dc(uri_query) as distinct_queries by clientip, useragent, _time
| where distinct_queries > 3
```
**What:** `bin _time span=X` buckets events into time windows; `dc()` counts DISTINCT values (variety, not volume); `where` filters the computed stats (post-aggregation threshold); `IN (...)` = tidy multi-value OR.
**When:** Core skeleton for behavioral detections: "entity does too many different things in a short window."

## Gotchas (additions)
- "N events" (top bar) = raw events entering the pipeline; "Statistics (N)" = rows surviving aggregation + where. 0 stats with many events = threshold/window question, not missing data.
- Behind a proxy/ELB, grouping only by clientip merges many actors into one row → add useragent to the `by` clause to separate them.
- dc(uri_query) alone can't separate scripts from humans on a busy site — legit browsing also produces variety. Pair the behavioral signal with the right scope (e.g., auth pages only).

## Field extraction

### Extract a field from another field (rex)
```
index=botsv3 sourcetype=bash_history
| rex field=source "/home/(?<username>[^/]+)/"
| stats count by username | sort - count
```
**What:** rex applies a regex to a field and births a new field from the capture group `(?<name>...)`. `[^/]+` = everything up to the next slash. Pattern: anchor + capture + stop.
**When:** The info I need is buried inside another field (paths, URLs, raw text) and no parsed field exists.

**Gotcha:** Not every sourcetype comes parsed — bash_history had no user field, only default metadata. Check `fieldsummary` first; if empty, read raw events — the answer may live in metadata like `source` (e.g. /home/USER/.bash_history).

---

## The stats family (compass)

- **stats** → CHANGES row count. Groups, reduces, summarizes. 3907 events → 22 rows. Powerful but destructive (events gone).
- **eventstats** → KEEPS row count. Same calc, but ATTACHES result onto every row as a new field. 22 rows in → 22 rows out, each tagged.
- **streamstats** → KEEPS row count, attaches looking only at PRECEDING rows (running totals, moving averages, time-evolving baselines). Depth: next session.

**One-line compass:** need fewer rows → stats. Need a column added → eventstats.

### Compare each entity against a computed baseline (eventstats)
```
index=botsv3 sourcetype=access_combined
| stats count by clientip
| eventstats median(count) as baseline
| where count > baseline * 10
```
**What:** stats reduces to one row per IP, then eventstats attaches the baseline back onto every row so each IP can be compared to it. `where count > baseline` lets the DATA set the threshold — not a hardcoded number.
**When:** Baselining — "who deviates from normal" without inventing an eyeball threshold.

---

## Baseline math

### Three questions behind "find the anomaly"
1. **Where is the center?** → median (NOT mean — mean gets dirty)
2. **How spread out?** → stdev (sets the width of the "normal band")
3. **Where is the line?** → avg ± 2*stdev; outside = anomaly

### Statistical anomaly band (stdev)
```
index=botsv3 sourcetype=access_combined
| stats count by clientip
| eventstats avg(count) as avg_count, stdev(count) as std_count
| eval upper_limit = avg_count + (2 * std_count)
| where count > upper_limit
```
**What:** stdev measures spread. Normal band = avg ± 2*stdev. `eval` = SPL's calculator, builds a new field from other fields.
**When:** "Show me statistical outliers" without hardcoding a threshold.

### The empirical rule (why "2")
- avg ± 1 stdev → ~68% of data
- avg ± 2 stdev → ~95% of data  ← default: normal = 95%, hunt the outer 5%
- avg ± 3 stdev → ~99.7% of data
The stdev multiplier is a SENSITIVITY DIAL: 1 = tight/noisy (more FP), 3 = loose/blind (misses), 2 = sane start. Same tradeoff as WAF tuning. Final value comes from TESTING against your own data, not from theory.

### Lessons — no single statistic is holy
- **Mean lies, median doesn't:** access_combined mean=177 but median=1 (most IPs hit once; two internal hosts skew the mean). Anomalies inflate the mean, so a big attacker can hide near an inflated average.
- **stdev gets masked too:** the big anomaly (2818) inflated stdev to 615, pushing the band to 1408 — so the SECOND heavy IP (833) slipped under "normal." Big anomalies hide smaller ones (**masking**).
- **The band math, worked by hand:** for values incl. one giant (480), each normal point sat ~50 from the inflated mean, but the giant sat 409 away; squared, it dominated the whole sum → stdev ≈144 driven almost entirely by one point. Without the giant, stdev would've been ~2.
- **Mature fixes for masking:** median+MAD (doesn't get dirty), OR exclude known giants before baselining, OR use percentiles (works regardless of distribution shape). Hunter reflex: peel off the loudest anomaly, baseline the clean rest, then look at the second layer.
- **Distribution shape matters:** stdev bands assume a bell curve. The IP data wasn't a bell (many 1s, few giants) — so the band was crude. For skewed data, percentile ("top 1%") is more honest than stdev.

### You don't compute this by hand
`stdev()`, `median()`, `avg()` do the math for you. You learned the mechanics not to memorize the formula, but to READ the result — to know when a statistic is lying (dirtied by an outlier) instead of trusting the number blindly. That judgment is the hunter skill, not typing the function.

## Robust baselining — choosing the right measure for the data's SHAPE

### MAD (Median Absolute Deviation) — stdev's outlier-immune twin
```
index=botsv3 sourcetype=access_combined
| stats count by clientip
| eventstats median(count) as median_count
| eval distance = abs(count - median_count)
| eventstats median(distance) as mad
| eval mad_safe = if(mad=0, 1, mad)
| where count > median_count + (10 * mad_safe)
```
**What:** Splunk has no mad() function — build it: (1) distance of each value from median, (2) median of those distances. `abs()` = absolute value. `if(cond, then, else)` = eval's decision function.
**When:** Skewed data with outliers, where stdev gets inflated by giants (masking). MAD ignores giants because median ignores the tails.

**MAD=0 trap:** if most values are identical (e.g. most IPs hit exactly 1), distances are mostly 0, so median-of-distances = 0, and the band collapses to `median + 0`. Fix with `if(mad=0, 1, mad)` or a fixed floor.

### Percentile — shape-agnostic, best for very skewed data
```
index=botsv3 sourcetype=access_combined
| stats count by clientip
| eventstats perc95(count) as p95
| where count > p95
```
**What:** perc95 = the value below which 95% of entities fall. `where count > p95` = grab the top 5%. No mean, no stdev — just sort and take the top slice.
**When:** Skewed / zero-heavy / outlier data (like BOTS IP counts). Nothing can dirty a percentile because it does no arithmetic — it just ranks.

### The real lesson — fit the tool to the data's shape
| Tool | Best for | On BOTS IP data |
|------|----------|-----------------|
| stdev (±2σ) | bell curve | inflated by giant → missed 833 (masking) |
| MAD | outliers + variety | collapsed to 0 (most values identical) |
| percentile (p95) | any shape, esp. skewed | caught both 833 & 2818, dropped noise ✓ |

"Which statistic is best?" is the wrong question. "Which tool fits THIS data's shape?" is right — and you only know by trying them and reading the results. That judgment is the advanced part, not typing the function.

### streamstats — the flowing baseline
```
index=botsv3 sourcetype=access_combined
| bin _time span=1h
| stats count as hits by _time
| sort _time
| streamstats window=5 avg(hits) as moving_avg
| eval spike = hits / moving_avg
| where spike > 3
```
**What:** streamstats keeps rows but calculates using ONLY preceding rows (running total, moving average) — unlike eventstats which sees the whole table. `window=5` = look back at last 5 rows only (moving average). `spike = hits/moving_avg` = how many times above recent normal.
**When:** Time-series anomalies — sudden spikes a fixed baseline would miss. "Did this suddenly jump vs the last N periods?"
**Critical:** streamstats is order-sensitive → always `sort _time` first.

### stats family — full compass
- stats → changes row count (reduce/summarize)
- eventstats → keeps rows, adds column from ALL rows (fixed baseline)
- streamstats → keeps rows, adds column from PRECEDING rows (flowing baseline, moving averages)

**Cross-validation win:** streamstats flagged the 09:00 traffic spike (3.3x) independently — the same hour the __main__/0.2 hunt found the forum crawler. Two methods, one time window = higher confidence.
