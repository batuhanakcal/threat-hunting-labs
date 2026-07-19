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

### Extract a field from another field (rex)
```
index=botsv3 sourcetype=bash_history
| rex field=source "/home/(?<username>[^/]+)/"
| stats count by username | sort - count
```
**What:** rex applies a regex to a field and births a new field from the capture group `(?<name>...)`. `[^/]+` = everything up to the next slash.
**When:** The info I need is buried inside another field (paths, URLs, raw text) and no parsed field exists. Anchor + capture + stop.

**Gotcha:** Not every sourcetype comes parsed (bash_history had no user field — only default metadata). Check fieldsummary first; if empty, read raw events — the answer may live in metadata like `source`.
