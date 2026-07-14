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
