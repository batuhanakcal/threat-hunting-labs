# Hunt 01 — Working notes

**Environment:** BOTS v3, sourcetype=access_combined + stream:*
**Question:** Is anything non-human interacting with Frothly's web server, and is it malicious?

## Findings so far
- Baseline: top traffic = ELB-HealthChecker (1,665) + normal browser UAs; top URIs = /, PDFs, CSS/PNG. Healthy-looking site.
- 4xx analysis: only 400/404, top = /favicon.ico (38, all-time) → noise, no loud scanner.
- UA anomalies: Hakai/2.0 (1 req — IoT botnet probe, single knock), "__main__/0.2" (197 req), "-" (6), "Hello, World" (1), bare "Mozilla/5.0" (1).
- __main__/0.2 deep-dive: single IP 172.16.0.149 (internal!), 22 min, ~9 req/min, all GET, all 200. Systematically enumerating forum: forumdisplay.php?fid=4..10, showthread.php?tid=*, member.php uid=27/31/40 + login/lostpw/register pages → recon-style crawling of users & auth surface.
- Entity pivot: IP lives in 5 sourcetypes (10,859 events) incl. stream:tcp/ip/http/arp → it's a machine on Frothly's local network.

## Open question
- stream:tcp map for 172.16.0.149: external destinations? odd ports? → decides "employee script" vs "compromised host doing recon".

## Lessons logged
- Private IPs: no reputation lookups; context is the only judge. (Earlier false start: mDNS 5353 + NetBIOS 137 = normal Mac chatter.)
- Not every 404 is recon; volume + variety matter.
- clientip behind ELB ≠ true source.
- Hunting loop: question → data layer → count by dimensions → new question.
## Session 2 — Closure

- TCP map: only internal 172.16.0.x destinations, only port 80. No external connections, no admin ports.
- DNS: environment collects DNS (218,456 stream:dns events) but field-blind search for the IP returns 0 → genuinely no DNS trace (not a visibility gap).
- Identity: src_ip 172.16.0.149 = host "gacrux" (AWS EC2 — hostnames carry i-* instance IDs; 02:* locally-administered MACs = VM).

## Verdict
Likely benign internal activity: a Python script (UA "__main__/0.2") on Frothly's AWS server gacrux systematically crawled the internal forum (197 GET requests / 22 min; forum pages, user profiles, login/lostpw/register). Fully internal, port 80 only, no external or DNS footprint. However, auth-surface enumeration is behaviorally indistinguishable from recon when seen in isolation → class of behavior worth a detection.

## Detection idea (to develop)
Alert when a single internal source enumerates >N distinct uri_query values on auth-related pages within a short window, with a non-browser user-agent.
