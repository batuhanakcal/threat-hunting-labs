# Hunt #02 Public S3 Bucket Exposure (`frothlywebcode`)

**Type:** Hypothesis-driven, pivot-led (PEAK)

**Environment:** Splunk BOTS v3 (Frothly), original discovery searches: All time

**Threat Hunter:** Batuhan Akcal

**Status:** Public ACL grants observed; successful-access impact requires validation

## Executive assessment

CloudTrail records show `AllUsers` READ and WRITE bucket ACL grants, followed by their removal
**56 minutes 8 seconds** later. S3 logs contain anonymous object requests and a warning-file key.
Those observations establish an exposure concern, but the saved aggregations do not establish
successful download counts, an anonymous write, or the identity of an external party.

**Confidence:** High in the ACL change shown in the raw CloudTrail screenshot; successful object
access and downstream impact remain unresolved. Integrity and confidentiality both need review.
**Time:** CloudTrail `eventTime` gives **2018-08-20 13:01:46Z–13:57:54Z**. The same screenshot
renders `_time` as 09:01:46–09:57:54, a **UTC−04:00 display offset**. Other sources must be checked
against their raw timestamps before combining them into a definitive cross-source timeline.

## How this hunt started

While reviewing `bash_history`, a command stood out on host `mars`:

```text
python /home/ec2-user/tools/s3-upload.py --bucket frothlywebcode --file frothly_web_memcaced.tar.gz --target frothly_html_memcached.tar.gz
```

An archive upload may be a normal deployment or part of data staging/exfiltration. The command
alone does not establish intent. That ambiguity led to the investigation.

![mars bash history s3-upload commands](../hunt-02-s3-images/hunt-02-S3-1.png)

Three invocations with changing `--file` values and an intervening `sudo pip install boto3`
are consistent with interactive troubleshooting, but do not by themselves identify the operator.

## Hypothesis and scope

> If the bucket's permissions allowed unintended public access, permission-change events and
> successful anonymous object operations should establish when access was possible and whether
> it was used. Request identity, response status, and asset ownership need separate checks.

| ABLE | Scope |
|---|---|
| Actor | Unspecified; administrative error and unauthorized access are alternative explanations |
| Behavior | Public permission changes and possible access to deployment artifacts |
| Location | `aws:s3:accesslogs`, `aws:cloudtrail`, `bash_history` |
| Evidence | ACL/policy grants; requester, operation, HTTP response, bytes sent, and timestamps |

**Stop condition:** Document the grants and observed requests, then identify the remaining
checks needed to establish impact. Archive contents and actual deployment behavior are outside
the available evidence. T1567.002 and T1530 are investigation hypotheses, not confirmed technique
mappings based solely on an upload or anonymous request.

## Execute

### Step 1: Pivot on the filename

```spl
index=botsv3 "*memcac*" | stats count by sourcetype
```

![filename pivot across sourcetypes](../hunt-02-s3-images/hunt-02-S3-2.png)

The search returned 19 sourcetypes and 1,471 events. Much of the volume concerned the memcached
service (`ps`: 832; `top`: 416), rather than the archive. Relevant sources included:

| Sourcetype | Count | Why it matters |
|---|---|---|
| `aws:s3:accesslogs` | 41 | Requests involving the archive name |
| `aws:cloudtrail` | 2 | Bucket-level API activity |
| `code42:security` | 11 | File-related telemetry |
| `bash_history` | 3 | Upload commands |

### Step 2: What operations were requested?

```spl
index=botsv3 sourcetype=aws:s3:accesslogs "*memcac*"
| rex field=_raw "(?<operation>REST\.\w+\.\w+)"
| stats count by operation | sort - count
```

![S3 operation breakdown](../hunt-02-s3-images/hunt-02-S3-3.png)

| Operation | Count |
|---|---|
| `REST.GET.OBJECT` | 17 |
| `REST.HEAD.OBJECT` | 14 |
| `REST.GET.BUCKETVERSIONS` | 3 |
| `REST.PUT.OBJECT` | 3 |
| `REST.GET.ACL` | 2 |
| `REST.GET.BUCKET` | 1 |
| `REST.OPTIONS.PREFLIGHT` | 1 |

These are **request counts**. An operation name alone does not establish success: a GET can
receive 403 or 404. Multiple reads per upload can also be normal deployment behavior.

### Step 3: Which object GET requests were anonymous?

```spl
index=botsv3 sourcetype=aws:s3:accesslogs "*memcac*" REST.GET.OBJECT
| rex field=_raw "\] (?<src_ip>\d+\.\d+\.\d+\.\d+) (?<requester>\S+)"
| stats count by src_ip, requester | sort - count
```

![authenticated vs anonymous requests](../hunt-02-s3-images/hunt-02-S3-4.png)

| Source IP | Requester | Count |
|---|---|---|
| 107.77.212.175 | `arn:aws:iam::622676721278:user/bstoll` | 4 |
| 52.53.233.88 | `-` (anonymous) | 2 |
| 52.53.233.88 | `assumed-role/EC2InstanceRole` | 2 |
| 54.183.247.244 | `-` (anonymous) | 2 |
| 54.183.247.244 | `assumed-role/EC2InstanceRole` | 2 |
| 54.67.37.214 | `-` (anonymous) | 2 |
| 54.67.37.214 | `assumed-role/EC2InstanceRole` | 2 |
| 35.182.246.222 | `-` (anonymous) | 1 |

**Seven of 17 GET requests were anonymous.** Six came from IPs also observed using a Frothly
EC2 role. The remaining IP merits asset-ownership review; absence of a role in this table does
not establish that it was external. Anonymous identity is distinct from response success.

The original regex covers IPv4 addresses only. The follow-up parser below accepts an address
token without that restriction. See [AWS's log field definitions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html).

### Step 4: Who changed the bucket ACL, and when?

```spl
index=botsv3 sourcetype=aws:cloudtrail (PutBucketAcl OR PutBucketPolicy OR PutObjectAcl)
| table _time, _raw
```

![PutBucketAcl events with raw UTC eventTime](../hunt-02-s3-images/hunt-02-S3-5.png)

Two `PutBucketAcl` events name `bstoll`, from `107.77.212.175`, with
`mfaAuthenticated: false`. The screenshot shows:

| Raw `eventTime` (UTC, 2018-08-20) | Displayed `_time` | ACL change |
|---|---|---|
| 13:01:46Z | 09:01:46 | `AllUsers` receives READ and WRITE |
| 13:57:54Z | 09:57:54 | `AllUsers` grants removed |

`AllUsers` includes unauthenticated users. **Bucket READ permits listing objects; it does not
itself grant object downloads.** Bucket WRITE grants object-write capabilities. Establishing
whether a particular existing archive could be replaced also requires ownership/version and
effective-permission checks. Object ACLs and bucket policies must be reviewed separately.
[AWS ACL permission semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)

The interval between these recorded changes is 56 minutes 8 seconds. Removing these grants
does not by itself prove all public access ended: an object ACL or bucket policy could still
allow reads. Effective access and intervening changes need verification.

### Step 5: Which object keys appear in requests?

```spl
index=botsv3 sourcetype=aws:s3:accesslogs frothlywebcode
| rex field=_raw "REST\.\w+\.\w+ (?<object>\S+)"
| stats count by object | sort - count
```

![object keys appearing in access logs](../hunt-02-s3-images/hunt-02-S3-6.png)

| Key grouping in the screenshot | Count |
|---|---|
| `-` (bucket-level operations) | 131 |
| `frothly_html_memcached.tar.gz` | 24 |
| `OPEN_BUCKET_PLEASE_FIX.txt` | 2 |
| Encoded/prefixed archive-name variant | 1 |

The warning-file name is a useful lead. A key in an access-log request is **not a complete bucket
inventory**, and does not prove that the object exists or that a write succeeded. Inspect the
operation, requester, response, and time for those two records before attributing a warning-file
upload to a third party. Review the encoded key separately instead of silently merging it.

## Working timeline

The ACL times are supported by raw UTC fields in the screenshot. Other rows preserve the
original investigation notes and need raw-event confirmation, including response status.

| Display time (2018-08-20) | Observation or note | Evidence status |
|---|---|---|
| 09:01:46 | `AllUsers` READ + WRITE granted | Raw CloudTrail screenshot; 13:01:46Z |
| 09:03:46 | Anonymous archive GET request | Original note; response status/time to verify |
| 09:04:17 | Archive PUT request, 35.182.246.222 | Original note; success and identity to verify |
| 09:33:34–09:33:38 | Anonymous and EC2-role GET requests | Original note; successful transfers to count |
| 09:57:54 | `AllUsers` grants removed | Raw CloudTrail screenshot; 13:57:54Z |
| 09:59:18 | Permission/version checks | Original note; occurs after grant removal |
| Time not established | Requests naming `OPEN_BUCKET_PLEASE_FIX.txt` | Key count shown; operation and timing unverified |

The ordering does not establish that the administrator discovered the issue through the later
permission checks. The reason for granting or removing access is not recorded here.

## Verdict and impact

**Public bucket ACL grants are documented. Successful anonymous access and the full impact
remain to be established.** Administrative error is plausible, but the actor's intent cannot be
resolved from this sequence alone.

The upload command and archive name suggest deployment code. A write grant raises an integrity
concern if unauthorized artifacts can enter a deployment workflow. No replaced artifact or
malicious deployment is demonstrated in the saved evidence. Confidentiality remains unresolved:
object names do not reveal whether an archive contains source code, secrets, or personal data.

## Follow-up validation — proposed, not yet run

Use an explicit time range that includes the ACL interval and surrounding activity. Check
Splunk display timezone against the raw S3 timestamp offset and CloudTrail `eventTime` first.
The following parser targets the space-delimited S3 format in this lab. Validate it against
raw records, especially quoted request URIs, before relying on its output.

```spl
index=botsv3 sourcetype=aws:s3:accesslogs frothlywebcode
| rex field=_raw "^\S+\s+(?<bucket>\S+)\s+\[(?<request_time>[^\]]+)\]\s+(?<src_ip>\S+)\s+(?<requester>\S+)\s+(?<request_id>\S+)\s+(?<operation>\S+)\s+(?<object>\S+)\s+\"(?<request_uri>.*?)\"\s+(?<http_status>\d{3})\s+(?<error_code>\S+)\s+(?<bytes_sent>\S+)\s+(?<object_size>\S+)"
| eval parse_status=if(isnull(http_status),"UNPARSED","parsed")
| table _time request_time parse_status bucket src_ip requester request_id operation object http_status error_code bytes_sent object_size _raw
| sort 0 _time
```

Retain and investigate **UNPARSED** rows. Then verify successful object GET/PUT operations,
response bytes, exact object key, request ID, and source ownership. A 206 response can represent
a partial read; a successful request count is not a count of complete, distinct archive copies.
Confirm the warning-file PUT and its timestamp before stating it was written during the interval.

## Candidate detections — revised queries pending validation

### Rule 1: Successful public bucket ACL change

```spl
index=botsv3 sourcetype=aws:cloudtrail
| spath
| search eventName=PutBucketAcl
| where isnull(errorCode)
| search "global/AllUsers"
| spath path=userIdentity.userName output=actor
| spath path=requestParameters.bucketName output=bucket
| spath path=userIdentity.sessionContext.attributes.mfaAuthenticated output=mfa_authenticated
| table _time eventTime actor sourceIPAddress bucket mfa_authenticated _raw
```

This is a detective alert candidate, not prevention. Review the actual grantee/permission pairs
and approved public-bucket exceptions. No false-positive rate or scheduled-alert latency is
measured. `AllUsers` string matching does **not** cover public bucket policies, which may use
`Principal: "*"`. A separate review query is:

```spl
index=botsv3 sourcetype=aws:cloudtrail
| spath
| search eventName=PutBucketPolicy
| where isnull(errorCode)
| spath path=requestParameters.bucketName output=bucket
| spath path=requestParameters.bucketPolicy output=bucket_policy
| table _time eventTime userIdentity.arn sourceIPAddress bucket bucket_policy _raw
```

Inspect every policy statement's Effect, Principal, Action, Resource, and Condition together.
Also review `PutObjectAcl` and existing policies when establishing effective object access.
`AuthenticatedUsers` is a separate broad-access ACL group covering AWS accounts, not synonymous
with anonymous public access.

### Rule 2: Successful anonymous object operations

Use the validated parser from the follow-up query above, then replace its final `table`/`sort`
with this pipeline:

```spl
| where requester="-" AND http_status>=200 AND http_status<300
  AND (operation="REST.GET.OBJECT" OR operation="REST.PUT.OBJECT")
| eval bytes_sent_num=tonumber(bytes_sent)
| stats count as successful_requests sum(bytes_sent_num) as response_bytes
  dc(src_ip) as distinct_sources values(http_status) as statuses by bucket operation object
```

Audit parser coverage before filtering. Null byte values must not be presented as confirmed zero
transfer. An anonymous successful request can be expected for a deliberately public resource;
apply bucket-purpose context before alerting. [Validation record requirements](../validation-notes.md)

## Recommendations

1. Review account/bucket S3 Block Public Access and object ownership settings; verify effective
   permissions after remediation, including object ACLs and policies.
2. Review the IAM user's permissions and MFA enforcement appropriate to the access path.
3. Preserve and validate the successful request evidence and warning-file origin.
4. Inspect archive contents and deployment consumption before deciding confidentiality or
   integrity impact. Check object versions/hashes and other writes in the interval.
5. Validate the candidate detections against approved public access and denied requests.

## Important Notes

- A filename can connect shell history, cloud API activity, and object access logs.
- Request identity, response success, resource permissions, and source ownership answer different questions.
- Aggregated keys are not a complete inventory; object names do not establish content sensitivity.
- Preserve uncertainty about intent while making the documented permission change actionable.
