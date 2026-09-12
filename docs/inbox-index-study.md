# Inbox pagination index study, 2026-09-11

Issue #104. Select `{ userId: 1, receivedAt: -1, _id: -1 }`, named
`inbox_stable_order`, for a controlled index creation after staging verification.
It removes the blocking sort from unfiltered pagination and limits early-page
document reads. The alternative with `inboxState` before the sort keys retains
a blocking sort for `inboxState != removed` and is not selected.

This PR does not create an index on Atlas or add automatic schema/index changes.
Production creation is a separate operational step. Existing ownership/provider
and scan uniqueness indexes remain intact.

## Method and evidence

Query implementation at `23eb087`, benchmark at
`34e167db5f8e9d7422592741143af6d561bcfeb5`. Node 24.20.0, Linux ARM64,
MongoDB 8.0.28 in an isolated loopback-only container; the database and container
were removed afterward. All variants used identical installed dependencies,
existing schema indexes and service code. Only the extra index changed.

The script calls `getEmailsForUser`, captures its actual aggregation pipelines
and collects their MongoDB `executionStats`. It does not hint queries. Each
candidate gets three warmups and twelve latency samples for each of ten query
shapes on 600- and 6,000-message inboxes, plus one other user's message. Each
write trial inserts, changes the sort date of, then removes 200 extra synthetic
messages; eight trials measure write overhead. Existing Pi services kept running.

[Raw samples and sanitized winning plans](measurements/inbox-indexes.json) include
existing indexes, documents/keys examined, blocking sorts, lookup statistics,
index sizes and write timings. Plans omit engine-generated projection bytecode.
Cursor statistics and scan lookup statistics are separate; do not add nested
plan counters repeatedly. The default response uses both a page and count query.

## Results

All latency values below are whole-service milliseconds, including count queries.

| Inbox size / query | Existing median / p95 | Selected index median / p95 | State-first index median / p95 |
| --- | --- | --- | --- |
| 600 / first page | 8.4 / 9.1 | 7.2 / 7.4 | 7.9 / 9.6 |
| 6,000 / first page | 17.5 / 17.9 | 7.1 / 7.5 | 14.4 / 14.8 |
| 6,000 / page 10 | 17.8 / 18.2 | 7.3 / 7.5 | 15.0 / 15.3 |
| 6,000 / account filter | 17.5 / 18.0 | 8.0 / 9.0 | 17.6 / 23.1 |
| 6,000 / time range | 8.5 / 8.7 | 7.3 / 8.9 | 8.0 / 8.2 |
| 6,000 / substring search | 31.8 / 32.3 | 16.8 / 17.4 | 31.2 / 31.6 |
| 6,000 / safe filter | 1236.6 / 1326.1 | 1238.0 / 1351.4 | 1239.4 / 1446.5 |
| 6,000 / beyond last page | 20.8 / 22.3 | 10.7 / 11.0 | 26.0 / 48.1 |

On the large inbox, first-page cursor documents/keys examined fell from
5,400/5,402 to 22/22. Two removed messages were inspected and discarded before
returning 20. Page 10 examines 222 documents/keys. The separate count still examines
5,402 keys, and deep offsets still scan preceding entries. Beyond the last page,
the selected index examines all 6,000 documents, versus 5,400 with existing indexes,
but avoids the blocking sort. This is not cursor pagination.

Risk filters, including reviewed/unscanned/phishing cases, still enrich the
matching inbox before the facet and retain their sort. No meaningful latency
improvement was established there. Arbitrary substring search is still a regex
scan; an early matching page improved, but the search count still examined 5,400
documents. Do not claim indexed substring search.

The selected index occupied 24,576 bytes for 600 messages and 90,112 bytes for
6,000; the state-first alternative occupied 110,592 bytes on the larger set.
These are MongoDB-reported index allocation sizes for synthetic documents, not
predictions for production storage or cache use.

At 6,000 messages, the 200-document insert median/p95 changed from 6.1/6.2 to
6.5/7.1 ms, and the sort-date update median/p95 from 15.6/20.2 to 17.1/17.3 ms.
At 600 messages, insert medians changed from 6.5 to 7.0 ms and update medians from
10.1 to 11.5 ms. The extra index has a measurable maintenance cost. The observed
read benefit and small synthetic storage cost justify selecting it for staging;
real Atlas latency and write patterns must be checked before production creation.

## Correctness and limits

Every candidate returned identical complete responses for all query shapes.
Pagination through the entire fixed dataset matched an independently sorted list
with no duplicates/gaps, unchanged totals and correct user isolation. Four-message
timestamp ties, missing `inboxState`, removed messages, account/time/search filters,
review decisions, unscanned messages and later/empty pages were included. Another
user's otherwise matching message did not leak into the results.

The script makes no concurrent inbox writes during pagination. Offset pagination
can shift when messages arrive or disappear between requests; an index does not
solve that. This is a synthetic local study, not a production performance or
hardware-temperature claim. Twelve samples do not establish a production SLA.

A partial index on `inboxState: present` was not selected for trial: the actual
query also includes legacy documents with missing state, so that partial set
cannot cover the required result without changing the contract.

## Reproduce

Start a disposable loopback-only MongoDB server and run:

```bash
node backend/scripts/benchmark-inbox-indexes.js mongodb://127.0.0.1:PORT/
```

The script rejects remote hosts and credentials, creates a uniquely named test
database and drops only that database on completion. It runs no schedulers,
Gmail, network detection or attachment processing. It asserts correctness while
measuring; there is no separate duplicate unit-test implementation of MongoDB.

## Controlled creation, verification and rollback

First use an isolated representative staging database. Connect with approved
operator credentials outside command history. Verify the selected database and
capture `db.emails.getIndexes()` and `db.scans.getIndexes()` before changing it.
Create only the selected index in that database's mongosh session:

```javascript
db.emails.createIndex(
  { userId: 1, receivedAt: -1, _id: -1 },
  { name: 'inbox_stable_order' }
)
```

Verify its exact key pattern and confirm every pre-existing unique index remains.
Use a real owned-user ObjectId, a current query and `executionStats` to check the
winning plan and work, then exercise the application counts and later pages:

```javascript
db.emails.find({ userId: ObjectId('REPLACE_WITH_STAGING_USER_ID'), inboxState: { $ne: 'removed' } })
  .sort({ receivedAt: -1, _id: -1 }).limit(20).explain('executionStats')
```

The script's full aggregation plans cover the scan enrichment and count query;
the short find above checks only the ordered email selection. Repeat actual
application timings and writes on staging. Preserve the before/after evidence.
If the measured tradeoff is acceptable, schedule production creation separately
under #74/#79 with a database backup and monitoring of the index build.

If rollback is needed, confirm the named index has exactly the key pattern above,
was created by this change and is not a pre-existing operator index. Then drop
only it:

```javascript
db.emails.dropIndex('inbox_stable_order')
```

Never use `syncIndexes`, `dropIndexes` or recreate collections for this change.
