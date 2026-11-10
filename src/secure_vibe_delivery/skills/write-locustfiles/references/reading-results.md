# Reading performance results

The report's Performance tab shows the load, the response-time chart, throughput, and a table
per endpoint.

| Measure | Pass mark | What it means |
|---|---|---|
| Failed requests | under 1% | Errors and timeouts as a share of all requests |
| p95 response time | within the agreed target (default 1,000 ms) | 95 out of 100 requests were at least this fast |
| No crashes | none | No dropped connections, and the app still answered after the test |
| Load and duration | 1.5 × peak for 15 minutes (gate mode) | A 2-minute quick run is indicative only |

## When it fails

1. **Find the endpoint.** The per-endpoint table shows which ones fail or are slow; one bad
   endpoint usually drags the totals.
2. **Failures:** read the Failures table for the error. 5xx errors mean the app broke under load
   (check its logs at that time); timeouts mean it couldn't keep up; 4xx errors often mean the
   locustfile is wrong (bad IDs, expired login), so fix the script first.
3. **Slow endpoints, common causes:**
   - many small database queries in a loop (the "N+1" problem): load related data in one query;
   - missing database indexes on columns used in filters and joins;
   - slow or blocking calls to other services: add timeouts, run them in the background, cache;
   - work that could be cached (product lists, settings);
   - too few app workers for the load (for example, more Uvicorn or Gunicorn workers).
4. **If response time climbs steadily during the hold**, something is accumulating: a memory
   leak, a growing queue, or connections not being returned to the pool.
5. **Re-run in gate mode** (15 minutes) before go-live. Quick runs can hide slow build-ups.

Fix one cause at a time and re-run, so you know what made the difference.
