# Proposal: durable webhook relay

**Status:** on hold, not implemented. Needs a decision with the owner.
**Written:** 2026-11-15

## TL;DR

When GitHub sends an event, aether-cloud replies "200 OK, got it" straight away and then forwards the event to the customer's self-hosted instance from **memory only**. If the server restarts, crashes, or the customer's instance is down for more than about 4 seconds, the event is **lost for good and nobody finds out**. The fix is to write each event to the database before replying to GitHub, and have a worker deliver it from there with retries.

## How it works today

```
GitHub ──POST /webhooks/github──▶ aether-cloud
                                   1. verify GitHub signature
                                   2. schedule forward_event() as a BackgroundTask (in memory)
                                   3. reply 200 to GitHub   ◀── GitHub now considers it delivered
                                   4. forward_event(): POST to relay_url
                                      attempt 1 → wait 1s → attempt 2 → wait 3s → attempt 3
                                      all failed? log "relay_failed_all_attempts" and drop it
```

Code: `app/routers/webhooks.py` (steps 1–3) and `app/services/relay_service.py` (step 4).

FastAPI `BackgroundTasks` run inside the web server process after the response has been sent. They are a list of functions held in RAM. Nothing about them is written anywhere.

## How events get lost

| Scenario | What happens |
|---|---|
| A deploy or restart while events are being forwarded | The process exits and the pending background tasks disappear with it. |
| A crash (out of memory, bug, host failure) | Same. |
| The customer's instance is down for more than ~4 seconds (their deploy, a network blip, maintenance) | All 3 attempts fail within about 4 seconds and the event is dropped. |
| The customer's instance returns 5xx for a while | Same: dropped after 3 attempts. |

In every case:
- **GitHub won't resend.** It received a 200, so from its point of view the delivery succeeded. GitHub's "Redeliver" button does exist, but someone would have to notice the loss and click it by hand.
- **No record remains** except one log line. There's nothing to inspect, retry or replay.

## Why it matters for this product

The engine reacts to events: a push that changes `package.json`, a merged pull request, and so on. A lost event means the engine **never sees that change**. A dependency or API change goes undetected, and no fix PR is opened. Silently missing changes is exactly the failure the product exists to prevent. Customers would see "Aether didn't notice", not an error message.

## Proposed fix: Postgres outbox

This is called the *transactional outbox* pattern. **Save the event first, reply second, deliver later.**

```
GitHub ──POST──▶ aether-cloud
                  1. verify GitHub signature
                  2. INSERT into relay_outbox (status = pending)   ◀── durable from here on
                  3. reply 200 to GitHub
                     (if the INSERT fails, reply 5xx instead: GitHub retries on its side)

relay worker (a loop inside the app, or a separate process)
                  4. claim due rows:  SELECT ... WHERE status='pending' AND next_attempt_at <= now()
                                      FOR UPDATE SKIP LOCKED LIMIT n
                  5. forward_event() exactly as today (SSRF checks, signing, raw body)
                  6. success      → status = delivered
                     failure      → attempts += 1, next_attempt_at = now() + backoff
                     too many     → status = dead (kept for inspection and manual replay)
```

### Table sketch

| Column | Purpose |
|---|---|
| `id` | primary key |
| `installation_id` | which customer |
| `delivery_id` | GitHub's delivery GUID, **unique**, so a GitHub retry doesn't create a second row |
| `event` | GitHub event name |
| `body` | raw bytes, exactly as GitHub sent them (needed for the relay signature) |
| `status` | `pending` / `delivered` / `dead` |
| `attempts`, `next_attempt_at`, `last_error` | retry bookkeeping |
| `created_at`, `delivered_at` | auditing and cleanup |

### Key design points

- **`FOR UPDATE SKIP LOCKED`** lets several workers (or both uvicorn workers) pull from the table without two of them taking the same row. This Postgres feature is what makes a database table work as a queue.
- **Backoff over hours, not seconds.** For example 10s, 30s, 2m, 10m, 30m, 1h, 3h, then `dead`. That survives a customer's deploy or a short outage.
- **At-least-once delivery.** A crash after sending but before marking a row `delivered` means it gets sent again. That's acceptable because the receiver already rejects repeated delivery IDs (see "Verifying Relayed Events" in the README).
- **Cleanup.** Delete `delivered` rows after N days so the table doesn't grow forever.
- **Look up the relay at send time, not at insert time,** so a customer who changes their `relay_url` gets pending events at the new address.

### What it costs

- One new table and migration, a worker loop, and tests. A moderate amount of work.
- Each incoming webhook gains one database write before the 200. GitHub allows 10 seconds per delivery, so that's plenty of time.
- Webhook intake now depends on Postgres being up. If it's down, we return 5xx and GitHub retries later, which is better than silently dropping events.

## Alternatives considered

| Option | Why not (for now) |
|---|---|
| **Redis Streams** | Fast, and Redis is already deployed. But Redis is configured with `allkeys-lru`, so under memory pressure it may **evict queued events**. Making it safe means changing eviction policy and persistence settings, and then we'd be running Redis as a database. |
| **External queue** (SQS, RabbitMQ, NATS) | Strong guarantees, but it's new infrastructure to run, pay for and secure. Too much at this stage. |
| **More retries inside the background task** | Doesn't help with restarts or crashes, which are the main problem. It only stretches the window. |
| **Rely on GitHub redelivery** | It needs a person to notice and act. Nobody notices a silent loss. |

## Open questions for the owner

1. Will the **hosted (non-self-hosted) product** consume events from this service too? If so, the outbox should probably serve both, and that affects the design. See the comment in `app/routers/webhooks.py` about the hosted path.
2. Should the worker run **inside the API process** (simpler) or as a **separate service** (scales independently, and a slow customer can't hold up web requests)?
3. How long should failed (`dead`) events be **kept**, and does anyone need an admin endpoint to list and replay them?
4. Is **at-least-once** delivery acceptable for bangalore? It must handle duplicates by delivery ID, which the current relay signature contract already requires.
