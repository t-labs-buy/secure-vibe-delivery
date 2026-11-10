---
name: write-locustfiles
description: Write or improve a Locust load-test script (locustfile.py) that behaves like real users, choose the expected peak, and read the results of a secure-vibe-delivery performance check (failures, p95 response time, crashes). Use when a project has no locustfile, the generated one needs real journeys, or the performance check fails.
---

# Write a locustfile

Locust plays many simulated users at once against a **test** copy of the app. The script,
`locustfile.py`, describes what one typical user does. A good one copies real behaviour;
a bad one hammers a single endpoint and proves nothing.

## Steps

1. **Pick the 3–5 journeys users do most.** Ask the person, or read the app's main pages and
   routes. A shop: browse products, search, view a product, view own orders, check out.
2. **Give each a weight** that matches how often it happens: `@task(5)` for browsing,
   `@task(1)` for checkout.
3. **Add think time** with `wait_time = between(1, 3)`: real people pause between clicks.
4. **Log in like a user** in `on_start`, with test-account credentials read from environment
   variables. Never hard-code passwords and never use real customer accounts.
5. **Group URLs with IDs** under one name (`name="/orders/[id]"`) so results stay readable.
6. **Check responses**, not just status codes, where it matters (`catch_response=True`).
7. **Save it as `locustfile.py`** in the project root; secure-vibe-delivery picks it up.

Code for each step: `references/locustfile-patterns.md`.

## Choosing the expected peak

The check runs 1.5 × the expected peak of users at the same time. If the client has no number,
estimate it: concurrent users ≈ visits in the busiest hour × average visit length in minutes ÷ 60.
For example, 1,200 visits in the busiest hour × 5 minutes ÷ 60 = 100 users at once, so pass
`peak_users=100` and Locust runs 150. Write the assumption down for the Delivery Lead.

## Rules

- **Never point it at production.** It deliberately puts the app under pressure.
- **If the app calls an AI model or a paid API**, a load test costs real money: use a test key
  with spending limits, or stub those calls in the test environment.
- **Don't create real side effects**: no real payments, emails or SMS. Use the test mode of
  each service.

When the performance check fails, read `references/reading-results.md`.
