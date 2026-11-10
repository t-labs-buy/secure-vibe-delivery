---
name: write-wrong-case-tests
description: Write tests that prove requests are refused when they should be (a logged-out visitor, a user asking for another user's data, a user with too low a role) and raise test coverage where it matters, for pytest or Jest. Use when a secure-vibe-delivery report warns that wrong-case tests are missing, coverage is below target, or tests are failing.
---

# Write wrong-case tests

AI-written code usually handles the happy path and forgets the rest. These tests prove the
rest: that the app says **no** when it should. They double as security evidence for the
go-live item "users see only their own data".

## The three cases, for every page and API that needs a login

1. **Not logged in** → refused (usually 401, or a redirect to the login page).
2. **Logged in as user A, asking for user B's data** → refused or not found (403 or 404),
   and B's data never appears in the response.
3. **Logged in with too low a role** (a normal user calling an admin action) → refused (403).

Also keep one **right case** per endpoint (the owner gets their own data), so a test that
refuses everything can't pass by accident.

## How to work

1. List the endpoints that need a login (routes with auth dependencies, decorators or
   middleware). Ask the person if access rules are unclear; don't invent them.
2. Pick the matching reference: `references/pytest-fastapi.md`,
   `references/pytest-flask-django.md` or `references/jest-supertest.md`.
3. Create test users and data in the test itself (fixtures), never real accounts.
4. Run the tests. **If a wrong-case test fails, the app has a real bug**: tell the person and
   fix the app, not the test.
5. For coverage targets, see `references/coverage.md`.

## Checking tests an AI wrote

A test must check what the code was **meant** to do, from the original request or ticket, not
what it happens to do now. A test that asserts the current (buggy) output locks the bug in.
Before keeping a test, ask: would this fail if the feature were broken?

When an existing test fails, decide which is wrong (the code or the test) by checking the
requirement, and tell the person which you changed and why.
