"""Deliberately vulnerable demo app used to exercise secure-vibe-delivery. DO NOT DEPLOY."""
import sqlite3
import time

import requests
from fastapi import FastAPI, HTTPException

app = FastAPI(title="vulnapp")

# Planted secret (AWS's documented example key, not a real credential)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8d"  # planted fake token
DB_PASSWORD = "SuperSecret123!"

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE orders (id INTEGER, owner TEXT, item TEXT)")
DB.execute("INSERT INTO orders VALUES (1, 'alice', 'book'), (2, 'bob', 'lamp')")

PRODUCTS = [{"id": i, "name": f"product-{i}"} for i in range(20)]


@app.get("/")
def index():
    return {"status": "ok"}


@app.get("/products")
def products():
    return PRODUCTS


@app.get("/orders")
def orders(owner: str):
    # Planted: SQL built by string formatting
    cur = DB.execute(f"SELECT id, item FROM orders WHERE owner = '{owner}'")
    return [{"id": r[0], "item": r[1]} for r in cur.fetchall()]


@app.get("/calc")
def calc(expr: str):
    # Planted: running text as code
    return {"result": eval(expr)}


@app.get("/fetch")
def fetch(url: str):
    # Planted: HTTPS certificate check switched off
    r = requests.get(url, verify=False, timeout=5)
    return {"status": r.status_code}


@app.get("/slow")
def slow():
    time.sleep(1.5)
    return {"slow": True}


@app.get("/flaky")
def flaky():
    if int(time.time() * 1000) % 10 == 0:
        raise HTTPException(status_code=500, detail="boom")
    return {"ok": True}


def discount(price: float, pct: float) -> float:
    if pct > 100:
        raise ValueError("pct > 100")
    return round(price * (1 - pct / 100), 2)


def unused_a(x):
    if x > 10:
        return "big"
    elif x > 5:
        return "medium"
    return "small"


def unused_b(items):
    out = []
    for i in items:
        if i % 2:
            out.append(i * 3)
        else:
            out.append(i // 2)
    return out
