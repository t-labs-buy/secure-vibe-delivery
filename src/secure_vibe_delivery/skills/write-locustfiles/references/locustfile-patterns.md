# Locustfile patterns

```python
import os
import random

from locust import HttpUser, between, task


class Shopper(HttpUser):
    wait_time = between(1, 3)            # pause like a real person between actions

    def on_start(self):
        """Runs once per simulated user: log in with a test account."""
        r = self.client.post("/login", json={
            "username": os.environ["SVD_LOAD_USER"],
            "password": os.environ["SVD_LOAD_PASSWORD"],
        })
        token = r.json().get("token")
        if token:
            self.client.headers["Authorization"] = f"Bearer {token}"

    @task(5)
    def browse(self):
        self.client.get("/products")

    @task(3)
    def view_product(self):
        product_id = random.randint(1, 50)
        # one line in the results for all product pages, not fifty
        self.client.get(f"/products/{product_id}", name="/products/[id]")

    @task(2)
    def search(self):
        self.client.get("/search", params={"q": random.choice(["lamp", "book", "chair"])})

    @task(1)
    def my_orders(self):
        with self.client.get("/orders/me", catch_response=True) as resp:
            if resp.status_code == 200 and "orders" not in resp.text:
                resp.failure("orders page returned 200 but no orders list")
```

Run it the way secure-vibe-delivery does, by asking your assistant, or by hand against a test
server:

```bash
locust -f locustfile.py --headless -u 150 -r 10 -t 2m --host http://127.0.0.1:8000
```

## Journeys that must happen in order

```python
from locust import SequentialTaskSet, task

class Checkout(SequentialTaskSet):
    @task
    def add_to_basket(self):
        self.client.post("/basket", json={"product_id": 7, "qty": 1})

    @task
    def pay(self):
        self.client.post("/checkout", json={"payment": "test-card"})   # test mode only
        self.interrupt()                                               # back to normal tasks
```

Give it its own user class, and use `weight` to set how many users take this journey compared
with the shoppers:

```python
class Buyer(HttpUser):
    wait_time = between(1, 3)
    tasks = [Checkout]
    weight = 1          # Shopper has weight 1 by default too; raise Shopper's to make buyers rarer
```

## Test data

Read IDs from a small list or a CSV of test records, so users don't all hit the same row
(which flatters caching) or request IDs that don't exist (which inflates errors).
