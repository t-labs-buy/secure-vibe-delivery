# Wrong-case tests: Flask and Django

## Flask (pytest)

```python
import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    return app.test_client()

def login(client, username, password="test-password"):
    return client.post("/login", data={"username": username, "password": password})

def test_logged_out_is_redirected(client):
    r = client.get("/orders/1")
    assert r.status_code in (302, 401)

def test_other_user_cannot_read_order(client):
    login(client, "bob")
    r = client.get("/orders/1")          # alice's order
    assert r.status_code in (403, 404)
```

## Django (TestCase)

```python
from django.contrib.auth.models import User
from django.test import TestCase
from shop.models import Order

class OrderAccessTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="x")
        self.bob = User.objects.create_user("bob", password="x")
        self.order = Order.objects.create(owner=self.alice, item="book")

    def test_logged_out_redirects_to_login(self):
        r = self.client.get(f"/orders/{self.order.id}/")
        self.assertEqual(r.status_code, 302)

    def test_other_user_cannot_read_order(self):
        self.client.force_login(self.bob)
        r = self.client.get(f"/orders/{self.order.id}/")
        self.assertIn(r.status_code, (403, 404))

    def test_normal_user_cannot_open_admin(self):
        self.client.force_login(self.alice)
        r = self.client.get("/admin/")
        self.assertNotEqual(r.status_code, 200)
```

Run Django tests with `python manage.py test`, or pytest with `pytest-django`.
