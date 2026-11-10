from fastapi.testclient import TestClient

from app import app, discount

client = TestClient(app)


def test_index():
    assert client.get("/").json() == {"status": "ok"}


def test_products():
    assert len(client.get("/products").json()) == 20


def test_discount():
    assert discount(100, 10) == 90


def test_discount_bug():
    # Planted failing test
    assert discount(100, 25) == 70
