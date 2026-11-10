# Wrong-case tests: pytest + FastAPI

```python
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import get_current_user   # the project's auth dependency

client = TestClient(app)

def as_user(user):
    """Make requests as this user by overriding the auth dependency."""
    app.dependency_overrides[get_current_user] = lambda: user

@pytest.fixture(autouse=True)
def reset_overrides():
    yield
    app.dependency_overrides.clear()

ALICE = {"id": 1, "name": "alice", "role": "user"}
BOB = {"id": 2, "name": "bob", "role": "user"}

def test_logged_out_is_refused():
    r = client.get("/orders/1")
    assert r.status_code == 401

def test_owner_can_read_own_order():
    as_user(ALICE)
    assert client.get("/orders/1").status_code == 200   # order 1 belongs to alice

def test_other_user_cannot_read_order():
    as_user(BOB)
    r = client.get("/orders/1")
    assert r.status_code in (403, 404)
    assert "alice" not in r.text

def test_normal_user_cannot_use_admin_action():
    as_user(ALICE)
    assert client.delete("/admin/users/2").status_code == 403
```

If the app uses real tokens instead of a dependency, log in through the API in a fixture and
send `headers={"Authorization": f"Bearer {token}"}`. Use a test database, never the real one.
