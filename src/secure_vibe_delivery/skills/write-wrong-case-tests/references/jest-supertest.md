# Wrong-case tests: Jest + supertest (Express and similar)

```js
const request = require("supertest");
const app = require("../src/app");          // export the app without calling listen()

async function tokenFor(username) {
  const r = await request(app).post("/login").send({ username, password: "test-password" });
  return r.body.token;
}

describe("order access", () => {
  test("logged-out request is refused", async () => {
    await request(app).get("/orders/1").expect(401);
  });

  test("owner can read their own order", async () => {
    const t = await tokenFor("alice");
    await request(app).get("/orders/1").set("Authorization", `Bearer ${t}`).expect(200);
  });

  test("another user cannot read the order", async () => {
    const t = await tokenFor("bob");
    const r = await request(app).get("/orders/1").set("Authorization", `Bearer ${t}`);
    expect([403, 404]).toContain(r.status);
    expect(JSON.stringify(r.body)).not.toContain("alice");
  });

  test("normal user cannot use an admin action", async () => {
    const t = await tokenFor("alice");
    await request(app).delete("/admin/users/2").set("Authorization", `Bearer ${t}`).expect(403);
  });
});
```

Install with `npm install --save-dev jest supertest`. Seed test users in a `beforeAll` against
a test database, never production.
