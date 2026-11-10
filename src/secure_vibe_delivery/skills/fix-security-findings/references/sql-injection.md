# SQL injection (CWE-89)

**The problem:** text from a user is pasted into an SQL query, so a crafted value like
`' OR '1'='1` changes what the query does.

**The fix:** pass values as *parameters*. The database driver keeps them separate from the SQL,
so they can never change its meaning. Never build SQL with `+`, f-strings, `%` or `.format()`.

## Python

```python
# sqlite3 (placeholders are ?)
cur = db.execute("SELECT id, item FROM orders WHERE owner = ?", (owner,))

# psycopg / psycopg2 (placeholders are %s, values as a separate tuple, not % formatting)
cur.execute("SELECT id FROM orders WHERE owner = %s", (owner,))

# SQLAlchemy Core / ORM
from sqlalchemy import text, select
db.execute(text("SELECT id FROM orders WHERE owner = :owner"), {"owner": owner})
db.execute(select(Order).where(Order.owner == owner))

# Django ORM (preferred) or raw with params
Order.objects.filter(owner=owner)
Order.objects.raw("SELECT * FROM shop_order WHERE owner = %s", [owner])
```

## JavaScript / TypeScript

```js
// node-postgres (pg)
await pool.query("SELECT id FROM orders WHERE owner = $1", [owner]);

// mysql2
await conn.execute("SELECT id FROM orders WHERE owner = ?", [owner]);

// Prisma: use the query API, or tagged templates (which parameterise)
await prisma.order.findMany({ where: { owner } });
await prisma.$queryRaw`SELECT id FROM "Order" WHERE owner = ${owner}`;  // safe
// NOT prisma.$queryRawUnsafe(`... ${owner}`)
```

## Things that can't be parameters

Table names, column names and `ORDER BY` directions can't be placeholders. Map user input to a
fixed allow-list instead:

```python
SORTABLE = {"date": "created_at", "total": "total"}
column = SORTABLE.get(sort_key, "created_at")
```

## Test that proves it

Call the endpoint with `' OR '1'='1` as the value and assert it returns only what a normal
value would (often nothing), not every row.
