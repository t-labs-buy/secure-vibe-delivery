# Code injection: running text as code (CWE-94, CWE-95)

**The problem:** `eval()`, `exec()` (Python) or `eval()`, `new Function()`, `vm.runInNewContext()`
(JavaScript) run whatever text they're given. If any of it comes from a user, they can run any
code on the server.

**The fix:** don't evaluate. Work out what the code was trying to do and do that explicitly.

| It was used for | Do this instead |
|---|---|
| Turning text into a number | `int(x)`, `float(x)`, `Number(x)` with validation |
| Reading data like `"[1, 2]"` or `{"a": 1}` | `json.loads(x)` / `JSON.parse(x)`; in Python, `ast.literal_eval(x)` for literals only |
| A calculator or formula | A small parser with an allow-list of operators (for example, walk Python's `ast` and accept only numbers and `+ - * /`), or a vetted library |
| Picking a function by name | A dict / object of allowed functions: `ACTIONS[name]()` |
| Templates | A real template engine with auto-escaping (Jinja2, Handlebars) |

```python
# Before
return {"result": eval(expr)}

# After: only numbers and + - * / ( )
import ast, operator
OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
       ast.USub: operator.neg}
def calc(expr: str) -> float:
    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in OPS:
            return OPS[type(n.op)](ev(n.left), ev(n.right))
        if isinstance(n, ast.UnaryOp) and type(n.op) in OPS:
            return OPS[type(n.op)](ev(n.operand))
        raise ValueError("unsupported expression")
    if len(expr) > 200:
        raise ValueError("expression too long")
    return ev(ast.parse(expr, mode="eval").body)
```

Return a clear 400 error for anything the parser refuses.

## Test that proves it

Send `__import__('os').system('id')` (Python) or `process.exit()` (JS) and assert a 400 error,
not a result.
