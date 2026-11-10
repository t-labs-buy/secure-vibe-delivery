# Raising coverage where it matters

Coverage is the share of code lines the tests ran. The roadmap's pass mark is 70%. The goal is
tested behaviour, not a number: 70% of meaningful tests beats 95% of trivial ones.

1. **Start from the report's least-covered files** (Functional tab, or the coverage chart).
2. **Prioritise risky code**: authentication and permissions, payment and money, data writes
   and deletes, input parsing. Then business rules. Skip trivial getters and generated code.
3. **Write wrong-case tests first** (`SKILL.md`): they raise coverage and prove security.
4. **Cover error paths**: invalid input, missing records, a failing external service (mock it).
5. **See exactly which lines are missed:**
   - pytest: `pytest --cov=. --cov-report=term-missing` lists missed line numbers per file.
   - Jest: `npx jest --coverage` and open `coverage/lcov-report/index.html`.
6. **Don't game it**: no tests without assertions, no excluding real code from coverage to
   pass the bar. Configured exclusions (generated code, migrations) are fine when the person
   agrees.
