# scanner

**Static detection of broken access control (OWASP A01) in Node.js / TypeScript web apps — without writing a security policy first.**

> Status: early development (v0.1). Express supported; NestJS next.

## Why another scanner?

Broken Access Control is #1 in the OWASP Top 10, yet SAST tools are weak at it: whether `DELETE /orders/:id` should check the order's owner is *business logic*, so pattern-based rules either miss it or flood you with false positives.

This tool takes a different approach, inspired by **"Bugs as Deviant Behavior"** (Engler et al., SOSP 2001): **the codebase is its own specification.**

1. It builds a **route model** of the app: every route, its full mounted path, its middleware chain (in execution order), the request inputs it reads, and how the handler restricts access (owner comparison, user-scoped query, role check).
2. It groups routes by resource and flags the ones that **deviate from their peers**: if `GET` and `PUT /api/orders/:id` both verify the owner but `DELETE` does not, `DELETE` is reported — with the peer routes as evidence.

No finding is ever reported without a *witness* in your own code. That is the core design choice for keeping false positives low.

## Quick start

```bash
pnpm install
pnpm scanner routes bench/fixtures/express-shop   # route map + access-control facts
pnpm scanner scan   bench/fixtures/express-shop   # findings (exit code 1 if any)
pnpm scanner scan   <dir> --json                  # machine-readable output
pnpm test                                         # checks against ground truth
```

Example finding:

```
HIGH  IDOR probable : vérification du propriétaire manquante  [A01:2021 · CWE-639 · confiance high]
  DELETE /api/orders/:id  src/routes/orders.ts:36
  DELETE /api/orders/:id accède à l'objet :id sans vérifier qu'il appartient à l'utilisateur,
  alors que 2 route(s) voisine(s) le vérifient.
    · témoin : GET /api/orders/:id (src/routes/orders.ts:13) — order.userId !== req.user.id
    · témoin : PUT /api/orders/:id (src/routes/orders.ts:22) — order.userId !== req.user.id
```

## Architecture

```
packages/
  core/                       Route model, findings, shared helpers
  adapters/express/           ts-morph front end: routes, mounts, middleware chains, handler facts
  analyzers/access-control/   Deviance-based A01 rules
  cli/                        `scanner routes` / `scanner scan`
bench/fixtures/               Vulnerable apps + fixed twins, each with an expected.json ground truth
tests/                        Every fixture is checked against its ground truth
```

Built on the TypeScript compiler API (via ts-morph) rather than a syntax-only parser: resolving imports and symbols is what lets the analysis follow a router from `routes/orders.ts` to where it is mounted in `app.ts`.

## What it understands today (Express)

- `express()`, `express.Router()`, `Router()` — ESM imports and CommonJS `require`
- Nested mounts: `app.use("/api/orders", requireAuth, ordersRouter)`
- Middleware **order**: `router.use(auth)` only protects routes registered after it
- Prefix-scoped middleware: `app.use("/admin", isAdmin)`
- Middleware factories: `requireRole("admin")`, `passport.authenticate("jwt")`
- Middleware classified by **behavior** (token verification, `req.user` assignment, 401/403 responses), with name-based fallback
- Named handlers resolved to their declaration
- Ownership: `resource.ownerId !== req.user.id` (comparison) and `db.query(..., [req.user.id])` (user-scoped query)

## Rules

| Rule | CWE | Triggers when |
|---|---|---|
| `missing-authentication` | CWE-306 | A route on `/:id` is public while its peers require authentication |
| `missing-ownership-check` | CWE-639 | An authenticated `/:id` route never checks ownership while peers do (IDOR) |
| `missing-role-check` | CWE-285 | A route requires no role while most of its peers do |

## Ground truth

| Fixture | Purpose | Expected A01 findings |
|---|---|---|
| `express-shop` | TypeScript app with 3 access-control bugs + 1 SQLi | 3 |
| `express-shop-fixed` | Same app, all bugs fixed — measures false positives | 0 |
| `express-js-mini` | CommonJS, `express.Router()`, prefix-scoped middleware, passport | 1 |

Current result: **all expected findings detected, zero false positives** on the fixtures. Fixtures are small and hand-written; real-world evaluation is the next milestone.

## Known limitations (v0.1)

- `router.route("/x").get(...)` chains are not yet recognized
- Ownership checks performed inside a called service function are not yet followed (intra-procedural only)
- Routes registered dynamically (loops, computed paths) are skipped
- A03 (injection) analysis is not implemented yet — the SQLi in `express-shop` is in the ground truth but not yet detected

## Roadmap

- [x] Express route model + deviance-based A01 rules
- [ ] NestJS adapter (guards, decorators, DI-resolved services)
- [ ] Inter-procedural taint engine (A03: SQL/NoSQL/command injection)
- [ ] Benchmark harness vs. Semgrep and CodeQL on real open-source apps
- [ ] SARIF output + GitHub Action
- [ ] Exploit-based verification in a sandbox (confirmed findings only)
- [ ] `scanner ui` — local dashboard

## License

MIT
