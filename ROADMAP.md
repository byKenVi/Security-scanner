# Roadmap

Target: a credible, published security research tool by **mid-January 2027** (Fall 2027 application deadlines), with numbers to show.

Every milestone follows the same loop: **fixture + `expected.json` first → code → `pnpm test` green → commit.**
A milestone is done only when its "Done when" criteria are met.

| # | Milestone | Target date | Why it matters |
|---|---|---|---|
| M1 | Express route model + A01 deviance rules | ✅ Oct 15 | Foundation |
| M1.5 | Publish + hygiene | Oct 25 | Public repo = visible work |
| M2 | NestJS adapter + inter-procedural ownership | Nov 15 | Your stack; real apps use services |
| M3 | Taint engine (A03 injection) | Dec 15 | Second research contribution |
| M4 | Benchmark + real-world bugs | Jan 10 | Numbers and CVEs for applications |
| M5 | Adoption: SARIF, GitHub Action, npm | Jan 20 | Stars and real users |
| M6 | arXiv preprint | Feb 15 | Academic proof |
| M7 | Exploit-based verification (sandbox) | Apr 2027 | "Confirmed findings only" |
| M8 | `scanner ui` local dashboard | After M7 | Demo polish |

---

## M1.5 — Publish + hygiene (by Oct 25)

- [ ] Pick the final project name; rename `scanner` in package names, CLI binary and README
- [ ] Translate all CLI and finding messages to **English** (international audience: profs, GitHub)
- [ ] Support `router.route("/x").get(...).put(...)` chains (+ fixture case)
- [ ] GitHub Actions workflow: `pnpm install && pnpm typecheck && pnpm test` on every push/PR
- [ ] Push to `github.com/byKenVi/<name>`, add topics (`security`, `sast`, `owasp`, `express`, `nestjs`, `typescript`), pin it on the profile

**Done when:** repo is public, CI badge is green, README renders cleanly.

---

## M2 — NestJS adapter + inter-procedural ownership (by Nov 15)

Fixtures first:
- [ ] `bench/fixtures/nest-shop`: controllers, services, `@UseGuards` at class and method level, a global guard via `APP_GUARD`, `@Roles()` + `RolesGuard`, `@Public()` opt-out decorator, ownership check **inside a service**, 3–4 planted A01 bugs
- [ ] `bench/fixtures/nest-shop-fixed`: same app, bugs fixed (expected: 0 findings)

Adapter (`packages/adapters/nestjs`):
- [ ] Discover controllers (`@Controller('prefix')`) and route methods (`@Get`, `@Post`, `@Put`, `@Patch`, `@Delete`, `@All`)
- [ ] Full paths: global prefix (`app.setGlobalPrefix`) + controller prefix + method path
- [ ] Guards: class-level + method-level + global (`APP_GUARD`, `app.useGlobalGuards`); classify by analyzing `canActivate()`
- [ ] Roles: `@Roles('admin')` / `@SetMetadata('roles', …)` read as role requirements
- [ ] Public opt-out: `@Public()` / `@SetMetadata('isPublic', true)` cancels a global auth guard
- [ ] Inputs: `@Param`, `@Query`, `@Body` (+ DTO class), `@Req`, `@Headers`
- [ ] Identity: `@Req() req` → `req.user.id`, and custom `@CurrentUser() user` → `user.id`

Shared inter-procedural analysis (`packages/core` or new `packages/dataflow`):
- [ ] Resolve `this.ordersService.remove(id, user.id)` through constructor injection using the type checker
- [ ] Function summaries: "parameter N is compared to / filtered by the identity" — computed once, reused at each call site, depth limit 5
- [ ] Use summaries in **both** adapters (removes the Express "intra-procedural only" limitation)
- [ ] Add an Express fixture case where ownership is checked in a service

**Done when:** all nest fixtures pass, Express fixtures still pass, 0 false positives on fixed twins.

---

## M3 — Taint engine, A03 injection (by Dec 15)

- [ ] Rule spec in YAML (`packages/analyzers/taint/rules/*.yaml`): sources, sinks, sanitizers
  - Sources: route inputs from the route model (`params`, `query`, `body`, `headers`, `cookies`)
  - Sinks: `pg`/`mysql2` `query` with concatenation or template literals, `sequelize.query`, `knex.raw`, Prisma `$queryRawUnsafe` / `$executeRawUnsafe`, TypeORM `query`, Mongoose `$where` + operator injection, `child_process.exec`, `eval` / `new Function`, `fs` paths (traversal), `res.redirect` (open redirect)
  - Sanitizers: parameterized queries (`$1` + params array), `parseInt`/`Number`, `class-validator` DTOs, `zod.parse`, `path.basename`
- [ ] Intra-procedural propagation (assignments, destructuring, template literals, string concat, object/array members)
- [ ] Inter-procedural via the M2 summaries ("param N flows to sink X")
- [ ] Every finding carries the **full trace**: source → each step (file:line) → sink
- [ ] Fixtures: `express-injection` (SQL, NoSQL, command, path traversal, redirect) + fixed twin; NestJS case through a service

**Done when:** the SQLi in `express-shop` is detected, all injection fixtures pass, fixed twins report 0.

---

## M4 — Benchmark + real-world bugs (by Jan 10)

- [ ] `bench/harness`: run this tool, **Semgrep** (`p/javascript`, `p/owasp-top-ten`) and **CodeQL** (`javascript-security-extended`) on every fixture; output precision / recall / false positives / runtime as a Markdown table
- [ ] Known vulnerable apps: **OWASP Juice Shop**, **NodeGoat**, **DVNA** — map their documented vulns to `expected.json`
- [ ] Real-world scan: 50–100 open-source Express/NestJS apps from GitHub (filter: >100 stars, has auth, active). Triage every finding by hand, record true/false positives
- [ ] Responsible disclosure for confirmed bugs (GitHub private security advisory, or maintainers' email; huntr for npm packages). Track in a private file, publish only after fixes
- [ ] Results table + methodology in README

**Done when:** the README shows a comparison table vs Semgrep/CodeQL and the number of confirmed real-world bugs.

---

## M5 — Adoption (by Jan 20)

- [ ] `--format sarif` output (GitHub code scanning reads it natively)
- [ ] GitHub Action (`action.yml`): scan on every PR, upload SARIF
- [ ] Publish to npm so `npx <name> scan .` works without cloning
- [ ] `--fail-on high` threshold, `.scannerignore` / inline `// scanner-ignore: <rule>` suppressions
- [ ] 30-second demo GIF in README; short post on LinkedIn / dev.to / Reddit r/netsec

**Done when:** a stranger can add the Action to their repo in 2 minutes.

---

## M6 — arXiv preprint (by Feb 15)

- [ ] 6–8 pages (cs.CR): problem → route model → deviance rules → taint → evaluation (M4 numbers) → limitations → related work (Engler 2001, CodeQL, Semgrep, access-control detection literature)
- [ ] arXiv requires an **endorser** for a first cs.CR submission: ask one of the professors you are contacting — a natural, concrete reason to start a conversation
- [ ] Link the preprint from README and from application documents

---

## M7 — Exploit-based verification (Feb–Apr 2027)

- [ ] Docker sandbox: install deps, start the app, seed a database
- [ ] Create two test users A and B; for each A01 finding, have B access A's object → confirmed if it succeeds
- [ ] Injection: error-based and time-based probes on the traced input
- [ ] Optional: LLM generates the HTTP exploit from the trace + route model; **execution decides**, never the LLM
- [ ] Findings marked `confirmed` / `unconfirmed`; `--confirmed-only` mode

---

## M8 — `scanner ui` (after M7)

Local dashboard on `localhost` reading the JSON report: route map with access-control coverage, taint traces step by step, suggested fixes as diffs. No server, no account, code never leaves the machine.

---

## Using this roadmap with Claude Code

Start each session with: *"Read CLAUDE.md and ROADMAP.md. We are working on M<x>, task: <task>."*
One milestone = one git branch. Tick the boxes in this file as tasks land.
