import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { extractExpressRoutes } from "@scanner/adapter-express";
import { analyzeAccessControl } from "@scanner/analyzer-access-control";

const FIXTURES = path.resolve(__dirname, "../bench/fixtures");
const IMPLEMENTED = new Set(["A01"]); // catégories OWASP déjà couvertes par un analyseur

interface Expected {
  routes?: { method: string; path: string; authenticated: boolean; roles: string[]; ownership: string | null }[];
  vulnerabilities: { owasp: string; rule: string; method: string; path: string }[];
}

for (const name of fs.readdirSync(FIXTURES)) {
  const dir = path.join(FIXTURES, name);
  const expected: Expected = JSON.parse(fs.readFileSync(path.join(dir, "expected.json"), "utf8"));
  const routes = extractExpressRoutes({ root: dir });
  const findings = analyzeAccessControl(routes);

  describe(name, () => {
    if (expected.routes) {
      it("extrait exactement les routes attendues", () => {
        const got = routes.map((r) => `${r.method} ${r.path}`).sort();
        const want = expected.routes!.map((r) => `${r.method} ${r.path}`).sort();
        expect(got).toEqual(want);
      });

      it("déduit les bons faits de contrôle d'accès", () => {
        for (const want of expected.routes!) {
          const got = routes.find((r) => r.method === want.method && r.path === want.path)!;
          expect({ route: `${want.method} ${want.path}`, ...pick(got.auth) }).toEqual({
            route: `${want.method} ${want.path}`,
            authenticated: want.authenticated,
            roles: want.roles,
            ownership: want.ownership,
          });
        }
      });
    }

    it("trouve toutes les failles A01 attendues, et rien d'autre", () => {
      const want = expected.vulnerabilities
        .filter((v) => IMPLEMENTED.has(v.owasp))
        .map((v) => `${v.rule} ${v.method} ${v.path}`)
        .sort();
      const got = findings.map((f) => `${f.ruleId} ${f.route.method} ${f.route.path}`).sort();
      expect(got).toEqual(want);
    });
  });
}

function pick(a: { authenticated: boolean; roles: string[]; ownership: string | null }) {
  return { authenticated: a.authenticated, roles: a.roles, ownership: a.ownership };
}
