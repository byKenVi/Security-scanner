import type { Finding, RouteInfo } from "@scanner/core";

/**
 * Analyse par incohérence (« bugs as deviant behavior », Engler et al., SOSP 2001).
 *
 * Idée : on n'impose pas une politique de sécurité de l'extérieur. On compare chaque route
 * à ses voisines sur la même ressource. Si la majorité des routes de /api/orders/:id
 * vérifient le propriétaire et qu'une seule ne le fait pas, c'est elle qui est suspecte.
 * Cette approche limite les faux positifs : on ne signale rien sans « témoin » dans le code.
 */
export function analyzeAccessControl(routes: RouteInfo[]): Finding[] {
  const findings: Finding[] = [];
  const groups = new Map<string, RouteInfo[]>();
  for (const r of routes) {
    const g = groups.get(r.resource) ?? [];
    g.push(r);
    groups.set(r.resource, g);
  }

  for (const [resource, group] of groups) {
    const withParams = group.filter((r) => r.pathParams.length > 0);

    for (const route of group) {
      const peers = group.filter((p) => p !== route);
      const paramPeers = withParams.filter((p) => p !== route);

      // R1 — route sur un objet identifié (:id) sans authentification, alors que ses voisines en ont une
      if (route.pathParams.length > 0 && !route.auth.authenticated) {
        const witnesses = paramPeers.filter((p) => p.auth.authenticated);
        if (witnesses.length > 0) {
          findings.push(
            make(route, {
              ruleId: "missing-authentication",
              cwe: "CWE-306",
              severity: "critical",
              title: "Authentification manquante",
              message: `${route.method} ${route.path} est accessible sans authentification, alors que ${witnesses.length} route(s) de ${resource} l'exigent.`,
              witnesses,
            }),
          );
          continue;
        }
      }

      // R2 — objet identifié par l'URL, utilisateur authentifié, mais aucune vérification du propriétaire
      if (route.pathParams.length > 0 && route.auth.authenticated && route.auth.roles.length === 0 && !route.auth.ownership) {
        const witnesses = paramPeers.filter((p) => p.auth.ownership !== null);
        if (witnesses.length > 0) {
          findings.push(
            make(route, {
              ruleId: "missing-ownership-check",
              cwe: "CWE-639",
              severity: "high",
              title: "IDOR probable : vérification du propriétaire manquante",
              message: `${route.method} ${route.path} accède à l'objet :${route.pathParams[0]} sans vérifier qu'il appartient à l'utilisateur, alors que ${witnesses.length} route(s) voisine(s) le vérifient.`,
              witnesses,
            }),
          );
          continue;
        }
      }

      // R3 — contrôle de rôle absent alors que les routes voisines en exigent un
      if (route.auth.roles.length === 0) {
        const witnesses = peers.filter((p) => p.auth.roles.length > 0);
        if (witnesses.length > 0 && witnesses.length * 2 >= peers.length) {
          const roles = [...new Set(witnesses.flatMap((w) => w.auth.roles))];
          findings.push(
            make(route, {
              ruleId: "missing-role-check",
              cwe: "CWE-285",
              severity: "high",
              title: "Contrôle de rôle manquant",
              message: `${route.method} ${route.path} n'exige aucun rôle, alors que ${witnesses.length} route(s) de ${resource} exigent : ${roles.join(", ")}.`,
              witnesses,
            }),
          );
        }
      }
    }
  }
  return findings;
}

function make(
  route: RouteInfo,
  f: { ruleId: string; cwe: string; severity: Finding["severity"]; title: string; message: string; witnesses: RouteInfo[] },
): Finding {
  return {
    ruleId: f.ruleId,
    owasp: "A01:2021",
    cwe: f.cwe,
    severity: f.severity,
    confidence: f.witnesses.length >= 2 ? "high" : "medium",
    title: f.title,
    message: f.message,
    route: { method: route.method, path: route.path, location: route.location },
    evidence: f.witnesses.map(
      (w) => `témoin : ${w.method} ${w.path} (${w.location.file}:${w.location.line}) — ${w.auth.evidence.slice(-1)[0] ?? "protégée"}`,
    ),
  };
}
