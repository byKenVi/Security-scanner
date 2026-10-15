/**
 * Modèle commun à tous les adaptateurs (Express, NestJS…) et analyseurs.
 * Les adaptateurs produisent des `RouteInfo`, les analyseurs produisent des `Finding`.
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "ALL";

export interface SourceLocation {
  file: string; // chemin relatif à la racine du projet scanné
  line: number;
}

export type MiddlewareKind = "authentication" | "role" | "other";

export interface MiddlewareInfo {
  name: string; // ex: "requireAuth", "requireRole('admin')"
  kind: MiddlewareKind;
  roles: string[]; // rôles exigés, si connus (arguments littéraux)
  location?: SourceLocation;
}

export type InputSource = "params" | "query" | "body" | "headers" | "cookies";

export interface RouteInput {
  source: InputSource;
  name: string | null; // null = l'objet entier (ex: req.body)
}

/**
 * Comment le handler restreint l'accès aux données de l'utilisateur courant :
 * - "comparison"   : compare une donnée à l'identité courante (order.userId !== req.user.id)
 * - "scoped-query" : passe l'identité courante à la couche de données (WHERE user_id = req.user.id)
 */
export type OwnershipKind = "comparison" | "scoped-query";

export interface AuthFacts {
  authenticated: boolean;
  roles: string[];
  ownership: OwnershipKind | null;
  evidence: string[]; // explications lisibles, pour le rapport
}

export interface RouteInfo {
  method: HttpMethod;
  path: string; // chemin complet, préfixes de montage inclus
  pathParams: string[];
  handler: { name: string; location: SourceLocation };
  location: SourceLocation; // où la route est déclarée
  middlewares: MiddlewareInfo[]; // chaîne complète, dans l'ordre d'exécution
  inputs: RouteInput[];
  auth: AuthFacts;
  resource: string; // clé de regroupement, ex: "/api/orders"
}

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  ruleId: string;
  owasp: string; // ex: "A01:2021"
  cwe: string; // ex: "CWE-639"
  severity: Severity;
  confidence: "high" | "medium" | "low";
  title: string;
  message: string;
  route: Pick<RouteInfo, "method" | "path" | "location">;
  evidence: string[];
}

export interface ScanResult {
  root: string;
  framework: string;
  routes: RouteInfo[];
  findings: Finding[];
}

/** Clé de ressource : segments du chemin avant le premier paramètre. */
export function resourceKey(path: string): string {
  const segments = path.split("/").filter(Boolean);
  const idx = segments.findIndex((s) => s.startsWith(":"));
  const kept = idx === -1 ? segments : segments.slice(0, idx);
  return "/" + kept.join("/");
}

export function joinPaths(...parts: string[]): string {
  const joined = parts
    .map((p) => p.trim())
    .filter((p) => p && p !== "/")
    .map((p) => p.replace(/^\/+|\/+$/g, ""))
    .join("/");
  return "/" + joined;
}

export function extractPathParams(path: string): string[] {
  return path
    .split("/")
    .filter((s) => s.startsWith(":"))
    .map((s) => s.slice(1).replace(/\?$/, ""));
}
