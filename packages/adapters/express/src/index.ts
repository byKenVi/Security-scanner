import * as fs from "node:fs";
import * as path from "node:path";
import {
  Node,
  Project,
  SyntaxKind,
  type CallExpression,
  type SourceFile,
  type VariableDeclaration,
} from "ts-morph";
import {
  extractPathParams,
  joinPaths,
  resourceKey,
  type AuthFacts,
  type HttpMethod,
  type InputSource,
  type MiddlewareInfo,
  type OwnershipKind,
  type RouteInfo,
  type RouteInput,
  type SourceLocation,
} from "@scanner/core";

/* ------------------------------------------------------------------ */
/* Types internes                                                      */
/* ------------------------------------------------------------------ */

interface Instance {
  kind: "app" | "router";
  name: string;
  decl: VariableDeclaration;
  registrations: Registration[];
  mounted: boolean;
}

type UseItem = { type: "middleware"; node: Node } | { type: "router"; instance: Instance };

type Registration =
  | { type: "route"; method: HttpMethod; path: string; middlewares: Node[]; handler: Node; node: CallExpression }
  | { type: "use"; prefix: string; items: UseItem[]; node: CallExpression };

interface ActiveMiddleware {
  prefix: string; // "" = s'applique à toutes les routes suivantes
  info: MiddlewareInfo;
}

const HTTP_METHODS: Record<string, HttpMethod> = {
  get: "GET",
  post: "POST",
  put: "PUT",
  patch: "PATCH",
  delete: "DELETE",
  all: "ALL",
};

const INPUT_SOURCES: InputSource[] = ["params", "query", "body", "headers", "cookies"];
const IDENTITY_FIELDS = ["id", "_id", "userId", "sub"];

/* ------------------------------------------------------------------ */
/* Point d'entrée                                                      */
/* ------------------------------------------------------------------ */

export interface ExtractOptions {
  root: string;
}

export function extractExpressRoutes({ root }: ExtractOptions): RouteInfo[] {
  const absRoot = path.resolve(root);
  const project = loadProject(absRoot);
  const ctx = new Context(absRoot);

  // 1. Repérer les instances express() / Router()
  for (const sf of project.getSourceFiles()) {
    for (const decl of sf.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      const kind = expressInstanceKind(decl);
      if (kind) ctx.instances.set(decl, { kind, name: decl.getName(), decl, registrations: [], mounted: false });
    }
  }

  // 2. Collecter les enregistrements (app.get, router.use, …)
  for (const sf of project.getSourceFiles()) {
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      collectRegistration(ctx, call);
    }
  }
  for (const inst of ctx.instances.values()) {
    inst.registrations.sort((a, b) => a.node.getStart() - b.node.getStart());
  }

  // 3. Parcourir depuis chaque app, puis les routers jamais montés
  const routes: RouteInfo[] = [];
  for (const inst of ctx.instances.values()) {
    if (inst.kind === "app") walk(ctx, inst, "", [], routes, new Set());
  }
  for (const inst of ctx.instances.values()) {
    if (inst.kind === "router" && !inst.mounted) walk(ctx, inst, "", [], routes, new Set());
  }
  return routes;
}

/* ------------------------------------------------------------------ */
/* Chargement du projet                                                */
/* ------------------------------------------------------------------ */

function loadProject(absRoot: string): Project {
  const tsconfig = path.join(absRoot, "tsconfig.json");
  if (fs.existsSync(tsconfig)) {
    return new Project({ tsConfigFilePath: tsconfig, skipFileDependencyResolution: true });
  }
  const project = new Project({ compilerOptions: { allowJs: true, checkJs: false } });
  project.addSourceFilesAtPaths([
    path.join(absRoot, "**/*.{ts,js,mjs,cjs}"),
    "!" + path.join(absRoot, "**/node_modules/**"),
    "!" + path.join(absRoot, "**/*.d.ts"),
  ]);
  return project;
}

class Context {
  instances = new Map<Node, Instance>();
  constructor(public root: string) {}

  loc(node: Node): SourceLocation {
    return {
      file: path.relative(this.root, node.getSourceFile().getFilePath()),
      line: node.getStartLineNumber(),
    };
  }

  instanceOf(node: Node): Instance | undefined {
    const decl = resolveDeclaration(node);
    return decl ? this.instances.get(decl) : undefined;
  }
}

/* ------------------------------------------------------------------ */
/* Résolution de symboles                                              */
/* ------------------------------------------------------------------ */

/** Suit les imports/alias jusqu'à la déclaration réelle. */
function resolveDeclaration(node: Node): Node | undefined {
  let symbol = node.getSymbol();
  if (!symbol) return undefined;
  if (symbol.isAlias()) symbol = symbol.getAliasedSymbol() ?? symbol;
  return symbol.getDeclarations()[0];
}

/** Vrai si l'identifiant vient de `import … from "express"` ou `require("express")`. */
function isFromExpress(node: Node): boolean {
  const symbol = node.getSymbol();
  const decl = symbol?.getDeclarations()[0];
  if (!decl) return false;
  const importDecl = decl.getFirstAncestorByKind(SyntaxKind.ImportDeclaration);
  if (importDecl) return importDecl.getModuleSpecifierValue() === "express";
  if (Node.isVariableDeclaration(decl)) {
    const init = decl.getInitializer();
    return !!init && /^require\(\s*["']express["']\s*\)/.test(init.getText());
  }
  return false;
}

function expressInstanceKind(decl: VariableDeclaration): "app" | "router" | null {
  const init = decl.getInitializer();
  if (!init || !Node.isCallExpression(init)) return null;
  const callee = init.getExpression();
  // express()
  if (Node.isIdentifier(callee) && isFromExpress(callee)) {
    return callee.getText() === "Router" ? "router" : "app";
  }
  // express.Router()
  if (Node.isPropertyAccessExpression(callee) && callee.getName() === "Router" && isFromExpress(callee.getExpression())) {
    return "router";
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Collecte des enregistrements                                        */
/* ------------------------------------------------------------------ */

function stringValue(node: Node | undefined): string | null {
  if (!node) return null;
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) return node.getLiteralValue();
  return null;
}

function collectRegistration(ctx: Context, call: CallExpression): void {
  const callee = call.getExpression();
  if (!Node.isPropertyAccessExpression(callee)) return;
  const instance = ctx.instanceOf(callee.getExpression());
  if (!instance) return;

  const methodName = callee.getName();
  const args = call.getArguments();

  if (methodName in HTTP_METHODS) {
    const routePath = stringValue(args[0]);
    if (routePath === null || args.length < 2) return; // ex: app.get("env")
    instance.registrations.push({
      type: "route",
      method: HTTP_METHODS[methodName],
      path: routePath,
      middlewares: args.slice(1, -1),
      handler: args[args.length - 1],
      node: call,
    });
    return;
  }

  if (methodName === "use") {
    const prefix = stringValue(args[0]);
    const rest = prefix === null ? args : args.slice(1);
    const items: UseItem[] = rest.map((arg) => {
      const target = ctx.instanceOf(arg);
      if (target && target.kind === "router") {
        target.mounted = true;
        return { type: "router", instance: target };
      }
      return { type: "middleware", node: arg };
    });
    instance.registrations.push({ type: "use", prefix: prefix ?? "", items, node: call });
  }
}

/* ------------------------------------------------------------------ */
/* Parcours et assemblage des routes                                   */
/* ------------------------------------------------------------------ */

function applies(active: ActiveMiddleware[], localPath: string): MiddlewareInfo[] {
  return active
    .filter((a) => a.prefix === "" || a.prefix === "/" || localPath === a.prefix || localPath.startsWith(a.prefix.replace(/\/$/, "") + "/"))
    .map((a) => a.info);
}

function walk(
  ctx: Context,
  instance: Instance,
  prefix: string,
  inherited: MiddlewareInfo[],
  out: RouteInfo[],
  stack: Set<Instance>,
): void {
  if (stack.has(instance)) return; // protection contre les cycles
  stack.add(instance);
  const active: ActiveMiddleware[] = inherited.map((info) => ({ prefix: "", info }));

  for (const reg of instance.registrations) {
    if (reg.type === "use") {
      const before: MiddlewareInfo[] = [];
      for (const item of reg.items) {
        if (item.type === "middleware") {
          const info = classifyMiddleware(ctx, item.node);
          before.push(info);
          if (!reg.items.some((i) => i.type === "router")) active.push({ prefix: reg.prefix, info });
        } else {
          const chain = [...applies(active, reg.prefix || "/"), ...before];
          walk(ctx, item.instance, joinPaths(prefix, reg.prefix), chain, out, stack);
        }
      }
      continue;
    }

    const fullPath = joinPaths(prefix, reg.path);
    const middlewares = [...applies(active, reg.path), ...reg.middlewares.map((m) => classifyMiddleware(ctx, m))];
    const handler = analyzeHandler(ctx, reg.handler);
    out.push({
      method: reg.method,
      path: fullPath,
      pathParams: extractPathParams(fullPath),
      handler: handler.ref,
      location: ctx.loc(reg.node),
      middlewares,
      inputs: handler.inputs,
      auth: buildAuthFacts(middlewares, handler.ownership, handler.ownershipEvidence),
      resource: resourceKey(fullPath),
    });
  }
  stack.delete(instance);
}

function buildAuthFacts(
  middlewares: MiddlewareInfo[],
  ownership: OwnershipKind | null,
  ownershipEvidence: string[],
): AuthFacts {
  const evidence: string[] = [];
  const authMw = middlewares.filter((m) => m.kind === "authentication");
  const roleMw = middlewares.filter((m) => m.kind === "role");
  for (const m of authMw) evidence.push(`authentification par ${m.name}`);
  for (const m of roleMw) evidence.push(`contrôle de rôle par ${m.name}`);
  evidence.push(...ownershipEvidence);
  return {
    authenticated: authMw.length > 0,
    roles: [...new Set(roleMw.flatMap((m) => m.roles))],
    ownership,
    evidence,
  };
}

/* ------------------------------------------------------------------ */
/* Classification des middlewares                                      */
/* ------------------------------------------------------------------ */

function functionLike(node: Node | undefined): Node | undefined {
  if (!node) return undefined;
  if (Node.isArrowFunction(node) || Node.isFunctionExpression(node) || Node.isFunctionDeclaration(node) || Node.isMethodDeclaration(node)) {
    return node;
  }
  if (Node.isVariableDeclaration(node)) return functionLike(node.getInitializer());
  return undefined;
}

function classifyMiddleware(ctx: Context, node: Node): MiddlewareInfo {
  const name = node.getText().length > 60 ? node.getText().slice(0, 57) + "..." : node.getText();
  let body: Node | undefined;
  let literalArgs: string[] = [];

  if (Node.isIdentifier(node) || Node.isPropertyAccessExpression(node)) {
    body = functionLike(resolveDeclaration(node));
  } else if (Node.isCallExpression(node)) {
    // fabrique : requireRole("admin"), passport.authenticate("jwt")
    body = functionLike(resolveDeclaration(node.getExpression()));
    literalArgs = node.getArguments().map(stringValue).filter((v): v is string => v !== null);
  } else {
    body = functionLike(node);
  }

  const signals = body ? bodySignals(body) : { auth: false, role: false, comparedRoles: [] as string[] };
  let kind: MiddlewareInfo["kind"] = "other";
  if (signals.role) kind = "role";
  else if (signals.auth) kind = "authentication";
  else if (/role|admin|permission|authori[sz]e/i.test(name)) kind = "role";
  else if (/auth|jwt|passport|session|protect|login/i.test(name)) kind = "authentication";

  const roles = kind === "role" ? [...new Set([...literalArgs, ...signals.comparedRoles])] : [];
  return { name, kind, roles, location: body ? ctx.loc(body) : ctx.loc(node) };
}

/** Indices comportementaux dans le corps d'un middleware. */
function bodySignals(body: Node): { auth: boolean; role: boolean; comparedRoles: string[] } {
  let status401 = false;
  let status403 = false;
  let verifiesToken = false;
  let setsUser = false;
  let readsRole = false;
  const comparedRoles: string[] = [];

  for (const call of body.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression().getText();
    const firstArg = call.getArguments()[0]?.getText();
    if (/(^|\.)(status|sendStatus)$/.test(callee) && firstArg === "401") status401 = true;
    if (/(^|\.)(status|sendStatus)$/.test(callee) && firstArg === "403") status403 = true;
    if (/(^|\.)verify\w*$/i.test(callee)) verifiesToken = true;
  }
  for (const bin of body.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    const op = bin.getOperatorToken().getKind();
    const left = bin.getLeft().getText();
    const right = bin.getRight();
    if (op === SyntaxKind.EqualsToken && /^req(uest)?\.user$/.test(left)) setsUser = true;
    if (/\.roles?\b|\.permissions?\b/.test(left) || /\.roles?\b/.test(right.getText())) {
      readsRole = true;
      const lit = stringValue(right) ?? stringValue(bin.getLeft());
      if (lit) comparedRoles.push(lit);
    }
  }
  if (/\.roles?\b|\.permissions?\b/.test(body.getText())) readsRole = true;

  return {
    auth: verifiesToken || setsUser || status401,
    role: readsRole && status403,
    comparedRoles,
  };
}

/* ------------------------------------------------------------------ */
/* Analyse des handlers                                                */
/* ------------------------------------------------------------------ */

interface HandlerAnalysis {
  ref: { name: string; location: SourceLocation };
  inputs: RouteInput[];
  ownership: OwnershipKind | null;
  ownershipEvidence: string[];
}

function analyzeHandler(ctx: Context, node: Node): HandlerAnalysis {
  const fn = Node.isIdentifier(node) || Node.isPropertyAccessExpression(node) ? functionLike(resolveDeclaration(node)) : functionLike(node);
  const name = Node.isIdentifier(node) || Node.isPropertyAccessExpression(node) ? node.getText() : "<anonyme>";
  if (!fn) {
    return { ref: { name, location: ctx.loc(node) }, inputs: [], ownership: null, ownershipEvidence: [] };
  }

  const reqName = requestParamName(fn);
  return {
    ref: { name, location: ctx.loc(fn) },
    inputs: collectInputs(fn, reqName),
    ...detectOwnership(ctx, fn, reqName),
  };
}

function requestParamName(fn: Node): string {
  const params = (fn as any).getParameters?.() ?? [];
  const first = params[0];
  if (first && Node.isIdentifier(first.getNameNode())) return first.getName();
  return "req";
}

function collectInputs(fn: Node, reqName: string): RouteInput[] {
  const seen = new Set<string>();
  const inputs: RouteInput[] = [];
  const add = (source: InputSource, name: string | null) => {
    const key = `${source}:${name}`;
    if (!seen.has(key)) {
      seen.add(key);
      inputs.push({ source, name });
    }
  };

  for (const pa of fn.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    if (pa.getExpression().getText() !== reqName) continue;
    const source = pa.getName() as InputSource;
    if (!INPUT_SOURCES.includes(source)) continue;

    const parent = pa.getParent();
    if (Node.isPropertyAccessExpression(parent) && parent.getExpression() === pa) {
      add(source, parent.getName()); // req.params.id
    } else if (Node.isVariableDeclaration(parent) && Node.isObjectBindingPattern(parent.getNameNode())) {
      for (const el of parent.getNameNode().asKindOrThrow(SyntaxKind.ObjectBindingPattern).getElements()) {
        add(source, el.getPropertyNameNode()?.getText() ?? el.getName()); // const { id } = req.params
      }
    } else {
      add(source, null); // req.body passé tel quel
    }
  }
  return inputs;
}

/**
 * Cherche les références à l'identité courante (req.user.id…) et regarde comment elles sont utilisées.
 */
function detectOwnership(
  ctx: Context,
  fn: Node,
  reqName: string,
): { ownership: OwnershipKind | null; ownershipEvidence: string[] } {
  const identityRe = new RegExp(`^${reqName}\\.user\\??\\.(${IDENTITY_FIELDS.join("|")})$`);
  let comparison: string | null = null;
  let scoped: string | null = null;

  for (const pa of fn.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    if (!identityRe.test(pa.getText())) continue;

    for (const anc of pa.getAncestors()) {
      if (anc === fn || Node.isStatement(anc)) break;
      if (Node.isBinaryExpression(anc) && isComparison(anc.getOperatorToken().getKind())) {
        comparison ??= `ligne ${anc.getStartLineNumber()} : ${anc.getText()}`;
        break;
      }
      if (Node.isCallExpression(anc) && anc.getArguments().some((a) => a.getPos() <= pa.getPos() && pa.getEnd() <= a.getEnd())) {
        scoped ??= `ligne ${anc.getStartLineNumber()} : identité passée à ${anc.getExpression().getText()}()`;
        break;
      }
    }
  }

  if (comparison) return { ownership: "comparison", ownershipEvidence: [`vérification du propriétaire (${comparison})`] };
  if (scoped) return { ownership: "scoped-query", ownershipEvidence: [`requête filtrée sur l'utilisateur (${scoped})`] };
  return { ownership: null, ownershipEvidence: [] };
}

function isComparison(kind: SyntaxKind): boolean {
  return (
    kind === SyntaxKind.EqualsEqualsEqualsToken ||
    kind === SyntaxKind.ExclamationEqualsEqualsToken ||
    kind === SyntaxKind.EqualsEqualsToken ||
    kind === SyntaxKind.ExclamationEqualsToken
  );
}

export type { SourceFile };
