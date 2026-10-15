import jwt from "jsonwebtoken";

export function requireAuth(req: any, res: any, next: any) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ error: "unauthenticated" });
  }
  try {
    req.user = jwt.verify(header.replace("Bearer ", ""), process.env.JWT_SECRET!);
    next();
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
}
