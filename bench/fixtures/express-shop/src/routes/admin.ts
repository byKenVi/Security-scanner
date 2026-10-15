import { Router } from "express";
import { requireRole } from "../middleware/roles";
import { db } from "../db";

const router = Router();

router.get("/users", requireRole("admin"), async (_req, res) => {
  res.json(await db.query("SELECT * FROM users"));
});

router.delete("/users/:id", requireRole("admin"), async (req, res) => {
  await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.status(204).end();
});

// VULN A01 (contrôle de rôle manquant) : tout utilisateur connecté peut promouvoir un compte
router.post("/users/:id/promote", async (req, res) => {
  await db.query("UPDATE users SET role = 'admin' WHERE id = $1", [req.params.id]);
  res.json({ promoted: true });
});

export default router;
