import { Router } from "express";
import { requireAuth } from "../middleware/auth";
import { db } from "../db";

const router = Router();

// Enregistrée AVANT router.use(requireAuth) : publique, et c'est voulu
router.post("/register", async (req, res) => {
  const { email, password } = req.body;
  await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, password]);
  res.status(201).end();
});

router.use(requireAuth);

router.get("/me", async (req: any, res) => {
  const [user] = await db.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
  res.json(user);
});

// CORRIGÉ : un utilisateur ne lit que son propre profil
router.get("/:id", async (req: any, res) => {
  if (req.params.id !== req.user.id) {
    return res.status(403).end();
  }
  const [user] = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(user);
});

// Vérification du propriétaire : OK
router.patch("/:id", async (req: any, res) => {
  if (req.params.id !== req.user.id) {
    return res.status(403).end();
  }
  await db.query("UPDATE users SET name = $1 WHERE id = $2", [req.body.name, req.params.id]);
  res.json({ updated: true });
});

export default router;
