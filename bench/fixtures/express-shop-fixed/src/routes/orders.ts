import { Router } from "express";
import { db } from "../db";

const router = Router();

// Liste filtrée sur l'utilisateur courant : OK
router.get("/", async (req: any, res) => {
  const rows = await db.query("SELECT * FROM orders WHERE user_id = $1", [req.user.id]);
  res.json(rows);
});

// Vérification du propriétaire : OK
router.get("/:id", async (req: any, res) => {
  const [order] = await db.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
  if (order.userId !== req.user.id) {
    return res.status(403).end();
  }
  res.json(order);
});

// Vérification du propriétaire : OK
router.put("/:id", async (req: any, res) => {
  const [order] = await db.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
  if (order.userId !== req.user.id) {
    return res.status(403).end();
  }
  await db.query("UPDATE orders SET note = $1 WHERE id = $2", [req.body.note, req.params.id]);
  res.json({ updated: true });
});

// CORRIGÉ : suppression filtrée sur le propriétaire
async function deleteOrder(req: any, res: any) {
  await db.query("DELETE FROM orders WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
  res.status(204).end();
}
router.delete("/:id", deleteOrder);

export default router;
