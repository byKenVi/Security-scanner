import express from "express";
import { requireAuth } from "./middleware/auth";
import ordersRouter from "./routes/orders";
import usersRouter from "./routes/users";
import adminRouter from "./routes/admin";
import { db } from "./db";

const app = express();
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  res.json({ token: db.issueToken(user, password) });
});

// CORRIGÉ : requête paramétrée
app.get("/products/search", async (req, res) => {
  const rows = await db.query("SELECT * FROM products WHERE name LIKE $1", [`%${req.query.q}%`]);
  res.json(rows);
});

app.use("/api/orders", requireAuth, ordersRouter);
app.use("/api/users", usersRouter);
app.use("/admin", requireAuth, adminRouter);

export default app;
