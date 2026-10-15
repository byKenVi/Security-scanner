const express = require("express");
const store = require("./store");

const router = express.Router();

router.get("/:noteId", async (req, res) => {
  const note = await store.find(req.params.noteId);
  if (note.ownerId !== req.user.id) return res.sendStatus(404);
  res.json(note);
});

// VULN A01 (IDOR)
router.put("/:noteId", async (req, res) => {
  const { title, body } = req.body;
  await store.update(req.params.noteId, { title, body });
  res.sendStatus(204);
});

module.exports = router;
