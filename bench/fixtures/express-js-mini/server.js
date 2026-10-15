const express = require("express");
const passport = require("passport");
const notes = require("./notes");

const app = express();

function isAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.sendStatus(403);
  next();
}

// middleware limité à un préfixe : ne doit s'appliquer qu'à /admin/*
app.use("/admin", passport.authenticate("jwt"), isAdmin);

app.get("/", (req, res) => res.send("home"));
app.get("/admin/stats", (req, res) => res.json({}));

app.use("/notes", passport.authenticate("jwt"), notes);

module.exports = app;
