const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.get("/user", async (req, res, db) => {
  const username = req.query.username;
  const sql = "SELECT * FROM users WHERE username = '" + username + "'";
  const rows = await db.query(sql); // CWE-89 SQL Injection
  res.json(rows);
});

app.get("/view", (req, res) => {
  const comment = req.query.comment || "";
  res.send("<html><body>" + comment + "</body></html>"); // CWE-79 XSS
});

app.get("/admin/reset", async (req, res, adminService) => {
  await adminService.resetPassword(req.query.userId); // CWE-306 Missing Authentication
  res.sendStatus(200);
});

app.get("/file", (req, res) => {
  const file = req.query.name;
  const data = fs.readFileSync(path.join("/srv/docs", file), "utf8"); // CWE-22 Path Traversal
  res.send(data);
});

module.exports = app;
