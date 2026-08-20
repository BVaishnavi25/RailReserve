// server.js — a minimal static file server for the Rail.Reserve frontend.
// The frontend is a static HTML/CSS/JS app (no build step); this just
// serves the files in ./public and lets index.html talk to the backend
// API (see public/config.js for the backend URL) over HTTP.

const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static__dirname));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Rail.Reserve frontend listening on http://localhost:${PORT}`);
});
