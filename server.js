
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    app: "Milton Financials",
    message: "Backend is running",
    supabaseConfigured: Boolean(
      process.env.SUPABASE_URL &&
      process.env.SUPABASE_SERVICE_ROLE_KEY
    )
  });
});

app.use(
  express.static(path.join(__dirname, "public"))
);

app.get("/{*path}", (req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found"
    });
  }

  res.sendFile(
    path.join(__dirname, "index.html"),
    (err) => {
      if (err) next(err);
    }
  );
});

app.use((err, _req, res, _next) => {
  console.error("Server error:", err.message);
  res.status(500).json({
    error: "Internal server error"
  });
});

app.listen(PORT, () => {
  console.log(
    `Milton Financials server listening on port ${PORT}`
  );
});
