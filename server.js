require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");

app.use(
helmet({
contentSecurityPolicy: false
})
);

app.use(express.json({ limit: "1mb" }));

let supabase = null;

if (
process.env.SUPABASE_URL &&
process.env.SUPABASE_SERVICE_ROLE_KEY
) {
supabase = createClient(
process.env.SUPABASE_URL,
process.env.SUPABASE_SERVICE_ROLE_KEY
);
}

app.get("/api/health", (_req, res) => {
res.json({
ok: true,
app: "Milton Financials",
message: "Backend is running",
supabaseConfigured: Boolean(supabase)
});
});

app.use(express.static(path.join(__dirname, "public")));

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
console.log("Milton Financials server listening on port ${PORT}");

if (!supabase) {
console.error("Supabase connection test skipped: environment variables are missing.");
return;
}

supabase
.from("payment_methods")
.select("name", { head: true, count: "exact" })
.then(({ count, error }) => {
if (error) {
console.error("Supabase database test failed:", error.message);
} else {
console.log(
"Supabase database test succeeded. Payment methods table is accessible. Row count: ${count}"
);
}
})
.catch(() => {
console.error("Supabase database test failed due to a network or unexpected error.");
});
});
