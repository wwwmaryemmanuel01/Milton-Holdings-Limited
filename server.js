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

// ========================================
// SUPABASE DATABASE CONNECTION
// ========================================

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

// ========================================
// SUPABASE AUTHENTICATION CONNECTION
// ========================================

const supabaseAuth =
  process.env.SUPABASE_URL &&
  process.env.SUPABASE_ANON_KEY
    ? createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_ANON_KEY,
        {
          auth: {
            persistSession: false,
            autoRefreshToken: false
          }
        }
      )
    : null;

// ========================================
// HEALTH CHECK
// ========================================

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    app: "Milton Financials",
    message: "Backend is running",
    supabaseConfigured: Boolean(supabase)
  });
});

// ========================================
// STAFF LOGIN API
// ========================================

app.post("/api/login", async (req, res) => {
  try {
    if (!supabaseAuth || !supabase) {
      return res.status(503).json({
        error: "Login service is not configured"
      });
    }

    const email = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    if (!email || !password || !email.includes("@")) {
      return res.status(400).json({
        error: "Please enter your registered email and password"
      });
    }

    const { data, error } =
      await supabaseAuth.auth.signInWithPassword({
        email,
        password
      });

    if (error || !data.user) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const { data: profile, error: profileError } = await supabase
      .from("staff_profiles")
      .select("id, full_name, phone, role")
      .eq("id", data.user.id)
      .maybeSingle();

    if (profileError || !profile) {
      await supabaseAuth.auth.signOut();

      return res.status(403).json({
        error: "No staff profile is linked to this account"
      });
    }

    const roles = {
      admin: "Administrator",
      administrator: "Administrator",
      "loan officer": "Loan Officer",
      cashier: "Cashier",
      manager: "Manager",
      director: "Director",
      "chief loan officer": "Chief Loan Officer",
      reporter: "Reporter",
      deleter: "Deleter"
    };

    const role = roles[String(profile.role || "").toLowerCase()];

    if (!role) {
      await supabaseAuth.auth.signOut();

      return res.status(403).json({
        error: "Your staff role is not recognized"
      });
    }

    return res.json({
      user: {
        id: data.user.id,
        fullName: profile.full_name || "",
        username: email,
        role: role
      },
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "Unable to complete login"
    });
  }
});

// ========================================
// PUBLIC WEBSITE
// ========================================

// Serve public/index.html at the main website URL.
app.use(express.static(path.join(__dirname, "public")));

// ========================================
// EXISTING STAFF MANAGEMENT SYSTEM
// ========================================

// Keep the original root index.html as the staff system.
app.get(["/staff", "/staff/"], (_req, res, next) => {
  res.sendFile(
    path.join(__dirname, "index.html"),
    (err) => {
      if (err) next(err);
    }
  );
});

// ========================================
// HANDLE UNKNOWN ROUTES
// ========================================

app.get("/{*path}", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found"
    });
  }

  return res.status(404).send("Page not found.");
});

// ========================================
// ERROR HANDLER
// ========================================

app.use((err, _req, res, _next) => {
  console.error("Server error:", err.message);

  res.status(500).json({
    error: "Internal server error"
  });
});

// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {
  console.log(`Milton Financials server listening on port ${PORT}`);

  if (!supabase) {
    console.error(
      "Supabase connection test skipped: environment variables are missing."
    );
    return;
  }

  supabase
    .from("payment_methods")
    .select("name", { head: true, count: "exact" })
    .then(({ count, error }) => {
      if (error) {
        console.error(
          "Supabase database test failed:",
          error.message
        );
      } else {
        console.log(
          `Supabase database test succeeded. Payment methods table is accessible. Row count: ${count}`
        );
      }
    })
    .catch(() => {
      console.error(
        "Supabase database test failed due to a network or unexpected error."
      );
    });
});
