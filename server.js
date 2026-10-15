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

    const { data: profile, error: profileError } =
      await supabase
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
// AUTHENTICATED TABLE APIs
// ========================================

function bearerToken(req) {
  const header = String(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function authenticate(req, res, next) {
  try {
    if (!supabase) {
      return res.status(503).json({
        error: "Database service is not configured"
      });
    }

    const token = bearerToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Sign-in required"
      });
    }

    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data?.user) {
      return res.status(401).json({
        error: "Session is invalid or expired"
      });
    }

    req.authUser = data.user;
    req.accessToken = token;
    next();
  } catch (error) {
    console.error(
      "Authentication middleware error:",
      error.message
    );

    return res.status(401).json({
      error: "Unable to verify session"
    });
  }
}

async function staffProfile(userId) {
  const { data, error } = await supabase
    .from("staff_profiles")
    .select("id, full_name, phone, role")
    .eq("id", userId)
    .maybeSingle();

  if (error) throw error;

  return data || null;
}

async function requireStaff(req, res, next) {
  try {
    const profile = await staffProfile(req.authUser.id);

    if (!profile) {
      return res.status(403).json({
        error: "Staff access required"
      });
    }

    req.staffProfile = profile;
    next();
  } catch (error) {
    console.error(
      "Staff authorization error:",
      error.message
    );

    return res.status(500).json({
      error: "Unable to verify staff permissions"
    });
  }
}

const normalizeRole = value =>
  String(value || "").trim().toLowerCase();

const adminRoles = new Set([
  "admin",
  "administrator",
  "manager",
  "director"
]);

// ========================================
// CUSTOMER REGISTRATION
// ========================================

app.post("/api/auth/register", async (req, res) => {
  try {
    if (!supabaseAuth || !supabase) {
      return res.status(503).json({
        error: "Registration service is not configured"
      });
    }

    const fullName = String(
      req.body?.fullName || req.body?.name || ""
    ).trim();

    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    const phone = String(req.body?.phone || "").trim();
    const password = String(req.body?.password || "");
    const address = String(req.body?.address || "").trim();

    if (
      !fullName ||
      !email ||
      !phone ||
      password.length < 8
    ) {
      return res.status(400).json({
        error:
          "Full name, email, phone and a password of at least 8 characters are required"
      });
    }

    const { data: authData, error: authError } =
      await supabaseAuth.auth.signUp({
        email,
        password,
        options: {
          data: {
            full_name: fullName,
            phone,
            account_type: "customer"
          }
        }
      });

    if (authError) {
      return res.status(400).json({
        error: authError.message
      });
    }

    if (!authData.user) {
      return res.status(400).json({
        error: "Account could not be created"
      });
    }

    const { error: customerError } = await supabase
      .from("customers")
      .upsert(
        {
          id: authData.user.id,
          full_name: fullName,
          phone,
          email,
          address: address || null
        },
        { onConflict: "id" }
      );

    if (customerError) {
      console.error(
        "Customer profile insert failed:",
        customerError.message
      );

      return res.status(500).json({
        error:
          "Account was created but customer profile setup failed. Contact support before registering again."
      });
    }

    return res.status(201).json({
      user: {
        id: authData.user.id,
        fullName,
        email,
        phone,
        role: "customer"
      },
      access_token: authData.session?.access_token || null,
      refresh_token: authData.session?.refresh_token || null,
      email_confirmation_required: !authData.session
    });
  } catch (error) {
    console.error("Registration error:", error.message);

    return res.status(500).json({
      error: "Unable to register account"
    });
  }
});

// ========================================
// UNIFIED STAFF AND CUSTOMER LOGIN
// ========================================

app.post("/api/auth/login", async (req, res) => {
  try {
    if (!supabaseAuth || !supabase) {
      return res.status(503).json({
        error: "Login service is not configured"
      });
    }

    const email = String(
      req.body?.email || req.body?.username || ""
    )
      .trim()
      .toLowerCase();

    const password = String(req.body?.password || "");

    const requestedRole = normalizeRole(
      req.body?.role || "customer"
    );

    if (!email || !password || !email.includes("@")) {
      return res.status(400).json({
        error: "Enter your registered email and password"
      });
    }

    const { data, error } =
      await supabaseAuth.auth.signInWithPassword({
        email,
        password
      });

    if (error || !data?.user || !data?.session) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const staff = await staffProfile(data.user.id);

    if (staff) {
      if (requestedRole === "customer") {
        await supabaseAuth.auth.signOut({
          scope: "local"
        });

        return res.status(403).json({
          error: "Choose staff/admin login for this account"
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

      const role = roles[normalizeRole(staff.role)];

      if (!role) {
        return res.status(403).json({
          error: "Staff role is not recognized"
        });
      }

      return res.json({
        user: {
          id: data.user.id,
          fullName: staff.full_name || "",
          email,
          username: email,
          phone: staff.phone || "",
          role
        },
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token
      });
    }

    if (requestedRole !== "customer") {
      return res.status(403).json({
        error: "No staff profile is linked to this account"
      });
    }

    const {
      data: customer,
      error: customerError
    } = await supabase
      .from("customers")
      .select("id, full_name, phone, email, address, account_no")
      .eq("id", data.user.id)
      .maybeSingle();

    if (customerError || !customer) {
      return res.status(403).json({
        error: "No customer profile is linked to this account"
      });
    }

    return res.json({
      user: {
        id: customer.id,
        fullName: customer.full_name,
        name: customer.full_name,
        email: customer.email || email,
        phone: customer.phone,
        address: customer.address,
        accountNo: customer.account_no,
        role: "customer"
      },
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token
    });
  } catch (error) {
    console.error("Unified login error:", error.message);

    return res.status(500).json({
      error: "Unable to complete login"
    });
  }
});

// ========================================
// CURRENT USER PROFILE
// ========================================

app.get("/api/me", authenticate, async (req, res) => {
  try {
    const staff = await staffProfile(req.authUser.id);

    if (staff) {
      return res.json({
        user: {
          id: staff.id,
          fullName: staff.full_name,
          phone: staff.phone,
          role: staff.role
        }
      });
    }

    const { data, error } = await supabase
      .from("customers")
      .select("id, full_name, phone, email, address, account_no")
      .eq("id", req.authUser.id)
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return res.status(404).json({
        error: "Profile not found"
      });
    }

    return res.json({
      user: {
        id: data.id,
        fullName: data.full_name,
        phone: data.phone,
        email: data.email,
        address: data.address,
        accountNo: data.account_no,
        role: "customer"
      }
    });
  } catch (error) {
    console.error("Profile fetch error:", error.message);

    return res.status(500).json({
      error: "Unable to load profile"
    });
  }
});

// ========================================
// ENABLED PAYMENT METHODS
// ========================================

app.get("/api/payment-methods", async (_req, res) => {
  try {
    if (!supabase) {
      return res.status(503).json({
        error: "Database service is not configured"
      });
    }

    const { data, error } = await supabase
      .from("payment_methods")
      .select("id, name")
      .eq("is_enabled", true)
      .order("name");

    if (error) throw error;

    return res.json({
      paymentMethods: data || []
    });
  } catch (error) {
    console.error(
      "Payment methods fetch error:",
      error.message
    );

    return res.status(500).json({
      error: "Unable to load payment methods"
    });
  }
});

// ========================================
// STAFF CUSTOMER LIST
// ========================================

app.get(
  "/api/customers",
  authenticate,
  requireStaff,
  async (req, res) => {
    try {
      const role = normalizeRole(req.staffProfile.role);

      if (
        !adminRoles.has(role) &&
        role !== "loan officer" &&
        role !== "cashier"
      ) {
        return res.status(403).json({
          error: "Your staff role cannot view customers"
        });
      }

      const { data, error } = await supabase
        .from("customers")
        .select(
          "id, full_name, phone, email, address, national_id, created_at"
        )
        .order("created_at", { ascending: false })
        .limit(1000);

      if (error) throw error;

      return res.json({
        customers: data || []
      });
    } catch (error) {
      console.error(
        "Customers fetch error:",
        error.message
      );

      return res.status(500).json({
        error: "Unable to load customers"
      });
    }
  }
);

// ========================================
// LIST LOAN APPLICATIONS
// ========================================

app.get(
  "/api/loan-applications",
  authenticate,
  async (req, res) => {
    try {
      const staff = await staffProfile(req.authUser.id);

      let query = supabase
        .from("loan_applications")
        .select(
          "id, customer_id, amount, interest_rate, term_months, purpose, status, applied_at, reviewed_at, reviewed_by"
        )
        .order("applied_at", { ascending: false })
        .limit(1000);

      if (!staff) {
        query = query.eq("customer_id", req.authUser.id);
      } else {
        const role = normalizeRole(staff.role);

        if (
          !adminRoles.has(role) &&
          !["loan officer", "chief loan officer"].includes(role)
        ) {
          return res.status(403).json({
            error:
              "Your staff role cannot view loan applications"
          });
        }
      }

      const { data, error } = await query;

      if (error) throw error;

      return res.json({
        applications: data || []
      });
    } catch (error) {
      console.error(
        "Applications fetch error:",
        error.message
      );

      return res.status(500).json({
        error: "Unable to load loan applications"
      });
    }
  }
);

// ========================================
// CUSTOMER SUBMITS LOAN APPLICATION
// ========================================

app.post(
  "/api/loan-applications",
  authenticate,
  async (req, res) => {
    try {
      const staff = await staffProfile(req.authUser.id);

      if (staff) {
        return res.status(403).json({
          error:
            "Staff accounts cannot submit customer loan applications"
        });
      }

      const amount = Number(req.body?.amount);

      const interestRate = Number(
        req.body?.interest_rate ??
        req.body?.interestRate
      );

      const termMonths = Number(
        req.body?.term_months ??
        req.body?.termMonths
      );

      const purpose = String(
        req.body?.purpose || ""
      ).trim();

      if (
        !Number.isFinite(amount) ||
        amount <= 0 ||
        !Number.isFinite(interestRate) ||
        interestRate < 0 ||
        !Number.isInteger(termMonths) ||
        termMonths < 1 ||
        termMonths > 120
      ) {
        return res.status(400).json({
          error:
            "Enter a valid loan amount, interest rate and term"
        });
      }

      const {
        data: customer,
        error: customerError
      } = await supabase
        .from("customers")
        .select("id")
        .eq("id", req.authUser.id)
        .maybeSingle();

      if (customerError) throw customerError;

      if (!customer) {
        return res.status(403).json({
          error:
            "Customer profile is required before applying"
        });
      }

      const { data, error } = await supabase
        .from("loan_applications")
        .insert({
          customer_id: customer.id,
          amount,
          interest_rate: interestRate,
          term_months: termMonths,
          purpose: purpose || null,
          status: "pending"
        })
        .select(
          "id, customer_id, amount, interest_rate, term_months, purpose, status, applied_at"
        )
        .single();

      if (error) throw error;

      return res.status(201).json({
        application: data
      });
    } catch (error) {
      console.error(
        "Application create error:",
        error.message
      );

      return res.status(500).json({
        error: "Unable to submit loan application"
      });
    }
  }
);

// ========================================
// APPROVE OR REJECT LOAN APPLICATION
// Requires the Supabase RPC migration
// review_loan_application
// ========================================

app.patch(
  "/api/loan-applications/:id/status",
  authenticate,
  requireStaff,
  async (req, res) => {
    try {
      const role = normalizeRole(req.staffProfile.role);

      if (
        !adminRoles.has(role) &&
        !["loan officer", "chief loan officer"].includes(role)
      ) {
        return res.status(403).json({
          error:
            "Your staff role cannot review loan applications"
        });
      }

      const status = normalizeRole(req.body?.status);
      const reason = String(
        req.body?.reason || ""
      ).trim();

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({
          error: "Status must be approved or rejected"
        });
      }

      if (status === "rejected" && !reason) {
        return res.status(400).json({
          error: "A rejection reason is required"
        });
      }

      if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          String(req.params.id)
        )
      ) {
        return res.status(400).json({
          error: "Invalid loan application ID"
        });
      }

      // The database function locks the application and
      // changes its status atomically.
      // Approval creates one linked loans row.

      const { data, error } = await supabase.rpc(
        "review_loan_application",
        {
          p_application_id: req.params.id,
          p_status: status,
          p_reviewed_by: req.staffProfile.id,
          p_rejection_reason:
            status === "rejected" ? reason : null
        }
      );

      if (error) {
        if (
          error.code === "PGRST202" ||
          /review_loan_application/i.test(
            error.message || ""
          )
        ) {
          console.error(
            "Missing Supabase migration: review_loan_application"
          );

          return res.status(503).json({
            error:
              "Application review is not enabled yet. Apply the supplied Supabase migration first."
          });
        }

        throw error;
      }

      if (!data || data.error === "not_found") {
        return res.status(404).json({
          error: "Loan application not found"
        });
      }

      if (data.error === "already_reviewed") {
        return res.status(409).json({
          error:
            "This application has already been reviewed and cannot be changed."
        });
      }

      if (data.error) {
        return res.status(409).json({
          error:
            "Application could not be reviewed: " +
            data.error
        });
      }

      return res.json({
        application: data.application,
        loan: data.loan || null,
        alreadyReviewed: Boolean(data.already_reviewed)
      });
    } catch (error) {
      console.error(
        "Application review error:",
        error.message
      );

      return res.status(500).json({
        error: "Unable to update loan application"
      });
    }
  }
);

// ========================================
// PUBLIC WEBSITE
// ========================================

// Serve public/index.html at the main website URL.
app.use(express.static(path.join(__dirname, "public")));

// ========================================
// EXISTING STAFF MANAGEMENT SYSTEM
// ========================================

// Keep the root index.html as the staff system.
app.get(
  ["/staff", "/staff/"],
  (_req, res, next) => {
    res.sendFile(
      path.join(__dirname, "index.html"),
      (err) => {
        if (err) next(err);
      }
    );
  }
);

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
  console.log(
    `Milton Financials server listening on port ${PORT}`
  );

  if (!supabase) {
    console.error(
      "Supabase connection test skipped: environment variables are missing."
    );
    return;
  }

  supabase
    .from("payment_methods")
    .select("name", {
      head: true,
      count: "exact"
    })
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
