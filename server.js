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
    console.error("Authentication middleware error:", error.message);

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
    console.error("Staff authorization error:", error.message);

    return res.status(500).json({
      error: "Unable to verify staff access"
    });
  }
}

async function requireStaff(req, res, next) {
  try {
    const profile = await staffProfile(req.authUser.id);
    if (!profile) {
      return res.status(403).json({ error: "Staff access required" });
    }
    req.staffProfile = profile;
    next();
  } catch (error) {
    console.error("Staff authorization error:", error.message);
    return res.status(500).json({
      error: "Unable to verify staff permissions"
    });
  }
}

const normalizeRole = value => String(value || "").trim().toLowerCase();
const adminRoles = new Set(["admin", "administrator", "manager", "director"]);

app.post("/api/auth/register", async (req, res) => {
  try {
    if (!supabaseAuth || !supabase) {
      return res.status(503).json({ error: "Registration service is not configured" });
    }

    const fullName = String(req.body?.fullName || req.body?.name || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const phone = String(req.body?.phone || "").trim();
    const password = String(req.body?.password || "");
    const address = String(req.body?.address || "").trim();

    if (!fullName || !email || !phone || password.length < 8) {
      return res.status(400).json({
        error: "Full name, email, phone and a password of at least 8 characters are required"
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

    if (authError) return res.status(400).json({ error: authError.message });
    if (!authData.user) {
      return res.status(400).json({ error: "Account could not be created" });
    }

    const { data: customerRecord, error: customerError } = await supabase
      .from("customers")
      .upsert({
        id: authData.user.id,
        full_name: fullName,
        phone,
        email,
        address: address || null
      }, { onConflict: "id" })
      .select("account_no")
      .single();

    if (customerError) {
      console.error("Customer profile insert failed:", customerError.message);
      return res.status(500).json({
        error: "Account was created but customer profile setup failed. Contact support before registering again."
      });
    }

    return res.status(201).json({
      user: {
        id: authData.user.id,
        fullName,
        email,
        phone,
        accountNo: customerRecord?.account_no || null,
        role: "customer"
      },
      access_token: authData.session?.access_token || null,
      refresh_token: authData.session?.refresh_token || null,
      email_confirmation_required: !authData.session
    });
  } catch (error) {
    console.error("Registration error:", error.message);
    return res.status(500).json({ error: "Unable to register account" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    if (!supabaseAuth || !supabase) {
      return res.status(503).json({ error: "Login service is not configured" });
    }

    const email = String(req.body?.email || req.body?.username || "")
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || "");
    const requestedRole = normalizeRole(req.body?.role || "customer");

    if (!email || !password || !email.includes("@")) {
      return res.status(400).json({
        error: "Enter your registered email and password"
      });
    }

    const { data, error } = await supabaseAuth.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data?.user || !data?.session) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const staff = await staffProfile(data.user.id);

    if (staff) {
      if (requestedRole === "customer") {
        await supabaseAuth.auth.signOut({ scope: "local" });
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
        return res.status(403).json({ error: "Staff role is not recognized" });
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

    const { data: customer, error: customerError } = await supabase
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
    return res.status(500).json({ error: "Unable to complete login" });
  }
});

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
    if (!data) return res.status(404).json({ error: "Profile not found" });

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
    return res.status(500).json({ error: "Unable to load profile" });
  }
});

app.get("/api/payment-methods", async (_req, res) => {
  try {
    if (!supabase) {
      return res.status(503).json({ error: "Database service is not configured" });
    }

    const { data, error } = await supabase
      .from("payment_methods")
      .select("id, name")
      .eq("is_enabled", true)
      .order("name");

    if (error) throw error;

    return res.json({ paymentMethods: data || [] });
  } catch (error) {
    console.error("Payment methods fetch error:", error.message);
    return res.status(500).json({ error: "Unable to load payment methods" });
  }
});

app.get("/api/customers", authenticate, requireStaff, async (req, res) => {
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
      .select("id, full_name, phone, email, address, national_id, created_at")
      .order("created_at", { ascending: false })
      .limit(1000);

    if (error) throw error;

    return res.json({ customers: data || [] });
  } catch (error) {
    console.error("Customers fetch error:", error.message);
    return res.status(500).json({ error: "Unable to load customers" });
  }
});

app.get("/api/loan-applications", authenticate, async (req, res) => {
  try {
    const staff = await staffProfile(req.authUser.id);

    let query = supabase
      .from("loan_applications")
      .select("id, customer_id, amount, interest_rate, term_months, purpose, status, applied_at, reviewed_at, reviewed_by")
      .order("applied_at", { ascending: false })
      .limit(1000);

    if (!staff) {
      query = query.eq("customer_id", req.authUser.id);
    } else if (
      !adminRoles.has(normalizeRole(staff.role)) &&
      !["loan officer", "chief loan officer"].includes(normalizeRole(staff.role))
    ) {
      return res.status(403).json({
        error: "Your staff role cannot view loan applications"
      });
    }

    const { data, error } = await query;
    if (error) throw error;

    return res.json({ applications: data || [] });
  } catch (error) {
    console.error("Applications fetch error:", error.message);
    return res.status(500).json({ error: "Unable to load loan applications" });
  }
});

app.post("/api/loan-applications", authenticate, async (req, res) => {
  try {
    const staff = await staffProfile(req.authUser.id);

    if (staff) {
      return res.status(403).json({
        error: "Staff accounts cannot submit customer loan applications"
      });
    }

    const amount = Number(req.body?.amount);
    const interestRate = Number(req.body?.interest_rate ?? req.body?.interestRate);
    const termMonths = Number(req.body?.term_months ?? req.body?.termMonths);
    const purpose = String(req.body?.purpose || "").trim();

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
        error: "Enter a valid loan amount, interest rate and term"
      });
    }

    const { data: customer, error: customerError } = await supabase
      .from("customers")
      .select("id")
      .eq("id", req.authUser.id)
      .maybeSingle();

    if (customerError) throw customerError;
    if (!customer) {
      return res.status(403).json({
        error: "Customer profile is required before applying"
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
      .select("id, customer_id, amount, interest_rate, term_months, purpose, status, applied_at")
      .single();

    if (error) throw error;

    return res.status(201).json({ application: data });
  } catch (error) {
    console.error("Application create error:", error.message);
    return res.status(500).json({ error: "Unable to submit loan application" });
  }
});

app.patch("/api/loan-applications/:id/status", authenticate, requireStaff, async (req, res) => {
  try {
    const role = normalizeRole(req.staffProfile.role);

    if (
      !adminRoles.has(role) &&
      !["loan officer", "chief loan officer"].includes(role)
    ) {
      return res.status(403).json({
        error: "Your staff role cannot review loan applications"
      });
    }

    const status = normalizeRole(req.body?.status);
    const reason = String(req.body?.reason || "").trim();

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

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(req.params.id))) {
      return res.status(400).json({ error: "Invalid loan application ID" });
    }

    // The database function reviews the application atomically.
    const { data, error } = await supabase.rpc("review_loan_application", {
      p_application_id: req.params.id,
      p_status: status,
      p_reviewed_by: req.staffProfile.id,
      p_rejection_reason: status === "rejected" ? reason : null
    });

    if (error) {
      if (error.code === "PGRST202" || /review_loan_application/i.test(error.message || "")) {
        console.error("Missing Supabase migration: review_loan_application");
        return res.status(503).json({
          error: "Application review is not enabled yet. Apply the supplied Supabase migration first."
        });
      }
      throw error;
    }

    if (!data || data.error === "not_found") {
      return res.status(404).json({ error: "Loan application not found" });
    }

    if (data.error === "already_reviewed") {
      return res.status(409).json({
        error: "This application has already been reviewed and cannot be changed."
      });
    }

    if (data.error) {
      return res.status(409).json({
        error: "Application could not be reviewed: " + data.error
      });
    }

    return res.json({
      application: data.application,
      loan: data.loan || null,
      alreadyReviewed: Boolean(data.already_reviewed)
    });
  } catch (error) {
    console.error("Application review error:", error.message);
    return res.status(500).json({ error: "Unable to update loan application" });
  }
});

// ========================================
// CUSTOMER LOANS, BALANCES, REPAYMENTS,
// REPAYMENT SCHEDULES AND STATEMENTS// These endpoints use the authenticated Supabase user ID.
// The service-role client bypasses RLS, so ownership checks below
// are required and must not be removed.
async function getLoanAccess(req) {
  const staff = await staffProfile(req.authUser.id);

  if (staff) {
    const role = normalizeRole(staff.role);
    const allowedStaffRoles = new Set([
      "admin", "administrator", "manager", "director",
      "loan officer", "chief loan officer", "cashier", "reporter"
    ]);

    if (!allowedStaffRoles.has(role)) {
      const error = new Error("Your staff role cannot view loan account records");
      error.statusCode = 403;
      throw error;
    }

    return { staff, customerId: null };
  }

  const { data: customer, error } = await supabase
    .from("customers")
    .select("id")
    .eq("id", req.authUser.id)
    .maybeSingle();

  if (error) throw error;

  if (!customer) {
    const err = new Error("Customer profile is required");
    err.statusCode = 403;
    throw err;
  }

  return { staff: null, customerId: customer.id };
}

function numberOrZero(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function roundMoney(value) {
  return Math.round((numberOrZero(value) + Number.EPSILON) * 100) / 100;
}

function parseApplicationPurpose(purpose) {
  if (!purpose) return {};
  if (typeof purpose === "object") return purpose;

  try {
    return JSON.parse(purpose);
  } catch (_error) {
    return {};
  }
}

function calculateFallbackTotal(loan, application) {
  // Prefer actual repayment schedule totals. This fallback is used only
  // when no schedule exists yet; the saved portal formula uses a flat
  // rate for business loans and a monthly rate for personal loans.
  const amount = numberOrZero(loan.principal_amount);
  const rate = numberOrZero(loan.interest_rate);
  const months = Math.max(1, numberOrZero(loan.term_months) || 1);
  const purpose = parseApplicationPurpose(application?.purpose);
  const loanType = String(purpose.loanType || "personal").toLowerCase();

  const interest = loanType === "business"
    ? amount * rate / 100
    : amount * rate / 100 * months;

  return {
    principal: roundMoney(amount),
    interest: roundMoney(interest),
    totalDue: roundMoney(amount + interest),
    totalSource: "estimated_until_schedule_exists"
  };
}

async function loadAccessibleLoanRecords(req) {
  const access = await getLoanAccess(req);

  let loanQuery = supabase
    .from("loans")
    .select("id, application_id, customer_id, principal_amount, interest_rate, term_months, status, disbursed_at, due_date, created_at")
    .order("created_at", { ascending: false })
    .limit(1000);

  if (access.customerId) {
    loanQuery = loanQuery.eq("customer_id", access.customerId);
  }

  const { data: loans, error: loanError } = await loanQuery;
  if (loanError) throw loanError;

  const loanRows = loans || [];
  const loanIds = loanRows.map(loan => loan.id);
  const applicationIds = [...new Set(
    loanRows.map(loan => loan.application_id).filter(Boolean)
  )];

  if (!loanIds.length) {
    return {
      ...access,
      loans: [],
      applications: {},
      disbursements: [],
      repayments: [],
      schedules: [],
      receipts: []
    };
  }

  const tasks = [
    supabase.from("loan_disbursements")
      .select("id, loan_id, amount, disbursed_at, payment_method, transaction_reference, notes, created_at")
      .in("loan_id", loanIds)
      .order("disbursed_at", { ascending: false }),

    supabase.from("repayments")
      .select("id, loan_id, amount, payment_method, transaction_reference, paid_at, created_at, notes")
      .in("loan_id", loanIds)
      .order("paid_at", { ascending: false }),

    supabase.from("repayment_schedules")
      .select("id, loan_id, installment_number, due_date, principal_due, interest_due, status, created_at")
      .in("loan_id", loanIds)
      .order("installment_number", { ascending: true })
  ];

  if (applicationIds.length) {
    tasks.push(
      supabase.from("loan_applications")
        .select("id, purpose, amount, interest_rate, term_months, status")
        .in("id", applicationIds)
    );
  }

  const results = await Promise.all(tasks);

  for (const result of results) {
    if (result.error) throw result.error;
  }

  const disbursements = results[0].data || [];
  const repayments = results[1].data || [];
  const schedules = results[2].data || [];
  const applicationRows = applicationIds.length ? (results[3].data || []) : [];
  const applications = Object.fromEntries(
    applicationRows.map(row => [row.id, row])
  );

  let receipts = [];
  const repaymentIds = repayments.map(row => row.id);

  if (repaymentIds.length) {
    const { data, error } = await supabase
      .from("payment_receipts")
      .select("id, repayment_id, receipt_number, issued_at, notes")
      .in("repayment_id", repaymentIds)
      .order("issued_at", { ascending: false });

    if (error) throw error;
    receipts = data || [];
  }

  return {
    ...access,
    loans: loanRows,
    applications,
    disbursements,
    repayments,
    schedules,
    receipts
  };
}

function summarizeLoan(loan, records) {
  const disbursements = records.disbursements.filter(
    row => row.loan_id === loan.id
  );
  const repayments = records.repayments.filter(
    row => row.loan_id === loan.id
  );
  const schedules = records.schedules.filter(
    row => row.loan_id === loan.id
  );
  const application = records.applications[loan.application_id] || null;

  const principal = roundMoney(loan.principal_amount);

  const scheduleTotal = schedules.reduce(
    (total, row) =>
      total + numberOrZero(row.principal_due) + numberOrZero(row.interest_due),
    0
  );

  const fallback = calculateFallbackTotal(loan, application);
  const totalDue = schedules.length
    ? roundMoney(scheduleTotal)
    : fallback.totalDue;

  // This schema has no repayment status column. These are recorded
  // repayments, not independently verified or confirmed payments.
  const totalPaid = roundMoney(
    repayments.reduce((total, row) => total + numberOrZero(row.amount), 0)
  );

  const balance = roundMoney(Math.max(0, totalDue - totalPaid));

  const totalDisbursed = roundMoney(
    disbursements.reduce((total, row) => total + numberOrZero(row.amount), 0)
  );

  return {
    id: loan.id,
    applicationId: loan.application_id,
    customerId: loan.customer_id,
    principalAmount: principal,
    interestRate: numberOrZero(loan.interest_rate),
    termMonths: numberOrZero(loan.term_months),
    status: loan.status,
    disbursedAt: loan.disbursed_at,
    dueDate: loan.due_date,
    createdAt: loan.created_at,
    totalDisbursed: totalDisbursed || (loan.disbursed_at ? principal : 0),
    totalDue,
    totalPaid,
    balance,
    totalSource: schedules.length ? "repayment_schedules" : fallback.totalSource,
    scheduleCount: schedules.length,
    repaymentCount: repayments.length,
    application
  };
}

function summarizeLoan(loan, records) {
  const disbursements = records.disbursements.filter(
    row => row.loan_id === loan.id
  );
  const repayments = records.repayments.filter(
    row => row.loan_id === loan.id
  );
  const schedules = records.schedules.filter(
    row => row.loan_id === loan.id
  );
  const application = records.applications[loan.application_id] || null;

  const principal = roundMoney(loan.principal_amount);

  const scheduleTotal = schedules.reduce(
    (total, row) =>
      total + numberOrZero(row.principal_due) +
      numberOrZero(row.interest_due),
    0
  );

  const fallback = calculateFallbackTotal(loan, application);
  const totalDue = schedules.length
    ? roundMoney(scheduleTotal)
    : fallback.totalDue;

  const totalPaid = roundMoney(
    repayments.reduce(
      (total, row) => total + numberOrZero(row.amount),
      0
    )
  );

  const balance = roundMoney(Math.max(0, totalDue - totalPaid));

  const totalDisbursed = roundMoney(
    disbursements.reduce(
      (total, row) => total + numberOrZero(row.amount),
      0
    )
  );

  return {
    ...loan,
    principal_amount: principal,
    total_disbursed: totalDisbursed || (loan.disbursed_at ? principal : 0),
    total_due: totalDue,
    total_paid: totalPaid,
    outstanding_balance: balance,
    interest_due: roundMoney(Math.max(0, totalDue - principal)),
    balance_calculation: schedules.length
      ? "repayment_schedules"
      : fallback.totalSource,
    application: application
      ? { id: application.id, status: application.status }
      : null,
    disbursements,
    repayments,
    schedules: schedules.map(schedule => ({
      ...schedule,
      principal_due: numberOrZero(schedule.principal_due),
      interest_due: numberOrZero(schedule.interest_due),
      installment_total: roundMoney(
        numberOrZero(schedule.principal_due) +
        numberOrZero(schedule.interest_due)
      )
    }))
  };
}

// GET /api/loans
// Customers see their own loans; authorized staff can view the portfolio.
app.get("/api/loans", authenticate, async (req, res) => {
  try {
    const records = await loadAccessibleLoanRecords(req);
    const loans = records.loans.map(loan => summarizeLoan(loan, records));

    return res.json({
      loans,
      summary: {
        count: loans.length,
        totalPrincipal: roundMoney(
          loans.reduce((sum, loan) => sum + loan.principal_amount, 0)
        ),
        totalDisbursed: roundMoney(
          loans.reduce((sum, loan) => sum + loan.total_disbursed, 0)
        ),
        totalDue: roundMoney(
          loans.reduce((sum, loan) => sum + loan.total_due, 0)
        ),
        totalPaid: roundMoney(
          loans.reduce((sum, loan) => sum + loan.total_paid, 0)
        ),
        outstandingBalance: roundMoney(
          loans.reduce((sum, loan) => sum + loan.outstanding_balance, 0)
        )
      }
    });
  } catch (error) {
    console.error("Loans fetch error:", error.message);
    return res.status(error.statusCode || 500).json({
      error: error.statusCode ? error.message : "Unable to load loan accounts"
    });
  }
});

// GET /api/repayments
app.get("/api/repayments", authenticate, async (req, res) => {
  try {
    const records = await loadAccessibleLoanRecords(req);

    const receiptByRepayment = Object.fromEntries(
      records.receipts.map(receipt => [receipt.repayment_id, receipt])
    );
    const loanById = Object.fromEntries(
      records.loans.map(loan => [loan.id, loan])
    );

    const repayments = records.repayments.map(repayment => ({
      ...repayment,
      receipt: receiptByRepayment[repayment.id] || null,
      loan: loanById[repayment.loan_id] ? {
        id: loanById[repayment.loan_id].id,
        principal_amount: numberOrZero(
          loanById[repayment.loan_id].principal_amount
        ),
        status: loanById[repayment.loan_id].status
      } : null
    }));

    return res.json({
      repayments,
      totalRecorded: roundMoney(
        repayments.reduce((sum, row) => sum + numberOrZero(row.amount), 0)
      ),
      note: "The repayments table has no status column; records are returned as recorded payments, not labeled confirmed."
    });
  } catch (error) {
    console.error("Repayments fetch error:", error.message);
    return res.status(error.statusCode || 500).json({
      error: error.statusCode ? error.message : "Unable to load repayment history"
    });
  }
});

// GET /api/repayment-schedules
app.get("/api/repayment-schedules", authenticate, async (req, res) => {
  try {
    const records = await loadAccessibleLoanRecords(req);
    const loanById = Object.fromEntries(
      records.loans.map(loan => [loan.id, loan])
    );

    const schedules = records.schedules.map(schedule => {
      const loan = loanById[schedule.loan_id];

      return {
        ...schedule,
        principal_due: numberOrZero(schedule.principal_due),
        interest_due: numberOrZero(schedule.interest_due),
        installment_total: roundMoney(
          numberOrZero(schedule.principal_due) +
          numberOrZero(schedule.interest_due)
        ),
        loan: loan ? {
          id: loan.id,
          customer_id: loan.customer_id,
          status: loan.status
        } : null
      };
    });

    return res.json({ schedules });
  } catch (error) {
    console.error("Repayment schedules fetch error:", error.message);
    return res.status(error.statusCode || 500).json({
      error: error.statusCode ? error.message : "Unable to load repayment schedules"
    });
  }
});

// GET /api/statements
// Principal and interest appear as debits; recorded repayments appear as credits.
// The schema has no repayment status field, so payments are not labelled confirmed.
app.get("/api/statements", authenticate, async (req, res) => {
  try {
    const records = await loadAccessibleLoanRecords(req);
    const requestedLoanId = String(
      req.query.loan_id || req.query.loan || ""
    ).trim();

    const fromDate = req.query.from
      ? new Date(String(req.query.from))
      : null;
    const toDate = req.query.to
      ? new Date(String(req.query.to))
      : null;

    if (fromDate && Number.isNaN(fromDate.getTime())) {
      return res.status(400).json({
        error: "Invalid statement start date"
      });
    }

    if (toDate && Number.isNaN(toDate.getTime())) {
      return res.status(400).json({
        error: "Invalid statement end date"
      });
    }

    const selectedLoans = requestedLoanId
      ? records.loans.filter(loan => loan.id === requestedLoanId)
      : records.loans;

    if (requestedLoanId && !selectedLoans.length) {
      return res.status(404).json({ error: "Loan account not found" });
    }

    const entries = [];

    for (const loan of selectedLoans) {
      const summary = summarizeLoan(loan, records);
      const startDate = loan.disbursed_at || loan.created_at;

      entries.push({
        id: `loan-${loan.id}`,
        loan_id: loan.id,
        date: startDate,
        type: "loan_principal",
        description: "Loan principal",
        debit: summary.principal_amount,
        credit: 0
      });

      if (summary.interest_due > 0) {
        entries.push({
          id: `interest-${loan.id}`,
          loan_id: loan.id,
          date: startDate,
          type: "interest_charge",
          description: "Loan interest",
          debit: summary.interest_due,
          credit: 0
        });
      }

      for (const repayment of records.repayments.filter(
        row => row.loan_id === loan.id
      )) {
        entries.push({
          id: repayment.id,
          loan_id: loan.id,
          date: repayment.paid_at || repayment.created_at,
          type: "repayment",
          description:
            `Repayment via ${repayment.payment_method || "unspecified method"}` +
            `${repayment.transaction_reference ? ` (${repayment.transaction_reference})` : ""}`,
          debit: 0,
          credit: numberOrZero(repayment.amount),
          payment_method: repayment.payment_method || null,
          transaction_reference: repayment.transaction_reference || null,
          receipt: records.receipts.find(
            receipt => receipt.repayment_id === repayment.id
          ) || null
        });
      }
    }

    const filtered = entries
      .filter(entry => {
        const date = entry.date ? new Date(entry.date) : null;

        if (fromDate && (!date || date < fromDate)) return false;
        if (toDate && (!date || date > toDate)) return false;

        return true;
      })
      .sort((a, b) => new Date(a.date || 0) - new Date(b.date || 0));

    const balanceByLoan = {};

      const statement = filtered.map(entry => {
      const previous = numberOrZero(balanceByLoan[entry.loan_id]);
      const balance = roundMoney(
        previous +
        numberOrZero(entry.debit) -
        numberOrZero(entry.credit)
      );

      balanceByLoan[entry.loan_id] = balance;

      return {
        ...entry,
        running_balance: balance
      };
    });

    return res.json({
      statements: statement,
      summary: {
        debitTotal: roundMoney(
          statement.reduce(
            (sum, row) => sum + numberOrZero(row.debit),
            0
          )
        ),
        creditTotal: roundMoney(
          statement.reduce(
            (sum, row) => sum + numberOrZero(row.credit),
            0
          )
        ),
        closingBalance: roundMoney(
          statement.reduce(
            (sum, row) =>
              sum +
              numberOrZero(row.debit) -
              numberOrZero(row.credit),
            0
          )
        )
      }
    });
  } catch (error) {
    console.error("Statements fetch error:", error.message);

    return res.status(error.statusCode || 500).json({
      error: error.statusCode
        ? error.message
        : "Unable to generate account statement"
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
    err => {
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

