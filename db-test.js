
require("dotenv").config();

const { createClient } = require("@supabase/supabase-js");

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("Missing Supabase environment variables.");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

async function testConnection() {
  const { data, error } = await supabase
    .from("payment_methods")
    .select("name, is_enabled")
    .limit(10);

  if (error) {
    console.error("Database query failed:", error.message);
    process.exit(1);
  }

  console.log("Supabase database query succeeded!");
  console.log("Payment methods found:", data);
}

testConnection();
