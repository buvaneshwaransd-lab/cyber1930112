const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ================== ENV ==================
const PORT = process.env.PORT || 8080;
const SECRET = process.env.JWT_SECRET || "supersecretkey";

// ================== DATABASE ==================
const promisePool = require("./config/database");

// ================== FILE STORAGE ==================
const recordsFile = path.join(__dirname, "records.json");

function readRecords() {
  if (!fs.existsSync(recordsFile)) return [];
  return JSON.parse(fs.readFileSync(recordsFile));
}

function writeRecords(records) {
  fs.writeFileSync(recordsFile, JSON.stringify(records, null, 2));
}

// ================== DATABASE INIT ==================
async function initializeDatabase() {
  try {
    console.log("🔄 Initializing database...");

    const [test] = await promisePool.query("SELECT 1 + 1 AS result");
    console.log("✅ DB connected:", test[0].result);

    await promisePool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        full_name VARCHAR(255),
        email VARCHAR(255) UNIQUE,
        phone VARCHAR(20) UNIQUE,
        password_hash VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await promisePool.query(`
      CREATE TABLE IF NOT EXISTS charge_sheets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        form_type VARCHAR(100),
        form_data JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    console.log("✅ Tables verified");

    const [users] = await promisePool.query(
      "SELECT COUNT(*) AS count FROM users"
    );

    if (users[0].count === 0) {
      const hash = await bcrypt.hash("test123", 10);
      await promisePool.query(
        "INSERT INTO users (full_name,email,phone,password_hash) VALUES (?,?,?,?)",
        ["Test User", "test@example.com", "1234567890", hash]
      );
      console.log("✅ Test user created");
    }

  } catch (err) {
    console.error("❌ DB init failed:", err.message);
    // IMPORTANT: do NOT crash the app
  }
}

// Delay DB init so Railway health check passes
setTimeout(() => initializeDatabase(), 3000);

// ================== AUTH ==================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({ success: false, message: "All fields required" });
    }

    const [exists] = await promisePool.query(
      "SELECT id FROM users WHERE email=? OR phone=?",
      [email, phone]
    );

    if (exists.length) {
      return res.status(400).json({ success: false, message: "User exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    await promisePool.query(
      "INSERT INTO users (full_name,email,phone,password_hash) VALUES (?,?,?,?)",
      [fullName, email, phone, hash]
    );

    res.json({ success: true, message: "Registration successful" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [users] = await promisePool.query(
      "SELECT * FROM users WHERE email=?",
      [email]
    );

    if (!users.length) {
      return res.status(401).json({ success: false, message: "Invalid login" });
    }

    const user = users[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.status(401).json({ success: false, message: "Invalid login" });
    }

    const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: "1h" });

    res.json({
      success: true,
      token,
      user: { id: user.id, fullName: user.full_name, email: user.email }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== RECORDS ==================
app.get("/api/records/:id", (req, res) => {
  const record = readRecords().find(r => String(r.id) === req.params.id);
  if (!record) return res.status(404).json({ message: "Not found" });
  res.json(record);
});

app.post("/api/records", (req, res) => {
  const records = readRecords();
  const newRecord = { id: Date.now(), ...req.body };
  records.push(newRecord);
  writeRecords(records);
  res.json({ success: true, record: newRecord });
});

// ================== ROOT ==================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================== START ==================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
