import express from "express";
import path from "path";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";
import session from "express-session";
import { createServer as createViteServer } from "vite";
import { SecurityLog } from "./src/types";

// Extend session types
declare module "express-session" {
  interface SessionData {
    user?: {
      id: number;
      username: string;
      email: string;
      twoFactorEnabled: boolean;
      createdAt: string;
    };
    pending2faUser?: {
      id: number;
      username: string;
      email: string;
      twoFactorEnabled: boolean;
    };
    otpCode?: string;
    otpExpiry?: number;
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // In-memory security event log for demonstration purposes
  const securityLogs: SecurityLog[] = [];

  function addLog(type: SecurityLog['type'], event: string, details: string) {
    const log: SecurityLog = {
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toISOString(),
      type,
      event,
      details,
    };
    securityLogs.unshift(log); // newest first
    // Keep logs size reasonable
    if (securityLogs.length > 50) {
      securityLogs.pop();
    }
  }

  // Session configuration
  app.use(
    session({
      secret: process.env.SESSION_SECRET || "secure-login-mvp-super-safe-key-val-123",
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true, // Prevents XSS cookie theft
        secure: false, // Set to true if on HTTPS but false for easy dev preview in frames
        maxAge: 30 * 60 * 1000, // 30 minutes
        sameSite: "strict", // Restricts cross-site request forgery
      },
    })
  );

  // Initialize SQLite Database
  const db = new sqlite3.Database(":memory:", (err) => {
    if (err) {
      console.error("Failed to connect to sqlite database", err);
    } else {
      console.log("Connected to in-memory SQLite database");
    }
  });

  // Helper Promise Database APIs
  const dbRun = (query: string, params: any[] = []): Promise<void> => {
    return new Promise((resolve, reject) => {
      db.run(query, params, function (err) {
        if (err) reject(err);
        else resolve();
      });
    });
  };

  const dbGet = <T>(query: string, params: any[] = []): Promise<T | undefined> => {
    return new Promise((resolve, reject) => {
      db.get(query, params, (err, row) => {
        if (err) reject(err);
        else resolve(row as T);
      });
    });
  };

  const dbAll = <T>(query: string, params: any[] = []): Promise<T[]> => {
    return new Promise((resolve, reject) => {
      db.all(query, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows as T[]);
      });
    });
  };

  // Bootstrap Database Schema
  async function bootstrap() {
    try {
      await dbRun(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          two_factor_enabled INTEGER DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Add a couple of initial seed users to demonstrate searches and injections immediately
      const demoPassHash = await bcrypt.hash("password123", 10);
      const adminPassHash = await bcrypt.hash("adminSecurePassWord2026!", 10);

      await dbRun(
        "INSERT OR IGNORE INTO users (username, email, password_hash, two_factor_enabled) VALUES (?, ?, ?, ?)",
        ["demo_user", "demo@loginmvp.io", demoPassHash, 0]
      );
      await dbRun(
        "INSERT OR IGNORE INTO users (username, email, password_hash, two_factor_enabled) VALUES (?, ?, ?, ?)",
        ["admin", "admin@securecorp.net", adminPassHash, 1] // Admin gets pre-enabled 2FA for quick verification
      );

      addLog("success", "Database Initialized", "SQLite tables created and seeded with 2 users: 'demo_user' and 'admin'.");
    } catch (e: any) {
      console.error("Failed to bootstrap SQLite keys", e);
      addLog("danger", "Database Error", `Schema bootstrap failed: ${e.message}`);
    }
  }

  await bootstrap();

  // API Check session state
  app.get("/api/auth/me", (req, res) => {
    if (req.session.user) {
      res.json({ authenticated: true, user: req.session.user });
    } else if (req.session.pending2faUser) {
      res.json({ authenticated: false, pending2fa: true, user: req.session.pending2faUser });
    } else {
      res.json({ authenticated: false });
    }
  });

  // API Fetch security logs for UI dashboard
  app.get("/api/security-logs", (req, res) => {
    res.json({ logs: securityLogs });
  });

  // API Clear Logs
  app.post("/api/security-logs/clear", (req, res) => {
    securityLogs.length = 0;
    addLog("info", "Logs Cleared", "Audit log monitor cleared by administrator action.");
    res.json({ success: true });
  });

  // API Registration
  app.post("/api/auth/register", async (req, res) => {
    const { username, email, password } = req.body;

    const auditDetails = `Username: '${username}', Email: '${email}'`;

    // 1. Input Validation
    if (!username || !email || !password) {
      addLog("warning", "Registration Failed", `Missing empty fields. ${auditDetails}`);
      return res.status(400).json({ error: "All fields are required" });
    }

    // Alphanumeric check for username to prevent SQL injection or bad values
    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
    if (!usernameRegex.test(username)) {
      addLog("warning", "Registration Failed", `Invalid username regex. ${auditDetails}`);
      return res.status(400).json({ error: "Username must be 3-30 letters, numbers or underscores only." });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      addLog("warning", "Registration Failed", `Invalid email syntax. ${auditDetails}`);
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    if (password.length < 8) {
      addLog("warning", "Registration Failed", `Password too short. Length: ${password.length}. ${auditDetails}`);
      return res.status(400).json({ error: "Password must be at least 8 characters long." });
    }

    try {
      // 2. SQL injection proof UNIQUE check (Prepared Statement)
      const existingUser = await dbGet<{ id: number }>(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        [username, email]
      );

      if (existingUser) {
        addLog("warning", "Registration Conflict", `Username or email already exists. ${auditDetails}`);
        return res.status(400).json({ error: "Username or email is already registered." });
      }

      // 3. Secure Hash (bcrypt)
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // 4. Secure Insert (Prepared Statement)
      await dbRun(
        "INSERT INTO users (username, email, password_hash, two_factor_enabled) VALUES (?, ?, ?, 0)",
        [username, email, hashedPassword]
      );

      addLog("success", "User Registered", `Registered successfully using secure bcrypt hashing. Saved as entry.`);
      res.status(201).json({ success: true, message: "User registered successfully." });
    } catch (err: any) {
      addLog("danger", "Registration Failure", `Internal query failed: ${err.message}`);
      res.status(500).json({ error: "An unexpected error occurred during registration." });
    }
  });

  // API Login
  app.post("/api/auth/login", async (req, res) => {
    const { loginId, password } = req.body; // loginId can be username or email

    if (!loginId || !password) {
      addLog("warning", "Login Failed", "Empty submission fields received.");
      return res.status(400).json({ error: "Both username/email and password are required." });
    }

    try {
      // Fetch user securely via parameterized queries
      const user = await dbGet<{
        id: number;
        username: string;
        email: string;
        password_hash: string;
        two_factor_enabled: number;
        created_at: string;
      }>("SELECT * FROM users WHERE username = ? OR email = ?", [loginId, loginId]);

      if (!user) {
        addLog("warning", "Authentication Attempt Failed", `Search for identity '${loginId}' returned no records.`);
        return res.status(401).json({ error: "Invalid username, email, or password." });
      }

      // Verify passwords with bcrypt.compare
      const passwordMatch = await bcrypt.compare(password, user.password_hash);
      if (!passwordMatch) {
        addLog("warning", "Authentication Attempt Failed", `Identity valid but password hash check failed for id: ${user.id}`);
        return res.status(401).json({ error: "Invalid username, email, or password." });
      }

      // Check if 2FA (Two Factor) is enabled
      const is2fa = user.two_factor_enabled === 1;

      if (is2fa) {
        // Generate OTP and place in pending verification status
        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
        const expiry = Date.now() + 5 * 60 * 1000; // 5 mins valid

        req.session.pending2faUser = {
          id: user.id,
          username: user.username,
          email: user.email,
          twoFactorEnabled: true,
        };
        req.session.otpCode = otp;
        req.session.otpExpiry = expiry;

        addLog(
          "success",
          "2FA Issued & Challenged",
          `Identity verified. 2FA is active. Generated transient 6-digit OTP code '${otp}' for user '${user.username}' (Sent to system logs simulate).`
        );

        return res.json({
          requires2fa: true,
          message: "A verification code has been dispatched to your secure devices (Simulated). Check logs to verify.",
        });
      } else {
        // Direct login
        req.session.user = {
          id: user.id,
          username: user.username,
          email: user.email,
          twoFactorEnabled: false,
          createdAt: user.created_at,
        };

        addLog("success", "User Login Successful", `Session initialized securely for user: '${user.username}'.`);
        return res.json({
          success: true,
          user: req.session.user,
        });
      }
    } catch (err: any) {
      addLog("danger", "Login Error", `Query fault detected: ${err.message}`);
      res.status(500).json({ error: "Database or internal state error." });
    }
  });

  // API Verify 2FA OTP
  app.post("/api/auth/verify-2fa", (req, res) => {
    const { otp } = req.body;
    const { pending2faUser, otpCode, otpExpiry } = req.session;

    if (!pending2faUser || !otpCode) {
      return res.status(400).json({ error: "No active 2FA login session found. Please log in again." });
    }

    if (!otp) {
      return res.status(400).json({ error: "The verification code is required." });
    }

    if (Date.now() > (otpExpiry || 0)) {
      addLog("warning", "2FA Verification Expired", `OTP code expired for pending user: '${pending2faUser.username}'`);
      return res.status(400).json({ error: "Verification code expired. Please restart login process." });
    }

    if (otp !== otpCode) {
      addLog("warning", "2FA Verification Mismatch", `Incorrect code inputted: '${otp}' for pending user: '${pending2faUser.username}'`);
      return res.status(401).json({ error: "Incorrect verification code. Please check your logs." });
    }

    // Success! Upgrade user session out of pending 2FA challenge
    req.session.user = {
      id: pending2faUser.id,
      username: pending2faUser.username,
      email: pending2faUser.email,
      twoFactorEnabled: true,
      createdAt: new Date().toISOString(), // Fetch or set creation details
    };

    // Clean up temporary 2FA caches
    delete req.session.pending2faUser;
    delete req.session.otpCode;
    delete req.session.otpExpiry;

    addLog("success", "2FA Verified Successfully", `Session fully logged in with active 2FA credentials for: '${req.session.user.username}'.`);
    res.json({ success: true, user: req.session.user });
  });

  // API Toggle 2FA in user workspace
  app.post("/api/auth/toggle-2fa", async (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Unauthorized session access." });
    }

    const { enabled } = req.body;
    const value = enabled ? 1 : 0;
    const userId = req.session.user.id;

    try {
      await dbRun("UPDATE users SET two_factor_enabled = ? WHERE id = ?", [value, userId]);

      req.session.user.twoFactorEnabled = enabled;
      addLog(
        "info",
        "2FA Settings Updated",
        `User '${req.session.user.username}' updated 2FA status to: ${enabled ? "ENABLED" : "DISABLED"}`
      );

      res.json({ success: true, twoFactorEnabled: enabled });
    } catch (err: any) {
      addLog("danger", "2FA Toggle Error", `DB UPDATE call failed: ${err.message}`);
      res.status(500).json({ error: "Failed to update 2FA state." });
    }
  });

  // API Logout
  app.post("/api/auth/logout", (req, res) => {
    const user = req.session.user;
    if (user) {
      req.session.destroy((err) => {
        if (err) {
          addLog("danger", "Logout Session Crash", `Failed to destroy session: ${err.message}`);
          return res.status(500).json({ error: "Could not successfully logout your session." });
        }
        res.clearCookie("connect.sid");
        addLog("info", "User Session Ended", `Logged out user: '${user.username}' safely. Cookie discarded.`);
        res.json({ success: true });
      });
    } else {
      res.json({ success: true });
    }
  });

  // API INTERACTIVE SQL INJECTION DEMO (PLAYGROUND)
  // This simulates what happens when code concatenates strings instead of using parameterized queries.
  app.post("/api/demo/search-users", async (req, res) => {
    const { searchQuery } = req.body;

    if (searchQuery === undefined || searchQuery === null) {
      return res.status(400).json({ error: "Search text is required." });
    }

    // 1. Raw unsafe concatenated string evaluation
    const rawSqlString = `SELECT id, username, email, two_factor_enabled FROM users WHERE username = '${searchQuery}' OR email = '${searchQuery}'`;
    
    // 2. Safe Parameterized prepared statement evaluation
    const secureSqlString = `SELECT id, username, email, two_factor_enabled FROM users WHERE username = ? OR email = ?`;

    const resultComparison: {
      raw: { queryUsed: string; success: boolean; resultsCount: number; results: any[]; error?: string };
      parameterized: { queryUsed: string; success: boolean; resultsCount: number; results: any[]; error?: string };
    } = {
      raw: { queryUsed: rawSqlString, success: false, resultsCount: 0, results: [] },
      parameterized: { queryUsed: secureSqlString + `   [Params: "${searchQuery}"]`, success: false, resultsCount: 0, results: [] },
    };

    addLog(
      "warning",
      "Interactive Playground Query",
      `Executing search for '${searchQuery}'. Running both Unsafe RAW and Safe PARAMETERIZED runs to contrast.`
    );

    // Run Raw Unsafe query
    try {
      // In SQLite, db.all run directly evaluates concatenated queries as instructions
      const rawResults = await dbAll<any>(rawSqlString);
      resultComparison.raw = {
        queryUsed: rawSqlString,
        success: true,
        resultsCount: rawResults.length,
        results: rawResults.map(r => ({ id: r.id, username: r.username, email: r.email, two_factor_enabled: r.two_factor_enabled })),
      };

      // If the query fetched more than one user on single exact search term, it usually indicates SQL Injection
      if (rawResults.length > 1 && searchQuery.includes("'")) {
        addLog(
          "danger",
          "SQL Injection Detected Unsafe Pathway!",
          `Injection input '${searchQuery}' returned ${rawResults.length} records! Concatenated query executed as instruction.`
        );
      }
    } catch (e: any) {
      resultComparison.raw = {
        queryUsed: rawSqlString,
        success: false,
        resultsCount: 0,
        results: [],
        error: e.message,
      };
      addLog("danger", "SQL Syntax Failure Unsafe Pathway", `Raw query crashed with injection syntax: ${e.message}`);
    }

    // Run Secure Parameterized query
    try {
      const safeResults = await dbAll<any>(secureSqlString, [searchQuery, searchQuery]);
      resultComparison.parameterized = {
        queryUsed: secureSqlString + `   (Bound values: [${searchQuery}, ${searchQuery}])`,
        success: true,
        resultsCount: safeResults.length,
        results: safeResults.map(r => ({ id: r.id, username: r.username, email: r.email, two_factor_enabled: r.two_factor_enabled })),
      };
    } catch (e: any) {
      resultComparison.parameterized = {
        queryUsed: secureSqlString,
        success: false,
        resultsCount: 0,
        results: [],
        error: e.message,
      };
    }

    res.json({ comparison: resultComparison });
  });

  // Serving the UI Vite Bundles
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // Handle all server errors gracefully
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error("Unhandled middleware error", err);
    res.status(500).json({ error: "An unhandled server exception occurred." });
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running secure login system on port ${PORT}`);
  });
}

startServer();
