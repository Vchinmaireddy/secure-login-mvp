import React, { useState, useEffect } from "react";
import { 
  Shield, 
  Lock, 
  Unlock, 
  User, 
  Mail, 
  Eye, 
  EyeOff, 
  Terminal, 
  Activity, 
  LogOut, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Trash2, 
  Settings, 
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  ChevronRight,
  HelpCircle,
  RefreshCw,
  UserCheck
} from "lucide-react";
import { User as UserType, SecurityLog, SqlInjectionComparison } from "./types";

export default function App() {
  // Session States
  const [currentUser, setCurrentUser] = useState<UserType | null>(null);
  const [isPending2fa, setIsPending2fa] = useState<boolean>(false);
  const [pendingUser, setPendingUser] = useState<any>(null);
  const [authLoading, setAuthLoading] = useState<boolean>(true);

  // Form States
  const [isRegisterMode, setIsRegisterMode] = useState<boolean>(false);
  const [loginId, setLoginId] = useState<string>("");
  const [loginPassword, setLoginPassword] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);

  // Registration Form States
  const [regUsername, setRegUsername] = useState<string>("");
  const [regEmail, setRegEmail] = useState<string>("");
  const [regPassword, setRegPassword] = useState<string>("");
  const [regConfirmPassword, setRegConfirmPassword] = useState<string>("");
  
  // Validation Focus States (to only show error when user touches field or submits)
  const [touchedReg, setTouchedReg] = useState({
    username: false,
    email: false,
    password: false,
    confirmPassword: false
  });

  // 2FA Verification Form
  const [otpCode, setOtpCode] = useState<string>("");

  // Feedback Notification banner
  const [notification, setNotification] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

  // Interactive SQL Injection Demo States
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [injectionResult, setInjectionResult] = useState<SqlInjectionComparison | null>(null);
  const [playgroundLoading, setPlaygroundLoading] = useState<boolean>(false);

  // Security logs state
  const [securityLogs, setSecurityLogs] = useState<SecurityLog[]>([]);
  const [activeTab, setActiveTab] = useState<"auth" | "playground" | "logs">("auth");

  // Fetch Session Configuration on mount
  useEffect(() => {
    checkSession();
    fetchLogs();
    
    // Set up rapid status polling to fetch logs as they happen
    const interval = setInterval(() => {
      fetchLogs();
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const triggerNotification = (type: "success" | "error" | "info", message: string) => {
    setNotification({ type, message });
    setTimeout(() => {
      setNotification(prev => prev?.message === message ? null : prev);
    }, 6000);
  };

  const checkSession = async () => {
    try {
      const res = await fetch("/api/auth/me");
      const data = await res.json();
      if (data.authenticated && data.user) {
        setCurrentUser(data.user);
        setIsPending2fa(false);
        setPendingUser(null);
      } else if (data.pending2fa && data.user) {
        setIsPending2fa(true);
        setPendingUser(data.user);
        setCurrentUser(null);
        setActiveTab("auth");
      } else {
        setCurrentUser(null);
        setIsPending2fa(false);
        setPendingUser(null);
      }
    } catch (e) {
      console.error("Session fetch failed", e);
    } finally {
      setAuthLoading(false);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await fetch("/api/security-logs");
      const data = await res.json();
      if (data.logs) {
        setSecurityLogs(data.logs);
      }
    } catch (e) {
      console.error("Failed to read security logs", e);
    }
  };

  const clearLogs = async () => {
    try {
      const res = await fetch("/api/security-logs/clear", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setSecurityLogs([]);
        triggerNotification("success", "Audit logs cleared successfully.");
      }
    } catch (e) {
      console.error("Log reset failed", e);
    }
  };

  // Client-Side Input Validations
  const validateEmail = (email: string) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validateUsername = (user: string) => {
    const userRegex = /^[a-zA-Z0-9_]{3,30}$/;
    return userRegex.test(user);
  };

  // Action: Handle registration submission
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouchedReg({
      username: true,
      email: true,
      password: true,
      confirmPassword: true
    });

    if (!regUsername || !regEmail || !regPassword || !regConfirmPassword) {
      triggerNotification("error", "Please fill in all registration fields.");
      return;
    }

    if (!validateUsername(regUsername)) {
      triggerNotification("error", "Username must be 3-30 characters, alphanumeric & underscores only.");
      return;
    }

    if (!validateEmail(regEmail)) {
      triggerNotification("error", "Please input a valid email format.");
      return;
    }

    if (regPassword.length < 8) {
      triggerNotification("error", "Passwords must be at least 8 characters long.");
      return;
    }

    if (regPassword !== regConfirmPassword) {
      triggerNotification("error", "Password confirmation does not match original password.");
      return;
    }

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: regUsername,
          email: regEmail,
          password: regPassword
        })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        triggerNotification("success", "Account created successfully using secure hash cryptography! Please sign in.");
        setIsRegisterMode(false);
        setLoginId(regUsername);
        
        // Reset registration form
        setRegUsername("");
        setRegEmail("");
        setRegPassword("");
        setRegConfirmPassword("");
        setTouchedReg({ username: false, email: false, password: false, confirmPassword: false });
        fetchLogs();
      } else {
        triggerNotification("error", data.error || "Failed to complete secure registration.");
      }
    } catch (e) {
      triggerNotification("error", "Network connection issues creating your security credentials.");
    }
  };

  // Action: Handle login submission
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!loginId || !loginPassword) {
      triggerNotification("error", "Please enter both username/email and password.");
      return;
    }

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          loginId,
          password: loginPassword
        })
      });

      const data = await res.json();
      fetchLogs();

      if (res.ok) {
        if (data.requires2fa) {
          setIsPending2fa(true);
          setPendingUser({ username: loginId });
          triggerNotification("info", "Two-Factor (2FA) challenged! Look at the 'Security Audit Log' at the bottom to find your simulated verification OTP.");
        } else if (data.success && data.user) {
          setCurrentUser(data.user);
          triggerNotification("success", `Secure session established. Welcome back, ${data.user.username}!`);
          setLoginPassword("");
        }
      } else {
        triggerNotification("error", data.error || "Login credentials unauthorized.");
      }
    } catch (e) {
      triggerNotification("error", "Error connecting to backend database server.");
    }
  };

  // Action: Handle 2FA Verification
  const handleVerify2fa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otpCode) {
      triggerNotification("error", "Please fill in the 6-digit verification code.");
      return;
    }

    try {
      const res = await fetch("/api/auth/verify-2fa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ otp: otpCode })
      });

      const data = await res.json();
      fetchLogs();

      if (res.ok && data.success) {
        setCurrentUser(data.user);
        setIsPending2fa(false);
        setPendingUser(null);
        setOtpCode("");
        triggerNotification("success", "2FA authentication clear! Session loaded.");
      } else {
        triggerNotification("error", data.error || "Invalid 2FA verification token.");
      }
    } catch (e) {
      triggerNotification("error", "Authentication transmission disrupted.");
    }
  };

  // Action: Toggle 2FA Setting inside Dashboard
  const handleToggle2fa = async (currentSetting: boolean) => {
    try {
      const res = await fetch("/api/auth/toggle-2fa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !currentSetting })
      });

      const data = await res.json();
      fetchLogs();

      if (res.ok && data.success) {
        setCurrentUser(prev => prev ? { ...prev, twoFactorEnabled: data.twoFactorEnabled } : null);
        triggerNotification("success", `Two-Factor Authentication is now ${data.twoFactorEnabled ? "ENABLED" : "DISABLED"}.`);
      } else {
        triggerNotification("error", "Failed to shift 2FA protocol.");
      }
    } catch (e) {
      triggerNotification("error", "Could not synchronize security updates.");
    }
  };

  // Action: Sign user out
  const handleLogout = async () => {
    try {
      const res = await fetch("/api/auth/logout", { method: "POST" });
      if (res.ok) {
        setCurrentUser(null);
        setIsPending2fa(false);
        setPendingUser(null);
        triggerNotification("success", "Logged out safely. Session cookies destroyed.");
        fetchLogs();
      }
    } catch (e) {
      triggerNotification("error", "Failed to communicate session termination.");
    }
  };

  // Action: Interactive SQL Injection Playground Execution
  const triggerSearchDemo = async (query: string) => {
    setSearchQuery(query);
    setPlaygroundLoading(true);
    try {
      const res = await fetch("/api/demo/search-users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ searchQuery: query })
      });

      const data = await res.json();
      if (res.ok && data.comparison) {
        setInjectionResult(data.comparison);
      } else {
        triggerNotification("error", "Error loading simulated database search results.");
      }
    } catch (e) {
      triggerNotification("error", "Failed to run playground SQL execution.");
    } finally {
      setPlaygroundLoading(false);
      fetchLogs();
    }
  };

  // Helpers for SQL Playground Display
  const presets = [
    { label: "Valid Query ('demo_user')", text: "demo_user" },
    { label: "Standard Injection (' OR '1'='1)", text: "' OR '1'='1" },
    { label: "Specific User Bypass (' OR username='admin' --)", text: "' OR username='admin' --" }
  ];

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col font-sans select-none antialiased selection:bg-teal-500 selection:text-slate-950">
      
      {/* Visual Header / Banner */}
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-teal-500/10 flex items-center justify-center border border-teal-500/30">
            <Shield className="w-6 h-6 text-teal-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-white flex items-center gap-2">
              Secure Login MVP <span className="bg-teal-500/10 text-teal-400 text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded border border-teal-500/20">Active Protection</span>
            </h1>
            <p className="text-xs text-slate-400">Interactive Security Validation Sandbox</p>
          </div>
        </div>

        {/* Global Nav Tabs */}
        <nav className="flex items-center gap-2">
          <button 
            id="tab_auth_system"
            onClick={() => setActiveTab("auth")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer flex items-center gap-2 ${
              activeTab === "auth" 
                ? "bg-slate-800 text-teal-400 border border-slate-700 shadow-md shadow-black/20" 
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
            }`}
          >
            <Lock className="w-4 h-4" />
            Auth Workspaces
          </button>
          
          <button 
            id="tab_sql_playground"
            onClick={() => {
              setActiveTab("playground");
              if (!injectionResult) triggerSearchDemo("demo_user");
            }}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer flex items-center gap-2 ${
              activeTab === "playground" 
                ? "bg-slate-800 text-teal-400 border border-slate-700 shadow-md shadow-black/20" 
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
            }`}
          >
            <Terminal className="w-4 h-4" />
            SQL Injection Sandbox
          </button>

          <button 
            id="tab_audit_logs"
            onClick={() => setActiveTab("logs")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer flex items-center gap-2 relative ${
              activeTab === "logs" 
                ? "bg-slate-800 text-teal-400 border border-slate-700 shadow-md shadow-black/20" 
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
            }`}
          >
            <Activity className="w-4 h-4" />
            Security Audit
            {securityLogs.filter(l => l.type === 'danger' || l.type === 'warning').length > 0 && (
              <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            )}
          </button>
        </nav>
      </header>

      {/* Main Container Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 flex flex-col gap-6">
        
        {/* Real-time Toast Messages */}
        {notification && (
          <div 
            id="global_notification_banner"
            className={`p-4 rounded-xl border flex items-start gap-3 shadow-lg transition-all duration-300 transform scale-100 ${
              notification.type === "success" 
                ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-300"
                : notification.type === "error"
                ? "bg-rose-950/40 border-rose-500/30 text-rose-300"
                : "bg-blue-950/40 border-blue-500/30 text-blue-300"
            }`}
          >
            {notification.type === "success" ? (
              <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5 animate-bounce" />
            ) : notification.type === "error" ? (
              <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-0.5">
                {notification.type === "success" ? "Operation Accomplished" : notification.type === "error" ? "Protection / Validation Alert" : "System Notification"}
              </h4>
              <p className="text-sm font-medium">{notification.message}</p>
            </div>
          </div>
        )}

        {authLoading ? (
          <div className="flex-1 flex flex-col items-center justify-center py-20 text-slate-400 gap-3">
            <RefreshCw className="w-8 h-8 text-teal-400 animate-spin" />
            <span>Verifying secure network session keys...</span>
          </div>
        ) : (
          <>
            {/* TAB 1: AUTH WORKSPACES */}
            {activeTab === "auth" && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                
                {/* Auth Screen Controls */}
                <div className="lg:col-span-7 flex flex-col gap-6">
                  {!currentUser && !isPending2fa ? (
                    /* LOGIN & REGISTER SIDE */
                    <div className="bg-slate-950 shadow-2xl rounded-2xl border border-slate-800 overflow-hidden transform transition-all">
                      <div className="border-b border-slate-800 bg-slate-950 p-6 flex justify-between items-center">
                        <div>
                          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                            {isRegisterMode ? "Generate Cryptographic Account" : "Access Authorization Portal"}
                          </h2>
                          <p className="text-xs text-slate-400 mt-1">
                            {isRegisterMode ? "Fill records to enroll. Keys are stored using secure hash routines." : "Login securely using existing user records."}
                          </p>
                        </div>
                        <span className="p-2 rounded-lg bg-teal-500/10 border border-teal-500/20 text-teal-400">
                          {isRegisterMode ? <UserCheck className="w-5 h-5" /> : <Lock className="w-5 h-5" />}
                        </span>
                      </div>

                      {/* LOGIN FORM */}
                      {!isRegisterMode ? (
                        <form id="login_form" onSubmit={handleLogin} className="p-6 space-y-4">
                          <div className="space-y-1">
                            <label className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">Username or Email Address</label>
                            <div className="relative">
                              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                                <User className="w-4 h-4" />
                              </span>
                              <input 
                                id="login_input_id"
                                type="text"
                                placeholder="demo_user or admin@securecorp.net"
                                value={loginId}
                                onChange={(e) => setLoginId(e.target.value)}
                                className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-teal-500 transition-colors placeholder:text-slate-600 text-sm font-medium"
                                required
                              />
                            </div>
                          </div>

                          <div className="space-y-1">
                            <div className="flex justify-between items-center">
                              <label className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">Account Password</label>
                            </div>
                            <div className="relative">
                              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                                <KeyRound className="w-4 h-4" />
                              </span>
                              <input 
                                id="login_input_password"
                                type={showPassword ? "text" : "password"}
                                placeholder="••••••••••••"
                                value={loginPassword}
                                onChange={(e) => setLoginPassword(e.target.value)}
                                className="w-full pl-10 pr-12 py-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-teal-500 transition-colors placeholder:text-slate-600 text-sm font-medium"
                                required
                              />
                              <button 
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                              >
                                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                              </button>
                            </div>
                          </div>

                          <div className="pt-2">
                            <button 
                              id="btn_submit_login"
                              type="submit"
                              className="w-full bg-gradient-to-r from-teal-600 to-teal-500 hover:from-teal-500 hover:to-teal-400 text-slate-950 font-semibold py-2.5 px-4 rounded-lg shadow-md transition-all flex items-center justify-center gap-2 text-sm cursor-pointer border border-teal-400/20 active:scale-95"
                            >
                              <ShieldCheck className="w-4 h-4" />
                              Authenticate Session
                            </button>
                          </div>

                          <div className="text-center pt-2 border-t border-slate-900">
                            <button 
                              type="button"
                              onClick={() => {
                                setIsRegisterMode(true);
                                setLoginPassword("");
                              }}
                              className="text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors cursor-pointer"
                            >
                              Don't have an account? Enlist and register here →
                            </button>
                          </div>
                        </form>
                      ) : (
                        /* REGISTRATION FORM */
                        <form id="register_form" onSubmit={handleRegister} className="p-6 space-y-4">
                          <div className="space-y-1">
                            <div className="flex justify-between items-center">
                              <label className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">Username Selection</label>
                              {touchedReg.username && (
                                <span className="text-[10px] font-bold">
                                  {validateUsername(regUsername) ? (
                                    <span className="text-emerald-400 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Approved</span>
                                  ) : (
                                    <span className="text-rose-400 flex items-center gap-1"><XCircle className="w-3 h-3" /> AlphaNumeric/3-30 chars</span>
                                  )}
                                </span>
                              )}
                            </div>
                            <div className="relative">
                              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                                <User className="w-4 h-4" />
                              </span>
                              <input 
                                id="reg_username"
                                type="text"
                                placeholder="secure_coder_2026"
                                value={regUsername}
                                onBlur={() => setTouchedReg(p => ({ ...p, username: true }))}
                                onChange={(e) => setRegUsername(e.target.value)}
                                className={`w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-900 border ${
                                  touchedReg.username && !validateUsername(regUsername) ? "border-rose-500" : "border-slate-800"
                                } text-slate-200 focus:outline-none focus:border-teal-500 transition-colors placeholder:text-slate-600 text-sm font-medium`}
                                required
                              />
                            </div>
                          </div>

                          <div className="space-y-1">
                            <div className="flex justify-between items-center">
                              <label className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">Email Address</label>
                              {touchedReg.email && (
                                <span className="text-[10px] font-bold">
                                  {validateEmail(regEmail) ? (
                                    <span className="text-emerald-400 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Syntax Ok</span>
                                  ) : (
                                    <span className="text-rose-400 flex items-center gap-1"><XCircle className="w-3 h-3" /> Need valid @ format</span>
                                  )}
                                </span>
                              )}
                            </div>
                            <div className="relative">
                              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                                <Mail className="w-4 h-4" />
                              </span>
                              <input 
                                id="reg_email"
                                type="email"
                                placeholder="developer@cyberdefence.org"
                                value={regEmail}
                                onBlur={() => setTouchedReg(p => ({ ...p, email: true }))}
                                onChange={(e) => setRegEmail(e.target.value)}
                                className={`w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-900 border ${
                                  touchedReg.email && !validateEmail(regEmail) ? "border-rose-500" : "border-slate-800"
                                } text-slate-200 focus:outline-none focus:border-teal-500 transition-colors placeholder:text-slate-600 text-sm font-medium`}
                                required
                              />
                            </div>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-1">
                              <div className="flex justify-between items-center">
                                <label className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">Password (min 8)</label>
                                {touchedReg.password && (
                                  <span className="text-[10px] font-bold">
                                    {regPassword.length >= 8 ? (
                                      <span className="text-emerald-400">Pass</span>
                                    ) : (
                                      <span className="text-rose-400">Short ({regPassword.length}/8)</span>
                                    )}
                                  </span>
                                )}
                              </div>
                              <div className="relative">
                                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                                  <KeyRound className="w-4 h-4" />
                                </span>
                                <input 
                                  id="reg_password"
                                  type="password"
                                  placeholder="••••••••••••"
                                  value={regPassword}
                                  onBlur={() => setTouchedReg(p => ({ ...p, password: true }))}
                                  onChange={(e) => setRegPassword(e.target.value)}
                                  className={`w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-900 border ${
                                    touchedReg.password && regPassword.length < 8 ? "border-rose-500" : "border-slate-800"
                                  } text-slate-200 focus:outline-none focus:border-teal-500 transition-colors placeholder:text-slate-600 text-sm font-medium`}
                                  required
                                />
                              </div>
                            </div>

                            <div className="space-y-1">
                              <div className="flex justify-between items-center">
                                <label className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">Confirm Password</label>
                                {touchedReg.confirmPassword && (
                                  <span className="text-[10px] font-bold">
                                    {(regPassword === regConfirmPassword && regConfirmPassword !== "") ? (
                                      <span className="text-emerald-400">Matches</span>
                                    ) : (
                                      <span className="text-rose-400">Mismatch</span>
                                    )}
                                  </span>
                                )}
                              </div>
                              <div className="relative">
                                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                                  <KeyRound className="w-4 h-4" />
                                </span>
                                <input 
                                  id="reg_confirm_password"
                                  type="password"
                                  placeholder="••••••••••••"
                                  value={regConfirmPassword}
                                  onBlur={() => setTouchedReg(p => ({ ...p, confirmPassword: true }))}
                                  onChange={(e) => setRegConfirmPassword(e.target.value)}
                                  className={`w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-900 border ${
                                    touchedReg.confirmPassword && regPassword !== regConfirmPassword ? "border-rose-500" : "border-slate-800"
                                  } text-slate-200 focus:outline-none focus:border-teal-500 transition-colors placeholder:text-slate-600 text-sm font-medium`}
                                  required
                                />
                              </div>
                            </div>
                          </div>

                          <div className="bg-slate-900/60 p-3.5 rounded-xl border border-slate-800/80 text-xs text-slate-400 leading-relaxed">
                            <span className="font-semibold text-slate-300">🔐 Secure Hashing Engine:</span> When registering, your raw password is never written to disk. Our backend applies standard <code className="text-teal-400 bg-slate-950 px-1 py-0.5 rounded font-mono">bcryptjs</code> cryptographically salted stretching rounds to build an secure 60-character hash footprint.
                          </div>

                          <div className="pt-2">
                            <button 
                              id="btn_submit_registration"
                              type="submit"
                              className="w-full bg-gradient-to-r from-teal-600 to-teal-500 hover:from-teal-500 hover:to-teal-400 text-slate-950 font-semibold py-2.5 px-4 rounded-lg shadow-md transition-all flex items-center justify-center gap-2 text-sm cursor-pointer border border-teal-400/20 active:scale-95"
                            >
                              <ShieldCheck className="w-4 h-4" />
                              Generate Secure Credentials
                            </button>
                          </div>

                          <div className="text-center pt-2 border-t border-slate-900">
                            <button 
                              type="button"
                              onClick={() => {
                                setIsRegisterMode(false);
                                setTouchedReg({ username: false, email: false, password: false, confirmPassword: false });
                              }}
                              className="text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors cursor-pointer"
                            >
                              Already registered? Access your workspace here →
                            </button>
                          </div>
                        </form>
                      )}
                    </div>
                  ) : isPending2fa ? (
                    /* 2FA CHALLENGE SUBMISSION SCREEN */
                    <div className="bg-slate-950 shadow-2xl rounded-2xl border border-rose-500/30 overflow-hidden transform transition-all animate-fade-in">
                      <div className="border-b border-rose-500/20 bg-rose-950/20 p-6 flex justify-between items-center">
                        <div>
                          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                            <ShieldAlert className="w-5 h-5 text-rose-400" />
                            Multi-Factor Verification
                          </h2>
                          <p className="text-xs text-slate-400 mt-1">
                            A transient 2FA code is requested to complete authorization.
                          </p>
                        </div>
                        <span className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                          <KeyRound className="w-5 h-5 animate-pulse" />
                        </span>
                      </div>

                      <form id="2fa_submission_form" onSubmit={handleVerify2fa} className="p-6 space-y-4">
                        <div className="bg-rose-950/20 border border-rose-900/40 rounded-xl p-4 text-xs text-rose-300 leading-relaxed">
                          <span className="font-bold">🔒 Multi-factor Security active:</span> Standard credentials verified. To prevent unauthorized logins, this profile requires a 6-digit One Time Password (OTP).
                          <div className="mt-2 bg-slate-950 p-2.5 rounded border border-rose-800/30 text-slate-300 font-mono text-[11px] flex justify-between items-center">
                            <span>📡 OTP generated on sandbox:</span>
                            <span className="text-teal-400 font-bold bg-teal-950/60 px-2 py-0.5 rounded border border-teal-500/20">Check Audit stream below!</span>
                          </div>
                        </div>

                        <div className="space-y-1">
                          <label className="block text-xs font-semibold tracking-wider text-slate-400 uppercase">Input 6-Digit Code</label>
                          <input 
                            id="otp_input_code"
                            type="text"
                            maxLength={6}
                            placeholder="Enter 6-digit code"
                            value={otpCode}
                            onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                            className="w-full text-center tracking-[1em] text-xl font-bold py-3 rounded-lg bg-slate-900 border border-rose-500/30 text-white focus:outline-none focus:border-rose-400 transition-colors placeholder:text-slate-700 placeholder:tracking-normal placeholder:text-sm font-mono"
                            required
                          />
                        </div>

                        <div className="flex gap-3 pt-2">
                          <button 
                            type="button"
                            onClick={() => {
                              setIsPending2fa(false);
                              setPendingUser(null);
                              setOtpCode("");
                            }}
                            className="flex-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 font-medium py-2 px-4 rounded-lg text-sm cursor-pointer transition-colors"
                          >
                            Cancel Login
                          </button>
                          <button 
                            id="btn_submit_2fa"
                            type="submit"
                            className="flex-1 bg-rose-500 hover:bg-rose-400 text-slate-950 font-bold py-2 px-4 rounded-lg text-sm cursor-pointer transition-colors shadow-md shadow-rose-950/20 flex items-center justify-center gap-2"
                          >
                            Verify & Proceed
                          </button>
                        </div>
                      </form>
                    </div>
                  ) : (
                    /* AUTHORIZED WORKSPACE DASHBOARD */
                    <div className="bg-slate-950 shadow-2xl rounded-2xl border border-slate-800 overflow-hidden transform transition-all">
                      <div className="border-b border-slate-800 bg-slate-950 p-6 flex justify-between items-center">
                        <div>
                          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                            🛡️ Your Secure Active Workspace
                          </h2>
                          <p className="text-xs text-slate-400 mt-1">
                            Session verified. Secure HTTP-only cookies are safeguarding your identity.
                          </p>
                        </div>
                        <button 
                          id="btn_logout"
                          onClick={handleLogout}
                          className="px-3.5 py-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 border border-rose-500/30 text-rose-400 hover:text-rose-300 cursor-pointer text-xs font-semibold flex items-center gap-1.5 transition-all"
                        >
                          <LogOut className="w-3.5 h-3.5" />
                          Sign Out
                        </button>
                      </div>

                      <div className="p-6 space-y-6">
                        
                        {/* Profile metrics */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
                            <span className="block text-[10px] uppercase font-bold tracking-widest text-slate-500 mb-1">Authenticated Subject</span>
                            <span className="text-base font-bold text-white block truncate">{currentUser?.username}</span>
                            <span className="text-xs text-teal-400 font-mono block mt-0.5">{currentUser?.email}</span>
                          </div>

                          <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80 flex flex-col justify-between">
                            <div>
                              <span className="block text-[10px] uppercase font-bold tracking-widest text-slate-500 mb-1">Stateful Session Token</span>
                              <span className="text-xs text-slate-400 font-mono block select-all bg-slate-950 p-1.5 rounded border border-slate-900 max-w-full overflow-hidden truncate">
                                Cookie: connect.sid=s%3A...
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Interactive Security Controls */}
                        <div className="bg-slate-900/40 p-5 rounded-2xl border border-slate-800/60 space-y-4">
                          <h3 className="text-sm font-bold text-white flex items-center gap-2">
                            <Settings className="w-4 h-4 text-teal-400" />
                            Multi-Factor Security Protocols
                          </h3>
                          
                          <div className="flex items-start justify-between gap-4 p-4 rounded-xl bg-slate-950 border border-slate-900">
                            <div className="space-y-1">
                              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">Enforce Two-Factor Sign-In OTP</h4>
                              <p className="text-xs text-slate-400 leading-relaxed max-w-md">
                                Forces a 6-digit random code challenge immediately following successful password checks. This guards against stolen credentials.
                              </p>
                            </div>
                            <button 
                              id="toggle_2fa_button"
                              onClick={() => handleToggle2fa(currentUser?.twoFactorEnabled || false)}
                              className={`px-4 py-2 rounded-lg text-xs font-bold tracking-wider cursor-pointer border uppercase transition-all ${
                                currentUser?.twoFactorEnabled 
                                  ? "bg-teal-500/10 text-teal-400 border-teal-500/30" 
                                  : "bg-slate-900 text-slate-500 border-slate-800 hover:border-slate-700 hover:text-slate-300"
                              }`}
                            >
                              {currentUser?.twoFactorEnabled ? "Active (On)" : "Disabled (Off)"}
                            </button>
                          </div>
                          
                          <div className="p-4 rounded-xl bg-slate-950 border border-slate-900 text-xs text-slate-300 leading-relaxed flex items-center gap-3">
                            <Shield className="w-5 h-5 text-teal-400 shrink-0" />
                            <span>
                              <strong>Want to test 2FA?</strong> Turn this on, sign out, then re-log inside of your profile to experience the secure multi-factor login challenge flow!
                            </span>
                          </div>
                        </div>

                      </div>
                    </div>
                  )}
                </div>

                {/* Helpful Educational Sidebar details */}
                <div className="lg:col-span-5 flex flex-col gap-6">
                  
                  {/* Account Presets Card to help immediately */}
                  <div className="bg-gradient-to-br from-slate-950 to-slate-900 p-5 rounded-2xl border border-slate-800 space-y-4">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <UserCheck className="w-4 h-4 text-teal-400" />
                      Testing Accounts (Simulated DB Seed)
                    </h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Two default credentials have been preseeded in memory so you can immediately experience normal logins and 2-Factor challenges:
                    </p>
                    <div className="space-y-2.5">
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-900 flex justify-between items-center text-xs">
                        <div>
                          <strong className="text-slate-300">demo_user</strong>
                          <span className="block text-slate-500 text-[10px]">No 2FA Required</span>
                        </div>
                        <span className="font-mono text-teal-400 bg-teal-950/40 px-2 py-1 rounded border border-teal-500/10">password123</span>
                      </div>

                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-900 flex justify-between items-center text-xs">
                        <div>
                          <strong className="text-slate-300">admin</strong>
                          <span className="block text-slate-500 text-[10px] text-rose-400 flex items-center gap-0.5">🔒 2FA Pre-Enabled</span>
                        </div>
                        <span className="font-mono text-rose-400 bg-rose-950/40 px-2 py-1 rounded border border-rose-500/10">adminSecurePassWord2026!</span>
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic Architecture Card */}
                  <div className="bg-gradient-to-br from-slate-950 to-slate-900 p-6 rounded-2xl border border-slate-800 space-y-4">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-teal-400" />
                      Security Architecture Principles
                    </h3>
                    
                    <ul className="space-y-3.5 text-xs text-slate-400">
                      <li className="flex items-start gap-2.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shrink-0 mt-1.5" />
                        <div>
                          <span className="font-semibold text-slate-200">Zero Raw Passwords Saved</span>
                          <p className="mt-0.5">Passwords are securely parsed on the backend in standard bcrypt blocks with automatic dynamic salts preventing rainbow tables.</p>
                        </div>
                      </li>
                      <li className="flex items-start gap-2.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shrink-0 mt-1.5" />
                        <div>
                          <span className="font-semibold text-slate-200">Parameterized Database Queries</span>
                          <p className="mt-0.5">Our SQLite interactions completely block malicious inputs by converting inputs to literals rather than raw instructions.</p>
                        </div>
                      </li>
                      <li className="flex items-start gap-2.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shrink-0 mt-1.5" />
                        <div>
                          <span className="font-semibold text-slate-200">Session Secure Flags</span>
                          <p className="mt-0.5">Sessions run strictly through <code className="text-teal-400 bg-slate-900 px-1 rounded">httpOnly</code> constraints, fully defeating document cookie extraction scripts (XSS block).</p>
                        </div>
                      </li>
                    </ul>
                  </div>

                </div>

              </div>
            )}

            {/* TAB 2: SQL INJECTION PLAYGROUND */}
            {activeTab === "playground" && (
              <div className="space-y-6">
                
                {/* Intro Card */}
                <div className="bg-slate-950 p-6 rounded-2xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
                  <div className="space-y-1">
                    <h2 className="text-lg font-bold text-white flex items-center gap-2">
                      <Terminal className="text-amber-400 w-5 h-5" />
                      SQL Injection Comparison Sandbox
                    </h2>
                    <p className="text-xs text-slate-400 leading-relaxed max-w-4xl">
                      A SQL injection occurs when user input is blended directly into a database command as query instructions. 
                      Type inputs below to see exactly how **Unsafe Concatenation** executes payload statements, versus how **Prepared Statements** treat inputs as literal text.
                    </p>
                  </div>

                  <div className="p-3 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded-xl max-w-sm text-xs">
                    💡 <strong>Quick Explainer:</strong> Standard injection payloads like <code className="text-white font-mono bg-slate-900 px-1 rounded">' OR '1'='1</code> force raw queries to evaluate always as true, exposing the entire database logs database!
                  </div>
                </div>

                {/* Search / Sandbox Input panel */}
                <div className="bg-slate-950 p-6 rounded-2xl border border-slate-800 space-y-4">
                  <span className="block text-xs font-bold text-slate-400 uppercase tracking-wider">Execute Custom Search Query</span>
                  
                  <div className="flex flex-col md:flex-row gap-3">
                    <input 
                      id="playground_search_input"
                      type="text"
                      placeholder="Type username/email, or SQL input (e.g. ' OR '1'='1)"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") triggerSearchDemo(searchQuery);
                      }}
                      className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-sm text-white font-mono placeholder:text-slate-600 focus:outline-none focus:border-teal-500 font-medium"
                    />
                    <button 
                      id="btn_trigger_search"
                      onClick={() => triggerSearchDemo(searchQuery)}
                      disabled={playgroundLoading}
                      className="bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold px-6 py-2 rounded-lg text-sm transition-colors cursor-pointer flex items-center gap-2"
                    >
                      {playgroundLoading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" /> Running...
                        </>
                      ) : (
                        "Query Database"
                      )}
                    </button>
                  </div>

                  {/* Preset Buttons */}
                  <div className="flex flex-wrap gap-2 items-center">
                    <span className="text-[11px] text-slate-500 font-bold uppercase tracking-wider mr-1">Dynamic Presets:</span>
                    {presets.map((p, idx) => (
                      <button 
                        key={idx}
                        onClick={() => triggerSearchDemo(p.text)}
                        className={`text-xs px-3 py-1.5 rounded-lg border cursor-pointer transition-all ${
                          searchQuery === p.text 
                            ? "bg-slate-800 text-teal-400 border-teal-500/30" 
                            : "bg-slate-900/60 text-slate-400 border-slate-830 hover:border-slate-700 hover:text-slate-300"
                        }`}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* COMPARISON PANELS DISPLAY */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

                  {/* LEFT SCREEN: UNSAFE PATHWAY */}
                  <div className="bg-slate-950 rounded-2xl border border-rose-500/20 overflow-hidden shadow-xl flex flex-col">
                    
                    {/* Header */}
                    <div className="bg-rose-950/20 px-5 py-4 border-b border-rose-500/20 flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5 text-rose-400" />
                        <span className="font-bold text-white text-sm">Vulnerable: UNSECURED Concatenation</span>
                      </div>
                      <span className="bg-rose-500/10 text-rose-400 text-[10px] font-bold px-2 py-0.5 rounded border border-rose-500/20 uppercase tracking-widest">
                        Exploitable
                      </span>
                    </div>

                    {/* Content */}
                    <div className="p-5 flex-1 flex flex-col gap-4">
                      
                      {/* Code Execution Block */}
                      <div className="space-y-1.5">
                        <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500">Node JS API implementation code:</span>
                        <pre className="bg-slate-900 p-3 rounded-lg text-[11px] text-rose-300 font-mono overflow-x-auto leading-relaxed border border-slate-800">
                          {`// ❌ VULNERABLE SYNTAX\nconst rawSqlStr = \`SELECT * FROM users WHERE username = '\${searchQuery}'\`\ndb.all(rawSqlStr);`}
                        </pre>
                      </div>

                      {/* Evaluated Query string live display */}
                      <div className="space-y-1.5">
                        <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500">Evaluated Query sent to SQLite Engine:</span>
                        <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto whitespace-pre-wrap break-all text-slate-300">
                          <span className="text-slate-500">QUERY:</span> {injectionResult?.raw.queryUsed}
                        </div>
                      </div>

                      {/* Injection Banner status */}
                      {injectionResult && (
                        <div className={`p-3.5 rounded-xl border flex items-center gap-2.5 text-xs font-medium leading-relaxed ${
                          injectionResult.raw.resultsCount > 1 && searchQuery.includes("'")
                            ? "bg-rose-950/40 border-rose-500/30 text-rose-300"
                            : "bg-slate-900/60 border-slate-800 text-slate-400"
                        }`}>
                          <AlertTriangle className={`w-4 h-4 shrink-0 ${injectionResult.raw.resultsCount > 1 && searchQuery.includes("'") ? 'text-rose-400 animate-pulse' : 'text-slate-500'}`} />
                          <span>
                            {injectionResult.raw.resultsCount > 1 && searchQuery.includes("'")
                              ? "⚠️ EXPLOITED! Injection code parsed successfully as SQLite statements, leaking entire user credentials files."
                              : "Database executed evaluation without parameter boundaries."}
                          </span>
                        </div>
                      )}

                      {/* Display Data Output results */}
                      <div className="flex-1 space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500">Query Outputs:</span>
                          <span className="text-[11px] font-mono font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded">
                            {injectionResult?.raw.resultsCount ?? 0} rows found
                          </span>
                        </div>

                        <div className="bg-slate-900 rounded-xl border border-slate-800 p-2.5 font-mono text-[11px] h-[180px] overflow-y-auto space-y-1 text-slate-300">
                          {playgroundLoading ? (
                            <span className="text-slate-500">Fetching records...</span>
                          ) : injectionResult?.raw?.success ? (
                            injectionResult.raw.results.length > 0 ? (
                              <table className="w-full text-left text-xs text-slate-300">
                                <thead className="text-[10px] uppercase font-bold text-slate-500 border-b border-slate-800">
                                  <tr>
                                    <th className="py-1">ID</th>
                                    <th className="py-1">Username</th>
                                    <th className="py-1">Email</th>
                                    <th className="py-1">2FA</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {injectionResult.raw.results.map((r, i) => (
                                    <tr key={i} className="border-b last:border-0 border-slate-800/40">
                                      <td className="py-1 text-slate-500">{r.id}</td>
                                      <td className="py-1 text-teal-400 font-bold">{r.username}</td>
                                      <td className="py-1 text-slate-400">{r.email}</td>
                                      <td className="py-1">{r.two_factor_enabled ? "True" : "False"}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            ) : (
                              <span className="text-slate-500 italic flex items-center justify-center h-full">No user accounts found matching query parameters.</span>
                            )
                          ) : (
                            <span className="text-rose-400">
                              Error compiling query: {injectionResult?.raw.error}
                            </span>
                          )}
                        </div>
                      </div>

                    </div>
                  </div>

                  {/* RIGHT SCREEN: SECURED PATHWAY */}
                  <div className="bg-slate-950 rounded-2xl border border-emerald-500/20 overflow-hidden shadow-xl flex flex-col">
                    
                    {/* Header */}
                    <div className="bg-emerald-950/20 px-5 py-4 border-b border-emerald-500/20 flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="w-5 h-5 text-emerald-400" />
                        <span className="font-bold text-white text-sm">SECURED: Parametric SQL Prepared Statements</span>
                      </div>
                      <span className="bg-emerald-500/10 text-emerald-400 text-[10px] font-bold px-2 py-0.5 rounded border border-emerald-500/20 uppercase tracking-widest">
                        Protected
                      </span>
                    </div>

                    {/* Content */}
                    <div className="p-5 flex-1 flex flex-col gap-4">
                      
                      {/* Code Execution Block */}
                      <div className="space-y-1.5">
                        <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500">Node JS API implementation code:</span>
                        <pre className="bg-slate-900 p-3 rounded-lg text-[11px] text-emerald-300 font-mono overflow-x-auto leading-relaxed border border-slate-800">
                          {`// ✅ SECURE SECURED PRACTICE\nconst secureQuery = "SELECT * FROM users WHERE username = ?"\ndb.all(secureQuery, [searchQuery]);`}
                        </pre>
                      </div>

                      {/* Evaluated Query string live display */}
                      <div className="space-y-1.5">
                        <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500">Evaluated Query sent to SQLite Engine:</span>
                        <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto whitespace-pre-wrap break-all text-slate-300">
                          <span className="text-slate-500">QUERY:</span> {injectionResult?.parameterized.queryUsed}
                        </div>
                      </div>

                      {/* Injection Banner status */}
                      {injectionResult && (
                        <div className={`p-3.5 rounded-xl border flex items-center gap-2.5 text-xs font-medium leading-relaxed ${
                          searchQuery.includes("'")
                            ? "bg-emerald-950/40 border-emerald-500/30 text-emerald-300"
                            : "bg-slate-900/60 border-slate-800 text-slate-500"
                        }`}>
                          <Shield className={`w-4 h-4 shrink-0 ${searchQuery.includes("'") ? 'text-emerald-400' : 'text-slate-500'}`} />
                          <span>
                            {searchQuery.includes("'")
                              ? "🛡️ IMMUNE: Injection inputs securely parsed as harmless text literals. Protection verified!"
                              : "Database sanitized search using standard preparation parameters."}
                          </span>
                        </div>
                      )}

                      {/* Display Data Output results */}
                      <div className="flex-1 space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500">Query Outputs:</span>
                          <span className="text-[11px] font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">
                            {injectionResult?.parameterized.resultsCount ?? 0} rows found
                          </span>
                        </div>

                        <div className="bg-slate-900 rounded-xl border border-slate-800 p-2.5 font-mono text-[11px] h-[180px] overflow-y-auto space-y-1 text-slate-300">
                          {playgroundLoading ? (
                            <span className="text-slate-500">Fetching records...</span>
                          ) : injectionResult?.parameterized?.success ? (
                            injectionResult.parameterized.results.length > 0 ? (
                              <table className="w-full text-left text-xs text-slate-300">
                                <thead className="text-[10px] uppercase font-bold text-slate-500 border-b border-slate-800">
                                  <tr>
                                    <th className="py-1">ID</th>
                                    <th className="py-1">Username</th>
                                    <th className="py-1">Email</th>
                                    <th className="py-1">2FA</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {injectionResult.parameterized.results.map((r, i) => (
                                    <tr key={i} className="border-b last:border-0 border-slate-800/40">
                                      <td className="py-1 text-slate-500">{r.id}</td>
                                      <td className="py-1 text-teal-400 font-bold">{r.username}</td>
                                      <td className="py-1 text-slate-400">{r.email}</td>
                                      <td className="py-1">{r.two_factor_enabled ? "True" : "False"}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            ) : (
                              <span className="text-slate-500 italic flex items-center justify-center h-full">No user accounts found matching query parameters.</span>
                            )
                          ) : (
                            <span className="text-emerald-400">
                              Error: {injectionResult?.parameterized.error}
                            </span>
                          )}
                        </div>
                      </div>

                    </div>
                  </div>

                </div>

              </div>
            )}

            {/* TAB 3: AUDIT EVENT LOG ANALYSIS */}
            {activeTab === "logs" && (
              <div className="bg-slate-950 rounded-2xl border border-slate-800 overflow-hidden flex flex-col shadow-2xl">
                
                {/* Panel title */}
                <div className="p-6 border-b border-slate-800 bg-slate-950 flex justify-between items-center">
                  <div className="space-y-1">
                    <h2 className="text-lg font-bold text-white flex items-center gap-2">
                      <Activity className="text-teal-400 w-5 h-5" />
                      Live Security Audit Events Stream
                    </h2>
                    <p className="text-xs text-slate-400">
                      Real-time monitor tracking security events, API authorization, password hash executions, and playground queries on the backend.
                    </p>
                  </div>

                  <button 
                    id="btn_clear_audit_logs"
                    onClick={clearLogs}
                    className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer text-xs flex items-center gap-1"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Clear Audit Logs
                  </button>
                </div>

                {/* Stream contents list */}
                <div className="p-6">
                  {securityLogs.length === 0 ? (
                    <div className="text-center py-16 text-slate-500 text-xs italic flex flex-col items-center justify-center gap-2">
                      <Shield className="w-8 h-8 text-slate-700" />
                      No security audit events captured in this session yet.
                    </div>
                  ) : (
                    <div className="space-y-3.5 max-h-[500px] overflow-y-auto pr-1">
                      {securityLogs.map((log) => (
                        <div 
                          key={log.id}
                          className={`p-4 rounded-xl border flex items-start gap-3.5 text-xs transition-colors ${
                            log.type === "success" 
                              ? "bg-emerald-950/10 border-emerald-500/20 text-slate-300" 
                              : log.type === "danger"
                              ? "bg-rose-950/10 border-rose-500/20 text-slate-300"
                              : log.type === "warning"
                              ? "bg-amber-950/10 border-amber-500/20 text-slate-300"
                              : "bg-slate-900/60 border-slate-850 text-slate-300"
                          }`}
                        >
                          {/* Left icon dot */}
                          <div className="mt-0.5 shrink-0">
                            {log.type === "success" ? (
                              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 block shadow shadow-emerald-500/20" />
                            ) : log.type === "danger" ? (
                              <span className="w-2.5 h-2.5 rounded-full bg-rose-400 block animate-ping shadow shadow-rose-500/20" />
                            ) : log.type === "warning" ? (
                              <span className="w-2.5 h-2.5 rounded-full bg-amber-400 block shadow shadow-amber-500/20" />
                            ) : (
                              <span className="w-2.5 h-2.5 rounded-full bg-slate-500 block" />
                            )}
                          </div>

                          {/* Event Text detail */}
                          <div className="flex-1 space-y-1">
                            <div className="flex justify-between items-start gap-4">
                              <span className="font-bold text-white uppercase text-[10px] tracking-wider">
                                {log.event}
                              </span>
                              <span className="font-mono text-[10px] text-slate-500">
                                {new Date(log.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                            <p className="font-mono text-[11px] text-slate-300 leading-relaxed bg-slate-950/40 p-2 rounded border border-slate-900/50">
                              {log.details}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Footer security headers validation */}
                <div className="bg-slate-900 p-4 border-t border-slate-800 text-xs text-slate-400 flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-[10px] tracking-wide uppercase text-teal-400 font-bold bg-teal-950/40 px-2 py-0.5 rounded border border-teal-500/10">
                    <ShieldCheck className="w-3 h-3" />
                    Security Headers Activated
                  </div>
                  <span className="font-mono text-[10px] text-slate-500">
                    CSP: default-src 'self' | SameSite: Strict | HttpOnly Cookies active
                  </span>
                </div>

              </div>
            )}
          </>
        )}

        {/* PERSISTENT FULL-STACK LIVE SECURITY AUDIT LOG STEAM - MINIFIED BAR AT BOTTOM */}
        {activeTab !== "logs" && (
          <div className="bg-slate-950 rounded-xl border border-slate-850 p-4 shadow-xl flex items-center justify-between text-xs transition-all mt-4 animate-fade-in-up">
            <div className="flex items-center gap-3">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-teal-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-teal-500"></span>
              </span>
              <div>
                <span className="font-bold text-slate-300 block uppercase text-[9px] tracking-wider">Audit Log Stream:</span>
                <span className="text-slate-400 font-mono text-[11px] truncate max-w-xl block">
                  {securityLogs.length > 0 ? (
                    `[${securityLogs[0].event.toUpperCase()}] ${securityLogs[0].details}`
                  ) : (
                    "Audit event sensor listening on port 3000..."
                  )}
                </span>
              </div>
            </div>

            <button 
              id="btn_quick_view_audit"
              onClick={() => setActiveTab("logs")}
              className="text-teal-400 hover:text-teal-300 underline font-semibold text-[11px] flex items-center gap-0.5 cursor-pointer"
            >
              Examine Security Logs
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        )}

      </main>

      {/* Footer system details */}
      <footer className="border-t border-slate-800 bg-slate-950/60 p-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-2">
          <span>Secure Login System MVP Sandbox • ISO/IEC 27001 Concept Alignment Demonstration</span>
          <span>Crafted for Secure Sandbox Deployments • Node 22x TS Runtime</span>
        </div>
      </footer>

    </div>
  );
}
