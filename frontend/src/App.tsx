import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  Activity, ArrowLeft, Check, CircleHelp, Command, Copy, Cpu, Database,
  Gauge, Globe2, LayoutDashboard, LockKeyhole, LogOut, Moon, Network,
  Plus, RefreshCw, Server, Settings2, ShieldCheck, Sun, Trash2, Users, X, Zap
} from "lucide-react";

type User = { id: string; name: string; uuid: string; quota_gb: number | null; expires_at: string | null; enabled: boolean; created_at: string; up_bytes: number; down_bytes: number; used_bytes: number; last_synced_at: string | null };
type Connection = { id: string; name: string; address: string; port: number; transport: string; path: string; service_name: string; host_header: string | null; server_name: string | null; certificate_file: string | null; private_key_file: string | null; enabled: boolean; tls_ready: boolean; created_at: string };
type Host = { platform: string; python_version: string; data_directory: string; capabilities: Record<string, { status: string; detail: string }> };
type Stats = { users_total: number; users_enabled: number; connections_total: number; connections_enabled: number; total_bytes: number; engine: string; version: string };
type Page = "نمای کلی" | "اتصال‌ها" | "کاربران" | "محیط اجرا" | "عیب‌یابی" | "امنیت" | "تنظیمات";
const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const fa = (n: number) => n.toLocaleString("fa-IR");
function formatBytes(value: number): string {
  if (!value || value < 0) return "۰ B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return amount.toLocaleString("fa-IR", { maximumFractionDigits: 1 }) + " " + units[index];
}
function formatExpiry(value: string | null): string {
  if (!value) return "بدون انقضا";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("fa-IR", { dateStyle: "medium", timeStyle: "short" });
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(API + path, {
    ...options,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "درخواست انجام نشد.");
  return data as T;
}

const navigation: { label: Page; icon: typeof LayoutDashboard; group: string }[] = [
  { label: "نمای کلی", icon: LayoutDashboard, group: "فضای کار" },
  { label: "اتصال‌ها", icon: Network, group: "فضای کار" },
  { label: "کاربران", icon: Users, group: "فضای کار" },
  { label: "محیط اجرا", icon: Server, group: "مدیریت" },
  { label: "عیب‌یابی", icon: Activity, group: "مدیریت" },
  { label: "امنیت", icon: ShieldCheck, group: "مدیریت" },
  { label: "تنظیمات", icon: Settings2, group: "مدیریت" }
];

export default function App() {
  const [page, setPage] = useState<Page>("نمای کلی");
  const [dark, setDark] = useState(true);
  const [booting, setBooting] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [admin, setAdmin] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [noticeError, setNoticeError] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [host, setHost] = useState<Host | null>(null);
  const [engine, setEngine] = useState("stopped");
  const [logs, setLogs] = useState("");
  const [filter, setFilter] = useState("");
  const [modal, setModal] = useState<"user" | "connection" | "links" | null>(null);
  const [selectedConnection, setSelectedConnection] = useState<Connection | null>(null);
  const [links, setLinks] = useState<{ user: string; link: string }[]>([]);
  const [userName, setUserName] = useState("");
  const [quota, setQuota] = useState("100");
  const [expires, setExpires] = useState("");
  const [connectionName, setConnectionName] = useState("");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("443");
  const [transport, setTransport] = useState("ws");
  const [path, setPath] = useState("/ray");
  const [serviceName, setServiceName] = useState("novapanel");
  const [hostHeader, setHostHeader] = useState("");
  const [sni, setSni] = useState("");
  const [cert, setCert] = useState("");
  const [privateKey, setPrivateKey] = useState("");

  const toast = useCallback((message: string, isError = false) => {
    setNotice(message);
    setNoticeError(isError);
  }, []);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 3500);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const refresh = useCallback(async () => {
    const me = await request<{ username: string }>("/api/me");
    const results = await Promise.all([
      request<Stats>("/api/dashboard"),
      request<User[]>("/api/users"),
      request<Connection[]>("/api/connections"),
      request<Host>("/api/host"),
      request<{ status: string }>("/api/engine/status")
    ]);
    setAdmin(me.username);
    setStats(results[0]);
    setUsers(results[1]);
    setConnections(results[2]);
    setHost(results[3]);
    setEngine(results[4].status);
  }, []);

  useEffect(() => {
    let mounted = true;
    async function initialize() {
      try {
        const status = await request<{ setup_required: boolean }>("/api/setup/status");
        if (!mounted) return;
        setSetupRequired(status.setup_required);
        if (status.setup_required) return;
        try {
          await refresh();
          if (mounted) setSignedIn(true);
        } catch {
          if (mounted) setSignedIn(false);
        }
      } catch {
        if (mounted) toast("ارتباط با API برقرار نشد. سرور Python را روشن کن.", true);
      } finally {
        if (mounted) setBooting(false);
      }
    }
    initialize();
    return () => { mounted = false; };
  }, [refresh, toast]);

  async function submitAuth(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await request(setupRequired ? "/api/setup" : "/api/login", {
        method: "POST",
        body: JSON.stringify({ username, password })
      });
      await refresh();
      setSignedIn(true);
      setSetupRequired(false);
      setPassword("");
      toast(setupRequired ? "حساب مدیر ساخته شد." : "ورود موفق بود.");
    } catch (error) {
      toast(error instanceof Error ? error.message : "ورود ناموفق بود.", true);
    } finally {
      setBusy(false);
    }
  }

  async function runAction(pathname: string, method = "POST", body?: unknown) {
    setBusy(true);
    try {
      const result = await request<{ status?: string; ok?: boolean; message?: string }>(pathname, {
        method,
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      await refresh();
      toast(result.message || "عملیات با موفقیت انجام شد.");
      return result;
    } catch (error) {
      toast(error instanceof Error ? error.message : "عملیات ناموفق بود.", true);
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    try { await request("/api/logout", { method: "POST" }); } catch { /* The session may already have expired. */ }
    setSignedIn(false);
    setUsers([]);
    setConnections([]);
    setStats(null);
  }

  async function createUser(event: FormEvent) {
    event.preventDefault();
    const result = await runAction("/api/users", "POST", {
      name: userName.trim(),
      quota_gb: quota ? Number(quota) : null,
      expires_at: expires ? new Date(expires).toISOString() : null
    });
    if (result) { setModal(null); setUserName(""); setQuota("100"); setExpires(""); }
  }

  async function createConnection(event: FormEvent) {
    event.preventDefault();
    const result = await runAction("/api/connections", "POST", {
      name: connectionName.trim(), address: address.trim(), port: Number(port),
      transport, path, service_name: serviceName, host_header: hostHeader || null,
      server_name: sni || null, certificate_file: cert || null, private_key_file: privateKey || null
    });
    if (result) {
      setModal(null);
      setConnectionName(""); setAddress(""); setPort("443"); setPath("/ray");
      setHostHeader(""); setSni(""); setCert(""); setPrivateKey("");
    }
  }

  async function removeUser(user: User) {
    if (!window.confirm("کاربر «" + user.name + "» حذف شود؟")) return;
    await runAction("/api/users/" + user.id, "DELETE");
  }

  async function removeConnection(connection: Connection) {
    if (!window.confirm("پروفایل «" + connection.name + "» حذف شود؟")) return;
    await runAction("/api/connections/" + connection.id, "DELETE");
  }

  async function showLinks(connection: Connection) {
    if (!connection.tls_ready) {
      toast("برای تولید لینک قابل استفاده، ابتدا مسیر گواهی و کلید TLS را تنظیم کن.", true);
      return;
    }
    try {
      const result = await request<{ user: string; link: string }[]>("/api/connections/" + connection.id + "/links");
      setLinks(result);
      setSelectedConnection(connection);
      setModal("links");
    } catch (error) {
      toast(error instanceof Error ? error.message : "دریافت لینک‌ها ناموفق بود.", true);
    }
  }

  async function copy(value: string) {
    try { await navigator.clipboard.writeText(value); toast("در کلیپ‌بورد کپی شد."); }
    catch { toast("مرورگر اجازهٔ کپی خودکار نداد.", true); }
  }

  const visibleUsers = useMemo(() => users.filter(user => (user.name + " " + user.uuid).toLowerCase().includes(filter.toLowerCase())), [users, filter]);
  const visibleConnections = useMemo(() => connections.filter(item => (item.name + " " + item.address + " " + item.transport).toLowerCase().includes(filter.toLowerCase())), [connections, filter]);

  if (booting) return <div className="boot-screen"><div className="brand-mark"><Command size={27}/></div><strong>NovaPanel</strong><div className="loader-line"><span/></div><p>فضای مدیریت در حال آماده‌سازی است</p></div>;

  if (!signedIn) return <div className="auth-screen" dir="rtl">
    <div className="auth-grid-bg"/>
    <div className="auth-glow glow-one"/><div className="auth-glow glow-two"/>
    <form className="auth-card" onSubmit={submitAuth}>
      <div className="auth-brand"><div className="brand-mark"><Command size={25}/></div><div><strong>NovaPanel</strong><span>CONTROL CENTER</span></div></div>
      <div className="auth-icon"><LockKeyhole size={24}/></div>
      <span className="eyebrow">دسترسی مدیریت</span>
      <h1>{setupRequired ? "پنل خودت رو راه‌اندازی کن" : "خوش برگشتی"}</h1>
      <p className="auth-description">{setupRequired ? "یک حساب مدیر بساز؛ این مرحله فقط برای اولین راه‌اندازی است." : "برای ورود به فضای مدیریت، اطلاعاتت را وارد کن."}</p>
      <label>نام کاربری<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} minLength={setupRequired ? 3 : 1} maxLength={48} required placeholder="مثلاً nova_admin"/></label>
      <label>رمز عبور<div className="password-control"><input type={showPassword ? "text" : "password"} autoComplete={setupRequired ? "new-password" : "current-password"} value={password} onChange={event => setPassword(event.target.value)} minLength={setupRequired ? 14 : 1} maxLength={256} required placeholder={setupRequired ? "حداقل ۱۴ کاراکتر" : "رمز عبور مدیر"}/><button type="button" className="show-password" onClick={() => setShowPassword(!showPassword)}>{showPassword ? "پنهان" : "نمایش"}</button></div></label>
      {setupRequired && <p className="form-hint">رمز قوی انتخاب کن و آن را در جای امن نگه دار.</p>}
      <button className="primary-button wide" disabled={busy}>{busy ? "در حال بررسی…" : setupRequired ? "ساخت حساب مدیر" : "ورود امن"} <ArrowLeft size={17}/></button>
      <div className="auth-foot"><ShieldCheck size={16}/> نشست مدیریت محافظت‌شده</div>
    </form>
    {notice && <Toast message={notice} error={noticeError}/>}
  </div>;

  return <div className={dark ? "app-shell dark" : "app-shell light"} dir="rtl">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Command size={23}/></div><div className="brand-copy"><strong>NovaPanel</strong><span>CONTROL CENTER</span></div></div>
      <div className="workspace-switch"><div className="workspace-icon"><Zap size={18}/></div><div><strong>فضای مدیریت</strong><small>زیرساخت شخصی</small></div></div>
      <div className="nav-caption">فضای کار</div>
      <nav>{navigation.slice(0, 3).map(({ label, icon: Icon }) => <button key={label} className={page === label ? "nav-item active" : "nav-item"} onClick={() => { setPage(label); setFilter(""); }}><Icon size={19}/><span>{label}</span>{label === "کاربران" && users.length > 0 && <small>{fa(users.length)}</small>}</button>)}</nav>
      <div className="nav-caption section-caption">مدیریت</div>
      <nav>{navigation.slice(3).map(({ label, icon: Icon }) => <button key={label} className={page === label ? "nav-item active" : "nav-item"} onClick={() => { setPage(label); setFilter(""); }}><Icon size={19}/><span>{label}</span></button>)}</nav>
      <div className="sidebar-bottom">
        <div className="security-card"><div className="security-card-icon"><ShieldCheck size={19}/></div><strong>امنیت از اولویت‌هاست</strong><p>قبل از اجرای سرویس، تنظیمات و دسترسی‌ها را بررسی کن.</p><button onClick={() => setPage("امنیت")}>چک‌لیست امنیت <ArrowLeft size={14}/></button></div>
        <div className="profile-row"><div className="avatar">{(admin[0] || "N").toUpperCase()}</div><div className="profile-copy"><strong>{admin}</strong><small>مدیر اصلی</small></div><button className="icon-button" title="خروج" aria-label="خروج" onClick={signOut}><LogOut size={17}/></button></div>
      </div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumbs"><span>NovaPanel</span><span>/</span><strong>{page}</strong></div><div className="topbar-actions"><span className="api-indicator"><i/> API متصل</span><div className="top-search"><Users size={16}/><input aria-label="جستجو" placeholder="جستجوی کاربر یا اتصال" value={filter} onChange={event => setFilter(event.target.value)}/></div><button className="icon-button" aria-label="تازه‌سازی" title="تازه‌سازی" onClick={() => refresh().then(() => toast("اطلاعات تازه شد.")).catch(error => toast(error.message, true))}><RefreshCw size={17}/></button><button className="icon-button" aria-label="تغییر تم" title="تغییر تم" onClick={() => setDark(!dark)}>{dark ? <Sun size={18}/> : <Moon size={18}/>}</button></div></header>
      <div className="page-content">
        <div key={page} className="page-view">
          {page === "نمای کلی" && <Overview stats={stats} users={users} connections={connections} host={host} engine={engine} go={setPage} refresh={() => refresh().then(() => toast("وضعیت به‌روزرسانی شد.")).catch(error => toast(error.message, true))} diagnose={() => setPage("عیب‌یابی")}/>}
          {page === "کاربران" && <section><PageHeading eyebrow="مدیریت دسترسی" title="کاربران" description="کاربران و شناسه‌های دسترسی را مدیریت کن." action={<button className="primary-button" onClick={() => setModal("user")}><Plus size={17}/> کاربر جدید</button>}/><div className="table-panel"><div className="table-toolbar"><div><strong>فهرست کاربران</strong><span>{fa(users.length)} کاربر ثبت‌شده</span></div><span className="toolbar-note"><Database size={15}/> پایگاه دادهٔ محلی</span></div>{visibleUsers.length ? <div className="table-scroll"><table><thead><tr><th>کاربر</th><th>شناسه UUID</th><th>مصرف / سهمیه</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>{visibleUsers.map(user => <tr key={user.id}><td><div className="user-cell"><span className="mini-avatar">{user.name.slice(0, 1).toUpperCase()}</span><strong>{user.name}</strong></div></td><td><button className="copy-code" onClick={() => copy(user.uuid)}><code>{user.uuid.slice(0, 12)}…</code><Copy size={14}/></button></td><td><div className="usage-cell"><div className="usage-head"><strong>{formatBytes(user.used_bytes || 0)}</strong><small>{user.quota_gb ? "از " + fa(user.quota_gb) + " GB" : "بدون سقف"}</small></div>{user.quota_gb && <div className="quota-track"><i style={{ width: Math.min(100, ((user.used_bytes || 0) / (user.quota_gb * 1024 ** 3)) * 100) + "%" }}/></div>}</div></td><td>{formatExpiry(user.expires_at)}</td><td><Pill good={user.enabled}>{user.enabled ? "فعال" : "غیرفعال"}</Pill></td><td><button className="icon-button danger" aria-label="حذف کاربر" onClick={() => removeUser(user)}><Trash2 size={16}/></button></td></tr>)}</tbody></table></div> : <Empty title="کاربری پیدا نشد" text="برای شروع یک کاربر جدید بساز." action={<button className="primary-button" onClick={() => setModal("user")}><Plus size={16}/> ساخت کاربر</button>}/>}</div><p className="subtle-note">مصرف از آمار Xray همگام می‌شود؛ با رسیدن به سهمیه یا انقضا، کاربر در بررسی بعدی غیرفعال می‌شود.</p></section>}
          {page === "اتصال‌ها" && <section><PageHeading eyebrow="پروفایل‌های اتصال" title="اتصال‌ها" description="پروفایل‌های سرور و روش انتقال را تعریف و مدیریت کن." action={<button className="primary-button" onClick={() => setModal("connection")}><Plus size={17}/> اتصال جدید</button>}/><div className="connection-grid">{visibleConnections.map(connection => <article className="connection-card" key={connection.id}><div className="connection-card-top"><div className="connection-symbol"><Network size={20}/></div><Pill good={connection.enabled}>{connection.enabled ? "فعال" : "غیرفعال"}</Pill><button className="icon-button danger" aria-label="حذف اتصال" onClick={() => removeConnection(connection)}><Trash2 size={16}/></button></div><h3>{connection.name}</h3><p className="connection-address"><Globe2 size={15}/>{connection.address}:{connection.port}</p><div className="connection-tags"><span>{connection.transport.toUpperCase()}</span><span>{connection.path}</span><span className={connection.tls_ready ? "tls-ready" : "tls-missing"}>{connection.tls_ready ? "فایل‌های TLS یافت شد" : "نیازمند گواهی TLS"}</span></div><div className="connection-card-footer"><span>{connection.tls_ready ? "قابل بررسی" : "لینک هنوز آماده نیست"}</span><button className="text-button" onClick={() => showLinks(connection)} disabled={!connection.tls_ready}>لینک کاربران <ArrowLeft size={14}/></button></div></article>)}{visibleConnections.length === 0 && <div className="empty-wide"><Empty title="پروفایلی وجود ندارد" text="اولین پروفایل اتصال را اضافه کن تا در این صفحه نمایش داده شود." action={<button className="primary-button" onClick={() => setModal("connection")}><Plus size={16}/> ساخت اتصال</button>}/></div>}</div></section>}
          {page === "محیط اجرا" && <section><PageHeading eyebrow="سلامت زیرساخت" title="محیط اجرا" description="قابلیت‌های شناسایی‌شده و مواردی که هنوز به آزمون بیرونی نیاز دارند." action={<button className="subtle-button" onClick={() => refresh().catch(error => toast(error.message, true))}><RefreshCw size={15}/> بررسی مجدد</button>}/><div className="host-hero"><div className="host-orb"><Cpu size={27}/></div><div className="host-info"><span>سیستم میزبان</span><h2>{host?.platform || "نامشخص"}</h2><p>Python {host?.python_version || "—"}</p><code>{host?.data_directory || ""}</code></div><Pill good={host?.capabilities.xray_binary?.status === "available"}>{host?.capabilities.xray_binary?.status === "available" ? "Xray شناسایی شد" : "Xray شناسایی نشد"}</Pill></div><div className="capability-grid">{Object.entries(host?.capabilities || {}).map(([key, item]) => <div className="capability-card" key={key}><div className="capability-symbol"><Activity size={19}/></div><strong>{({ persistent_storage: "فضای ذخیره‌سازی", separate_processes: "اجرای پردازش", xray_binary: "موتور Xray", inbound_tcp_udp: "دسترسی TCP/UDP" } as Record<string, string>)[key] || key}</strong><p>{item.detail}</p><CapabilityStatus status={item.status}/></div>)}</div><div className="notice-card"><CircleHelp size={19}/><p>اجرای Python یا وجود یک پورت به‌تنهایی پشتیبانی VPN را تضمین نمی‌کند. محدودیت و قوانین میزبان باید جداگانه بررسی شوند.</p></div></section>}
          {page === "عیب‌یابی" && <section><PageHeading eyebrow="ابزارهای عملیاتی" title="عیب‌یابی" description="تنظیمات را اعتبارسنجی کن و وضعیت اجرای موتور را بررسی کن." action={<button className="subtle-button" onClick={async () => { try { const result = await request<{ log: string }>("/api/engine/log"); setLogs(result.log || "هنوز خروجی‌ای ثبت نشده است."); } catch (error) { toast(error instanceof Error ? error.message : "خواندن لاگ ناموفق بود.", true); } }}><RefreshCw size={15}/> تازه‌سازی لاگ</button>}/><div className="diagnostic-grid"><div className="panel diagnostic-card"><div className="diagnostic-icon"><Check size={22}/></div><h3>اعتبارسنجی پیکربندی</h3><p>پیکربندی با باینری نصب‌شده بررسی می‌شود؛ این تست اتصال بیرونی را تضمین نمی‌کند.</p><button className="primary-button" disabled={busy} onClick={() => runAction("/api/engine/config-test")}>اجرای تست</button></div><div className="panel diagnostic-card"><div className="diagnostic-icon"><Cpu size={22}/></div><h3>موتور Xray</h3><p>وضعیت فعلی پردازش تحت مدیریت پنل.</p><div className="engine-state"><i className={engine === "running" ? "online" : ""}/>{engine === "running" ? "در حال اجرا" : "متوقف"}</div><div className="button-row"><button className="primary-button" disabled={busy || engine === "running"} onClick={() => runAction("/api/engine/start")}>اجرا</button><button className="subtle-button" disabled={busy || engine !== "running"} onClick={() => runAction("/api/engine/stop")}>توقف</button></div></div></div><div className="log-panel"><div className="log-header"><strong>خروجی موتور</strong><button className="icon-button" aria-label="کپی لاگ" onClick={() => copy(logs)}><Copy size={15}/></button></div><pre>{logs || "هنوز لاگی ثبت نشده است."}</pre></div></section>}
          {page === "امنیت" && <section><PageHeading eyebrow="حفاظت و دسترسی" title="امنیت" description="وضعیت واقعی چند مورد مهم و چک‌لیست آماده‌سازی سرور."/><div className="security-summary"><div className="security-summary-icon"><ShieldCheck size={28}/></div><div><h2>بررسی قبل از استقرار</h2><p>این چک‌لیست راهنمای سخت‌سازی است، نه تضمین یا گواهی امنیت.</p></div><Pill good={false}>نیازمند بررسی</Pill></div><SecurityRow title="رمز عبور مدیر" detail="حداقل ۱۴ کاراکتر و ذخیره‌سازی PBKDF2." done/><SecurityRow title="کلید نشست پایدار" detail="روی سرور NOVAPANEL_SECRET_KEY تصادفی و ثابت تنظیم کن."/><SecurityRow title="HTTPS و کوکی Secure" detail="پس از فعال کردن HTTPS، NOVAPANEL_COOKIE_SECURE=1 تنظیم شود."/><SecurityRow title="دسترسی مدیریتی" detail="پنل را پشت HTTPS و فایروال قرار بده و دسترسی را محدود کن."/><SecurityRow title="قوانین میزبان" detail="اجازهٔ پروکسی و پورت‌های موردنیاز را از ارائه‌دهنده تأیید کن."/><SecurityRow title="سهمیه و انقضا" detail="فعلاً ثبت می‌شوند و محدودیت خودکار تا زمان پیاده‌سازی حسابداری مصرف اعمال نمی‌شود."/></section>}
          {page === "تنظیمات" && <section><PageHeading eyebrow="تنظیمات برنامه" title="تنظیمات" description="ترجیحات رابط کاربری و مشخصات برنامه."/><div className="settings-panel"><div className="settings-row"><div className="settings-icon"><Sun size={19}/></div><div><strong>حالت ظاهری</strong><p>تم یشمی تیره یا روشن</p></div><button className="subtle-button" onClick={() => setDark(!dark)}>تغییر تم</button></div><div className="settings-row"><div className="settings-icon"><Database size={19}/></div><div><strong>نشانی API</strong><p>{API}</p></div><Pill good>محلی</Pill></div><div className="settings-row"><div className="settings-icon"><Command size={19}/></div><div><strong>NovaPanel</strong><p>نسخهٔ {stats?.version || "0.2.0"} · AGPL-3.0-or-later · {admin}</p></div><a href="https://github.com/Blackthor86/NovaPanel" target="_blank" rel="noreferrer">مخزن GitHub ↗</a></div><div className="settings-row"><div className="settings-icon"><LogOut size={19}/></div><div><strong>پایان نشست</strong><p>از حساب مدیر خارج شو.</p></div><button className="subtle-button" onClick={signOut}>خروج امن</button></div></div></section>}
        </div>
        <footer className="page-footer"><span><span className="footer-orb"/> NovaPanel · کنترل شفاف زیرساخت</span><span>© 2026 Blackthor86 · AGPL-3.0-or-later</span></footer>
      </div>
    </main>
    {modal && <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) setModal(null); }}><div className="modal-card animate-rise"><div className="modal-header"><div><span className="eyebrow">NOVAPANEL / MANAGEMENT</span><h2>{modal === "user" ? "ساخت کاربر جدید" : modal === "connection" ? "تعریف اتصال" : "لینک‌های دسترسی"}</h2></div><button className="icon-button" onClick={() => setModal(null)} aria-label="بستن"><X size={19}/></button></div>
      {modal === "user" && <form className="form-stack" onSubmit={createUser}><label>نام کاربر<input autoFocus required maxLength={80} value={userName} onChange={event => setUserName(event.target.value)} placeholder="مثلاً استفاده شخصی"/></label><label>سهمیه ترافیک (GB)<input type="number" min="1" max="1000000" value={quota} onChange={event => setQuota(event.target.value)}/></label><label>تاریخ انقضا (اختیاری)<input type="datetime-local" value={expires} onChange={event => setExpires(event.target.value)}/></label><p className="form-hint">مصرف از آمار داخلی Xray محاسبه می‌شود؛ برای اعمال سهمیه باید موتور در حال اجرا باشد.</p><button className="primary-button wide" disabled={busy}><Plus size={16}/> ساخت کاربر</button></form>}
      {modal === "connection" && <form className="form-stack" onSubmit={createConnection}><div className="form-two"><label>نام اتصال<input required maxLength={80} value={connectionName} onChange={event => setConnectionName(event.target.value)} placeholder="مثلاً Edge WS"/></label><label>دامنه یا IP<input required value={address} onChange={event => setAddress(event.target.value)} placeholder="vpn.example.com"/></label></div><div className="form-two"><label>پورت<input type="number" min="1" max="65535" required value={port} onChange={event => setPort(event.target.value)}/></label><label>ترنسپورت<select value={transport} onChange={event => setTransport(event.target.value)}><option value="ws">WebSocket (WS)</option><option value="grpc">gRPC</option><option value="httpupgrade">HTTP Upgrade</option><option value="xhttp">XHTTP</option></select></label></div>{transport === "grpc" ? <label>نام سرویس gRPC<input value={serviceName} onChange={event => setServiceName(event.target.value)}/></label> : <label>مسیر اتصال<input required value={path} onChange={event => setPath(event.target.value)}/></label>}<div className="form-two"><label>SNI (اختیاری)<input value={sni} onChange={event => setSni(event.target.value)} placeholder="vpn.example.com"/></label><label>Host header (اختیاری)<input value={hostHeader} onChange={event => setHostHeader(event.target.value)} placeholder="cdn.example.com"/></label></div><label>مسیر فایل گواهی TLS<input value={cert} onChange={event => setCert(event.target.value)} placeholder="مسیر fullchain.pem"/></label><label>مسیر کلید خصوصی TLS<input value={privateKey} onChange={event => setPrivateKey(event.target.value)} placeholder="مسیر privkey.pem"/></label><p className="form-hint">گواهی معتبر و قابل‌خواندن روی میزبان برای اجرای واقعی لازم است.</p><button className="primary-button wide" disabled={busy}><Plus size={16}/> ذخیرهٔ اتصال</button></form>}
      {modal === "links" && <div className="links-list">{links.length ? links.map(item => <div className="link-item" key={item.user}><div><strong>{item.user}</strong><code>{item.link}</code></div><button className="subtle-button" onClick={() => copy(item.link)}><Copy size={15}/> کپی</button></div>) : <Empty title="کاربر فعالی وجود ندارد" text="ابتدا کاربر فعال بساز تا لینک دریافت کند."/>}<p className="form-hint">لینک‌ها اطلاعات دسترسی خصوصی‌اند؛ آن‌ها را در مخزن عمومی یا گفت‌وگوی عمومی نفرست.</p></div>}
    </div></div>}
    {notice && <Toast message={notice} error={noticeError}/>}
  </div>;
}

function Overview({stats, users, connections, host, engine, go, refresh, diagnose}:{stats:Stats|null;users:User[];connections:Connection[];host:Host|null;engine:string;go:(page:Page)=>void;refresh:()=>void;diagnose:()=>void}) {
  return <section>
    <div className="welcome-row"><div><div className="eyebrow">پنل کنترل زیرساخت</div><h1>خوش اومدی، مدیریت با توئه.</h1><p className="page-subtitle">وضعیت سرویس، کاربران و مقصدهای اتصال در یک نمای روشن.</p></div><div className="welcome-actions"><button className="subtle-button" onClick={refresh}><RefreshCw size={15}/> تازه‌سازی</button><button className="primary-button" onClick={() => go("اتصال‌ها")}><Plus size={17}/> اتصال جدید</button></div></div>
    <div className="hero-banner"><div className="hero-copy"><span className="hero-kicker"><Zap size={14}/> NOVAPANEL CONTROL</span><h2>زیرساختت، <em>تحت کنترل تو.</em></h2><p>اتصال‌ها را مدیریت کن، وضعیت موتور را بسنج و پیش از اجرا، پیکربندی را اعتبارسنجی کن.</p><div className="hero-actions"><button onClick={diagnose}>ابزارهای عیب‌یابی <ArrowLeft size={15}/></button><button className="hero-secondary" onClick={() => go("محیط اجرا")}>بررسی محیط</button></div></div><div className="hero-art" aria-hidden="true"><div className="orbit orbit-a"/><div className="orbit orbit-b"/><div className="orbit orbit-c"/><div className="hero-core"><Command size={42}/></div><span className="orbit-node node-a"><ShieldCheck size={18}/></span><span className="orbit-node node-b"><Network size={18}/></span><span className="orbit-node node-c"><Zap size={18}/></span></div></div>
    <div className="metrics-grid"><Metric title="اتصال‌های فعال" value={fa(connections.filter(item => item.enabled).length)} note={fa(connections.length) + " پروفایل ثبت‌شده"} icon={<Network/>}/><Metric title="کاربران فعال" value={fa(users.filter(user => user.enabled).length)} note={fa(users.length) + " کاربر ثبت‌شده"} icon={<Users/>}/><Metric title="موتور Xray" value={engine === "running" ? "فعال" : "متوقف"} note={host?.capabilities.xray_binary?.status === "available" ? "باینری شناسایی شده" : "نیازمند نصب و تنظیم"} icon={<Gauge/>}/><Metric title="مصرف کل ثبت‌شده" value={formatBytes(stats?.total_bytes || 0)} note="ترافیک ثبت‌شده توسط Xray" icon={<Activity/>}/></div>
    <div className="content-grid"><section className="panel"><PanelHeading title="وضعیت سرویس‌ها" subtitle="وضعیت جاری اجزای مدیریت"/><Service icon={<Database/>} title="پایگاه داده" detail="SQLite · ذخیره‌سازی محلی" status="آماده" good/><Service icon={<Network/>} title="پروفایل‌های اتصال" detail={fa(connections.length) + " پروفایل ثبت‌شده"} status={connections.length ? "تعریف شده" : "نیازمند تنظیم"} good={connections.length > 0}/><Service icon={<Cpu/>} title="موتور Xray" detail="پردازش تحت کنترل پنل" status={engine === "running" ? "در حال اجرا" : "متوقف"} good={engine === "running"}/><div className="panel-footer"><span><i className="status-dot online"/> API محلی</span><span>نسخهٔ {stats?.version || "0.2.0"}</span></div></section><section className="panel host-panel"><PanelHeading title="محیط اجرا" subtitle="قابلیت‌های قابل تشخیص"/><div className="host-summary"><div className="host-orb"><Globe2 size={23}/></div><div><strong>{host?.platform || "نامشخص"}</strong><span>Python {host?.python_version || "—"}</span></div></div><Capability label="فضای ذخیره‌سازی" status={host?.capabilities.persistent_storage?.status || "unknown"}/><Capability label="باینری Xray" status={host?.capabilities.xray_binary?.status || "unknown"}/><Capability label="دسترسی TCP/UDP" status={host?.capabilities.inbound_tcp_udp?.status || "unknown"}/><button className="full-width-button" onClick={() => go("محیط اجرا")}>جزئیات محیط اجرا <ArrowLeft size={15}/></button></section></div>
    <section className="panel quick-panel"><PanelHeading title="دسترسی سریع" subtitle="کارهای متداول از همین‌جا"/><div className="quick-actions"><Quick icon={<Users/>} title="ساخت کاربر" detail="ایجاد شناسهٔ دسترسی" onClick={() => go("کاربران")}/><Quick icon={<Network/>} title="تعریف اتصال" detail="تنظیم ترنسپورت" onClick={() => go("اتصال‌ها")}/><Quick icon={<ShieldCheck/>} title="بررسی امنیت" detail="چک‌لیست سخت‌سازی" onClick={() => go("امنیت")}/><Quick icon={<Activity/>} title="تست پیکربندی" detail="اعتبارسنجی با Xray" onClick={diagnose}/></div></section>
    <div className="notice-card"><CircleHelp size={18}/><p>قابلیت شبکه فقط پس از بررسی تنظیمات و شرایط واقعی میزبان مشخص می‌شود.</p></div>
  </section>;
}
function Metric({title,value,note,icon}:{title:string;value:string;note:string;icon:ReactNode}){return <div className="metric-card"><div className="metric-top"><span>{title}</span><span className="metric-icon">{icon}</span></div><div className="metric-value">{value}</div><div className="metric-note">{note}</div></div>}
function PanelHeading({title,subtitle}:{title:string;subtitle:string}){return <div className="panel-heading"><div><h2>{title}</h2><p>{subtitle}</p></div></div>}
function Service({icon,title,detail,status,good=false}:{icon:ReactNode;title:string;detail:string;status:string;good?:boolean}){return <div className="service-row"><span className="service-symbol">{icon}</span><div className="service-copy"><strong>{title}</strong><small>{detail}</small></div><Pill good={good}>{status}</Pill></div>}
function PageHeading({eyebrow,title,description,action}:{eyebrow:string;title:string;description:string;action?:ReactNode}){return <div className="page-heading-row"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p className="page-subtitle">{description}</p></div>{action}</div>}
function Empty({title,text,action}:{title:string;text:string;action?:ReactNode}){return <div className="empty-state"><div className="empty-icon"><Database size={25}/></div><h3>{title}</h3><p>{text}</p>{action}</div>}
function Pill({children,good}:{children:ReactNode;good:boolean}){return <span className={good ? "pill success" : "pill warning"}><i/>{children}</span>}
function CapabilityStatus({status}:{status:string}){return <span className={"capability-status " + status}><i/>{status === "available" ? "قابل دسترس" : status === "unavailable" ? "غیرفعال" : "تأیید نشده"}</span>}
function Capability({label,status}:{label:string;status:string}){return <div className="capability-row"><span>{label}</span><CapabilityStatus status={status}/></div>}
function SecurityRow({title,detail,done=false}:{title:string;detail:string;done?:boolean}){return <div className="security-item"><span className={done ? "security-check done" : "security-check"}>{done ? <Check size={16}/> : <CircleHelp size={16}/>}</span><div><strong>{title}</strong><p>{detail}</p></div><Pill good={done}>{done ? "فعال" : "بررسی شود"}</Pill></div>}
function Quick({icon,title,detail,onClick}:{icon:ReactNode;title:string;detail:string;onClick:()=>void}){return <button className="quick-action" onClick={onClick}><span className="quick-action-icon">{icon}</span><strong>{title}</strong><small>{detail}</small><ArrowLeft className="quick-arrow" size={15}/></button>}
function Toast({message,error}:{message:string;error:boolean}){return <div className={error ? "toast toast-error" : "toast"}><span className="toast-icon">{error ? <CircleHelp size={17}/> : <Check size={17}/>}</span>{message}</div>}
