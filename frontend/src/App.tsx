import { useEffect, useState } from "react";
import { Activity, ArrowDownLeft, Bell, Check, ChevronDown, CircleHelp, Command, Database, Gauge, Globe2, LayoutDashboard, Moon, MoreHorizontal, Network, Plus, Search, Server, Settings2, ShieldCheck, Sun, Users, Zap } from "lucide-react";

type HostReport = { platform: string; python_version: string; capabilities: Record<string, { status: "available" | "unavailable" | "unknown"; detail: string }> };
const navItems = [{ label: "نمای کلی", icon: LayoutDashboard }, { label: "اتصال‌ها", icon: Network }, { label: "کاربران", icon: Users }, { label: "محیط اجرا", icon: Server }];
const services = [{ name: "Xray Core", detail: "موتور اتصال", state: "هنوز راه‌اندازی نشده", tone: "muted" }, { name: "Host Compatibility", detail: "بررسی محیط اجرا", state: "آمادهٔ بررسی", tone: "green" }, { name: "API Service", detail: "رابط برنامه‌نویسی", state: "دموی محلی", tone: "blue" }];

export default function App() {
  const [active, setActive] = useState("نمای کلی");
  const [dark, setDark] = useState(true);
  const [host, setHost] = useState<HostReport | null>(null);
  const [apiState, setApiState] = useState("در حال بررسی API");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let alive = true;
    Promise.all([
      fetch("http://127.0.0.1:8000/api/health").then((r) => { if (!r.ok) throw new Error(); return r.json(); }),
      fetch("http://127.0.0.1:8000/api/host").then((r) => { if (!r.ok) throw new Error(); return r.json() as Promise<HostReport>; }),
    ]).then(([, report]) => { if (alive) { setHost(report); setApiState("API متصل"); } })
      .catch(() => { if (alive) setApiState("API در دسترس نیست"); });
    return () => { alive = false; };
  }, []);

  function toast(message: string) {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 3000);
  }

  return <div className={dark ? "app-shell dark" : "app-shell light"} dir="rtl">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Command size={23}/></div><div className="brand-copy"><strong>NovaPanel</strong><span>CONTROL CENTER</span></div><button className="icon-button" aria-label="بیشتر" onClick={() => toast("گزینه‌های بیشتر به‌زودی اضافه می‌شود.")}><MoreHorizontal size={18}/></button></div>
      <div className="workspace-switch"><div className="workspace-icon"><Zap size={17}/></div><div className="workspace-copy"><strong>فضای شخصی</strong><span>نسخهٔ توسعه</span></div><ChevronDown size={16}/></div>
      <div className="nav-caption">فضای کار</div>
      <nav className="main-nav">{navItems.map(({label, icon: Icon}) => <button key={label} className={active === label ? "nav-item active" : "nav-item"} onClick={() => setActive(label)}><Icon size={18}/><span>{label}</span></button>)}</nav>
      <div className="nav-caption section-caption">مدیریت</div>
      <nav className="main-nav"><button className={active === "عیب‌یابی" ? "nav-item active" : "nav-item"} onClick={() => setActive("عیب‌یابی")}><Activity size={18}/><span>عیب‌یابی</span></button><button className={active === "امنیت" ? "nav-item active" : "nav-item"} onClick={() => setActive("امنیت")}><ShieldCheck size={18}/><span>امنیت</span></button><button className={active === "تنظیمات" ? "nav-item active" : "nav-item"} onClick={() => setActive("تنظیمات")}><Settings2 size={18}/><span>تنظیمات</span></button></nav>
      <div className="sidebar-bottom"><div className="help-card"><div className="help-icon"><CircleHelp size={18}/></div><strong>به کمک نیاز داری؟</strong><p>راهنمای NovaPanel رو ببین.</p><button onClick={() => toast("راهنما در حال آماده‌سازی است.")}>مشاهدهٔ راهنما <ArrowDownLeft size={14}/></button></div><div className="profile-row"><div className="avatar">B</div><div className="profile-copy"><strong>Blackthor86</strong><span>مدیر پروژه</span></div></div></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumbs"><span>NovaPanel</span><span>/</span><strong>{active}</strong></div><div className="topbar-actions"><div className="api-indicator"><span className={apiState === "API متصل" ? "status-dot online" : "status-dot"}></span>{apiState}</div><button className="icon-button" aria-label="جستجو" onClick={() => toast("جستجو در نسخهٔ بعدی اضافه می‌شود.")}><Search size={18}/></button><button className="icon-button" aria-label="اعلان‌ها" onClick={() => toast("اعلان جدیدی وجود ندارد.")}><Bell size={18}/></button><span className="topbar-divider"></span><button className="icon-button" aria-label="تغییر تم" onClick={() => setDark(!dark)}>{dark ? <Sun size={18}/> : <Moon size={18}/>}</button></div></header>
      <div className="page-content">
        <div className="welcome-row"><div><div className="eyebrow"><span className="eyebrow-line"></span> پنل مدیریت زیرساخت</div><h1>{active === "نمای کلی" ? "خوش اومدی، Blackthor" : active}</h1><p className="page-subtitle">{active === "نمای کلی" ? "وضعیت سرویس و محیط اجرات رو از یک‌جا بررسی کن." : "این بخش در حال توسعه است و به‌زودی کامل‌تر می‌شود."}</p></div><button className="primary-button" onClick={() => toast("ساخت اتصال در مرحلهٔ بعدی فعال می‌شود.")}><Plus size={17}/> اتصال جدید</button></div>
        <div className="dev-banner"><div className="dev-banner-icon"><CircleHelp size={19}/></div><div><strong>نسخهٔ اولیه — در حال توسعه</strong><p>اطلاعات این صفحه نمایشی است. موتور اتصال هنوز نصب یا اجرا نشده است.</p></div><span className="dev-pill">PREVIEW</span></div>
        <section className="metrics-grid"><Metric title="اتصال‌های فعال" value="۰" note="هنوز اتصالی پیکربندی نشده" icon={<Network size={18}/>} accent="purple"/><Metric title="کاربران" value="۰" note="مدیریت کاربران به‌زودی" icon={<Users size={18}/>} accent="blue"/><Metric title="مصرف ترافیک" value="—" note="پس از اتصال هسته در دسترس است" icon={<Gauge size={18}/>} accent="orange"/><Metric title="وضعیت امنیت" value="پیکربندی نشده" note="بررسی امنیتی هنوز انجام نشده" icon={<ShieldCheck size={18}/>} accent="green" compact/></section>
        <div className="content-grid">
          <section className="panel"><div className="panel-heading"><div><h2>وضعیت سرویس‌ها</h2><p>وضعیت اجزای اصلی NovaPanel</p></div><button className="subtle-button" onClick={() => toast("وضعیت سرویس‌ها به‌روزرسانی شد.")}><Activity size={15}/> بررسی وضعیت</button></div><div className="service-list">{services.map((service) => <div className="service-row" key={service.name}><div className={"service-symbol " + service.tone}><Server size={18}/></div><div className="service-copy"><strong>{service.name}</strong><span>{service.detail}</span></div><div className="service-state"><span className={"state-dot " + service.tone}></span>{service.state}</div></div>)}</div><div className="panel-footer"><span><span className="status-dot online"></span> API محلی</span><span>نسخهٔ ۰٫۱٫۰</span></div></section>
          <section className="panel host-panel"><div className="panel-heading"><div><h2>محیط اجرا</h2><p>اطلاعات قابل تشخیص در این محیط</p></div><div className="host-icon"><Database size={18}/></div></div><div className="host-summary"><div className="host-orb"><Globe2 size={23}/></div><div><strong>{host?.platform ?? "در انتظار اتصال API"}</strong><span>{host ? "Python " + host.python_version : "اطلاعات محیط هنوز دریافت نشده"}</span></div></div><div className="capability-list"><Capability label="فضای ذخیره‌سازی" status={host?.capabilities.persistent_storage.status ?? "unknown"}/><Capability label="اجرای پردازش جداگانه" status={host?.capabilities.separate_processes.status ?? "unknown"}/><Capability label="دسترسی شبکه TCP/UDP" status={host?.capabilities.inbound_tcp_udp.status ?? "unknown"}/></div><button className="full-width-button" onClick={() => setActive("محیط اجرا")}>جزئیات محیط اجرا <ArrowDownLeft size={16}/></button></section>
        </div>
        <section className="panel quick-panel"><div className="panel-heading"><div><h2>شروع سریع</h2><p>قدم‌های بعدی برای آماده‌سازی NovaPanel</p></div><span className="progress-label">۱ از ۴</span></div><div className="progress-track"><span></span></div><div className="steps-grid"><QuickStep done title="ساخت مخزن" detail="مخزن خصوصی GitHub آماده است"/><QuickStep title="راه‌اندازی محلی" detail="اجرای API و داشبورد"/><QuickStep title="اتصال موتور" detail="یکپارچه‌سازی امن Xray"/><QuickStep title="آزمایش نهایی" detail="بررسی عملکرد و امنیت"/></div></section>
        <footer className="page-footer"><span>NovaPanel · ساخته‌شده با تمرکز بر امنیت و شفافیت</span><span>© 2026 Blackthor86 · AGPL-3.0-or-later</span></footer>
      </div>
    </main>
    {notice && <div className="toast"><Check size={17}/>{notice}</div>}
  </div>;
}

function Metric({title,value,note,icon,accent,compact=false}:{title:string;value:string;note:string;icon:React.ReactNode;accent:string;compact?:boolean}) {
  return <div className="metric-card"><div className="metric-top"><span>{title}</span><span className={"metric-icon " + accent}>{icon}</span></div><div className={compact ? "metric-value compact" : "metric-value"}>{value}</div><div className="metric-note">{note}</div></div>;
}
function Capability({label,status}:{label:string;status:"available"|"unavailable"|"unknown"}) {
  const text = status === "available" ? "قابل دسترس" : status === "unavailable" ? "غیرفعال" : "بررسی نشده";
  return <div className="capability-row"><span>{label}</span><span className={"capability-status " + status}><i/>{text}</span></div>;
}
function QuickStep({done=false,title,detail}:{done?:boolean;title:string;detail:string}) {
  return <div className="quick-step"><span className={done ? "step-check done" : "step-check"}>{done ? <Check size={14}/> : <span/>}</span><div><strong>{title}</strong><p>{detail}</p></div></div>;
}
