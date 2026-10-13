# راه‌اندازی NovaPanel روی کامپیوتر شخصی

این راهنما برای اجرای NovaPanel روی کامپیوتر شخصی است. برای شروع، Python و Node.js لازم‌اند؛ اجرای واقعی VPN علاوه بر پنل به موتور Xray و دسترسی شبکهٔ مجاز نیاز دارد.

## چیزهایی که لازم داری

- Python 3.11 یا جدیدتر
- Node.js 20 یا جدیدتر
- Git اختیاری است؛ می‌توانی فایل‌های مخزن را از GitHub هم دریافت کنی.

## ۱. اجرای بک‌اند Python

ترمینال را در پوشهٔ اصلی پروژه باز کن و این دستورها را اجرا کن.

### ویندوز

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

اگر PowerShell اجازهٔ فعال‌سازی محیط را نداد، می‌توانی مستقیم از فایل اجرایی محیط استفاده کنی:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

بک‌اند روی `http://127.0.0.1:8000` اجرا می‌شود. مستندات API در `http://127.0.0.1:8000/docs` قرار دارد.

## ۲. اجرای داشبورد

یک پنجرهٔ ترمینال دیگر باز کن:

```bash
cd frontend
npm install
npm run dev
```

آدرس محلی که Vite نمایش می‌دهد در مرورگر باز کن؛ معمولاً `http://127.0.0.1:5173` است. در اولین اجرا، فقط یک رمز قویِ حداقل ۱۴ کاراکتری برای مدیر بساز؛ نیازی به نام کاربری نیست.

برای خاموش کردن هر بخش، در ترمینال مربوطه `Ctrl+C` بزن.

## ۳. اجرای تست بک‌اند

در ترمینال ریشهٔ پروژه، پس از نصب وابستگی‌ها:

```bash
python -m pytest -q
```

## نکات مهم

- فعلاً از این نسخه روی اینترنت عمومی استفاده نکن؛ احراز هویت و اتصال به موتور هنوز پیاده‌سازی نشده‌اند.
- آمار داشبورد نمایشی است و به معنی وجود VPN فعال نیست.
- وضعیت TCP/UDP از داخل برنامه به‌تنهایی قابل تأیید نیست؛ باید با تنظیمات میزبان و تست بیرونی بررسی شود.
- هیچ توکن، لینک اشتراک یا اطلاعات خصوصی را در GitHub یا گزارش خطا قرار نده.
