# Umarmathi Pivot Point Calculator & Live Trading Engine (v7.0)

OWASP Top 10 Secured Financial Streaming Architecture with Signup/Login, OWASP Password Policy Enforcement, Role-Based Access Control (RBAC), and Real-Time Price Crossing Alerts.

## Features in v7.0
- **Direct User Registration & Login**: Full email/password signup and login endpoints (`/api/v1/auth/signup`, `/api/v1/auth/login`, `/api/v1/auth/me`).
- **OWASP Password Policy Enforcement**:
  - Minimum 8 characters long
  - At least 1 uppercase letter (`A-Z`)
  - At least 1 lowercase letter (`a-z`)
  - At least 1 numeric digit (`0-9`)
  - At least 1 special character (`!@#$%^&*()_+-=[]{}|;:,.<>?/`)
- **Interactive UI Modal**:
  - Live password strength indicator and policy checklist.
  - User profile badge displaying logged-in email and role.
  - Google OAuth 2.0 PKCE sign-in support.
- **Trading Engine & Price Crossing Alerts**:
  - Standard Floor, Fibonacci, and Camarilla pivot calculation models.
  - Multi-asset ticker support: XAUUSD (Gold), XAGUSD (Silver), EURUSD, GBPUSD, USDJPY.
  - Animated rose/red price crossing banner alerts on live tick stream.
- **OWASP Perimeter Security**:
  - Security headers middleware (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `HSTS`).
  - Fernet AES-256 field-level encryption for user PII.
  - Audit logging for signup, login, password violations, and alert breaches.

## Deployment on Render
1. Push repository to GitHub.
2. Select Web Service on Render.
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Health check path: `/healthz`
