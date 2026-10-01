import os

from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", 60))  # 1 hour

SESSION_COOKIE_NAME = "hedr_session"
# Must be false for local http://localhost dev - a Secure cookie is never
# sent by the browser over plain HTTP. Set true once served over HTTPS.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").strip().lower() == "true"

# --- Email (used for MFA verification codes) ---------------------------------
# Plain SMTP, no extra dependency. Nothing is sent - and MFA cannot be
# enabled or used to sign in - until SMTP_HOST and SMTP_FROM are set.
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM")
# "starttls" (port 587, default), "ssl" (implicit TLS, port 465) or "none".
SMTP_SECURITY = os.environ.get("SMTP_SECURITY", "starttls").strip().lower()

# --- Email OTP / MFA limits ----------------------------------------------------
OTP_LENGTH = 6
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", 300))  # a code is valid for 5 minutes
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", 5))  # wrong guesses before a code is voided
OTP_RESEND_COOLDOWN_SECONDS = int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", 30))
OTP_MAX_REQUESTS = int(os.environ.get("OTP_MAX_REQUESTS", 3))  # codes issued per user+purpose ...
OTP_REQUEST_WINDOW_SECONDS = int(os.environ.get("OTP_REQUEST_WINDOW_SECONDS", 600))  # ... per window
# How long a sign-in may stay "password verified, code pending" in total,
# however many times the code is re-sent.
MFA_LOGIN_MAX_AGE_SECONDS = int(os.environ.get("MFA_LOGIN_MAX_AGE_SECONDS", 900))
# Per-IP cap on MFA verify/resend calls (on top of the per-code attempt limit).
MFA_IP_MAX_REQUESTS = int(os.environ.get("MFA_IP_MAX_REQUESTS", 30))
MFA_IP_WINDOW_SECONDS = int(os.environ.get("MFA_IP_WINDOW_SECONDS", 600))
