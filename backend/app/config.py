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
