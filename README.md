# Kisan Advisor

Flask + SQLite + Makerend (OpenAI-compatible API). Crop disease diagnosis, login/signup, history, text + voice chatbot.

## Local run
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env # fill MAKEREND_API_KEY and SECRET_KEY
.\.venv\Scripts\python.exe app.py # http://localhost:5000
```

## Deploy (Vercel)
1. Push this folder to GitHub (`.env` and `.venv` are ignored).
2. Vercel -> Add New Project -> import repo (Framework: Flask / Other).
3. Settings -> Environment Variables: `MAKEREND_API_KEY`, `MAKEREND_BASE_URL`, `MAKEREND_MODEL`, `SECRET_KEY`.
4. Deploy. Check `/api/health`.

SQLite on Vercel lives in /tmp: it is temporary and resets on cold start.
For permanent users/history, switch the db() helper to Turso / Neon / Supabase.
