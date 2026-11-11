# Kisan Advisor

Flask + SQLite + Gemini. Crop disease diagnosis, login/signup, history, text + voice chatbot.

## Local run
```
pip install -r requirements.txt
copy .env.example .env      # fill GEMINI_API_KEY and SECRET_KEY
python app.py               # http://localhost:5000
```

## Deploy (Vercel)
1. Push this folder to GitHub (`.env` and `.venv` are ignored).
2. Vercel -> Add New Project -> import repo (Framework: Flask / Other).
3. Settings -> Environment Variables: `GEMINI_API_KEY`, `SECRET_KEY`.
4. Deploy. Check `/api/health`.

SQLite on Vercel lives in /tmp: it is temporary and resets on cold start.
For permanent users/history, switch the db() helper to Turso / Neon / Supabase.
