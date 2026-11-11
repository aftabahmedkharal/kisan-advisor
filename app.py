import os, re, json, time, sqlite3, hashlib
from datetime import timedelta
from functools import wraps

import requests
from flask import Flask, request, jsonify, session, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))


def _load_env():
    p = os.path.join(BASE, ".env")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env()

ON_VERCEL = bool(os.environ.get("VERCEL"))
MAKEREND_API_KEY = os.environ.get("MAKEREND_API_KEY", "")
MAKEREND_BASE_URL = os.environ.get("MAKEREND_BASE_URL", "https://makerend.com/v1").rstrip("/")
MAKEREND_MODEL = os.environ.get("MAKEREND_MODEL", "gpt-6.1-terra")
# Vercel me sirf /tmp writable hai (temporary, cold start pe reset ho sakta hai)
DB_PATH = os.environ.get("DB_PATH") or ("/tmp/kisan.db" if ON_VERCEL else os.path.join(BASE, "kisan.db"))
MODELS = [MAKEREND_MODEL]

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or hashlib.sha256(("kisan:" + MAKEREND_API_KEY).encode()).hexdigest(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_VERCEL,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,  # Vercel body limit ~4.5MB
)

# ---------------- messages ----------------
MSG = {
    "busy": ("Servers are busy. Please try again in a minute.", "سرور مصروف ہے۔ ایک منٹ بعد دوبارہ کوشش کریں۔"),
    "nokey": ("AI key is not set on the server.", "سرور پر AI کی (key) سیٹ نہیں ہے۔"),
    "badkey": ("AI key is invalid. Check MAKEREND_API_KEY.", "AI کی (key) غلط ہے۔"),
    "noimg": ("No image received.", "تصویر موصول نہیں ہوئی۔"),
    "badimg": ("Please upload a JPG, PNG or WEBP image.", "براہ کرم JPG، PNG یا WEBP تصویر دیں۔"),
    "big": ("Image is too large (max 4MB).", "تصویر بہت بڑی ہے (زیادہ سے زیادہ 4MB)۔"),
    "nomsg": ("Please type a message.", "براہ کرم پیغام لکھیں۔"),
}


def m(key, lang):
    return MSG[key][1 if lang == "ur" else 0]


def get_lang(v):
    return "ur" if str(v or "").lower() in ("ur", "urdu") else "en"


@app.errorhandler(413)
def too_big(_):
    return jsonify(error="big", message=m("big", "en")), 413


@app.errorhandler(404)
def nf(_):
    return jsonify(error="not_found"), 404


@app.errorhandler(500)
def ise(_):
    return jsonify(error="server", message="Server error"), 500


# ---------------- database (sqlite) ----------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE, pw TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS history(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
  created INTEGER NOT NULL, result TEXT NOT NULL, thumb TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_hist_user ON history(user_id, created DESC);
"""


def db():
    if "db" not in g:
        d = os.path.dirname(DB_PATH)
        if d:
            os.makedirs(d, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.executescript(SCHEMA)
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


# ---------------- auth ----------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT id, name, email FROM users WHERE id=?", (uid,)).fetchone()


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        u = current_user()
        if not u:
            session.clear()
            return jsonify(error="login_required"), 401
        g.user = u
        return f(*a, **k)

    return w


def user_json(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"]}


@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(user=user_json(u) if u else None)


@app.post("/api/signup")
def signup():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()[:80]
    email = str(d.get("email", "")).strip().lower()[:200]
    pw = str(d.get("password", ""))
    if not name or not email or not pw:
        return jsonify(error="fill"), 400
    if not EMAIL_RE.match(email):
        return jsonify(error="email"), 400
    if len(pw) < 6 or len(pw) > 200:
        return jsonify(error="passlen"), 400
    try:
        cur = db().execute(
            "INSERT INTO users(name,email,pw,created) VALUES(?,?,?,?)",
            (name, email, generate_password_hash(pw, method="pbkdf2:sha256"), int(time.time())),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="exists"), 409
    session.clear()
    session.permanent = True
    session["uid"] = cur.lastrowid
    return jsonify(user={"id": cur.lastrowid, "name": name, "email": email})


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    pw = str(d.get("password", ""))
    if not email or not pw:
        return jsonify(error="fill"), 400
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not check_password_hash(u["pw"], pw):
        return jsonify(error="bad"), 401
    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    return jsonify(user=user_json(u))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


# ---------------- Makerend (OpenAI-compatible REST) ----------------
class AIError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def makerend(model, messages, json_mode=False, temperature=0.3, timeout=45):
    if not MAKEREND_API_KEY:
        raise AIError("nokey")
    body = {"model": model, "messages": messages, "temperature": temperature}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    try:
        r = requests.post(
            f"{MAKEREND_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {MAKEREND_API_KEY}", "Content-Type": "application/json"},
            json=body,
            timeout=timeout,
        )
    except requests.RequestException:
        raise AIError("busy")
    if r.status_code in (401, 403):
        raise AIError("badkey")
    if r.status_code != 200:
        print("makerend", model, r.status_code)
        raise AIError("busy")
    try:
        text = str(r.json()["choices"][0]["message"]["content"] or "").strip()
    except Exception:
        raise AIError("busy")
    if not text:
        raise AIError("busy")
    return text


def ask(contents, system=None, json_mode=False, temperature=0.3, parse=None):
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    for item in contents:
        role = "assistant" if item.get("role") in ("model", "assistant") else "user"
        parts = item.get("parts", [])
        text_parts = []
        for part in parts:
            if "text" in part:
                text_parts.append({"type": "text", "text": part["text"]})
            elif "inline_data" in part:
                image = part["inline_data"]
                text_parts.append({"type": "image_url", "image_url": {
                    "url": f"data:{image['mime_type']};base64,{image['data']}"
                }})
        content = "\n".join(p["text"] for p in text_parts if p["type"] == "text")
        if any(p["type"] == "image_url" for p in text_parts):
            content = text_parts
        messages.append({"role": role, "content": content})
    last = AIError("busy")
    for mod in MODELS:
        try:
            text = makerend(mod, messages, json_mode, temperature)
            return parse(text) if parse else text
        except AIError as e:
            if e.kind in ("nokey", "badkey"):
                raise
            last = e
        except Exception as e:  # parse failure
            print("parse failed", mod, str(e)[:100])
            last = AIError("busy")
    raise last


def parse_json(text):
    t = text.strip()
    t = re.sub(r"^```(?:json)?", "", t).strip()
    t = re.sub(r"```$", "", t).strip()
    return json.loads(t)


def as_list(v):
    return [str(x) for x in v if x] if isinstance(v, list) else []


def clean_result(r):
    if isinstance(r, list) and r:
        r = r[0]
    if not isinstance(r, dict):
        raise ValueError("bad json")
    out = {k: str(r.get(k) or "") for k in ("crop", "disease", "cause", "urgency")}
    out["is_plant"] = bool(r.get("is_plant", True))
    sev = str(r.get("severity", "none")).lower()
    out["severity"] = sev if sev in ("none", "low", "medium", "high") else "none"
    try:
        c = int(float(r.get("confidence", 0)))
    except Exception:
        c = 0
    out["confidence"] = max(0, min(85, c))
    out["symptoms"] = as_list(r.get("symptoms"))
    out["prevention"] = as_list(r.get("prevention"))
    tr = r.get("treatment") if isinstance(r.get("treatment"), dict) else {}
    out["treatment"] = {"organic": as_list(tr.get("organic")), "chemical": as_list(tr.get("chemical"))}
    return out


PROMPT = """
You are an expert plant pathologist and AI visual diagnostic engine helping Pakistani farmers.
Analyze the provided leaf/crop image using strict diagnostic criteria.

CRITICAL DIAGNOSTIC RULES (MUST FOLLOW):

1. RUST DISEASE RULE:
   - ONLY diagnose Rust (e.g., Puccinia malvacearum) if true raised, powdery, or 3D blister-like pustules (uredinia) are clearly visible.
   - Flat brown necrotic spots surrounded by bright yellow halos are NOT Rust. Classify them as "Fungal Leaf Spot (Cercospora / Septoria / Alternaria)".

2. LEAF MINER RULE:
   - ONLY diagnose Leaf Miner (Phyllocnistis citrella) if distinct, translucent, or silvery serpentine (snake-like winding) tunnels are visible across the leaf blade.
   - Clean-cut holes, leaf-edge chewing, or round dead spots are NOT leaf miner damage. Classify them as "Foliage-Feeding Insect Damage" or "Shot-Hole Disease".

3. HOST PLANT RULE:
   - Do NOT guess specific crop names like "Hollyhock" or "Citrus" unless the distinct leaf shape (e.g., deep lobes, palmate structure, citrus petiole wings) is 100 percent unmistakable. Otherwise use "Broadleaf Foliage".

4. AMBIGUITY HANDLING:
   - If key diagnostic angles (such as the leaf underside) are missing, default to the broader, visually evident category rather than specific high-severity diseases.

5. GENERAL RULES:
   - Never give confidence above 85 from a single photo. Lower it when unsure.
   - Healthy plant: disease "Healthy", severity "none".
   - Not a plant or too blurry: is_plant false.
   - Use simple language a farmer understands. Keep sentences short.
   - Give organic or low-cost options first, then chemical options available in Pakistan.
   - For chemicals give the generic active ingredient and safety steps, and tell the farmer to check the product label for the exact dose.
   - Only suggest crop rotation for annual field crops, not trees or perennials.

OUTPUT: Return ONLY valid JSON, no Markdown, with exactly this structure:

{
  "is_plant": true,
  "crop": "Verified species or Broadleaf Foliage",
  "disease": "Exact primary diagnosis name, or Healthy",
  "confidence": 0,
  "severity": "none | low | medium | high",
  "symptoms": ["Observed visual symptom 1", "Observed visual symptom 2"],
  "cause": "Specific pathogen family or pest description",
  "treatment": {
    "organic": ["Action step 1", "Action step 2"],
    "chemical": ["Targeted active ingredient and safety steps"]
  },
  "prevention": ["Cultural prevention step 1", "Cultural prevention step 2"],
  "urgency": "How soon the farmer should act."
}

confidence is an integer from 0 to 100. Keep JSON keys in English.

Language: {LANG}.
"""

CHAT_SYSTEM = """You are "Kisan Assistant", a friendly farming advisor inside the Kisan Advisor app, helping farmers in Pakistan and South Asia.

Rules:
- Topics: crops, diseases, pests, weeds, fertilizer, irrigation, soil, sowing/harvest timing, storage, basic farm management. If the question is unrelated, politely steer back to farming.
- Reply in the SAME language and script the farmer used: Urdu script -> Urdu, Roman Urdu -> Roman Urdu, English -> English. If unclear, use {LANG}.
- Use simple words and short sentences. Keep answers under about 120 words unless the farmer asks for detail. Your answer may be read aloud, so avoid tables, headings and emojis.
- You may use short "- " bullet lines and **bold** sparingly.
- Give organic or low-cost options first, then chemicals by generic active ingredient. Always say to read the product label for dose and to use gloves and a mask. For serious or spreading problems, advise visiting the local agriculture extension office.
- Never invent mandi prices, weather or government schemes. You cannot check live data; say so if asked.
- If a diagnosis from the app is provided below, use it as context.
{CTX}"""


@app.post("/api/analyze")
@login_required
def analyze():
    lang = get_lang(request.form.get("lang"))
    f = request.files.get("image")
    if not f:
        return jsonify(error="noimg", message=m("noimg", lang)), 400
    data = f.read()
    mime = (f.mimetype or "").lower()
    if mime not in ("image/jpeg", "image/png", "image/webp"):
        return jsonify(error="badimg", message=m("badimg", lang)), 400
    import base64

    parts = [{"inline_data": {"mime_type": mime, "data": base64.b64encode(data).decode()}}]
    note = request.form.get("note", "").strip()[:500]
    if note:
        parts.append({"text": "Farmer's note: " + note})
    parts.append({"text": PROMPT.replace("{LANG}", "Urdu" if lang == "ur" else "English")})
    try:
        result = ask([{"role": "user", "parts": parts}], json_mode=True, temperature=0.2,
                     parse=lambda t: clean_result(parse_json(t)))
    except AIError as e:
        return jsonify(error=e.kind, message=m(e.kind if e.kind in MSG else "busy", lang)), 503 if e.kind == "busy" else 500

    item = None
    if result["is_plant"]:
        thumb = request.form.get("thumb", "")
        if not (thumb.startswith("data:image/jpeg;base64,") and len(thumb) < 150_000):
            thumb = ""
        now = int(time.time() * 1000)
        c = db()
        cur = c.execute("INSERT INTO history(user_id,created,result,thumb) VALUES(?,?,?,?)",
                        (g.user["id"], now, json.dumps(result, ensure_ascii=False), thumb))
        c.execute("DELETE FROM history WHERE user_id=? AND id NOT IN "
                  "(SELECT id FROM history WHERE user_id=? ORDER BY created DESC LIMIT 16)",
                  (g.user["id"], g.user["id"]))
        c.commit()
        item = {"id": cur.lastrowid, "created": now, "r": result, "thumb": thumb}
    return jsonify(result=result, item=item)


@app.get("/api/history")
@login_required
def history():
    rows = db().execute("SELECT id, created, result, thumb FROM history WHERE user_id=? "
                        "ORDER BY created DESC LIMIT 16", (g.user["id"],)).fetchall()
    return jsonify(items=[{"id": r["id"], "created": r["created"], "r": json.loads(r["result"]),
                           "thumb": r["thumb"]} for r in rows])


@app.post("/api/chat")
@login_required
def chat():
    d = request.get_json(silent=True) or {}
    lang = get_lang(d.get("lang"))
    contents = []
    for x in (d.get("messages") or [])[-14:]:
        if not isinstance(x, dict):
            continue
        text = str(x.get("text", "")).strip()[:2000]
        role = "user" if x.get("role") == "user" else "model"
        if text:
            contents.append({"role": role, "parts": [{"text": text}]})
    while contents and contents[0]["role"] != "user":
        contents.pop(0)
    if not contents or contents[-1]["role"] != "user":
        return jsonify(error="nomsg", message=m("nomsg", lang)), 400
    ctx = str(d.get("context", "")).strip()[:800]
    system = CHAT_SYSTEM.replace("{LANG}", "Urdu" if lang == "ur" else "English").replace(
        "{CTX}", f"\nCurrent diagnosis in the app: {ctx}" if ctx else "")
    try:
        reply = ask(contents, system=system, temperature=0.5)
    except AIError as e:
        return jsonify(error=e.kind, message=m(e.kind if e.kind in MSG else "busy", lang)), 503 if e.kind == "busy" else 500
    return jsonify(reply=reply)


@app.get("/api/health")
def health():
    return jsonify(ok=True, key_set=bool(MAKEREND_API_KEY), provider="makerend", base_url=MAKEREND_BASE_URL,
                   models=MODELS, db=DB_PATH)


@app.get("/")
def home():
    r = send_from_directory(os.path.join(BASE, "templates"), "index.html")
    r.headers["Cache-Control"] = "no-cache"
    return r


@app.get("/favicon.ico")
def favicon():
    return "", 204


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
