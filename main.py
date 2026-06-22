# -*- coding: utf-8 -*-
"""
미국 ETF 추천·분석 웹앱 (개인용)
- 백엔드: FastAPI 단일 파일
- 데이터: yfinance (실패 시 폴백 기본값 + source 표시)
- 프론트: static/index.html (단일 파일)
- 실행: uvicorn main:app --port 8000  (또는 python main.py)

[정직성 원칙]
- 아래 점수 공식은 프론트 화면에 표시되는 설명과 1:1로 일치한다.
- 세금·매매수수료·환율은 반영하지 않는다. 모든 수치는 교육·참고용이다.
- 수익률/변동성/배당수익률은 yfinance 과거 데이터로 계산하며,
  실패 시 종목별 폴백값을 쓰고 source="fallback"으로 표시한다.
"""

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import os
import time
import hmac
import hashlib
import sqlite3
import re
from concurrent.futures import ThreadPoolExecutor

# yfinance 는 선택적 의존성. 설치/네트워크 실패해도 앱은 폴백으로 동작해야 한다.
# pandas 는 yfinance 가 의존하므로 같은 블록에서 가져온다(없으면 함께 폴백).
try:
    import yfinance as yf
    import pandas as pd
    _YF_OK = True
except Exception:
    _YF_OK = False

app = FastAPI(title="ETF 추천·분석")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# ---------------------------------------------------------------------------
# 0) 회원가입·로그인 + 즐겨찾기 저장 (SQLite, 표준 라이브러리만)
#    - 데이터는 DATA_DIR(기본 ./data) 아래 app.db 파일에 저장한다.
#      NAS 등에서는 DATA_DIR 을 영구 볼륨으로 지정하면 그곳에 저장된다.
#    - 비밀번호는 PBKDF2-HMAC-SHA256(솔트+20만회)로 해시해 저장(원문 저장 안 함).
#    - 로그인 상태는 서명 쿠키(user_id + HMAC)로 유지. 서버 비밀키로 위조 방지.
# ---------------------------------------------------------------------------
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "app.db")
SESSION_COOKIE = "etf_session"
# 로그인 없이 열어둘 경로(로그인/회원가입 화면·API, 아이콘·매니페스트)
_OPEN_PATHS = {"/login", "/api/login", "/api/register", "/favicon.ico", "/manifest.webmanifest"}


def _admin_user():
    """마스터(관리자) 아이디. ADMIN_USER 환경변수로 지정한 계정이 관리자."""
    return os.environ.get("ADMIN_USER", "").strip().lower()


def _accounts_enabled():
    """ADMIN_USER 가 있으면 계정·로그인 모드, 없으면 개방 모드(로그인 없이 사용)."""
    return bool(_admin_user())


def is_admin(username: str) -> bool:
    a = _admin_user()
    return bool(a) and (username or "").strip().lower() == a


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            pw_hash   TEXT NOT NULL,
            approved  INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS favorites (
            user_id   INTEGER NOT NULL,
            ticker    TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (user_id, ticker)
        );
        """
    )
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)")]
    # 기존 DB 업그레이드
    if "approved" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 0")
    if "username" not in cols and "email" in cols:
        conn.execute("ALTER TABLE users RENAME COLUMN email TO username")
    # 관리자 계정: 있으면 승인 유지, 없고 ADMIN_PASSWORD 있으면 자동 생성(승인 상태)
    admin = _admin_user()
    if admin:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (admin,)).fetchone()
        if row is not None:
            conn.execute("UPDATE users SET approved = 1 WHERE username = ?", (admin,))
        else:
            pw = os.environ.get("ADMIN_PASSWORD", "")
            if pw:
                conn.execute(
                    "INSERT INTO users (username, pw_hash, approved) VALUES (?, ?, 1)",
                    (admin, hash_pw(pw)),
                )
    conn.commit()
    conn.close()


def get_user(uid):
    conn = get_db()
    row = conn.execute("SELECT id, username, approved FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def _secret() -> bytes:
    """세션 서명용 비밀키. 환경변수 SECRET_KEY 우선, 없으면 DATA_DIR에 생성·보관
    (재시작해도 로그인 유지). NAS 운영 시 SECRET_KEY 를 직접 지정하면 더 안전."""
    s = os.environ.get("SECRET_KEY", "").strip()
    if s:
        return s.encode("utf-8")
    keyfile = os.path.join(DATA_DIR, "secret.key")
    if os.path.exists(keyfile):
        with open(keyfile, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(keyfile, "wb") as f:
        f.write(key)
    return key


def hash_pw(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return salt.hex() + "$" + dk.hex()


def verify_pw(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# DB 초기화는 hash_pw 정의 이후에 실행(관리자 자동 생성에 필요)
init_db()


def make_session(user_id: int) -> str:
    sig = hmac.new(_secret(), str(user_id).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{user_id}.{sig}"


def parse_session(token: str):
    try:
        uid, sig = token.rsplit(".", 1)
        expect = hmac.new(_secret(), uid.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expect):
            return int(uid)
    except Exception:
        pass
    return None


def current_user_id(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    return parse_session(token) if token else None


def _is_https(request: Request) -> bool:
    # NAS/프록시 뒤에서 HTTPS 종료 시 x-forwarded-proto 로 판별.
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def _set_session_cookie(resp, user_id: int, request: Request):
    resp.set_cookie(
        SESSION_COOKIE, make_session(user_id),
        max_age=60 * 60 * 24 * 30,  # 30일
        httponly=True, samesite="lax", secure=_is_https(request),
    )


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    path = request.url.path
    # 개방 모드(ADMIN_USER 미설정): 로그인 없이 누구나 사용
    if not _accounts_enabled():
        return await call_next(request)
    if path in _OPEN_PATHS or path.startswith("/static/"):
        return await call_next(request)

    uid = current_user_id(request)
    if uid is None:
        # 미로그인: API 는 401, 일반 페이지는 로그인 화면으로
        if path.startswith("/api"):
            return JSONResponse({"error": "로그인이 필요합니다."}, status_code=401)
        return RedirectResponse("/login", status_code=302)

    # 로그인됨. API 는 승인/권한 검사 (페이지는 통과시키고 화면에서 승인 대기 안내)
    if path.startswith("/api"):
        # 상태 확인·로그아웃은 미승인자도 허용
        if path in ("/api/me", "/api/logout"):
            return await call_next(request)
        row = get_user(uid)
        if row is None:
            return JSONResponse({"error": "로그인이 필요합니다."}, status_code=401)
        if path.startswith("/api/admin"):
            if not is_admin(row["username"]):
                return JSONResponse({"error": "권한이 없습니다."}, status_code=403)
        elif not (row["approved"] or is_admin(row["username"])):
            return JSONResponse({"error": "관리자 승인 대기중입니다."}, status_code=403)
    return await call_next(request)


_LOGIN_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
<meta name="theme-color" content="#f5f5f7" />
<title>로그인 · ETF 추천·분석</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
<style>
  :root { --blue:#0066cc; --ink:#1d1d1f; --sub:#6e6e73; --line:#e5e5e7; --bg:#f5f5f7; --card:#fff; }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif; background:var(--bg); color:var(--ink);
    -webkit-font-smoothing:antialiased; padding:24px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:16px;
    padding:32px 28px; width:100%; max-width:360px; }
  h1 { font-size:22px; font-weight:700; margin:0; letter-spacing:-0.02em; }
  .sub { color:var(--sub); font-size:14px; margin:8px 0 22px; }
  label { display:block; font-size:13px; font-weight:600; color:var(--sub); margin:14px 0 6px; }
  input { width:100%; border:1px solid var(--line); border-radius:12px; padding:13px 14px;
    font-size:16px; font-family:inherit; color:var(--ink); outline:none; }
  input:focus { border-color:var(--blue); }
  button { width:100%; border:none; background:var(--blue); color:#fff; border-radius:999px;
    padding:13px; font-size:15px; font-weight:600; font-family:inherit; cursor:pointer;
    margin-top:18px; transition:opacity .15s ease; }
  button:hover { opacity:.9; }
  .toggle { text-align:center; font-size:13px; color:var(--sub); margin-top:16px; }
  .toggle a { color:var(--blue); cursor:pointer; text-decoration:none; font-weight:600; }
  .err { color:#c0392b; font-size:13px; min-height:18px; margin:12px 0 0; }
</style>
</head>
<body>
  <div class="card">
    <h1>ETF 추천·분석</h1>
    <p class="sub" id="sub">로그인하고 즐겨찾기를 사용해 보세요.</p>
    <form id="f">
      <label for="uid">아이디</label>
      <input id="uid" type="text" autocomplete="username" placeholder="아이디" autofocus />
      <label for="pw">비밀번호</label>
      <input id="pw" type="password" autocomplete="current-password" placeholder="비밀번호 (8자 이상)" />
      <button type="submit" id="submitBtn">로그인</button>
    </form>
    <p class="err" id="err"></p>
    <p class="toggle" id="toggle">계정이 없으신가요? <a id="toggleLink">회원가입</a></p>
  </div>
<script>
  var mode = 'login';  // 'login' | 'register'
  var f = document.getElementById('f'), err = document.getElementById('err');
  var submitBtn = document.getElementById('submitBtn');
  var sub = document.getElementById('sub'), toggle = document.getElementById('toggle');
  var pw = document.getElementById('pw');

  // 토글 링크(로그인 ↔ 회원가입)는 innerHTML로 바뀌므로 이벤트 위임으로 처리
  toggle.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'toggleLink') {
      err.textContent = '';
      mode = (mode === 'login') ? 'register' : 'login';
      if (mode === 'register') {
        submitBtn.textContent = '회원가입';
        sub.textContent = '아이디와 비밀번호로 가입하세요.';
        pw.setAttribute('autocomplete', 'new-password');
        toggle.innerHTML = '이미 계정이 있으신가요? <a id="toggleLink">로그인</a>';
      } else {
        submitBtn.textContent = '로그인';
        sub.textContent = '로그인하고 즐겨찾기를 사용해 보세요.';
        pw.setAttribute('autocomplete', 'current-password');
        toggle.innerHTML = '계정이 없으신가요? <a id="toggleLink">회원가입</a>';
      }
    }
  });

  f.addEventListener('submit', async function (e) {
    e.preventDefault();
    err.textContent = '';
    var username = document.getElementById('uid').value.trim();
    var password = pw.value;
    try {
      var r = await fetch('/api/' + mode, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
      });
      if (r.ok) { location.href = '/'; return; }
      var d = await r.json().catch(function () { return {}; });
      err.textContent = d.error || '요청을 처리하지 못했습니다.';
    } catch (e2) {
      err.textContent = '서버에 연결하지 못했습니다.';
    }
  });
</script>
</body>
</html>"""

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")


@app.get("/login")
def login_page():
    return HTMLResponse(_LOGIN_HTML)


async def _read_credentials(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    return username, password


@app.post("/api/register")
async def api_register(request: Request):
    username, password = await _read_credentials(request)
    if not _USERNAME_RE.match(username):
        return JSONResponse({"error": "아이디는 영문/숫자/밑줄 3~20자여야 합니다."}, status_code=400)
    if len(password) < 8:
        return JSONResponse({"error": "비밀번호는 8자 이상이어야 합니다."}, status_code=400)
    # 관리자 아이디면 자동 승인, 그 외는 승인 대기(approved=0)
    approved = 1 if is_admin(username) else 0
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, pw_hash, approved) VALUES (?, ?, ?)",
            (username, hash_pw(password), approved),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return JSONResponse({"error": "이미 사용 중인 아이디입니다."}, status_code=409)
    finally:
        conn.close()
    resp = JSONResponse({"ok": True, "approved": bool(approved)})
    _set_session_cookie(resp, user_id, request)
    return resp


@app.post("/api/login")
async def api_login(request: Request):
    username, password = await _read_credentials(request)
    conn = get_db()
    row = conn.execute("SELECT id, pw_hash FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row is None or not verify_pw(password, row["pw_hash"]):
        return JSONResponse({"error": "아이디 또는 비밀번호가 올바르지 않습니다."}, status_code=401)
    resp = JSONResponse({"ok": True})
    _set_session_cookie(resp, row["id"], request)
    return resp


@app.post("/api/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/me")
def api_me(request: Request):
    # 개방 모드: 로그인 개념 없음
    if not _accounts_enabled():
        return {"open": True}
    uid = current_user_id(request)
    conn = get_db()
    row = conn.execute("SELECT username, approved FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None:
        conn.close()
        return JSONResponse({"error": "로그인이 필요합니다."}, status_code=401)
    admin = is_admin(row["username"])
    out = {"username": row["username"], "approved": bool(row["approved"]) or admin, "is_admin": admin}
    if admin:
        out["pending_count"] = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE approved = 0"
        ).fetchone()["c"]
    conn.close()
    return out


# ---- 관리자(마스터) 전용: 가입 승인 관리 ----
@app.get("/api/admin/users")
def api_admin_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, approved, created_at FROM users ORDER BY approved, created_at"
    ).fetchall()
    conn.close()
    pending = [{"id": r["id"], "username": r["username"], "created_at": r["created_at"]}
               for r in rows if not r["approved"]]
    approved = [{"id": r["id"], "username": r["username"]} for r in rows if r["approved"]]
    return {"pending": pending, "approved": approved}


async def _read_target_id(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return None
    try:
        return int(body.get("id"))
    except (TypeError, ValueError):
        return None


@app.post("/api/admin/approve")
async def api_admin_approve(request: Request):
    uid = await _read_target_id(request)
    if uid is None:
        return JSONResponse({"error": "잘못된 요청입니다."}, status_code=400)
    conn = get_db()
    conn.execute("UPDATE users SET approved = 1 WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/admin/reject")
async def api_admin_reject(request: Request):
    uid = await _read_target_id(request)
    if uid is None:
        return JSONResponse({"error": "잘못된 요청입니다."}, status_code=400)
    conn = get_db()
    row = conn.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
    if row is not None and is_admin(row["username"]):
        conn.close()
        return JSONResponse({"error": "관리자 계정은 삭제할 수 없습니다."}, status_code=400)
    conn.execute("DELETE FROM favorites WHERE user_id = ?", (uid,))
    conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/favorites")
def api_favorites_list(request: Request):
    uid = current_user_id(request)
    if uid is None:  # 개방 모드 등: 즐겨찾기는 클라이언트(localStorage)에서 관리
        return {"tickers": []}
    conn = get_db()
    rows = conn.execute(
        "SELECT ticker FROM favorites WHERE user_id = ? ORDER BY created_at", (uid,)
    ).fetchall()
    conn.close()
    return {"tickers": [r["ticker"] for r in rows]}


@app.post("/api/favorites")
async def api_favorites_add(request: Request):
    uid = current_user_id(request)
    if uid is None:
        return JSONResponse({"ok": True}, status_code=200)
    try:
        body = await request.json()
    except Exception:
        body = {}
    ticker = (body.get("ticker") if isinstance(body, dict) else "") or ""
    ticker = ticker.strip().upper()
    if ticker not in POOL_BY_TICKER:
        return JSONResponse({"error": "알 수 없는 종목입니다."}, status_code=400)
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO favorites (user_id, ticker) VALUES (?, ?)", (uid, ticker)
    )
    conn.commit()
    conn.close()
    return {"ok": True, "ticker": ticker}


@app.delete("/api/favorites")
def api_favorites_remove(request: Request, ticker: str = ""):
    uid = current_user_id(request)
    if uid is None:
        return {"ok": True}
    conn = get_db()
    conn.execute(
        "DELETE FROM favorites WHERE user_id = ? AND ticker = ?", (uid, ticker.strip().upper())
    )
    conn.commit()
    conn.close()
    return {"ok": True}


# 홈화면 추가(PWA)용 웹 매니페스트. 아이콘은 static/pwa/ 에 둔다.
_MANIFEST = {
    "name": "ETF 추천·분석",
    "short_name": "ETF 추천",
    "lang": "ko",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": "#f5f5f7",
    "theme_color": "#f5f5f7",
    "icons": [
        {"src": "/static/pwa/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/static/pwa/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/static/pwa/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "maskable"},
        {"src": "/static/pwa/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
    ],
}


@app.get("/manifest.webmanifest")
def manifest():
    return JSONResponse(_MANIFEST, media_type="application/manifest+json")

# ---------------------------------------------------------------------------
# 1) 추천 대상 ETF 고정 풀 (대표 미국 ETF)
#    fallback 값(yield/ret1y/vol)은 yfinance 실패 시에만 사용하는 보수적 기본값.
#    단위: yield/ret1y/vol 모두 % (연 환산).
# ---------------------------------------------------------------------------
ETF_POOL = [
    # 성장(주식)
    {"ticker": "VOO", "name": "S&P 500", "cat": "성장", "yield": 1.3, "ret1y": 14.0, "vol": 17.0},
    {"ticker": "VTI", "name": "미국 전체 주식", "cat": "성장", "yield": 1.3, "ret1y": 13.5, "vol": 17.5},
    {"ticker": "QQQ", "name": "나스닥 100", "cat": "성장", "yield": 0.6, "ret1y": 20.0, "vol": 22.0},
    {"ticker": "VUG", "name": "미국 대형 성장주", "cat": "성장", "yield": 0.5, "ret1y": 22.0, "vol": 21.0},
    {"ticker": "SCHG", "name": "미국 대형 성장주(슈왑)", "cat": "성장", "yield": 0.4, "ret1y": 23.0, "vol": 21.5},
    # 배당
    {"ticker": "SCHD", "name": "미국 배당주(슈왑)", "cat": "배당", "yield": 3.5, "ret1y": 8.0, "vol": 14.0},
    {"ticker": "VYM", "name": "미국 고배당", "cat": "배당", "yield": 2.9, "ret1y": 9.0, "vol": 13.5},
    {"ticker": "DGRO", "name": "배당성장", "cat": "배당", "yield": 2.3, "ret1y": 10.0, "vol": 14.0},
    {"ticker": "HDV", "name": "고배당(아이셰어즈)", "cat": "배당", "yield": 3.6, "ret1y": 7.0, "vol": 13.0},
    {"ticker": "VIG", "name": "배당성장(뱅가드)", "cat": "배당", "yield": 1.8, "ret1y": 11.0, "vol": 14.5},
    # 채권/안정
    {"ticker": "BND", "name": "미국 종합채권", "cat": "채권", "yield": 3.5, "ret1y": 2.0, "vol": 6.0},
    {"ticker": "AGG", "name": "미국 종합채권(아이셰어즈)", "cat": "채권", "yield": 3.5, "ret1y": 2.0, "vol": 6.0},
    {"ticker": "TLT", "name": "미국 장기국채(20년+)", "cat": "채권", "yield": 4.0, "ret1y": -2.0, "vol": 14.0},
    {"ticker": "SHY", "name": "미국 단기국채(1~3년)", "cat": "채권", "yield": 4.2, "ret1y": 4.0, "vol": 1.5},
    {"ticker": "BNDX", "name": "미국 외 종합채권(환헤지)", "cat": "채권", "yield": 3.2, "ret1y": 3.0, "vol": 5.0},
    # 분산/기타
    {"ticker": "VT", "name": "전세계 주식", "cat": "분산", "yield": 1.9, "ret1y": 12.0, "vol": 16.0},
    {"ticker": "VEA", "name": "선진국(미국 제외)", "cat": "분산", "yield": 3.0, "ret1y": 8.0, "vol": 16.0},
    {"ticker": "VWO", "name": "신흥국 주식", "cat": "분산", "yield": 2.7, "ret1y": 9.0, "vol": 18.0},
    {"ticker": "VNQ", "name": "미국 리츠(부동산)", "cat": "분산", "yield": 3.8, "ret1y": 6.0, "vol": 19.0},
    {"ticker": "GLD", "name": "금", "cat": "분산", "yield": 0.0, "ret1y": 15.0, "vol": 14.0},
    # 섹터(미국 11개 GICS 섹터, SPDR Select Sector ETF)
    # yield/ret1y는 stockanalysis.com 조회값(2026-06-19 기준) 기반 폴백.
    # vol은 직접 제공되지 않아 베타×시장변동성을 기준으로 섹터 특성(경기방어/경기민감)을 반영해 추정.
    {"ticker": "XLK", "name": "기술 섹터", "cat": "섹터", "yield": 0.4, "ret1y": 59.6, "vol": 22.0},
    {"ticker": "XLF", "name": "금융 섹터", "cat": "섹터", "yield": 1.5, "ret1y": 8.3, "vol": 18.0},
    {"ticker": "XLV", "name": "헬스케어 섹터", "cat": "섹터", "yield": 1.7, "ret1y": 13.9, "vol": 14.0},
    {"ticker": "XLE", "name": "에너지 섹터", "cat": "섹터", "yield": 2.8, "ret1y": 25.2, "vol": 23.0},
    {"ticker": "XLY", "name": "임의소비재 섹터", "cat": "섹터", "yield": 0.8, "ret1y": 12.3, "vol": 20.0},
    {"ticker": "XLP", "name": "필수소비재 섹터", "cat": "섹터", "yield": 2.6, "ret1y": 6.3, "vol": 12.5},
    {"ticker": "XLI", "name": "산업재 섹터", "cat": "섹터", "yield": 1.1, "ret1y": 28.6, "vol": 17.5},
    {"ticker": "XLU", "name": "유틸리티 섹터", "cat": "섹터", "yield": 2.7, "ret1y": 14.6, "vol": 14.5},
    {"ticker": "XLB", "name": "소재 섹터", "cat": "섹터", "yield": 1.6, "ret1y": 21.1, "vol": 17.5},
    {"ticker": "XLRE", "name": "리츠(부동산) 섹터", "cat": "섹터", "yield": 3.2, "ret1y": 8.7, "vol": 18.0},
    {"ticker": "XLC", "name": "커뮤니케이션서비스 섹터", "cat": "섹터", "yield": 1.3, "ret1y": 7.1, "vol": 19.0},
]

POOL_BY_TICKER = {e["ticker"]: e for e in ETF_POOL}

# 간단한 메모리 캐시 (티커 -> (저장시각, 결과)).
# - 실시간(yfinance) 결과만 캐시한다. 폴백값은 캐시하지 않아
#   네트워크가 복구되면 다음 호출에서 곧바로 실시간으로 전환된다.
# - TTL 이 지나면 캐시를 무시하고 다시 받아 오래된 값을 보여주지 않는다.
_METRIC_CACHE = {}
_CACHE_TTL_SEC = 3600  # 1시간


def _clamp(x, lo, hi):
    return max(lo, min(hi, x))


# ---------------------------------------------------------------------------
# 2) yfinance 로 실시간 지표 계산 (실패 시 폴백)
#    - ret1y: 최근 1년 가격 수익률(%)
#    - vol:   최근 1년 일간수익률 표준편차 × √252 (연 환산 변동성, %)
#    - yield: 최근 12개월 배당 합계 / 현재가 × 100 (%)
# ---------------------------------------------------------------------------
def fetch_metrics(ticker: str):
    base = POOL_BY_TICKER[ticker]

    # 캐시에 신선한(TTL 이내) 실시간 데이터가 있으면 재사용
    cached = _METRIC_CACHE.get(ticker)
    if cached is not None:
        ts, prev = cached
        if time.time() - ts < _CACHE_TTL_SEC:
            return prev

    if _YF_OK:
        try:
            tk = yf.Ticker(ticker)
            # timeout 으로 네트워크 지연 시 빠르게 폴백 (앱이 멈추지 않도록)
            hist = tk.history(period="1y", auto_adjust=True, timeout=5)
            if hist is not None and len(hist) > 30:
                closes = hist["Close"].dropna()
                ret1y = (closes.iloc[-1] / closes.iloc[0] - 1.0) * 100.0
                daily = closes.pct_change().dropna()
                vol = float(daily.std() * (252 ** 0.5) * 100.0)

                # 배당수익률: 최근 1년 배당 합계 / 현재가
                price = float(closes.iloc[-1])
                div_yield = base["yield"]  # 기본값
                try:
                    divs = tk.dividends
                    if divs is not None and len(divs) > 0:
                        last_year = divs[divs.index >= (closes.index[-1] - pd.Timedelta(days=365))]
                        if len(last_year) > 0 and price > 0:
                            div_yield = float(last_year.sum() / price * 100.0)
                except Exception:
                    pass

                result = {
                    "ticker": ticker,
                    "ret1y": round(float(ret1y), 2),
                    "vol": round(float(vol), 2),
                    "yield": round(float(div_yield), 2),
                    "price": round(price, 2),
                    "source": "yfinance",
                }
                _METRIC_CACHE[ticker] = (time.time(), result)  # 실시간 결과만 캐시
                return result
        except Exception:
            pass

    # ---- 폴백 ----  (캐시하지 않음: 다음 호출에서 실시간 재시도)
    return {
        "ticker": ticker,
        "ret1y": base["ret1y"],
        "vol": base["vol"],
        "yield": base["yield"],
        "price": None,
        "source": "fallback",
    }


# ---------------------------------------------------------------------------
# 2-1) 환율(USD/KRW) 조회
#    - rate:     현재 1달러 = 몇 원 (yfinance "KRW=X", 실패 시 폴백 추정값)
#    - change1y: 최근 1년 환율 변동률(%). 원화 환산 수익률 계산용.
#                폴백이면 변동을 알 수 없어 None (원화 환산 수익률은 표시 안 함).
#    환율 자체도 늘 변동하며, 여기 값은 참고용이다.
# ---------------------------------------------------------------------------
_FX_FALLBACK_RATE = 1385.0  # USD/KRW 대략값(폴백)
_FX_CACHE = {}


def fetch_fx():
    cached = _FX_CACHE.get("KRW")
    if cached is not None and time.time() - cached[0] < _CACHE_TTL_SEC:
        return cached[1]

    if _YF_OK:
        try:
            hist = yf.Ticker("KRW=X").history(period="1y", timeout=5)
            if hist is not None and len(hist) > 30:
                closes = hist["Close"].dropna()
                rate = float(closes.iloc[-1])
                rate_1y = float(closes.iloc[0])
                change1y = (rate / rate_1y - 1.0) * 100.0 if rate_1y > 0 else None
                result = {
                    "rate": round(rate, 2),
                    "change1y": round(change1y, 2) if change1y is not None else None,
                    "source": "yfinance",
                }
                _FX_CACHE["KRW"] = (time.time(), result)
                return result
        except Exception:
            pass

    # 폴백: 대략 환율만, 변동률은 알 수 없음
    return {"rate": _FX_FALLBACK_RATE, "change1y": None, "source": "fallback"}


# ---------------------------------------------------------------------------
# 3) 점수 공식 (프론트 설명과 1:1 일치)
#
#  3-1) 종목별 3개 세부점수(0~100)
#    수익성 R = clamp((ret1y + 10) / 50 × 100, 0, 100)   # -10%→0, +40%→100
#    배당   D = clamp(yield / 5 × 100, 0, 100)            # 0%→0, 5%이상→100
#    안정성 S = clamp((35 - vol) / 35 × 100, 0, 100)      # 변동성 0%→100, 35%이상→0
#
#  3-2) 목표(goal)별 기본 가중치
#    성장:   R 0.60, D 0.10, S 0.30
#    배당:   R 0.20, D 0.60, S 0.20
#    분산:   R 0.34, D 0.33, S 0.33
#
#  3-3) 위험성향(risk)으로 안정성 가중치 조정 (shift = 0.20)
#    안정형: S += 0.20  (R,D 에서 0.10씩 차감)
#    중립형: 변화 없음
#    공격형: R += 0.20, S -= 0.20
#    조정 후 음수는 0으로 자르고 합이 1이 되도록 재정규화.
#
#  최종점수 = wR×R + wD×D + wS×S  (0~100)
# ---------------------------------------------------------------------------
GOAL_WEIGHTS = {
    "growth": {"R": 0.60, "D": 0.10, "S": 0.30},
    "dividend": {"R": 0.20, "D": 0.60, "S": 0.20},
    "diversified": {"R": 0.34, "D": 0.33, "S": 0.33},
}
RISK_SHIFT = 0.20


def compute_weights(goal: str, risk: str):
    w = dict(GOAL_WEIGHTS.get(goal, GOAL_WEIGHTS["diversified"]))
    if risk == "conservative":
        w["S"] += RISK_SHIFT
        w["R"] -= RISK_SHIFT / 2
        w["D"] -= RISK_SHIFT / 2
    elif risk == "aggressive":
        w["R"] += RISK_SHIFT
        w["S"] -= RISK_SHIFT
    # 음수 제거 후 재정규화
    for k in w:
        w[k] = max(0.0, w[k])
    total = sum(w.values()) or 1.0
    return {k: round(v / total, 3) for k, v in w.items()}


def sub_scores(m):
    R = _clamp((m["ret1y"] + 10) / 50 * 100, 0, 100)
    D = _clamp(m["yield"] / 5 * 100, 0, 100)
    S = _clamp((35 - m["vol"]) / 35 * 100, 0, 100)
    return {"R": round(R, 1), "D": round(D, 1), "S": round(S, 1)}


def make_reason(cat, sc, w):
    """가중치가 높은 항목 중 점수가 좋은 것을 근거로 한국어 설명 생성."""
    names = {"R": "수익성", "D": "배당", "S": "안정성"}
    # 가중치 × 점수 기여도 순으로 정렬
    contrib = sorted(["R", "D", "S"], key=lambda k: w[k] * sc[k], reverse=True)
    top = contrib[0]
    parts = [f"{names[k]} {sc[k]:.0f}점" for k in contrib if w[k] > 0]
    return f"{cat} ETF. {names[top]}이(가) 목표·성향에 가장 잘 맞음 ({', '.join(parts)})"


@app.get("/api/etfs")
def list_etfs():
    """추천 대상 풀 메타데이터 (계산 없이 가벼움)."""
    return {"etfs": [{"ticker": e["ticker"], "name": e["name"], "cat": e["cat"]} for e in ETF_POOL]}


@app.get("/api/recommend")
def recommend(
    goal: str = "diversified",
    risk: str = "neutral",
    tickers: str = "",
    dividends: str = "all",
    min_yield: float = 0.0,
    top: int = 0,
):
    """
    goal: growth | dividend | diversified
    risk: conservative | neutral | aggressive
    tickers: 콤마구분. 비우면 전체 풀 대상.
    dividends: all | yes(배당 주는 것만) | no(무배당만)  — 실제 배당수익률 기준
    min_yield: 최소 배당수익률(%) 이상만 표시. 0이면 제한 없음.
    top: 점수 상위 N개만 표시. 0이면 전체.
    점수 계산식은 필터와 무관하게 동일하다. 필터는 '무엇을/몇 개 보여줄지'만 정한다.
    """
    w = compute_weights(goal, risk)

    if tickers.strip():
        wanted = [t.strip().upper() for t in tickers.split(",") if t.strip().upper() in POOL_BY_TICKER]
    else:
        wanted = [e["ticker"] for e in ETF_POOL]

    # yfinance 는 종목당 네트워크 호출이라 순차로 돌리면 느리다(특히 무료 서버).
    # 종목 지표와 환율을 모두 동시에 받아 대기 시간을 크게 줄인다. (실패 시 각자 폴백)
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(wanted))) + 1) as ex:
        fx_future = ex.submit(fetch_fx)
        metric_list = list(ex.map(fetch_metrics, wanted)) if wanted else []
    fx = fx_future.result()

    rows = []
    sources = set()
    for m in metric_list:
        t = m["ticker"]
        y = m["yield"]
        # --- 배당 필터 (실제 배당수익률 기준) ---
        if dividends == "yes" and not (y > 0):
            continue
        if dividends == "no" and y > 0:
            continue
        if min_yield > 0 and y < min_yield:
            continue
        sources.add(m["source"])
        sc = sub_scores(m)
        score = w["R"] * sc["R"] + w["D"] * sc["D"] + w["S"] * sc["S"]
        meta = POOL_BY_TICKER[t]

        # 환율 적용 (점수에는 영향 없음, 참고용 표시)
        price_krw = round(m["price"] * fx["rate"]) if m["price"] is not None else None
        # 원화 환산 1년 수익률 ≈ (1+달러수익률)×(1+환율변동률) − 1
        #   실시간 가격·환율이 둘 다 있을 때만 계산(폴백이면 환율 변동을 몰라 표시 안 함)
        ret1y_krw = None
        if m["source"] == "yfinance" and fx["change1y"] is not None:
            ret1y_krw = round(((1 + m["ret1y"] / 100.0) * (1 + fx["change1y"] / 100.0) - 1) * 100.0, 2)

        rows.append({
            "ticker": t,
            "name": meta["name"],
            "cat": meta["cat"],
            "ret1y": m["ret1y"],
            "ret1y_krw": ret1y_krw,
            "vol": m["vol"],
            "yield": m["yield"],
            "price": m["price"],
            "price_krw": price_krw,
            "source": m["source"],
            "scores": sc,
            "score": round(score, 1),
            "reason": make_reason(meta["cat"], sc, w),
        })

    rows.sort(key=lambda r: r["score"], reverse=True)

    matched = len(rows)  # 필터 통과한 전체 개수 (Top N 자르기 전)
    if top and top > 0:
        rows = rows[:top]

    overall_source = "yfinance" if sources == {"yfinance"} else ("fallback" if sources == {"fallback"} else "mixed")
    return {
        "goal": goal,
        "risk": risk,
        "weights": w,
        "source": overall_source,
        "fx": fx,
        "filters": {"dividends": dividends, "min_yield": min_yield, "top": top, "matched": matched},
        "results": rows,
        "disclaimer": (
            "교육·참고용입니다. 투자 권유가 아닙니다. "
            "점수는 달러 기준 수익률·변동성·배당으로 계산하며, 세금·매매수수료는 반영하지 않습니다. "
            "환율(USD/KRW)과 원화 환산 수익률은 참고로 표시하며 환율도 늘 변동합니다."
        ),
    }


# 정적 파일 (프론트)
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(path):
        # 화면(HTML)은 캐시하지 않게 해, 재배포 시 새로고침만 하면 바로 최신 화면이 뜨도록.
        # (아이콘 등 /static 자산은 그대로 캐시 허용)
        return FileResponse(path, headers={"Cache-Control": "no-cache, must-revalidate"})
    return JSONResponse({"error": "static/index.html 이(가) 없습니다."}, status_code=404)


if __name__ == "__main__":
    import uvicorn
    # 클라우드 배포 시 호스트가 PORT 환경변수를 주입한다. 없으면 로컬 기본값 8000.
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
