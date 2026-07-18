"""
Trading-bot dashboard — a deployed, view-from-anywhere window into the Alpaca account.

Reads live state straight from Alpaca (account, positions, orders, equity curve) so it
needs nothing from the local bot or machine. Secret keys stay server-side; the whole
page is protected by HTTP Basic Auth so a public URL isn't wide open.

Endpoints:
  GET  /              -> the dashboard page (Basic Auth)
  GET  /api/summary   -> account equity/cash/P&L
  GET  /api/positions -> open positions
  GET  /api/orders    -> recent orders
  GET  /api/history   -> portfolio equity curve
  POST /api/flatten   -> close ALL positions (destructive — confirmed in UI)
  POST /api/cancel    -> cancel ALL open orders

Run locally:  uvicorn app:app --reload
Deploy:       uvicorn app:app --host 0.0.0.0 --port $PORT
"""
import os
import json
import pathlib
import secrets
import threading
from datetime import datetime, timedelta, timezone
import requests
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from dotenv import load_dotenv

load_dotenv()

KEY = os.getenv("APCA_API_KEY_ID")
SECRET = os.getenv("APCA_API_SECRET_KEY")
# Pick the account by env: ALPACA_ENV=paper|live selects the right trading URL.
# APCA_BASE_URL still wins if set, so nothing breaks for existing deploys.
_ENVS = {"paper": "https://paper-api.alpaca.markets", "live": "https://api.alpaca.markets"}
ALPACA_ENV = os.getenv("ALPACA_ENV", "paper").strip().lower()
if ALPACA_ENV not in _ENVS:
    raise SystemExit(f"ALPACA_ENV must be 'paper' or 'live', got {ALPACA_ENV!r}")
BASE = os.getenv("APCA_BASE_URL") or _ENVS[ALPACA_ENV]
DATA_BASE = "https://data.alpaca.markets"
# Dashboard login (override in prod via env). Defaults are obvious on purpose for local use.
DASH_USER = os.getenv("DASHBOARD_USER", "admin")
DASH_PASS = os.getenv("DASHBOARD_PASS", "changeme")

if not KEY or not SECRET:
    raise SystemExit("Missing APCA_API_KEY_ID / APCA_API_SECRET_KEY")

HEADERS = {"APCA-API-KEY-ID": KEY, "APCA-API-SECRET-KEY": SECRET}
app = FastAPI(title="Trading Bot Dashboard")
security = HTTPBasic()


def auth(creds: HTTPBasicCredentials = Depends(security)):
    ok_u = secrets.compare_digest(creds.username, DASH_USER)
    ok_p = secrets.compare_digest(creds.password, DASH_PASS)
    if not (ok_u and ok_p):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad credentials",
                            {"WWW-Authenticate": "Basic"})
    return creds.username


def alpaca(method, path, base=BASE, **kw):
    r = requests.request(method, f"{base}{path}", headers=HEADERS, timeout=15, **kw)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text)
    return r.json() if r.text else {}


@app.get("/api/summary")
def summary(_: str = Depends(auth)):
    a = alpaca("GET", "/v2/account")
    eq = float(a["portfolio_value"])
    last = float(a.get("last_equity", eq))
    return {
        "equity": eq,
        "cash": float(a["cash"]),
        "buying_power": float(a["buying_power"]),
        "day_pl": eq - last,
        "day_pl_pct": ((eq - last) / last * 100) if last else 0,
        "status": a.get("status"),
        "account_number": a.get("account_number"),
        "paper": "paper" in BASE,
    }


@app.get("/api/positions")
def positions(_: str = Depends(auth)):
    out = []
    for p in alpaca("GET", "/v2/positions"):
        out.append({
            "symbol": p["symbol"], "qty": float(p["qty"]),
            "avg_entry": float(p["avg_entry_price"]), "price": float(p["current_price"]),
            "value": float(p["market_value"]), "pl": float(p["unrealized_pl"]),
            "pl_pct": float(p["unrealized_plpc"]) * 100,
        })
    return sorted(out, key=lambda x: -x["value"])


@app.get("/api/orders")
def orders(_: str = Depends(auth)):
    data = alpaca("GET", "/v2/orders", params={"status": "all", "limit": 25, "direction": "desc"})
    return [{
        "symbol": o["symbol"], "side": o["side"], "qty": o.get("qty"),
        "notional": o.get("notional"), "type": o["type"], "status": o["status"],
        "submitted": o.get("submitted_at", "")[:19].replace("T", " "),
        "filled_avg": o.get("filled_avg_price"),
    } for o in data]


@app.get("/api/history")
def history(_: str = Depends(auth)):
    h = alpaca("GET", "/v2/account/portfolio/history",
               params={"period": "1M", "timeframe": "1D", "extended_hours": "true"})
    pts = [{"t": t * 1000, "equity": e}
           for t, e in zip(h.get("timestamp", []), h.get("equity", [])) if e is not None]
    return {"points": pts, "base_value": h.get("base_value")}


@app.post("/api/flatten")
def flatten(_: str = Depends(auth)):
    res = alpaca("DELETE", "/v2/positions", params={"cancel_orders": "true"})
    return {"closed": res}


@app.post("/api/cancel")
def cancel(_: str = Depends(auth)):
    res = alpaca("DELETE", "/v2/orders")
    return {"canceled": res}


# ---------- signal computation (mirrors the bot's strategies, computed from live bars) ----------
def _crypto_closes(symbols, days=70):
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    r = requests.get(f"{DATA_BASE}/v1beta3/crypto/us/bars",
                     params={"symbols": ",".join(symbols), "timeframe": "1D", "start": start, "limit": 1000},
                     headers=HEADERS, timeout=20)
    r.raise_for_status()
    bars = r.json().get("bars", {})
    return {s: [b["c"] for b in bars.get(s, [])] for s in symbols}


def _stock_closes(symbols, days=400):
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    r = requests.get(f"{DATA_BASE}/v2/stocks/bars",
                     params={"symbols": ",".join(symbols), "timeframe": "1Day", "start": start,
                             "limit": 10000, "feed": "iex", "adjustment": "split"},
                     headers=HEADERS, timeout=25)
    r.raise_for_status()
    bars = r.json().get("bars", {})
    return {s: [b["c"] for b in bars.get(s, [])] for s in symbols}


def donchian_sig(c):
    if len(c) < 21:
        return "hold", "not enough data yet"
    last, hi20, lo10 = c[-1], max(c[-21:-1]), min(c[-11:-1])
    if last > hi20:
        return "buy", f"price ${last:,.0f} broke above the 20-day high ${hi20:,.0f}"
    if last < lo10:
        return "sell", f"price ${last:,.0f} fell below the 10-day low ${lo10:,.0f}"
    return "hold", f"price ${last:,.0f} ranging inside ${lo10:,.0f}–${hi20:,.0f} — wait for a breakout"


def rsi_sig(c, n=14):
    if len(c) < n + 2:
        return "hold", "not enough data yet"
    d = [c[i] - c[i - 1] for i in range(1, len(c))]
    def rsi_at(end):
        w = d[end - n:end]
        g = sum(x for x in w if x > 0) / n
        l = sum(-x for x in w if x < 0) / n
        return 100.0 if l == 0 else 100 - 100 / (1 + g / l)
    last, prev = rsi_at(len(d)), rsi_at(len(d) - 1)
    if prev < 30 <= last:
        return "buy", f"RSI bounced up through 30 ({prev:.0f}→{last:.0f}) — oversold bounce"
    if prev < 60 <= last:
        return "sell", f"RSI crossed up through 60 ({prev:.0f}→{last:.0f}) — exit target"
    return "hold", f"RSI {last:.0f} — no entry/exit cross"


def sma_sig(c):
    if len(c) < 200:
        return "hold", f"only {len(c)} days of data, need 200 for the trend"
    fast, slow = sum(c[-50:]) / 50, sum(c[-200:]) / 200
    if fast > slow:
        return "buy", f"50-day avg ${fast:,.0f} above 200-day ${slow:,.0f} — uptrend, hold it"
    return "sell", f"50-day avg ${fast:,.0f} below 200-day ${slow:,.0f} — downtrend, stay out"


@app.get("/api/signals")
def signals(_: str = Depends(auth)):
    held = {p["symbol"] for p in alpaca("GET", "/v2/positions")}
    def is_held(s):
        return s in held or s.replace("/", "") in held
    out = []
    try:
        cc = _crypto_closes(["BTC/USD", "ETH/USD"])
    except Exception:
        cc = {}
    for sym, fn, strat in [("BTC/USD", donchian_sig, "Donchian-20"), ("ETH/USD", rsi_sig, "RSI(14)")]:
        cl = cc.get(sym, [])
        sig, why = fn(cl) if cl else ("hold", "price feed unavailable")
        out.append({"symbol": sym, "sleeve": "crypto", "strategy": strat, "signal": sig,
                    "reason": why, "price": cl[-1] if cl else None, "holding": is_held(sym)})
    try:
        sc = _stock_closes(["SMH", "GRID", "COPX", "SPY"])
    except Exception:
        sc = {}
    for sym in ["SMH", "GRID", "COPX", "SPY"]:
        cl = sc.get(sym, [])
        sig, why = sma_sig(cl) if cl else ("hold", "price feed unavailable")
        out.append({"symbol": sym, "sleeve": "equity", "strategy": "SMA 50/200", "signal": sig,
                    "reason": why, "price": cl[-1] if cl else None, "holding": is_held(sym)})
    regime = None
    try:
        fg = requests.get("https://api.alternative.me/fng/?limit=1", timeout=10).json()["data"][0]
        regime = {"value": int(fg["value"]), "label": fg["value_classification"]}
    except Exception:
        pass
    return {"signals": out, "regime": regime}


# ================= Learning Academy (prediction-only — never places orders) =================
# Each asset class is one of:
#   live    -> real Alpaca price feed (stocks/ETFs, crypto)
#   proxy   -> can't buy the thing itself on a brokerage, so an ETF stands in (real price)
#   concept -> no market feed; taught with lessons/quizzes only
#   soon    -> teased and locked; unlock later
ASSET_CLASSES = {
    "stocks":      {"name": "Stocks & ETFs", "icon": "📈", "kind": "live",
                    "blurb": "Shares of companies and baskets of them. The bread and butter of investing."},
    "crypto":      {"name": "Crypto",        "icon": "🪙", "kind": "live",
                    "blurb": "Digital assets that trade 24/7 and move fast — great for learning volatility."},
    "realestate":  {"name": "Real Estate",   "icon": "🏠", "kind": "proxy",
                    "blurb": "You can't buy a house through a brokerage, but REIT funds let you own property income. Proxy: VNQ."},
    "bonds":       {"name": "Bonds",         "icon": "🏛️", "kind": "proxy",
                    "blurb": "Loans to governments and companies that pay interest. Proxy: BND."},
    "commodities": {"name": "Commodities",   "icon": "🥇", "kind": "proxy",
                    "blurb": "Physical goods like gold and oil, accessed through funds. Proxy: GLD."},
    "options":     {"name": "Options",       "icon": "⚖️", "kind": "soon",
                    "blurb": "Contracts to buy or sell later. Powerful and risky — unlocking once you level up."},
    "insurance":   {"name": "Insurance",     "icon": "🛡️", "kind": "concept",
                    "blurb": "Protecting what you already have. No price feed — you learn the concepts and earn XP."},
}

# Live/proxy assets become "predict higher or lower" challenge cards.
GAME_CATALOG = [
    {"id": "spy",  "symbol": "SPY",     "name": "S&P 500",              "cls": "stocks",
     "hint": "The broad US market. Slow and steady — genuinely hard to call day to day."},
    {"id": "smh",  "symbol": "SMH",     "name": "Semiconductors",        "cls": "stocks",
     "hint": "Chip stocks — high growth, high swings. Your bot holds this one."},
    {"id": "grid", "symbol": "GRID",    "name": "Clean Energy Grid",     "cls": "stocks",
     "hint": "Infrastructure theme. Moves with energy policy and interest rates."},
    {"id": "btc",  "symbol": "BTC/USD", "name": "Bitcoin",               "cls": "crypto",
     "hint": "The original crypto. Sentiment-driven — watch the Fear & Greed gauge."},
    {"id": "eth",  "symbol": "ETH/USD", "name": "Ethereum",              "cls": "crypto",
     "hint": "Smart-contract platform. Often follows Bitcoin, but amplified."},
    {"id": "vnq",  "symbol": "VNQ",     "name": "US Real Estate (REITs)", "cls": "realestate",
     "hint": "Owns malls, offices and apartments. Very sensitive to interest rates."},
    {"id": "bnd",  "symbol": "BND",     "name": "Total Bond Market",     "cls": "bonds",
     "hint": "Bonds tend to rise when rates fall. The calm counterweight to stocks."},
    {"id": "gld",  "symbol": "GLD",     "name": "Gold",                  "cls": "commodities",
     "hint": "The classic safe haven. Often climbs when fear is high."},
]

# Concept classes are taught with quizzes. Instant XP, no market feed.
QUIZZES = {
    "insurance": [
        {"q": "What is a deductible?",
         "choices": ["The amount YOU pay before insurance starts covering", "Your monthly bill",
                     "The insurer's profit margin", "A tax on every claim"], "answer": 0,
         "teach": "A deductible is what you pay out of pocket first. A higher deductible means a lower monthly premium — but more risk lands on you."},
        {"q": "Why is term life insurance usually cheaper than whole life?",
         "choices": ["It only covers a set period and builds no cash value", "It pays out more money",
                     "It is subsidized by the government", "It almost never pays out"], "answer": 0,
         "teach": "Term life is pure protection for N years, so it's cheap. Whole life bundles in a savings/investment component, which makes it cost more."},
        {"q": "An emergency fund is best thought of as…",
         "choices": ["Self-insurance against life's surprises", "A way to get rich quickly",
                     "Something only businesses need", "Identical to insurance you buy"], "answer": 0,
         "teach": "3–6 months of expenses in cash is self-insurance — it stops a small shock from turning into high-interest debt."},
    ],
    "bonds": [
        {"q": "When interest rates RISE, existing bond prices usually…",
         "choices": ["Fall", "Rise", "Stay exactly the same", "Double"], "answer": 0,
         "teach": "Bond prices move opposite to rates. New bonds pay more, so older, lower-paying bonds are worth less. This is why BND dips when rates climb."},
    ],
    "realestate": [
        {"q": "What is a REIT?",
         "choices": ["A company that owns income property, traded like a stock", "A type of mortgage",
                     "A government housing program", "A real-estate agent's license"], "answer": 0,
         "teach": "A REIT (Real Estate Investment Trust) owns rent-producing property and must pay out most of its income as dividends — so you get real-estate exposure without a down payment."},
        {"q": "Why is real estate sensitive to interest rates?",
         "choices": ["Higher rates make mortgages costlier, cooling property demand", "Rates don't affect it",
                     "Property is paid in cash only", "Rates only affect stocks"], "answer": 0,
         "teach": "When rates rise, borrowing to buy property gets expensive, so demand and prices soften. That's why REIT funds like VNQ often fall when rates climb."},
    ],
    "stocks": [
        {"q": "What is an ETF?",
         "choices": ["A basket of many stocks you can buy in one trade", "A single company's stock",
                     "A type of savings account", "A government bond"], "answer": 0,
         "teach": "An ETF (Exchange-Traded Fund) bundles many holdings into one ticker — instant diversification. SPY holds all 500 S&P companies at once."},
        {"q": "What does diversification do for you?",
         "choices": ["Spreads risk so one bad stock can't sink you", "Guarantees a profit",
                     "Doubles your returns", "Eliminates all risk"], "answer": 0,
         "teach": "Diversification means not betting everything on one name. It can't remove risk entirely, but it stops a single blow-up from wiping you out."},
    ],
    "crypto": [
        {"q": "What does 'volatility' mean for an asset like Bitcoin?",
         "choices": ["It can swing up or down sharply and quickly", "It always goes up",
                     "It never changes price", "It's backed by gold"], "answer": 0,
         "teach": "High volatility means big, fast price swings in both directions. It's why crypto can be exciting — and why position sizes should stay small while learning."},
        {"q": "If you lose your crypto wallet's private key, you…",
         "choices": ["Lose access to those funds permanently", "Call support to reset it",
                     "Get it mailed to you", "Keep the funds anyway"], "answer": 0,
         "teach": "In crypto, the private key IS ownership. There's no password-reset — which is why 'not your keys, not your coins' is the classic warning."},
    ],
    "commodities": [
        {"q": "Why do investors buy gold?",
         "choices": ["As a safe haven that often holds value when markets panic", "Because it pays high interest",
                     "Because it always beats stocks", "Because it's a tech growth play"], "answer": 0,
         "teach": "Gold produces no income, but it's a classic safe haven — demand tends to rise when fear is high or currencies weaken, which can steady a portfolio."},
    ],
}


def _latest_prices(symbols):
    """Latest trade price for a mix of stock and crypto symbols. Missing symbols are simply absent."""
    out, stocks, cryptos = {}, [s for s in symbols if "/" not in s], [s for s in symbols if "/" in s]
    if stocks:
        r = requests.get(f"{DATA_BASE}/v2/stocks/trades/latest",
                         params={"symbols": ",".join(stocks), "feed": "iex"}, headers=HEADERS, timeout=15)
        if r.ok:
            for s, t in r.json().get("trades", {}).items():
                out[s] = t.get("p")
    if cryptos:
        r = requests.get(f"{DATA_BASE}/v1beta3/crypto/us/latest/trades",
                         params={"symbols": ",".join(cryptos)}, headers=HEADERS, timeout=15)
        if r.ok:
            for s, t in r.json().get("trades", {}).items():
                out[s] = t.get("p")
    return out


@app.get("/api/game/catalog")
def game_catalog(_: str = Depends(auth)):
    prices = _latest_prices([a["symbol"] for a in GAME_CATALOG])
    assets = [{**a, "kind": ASSET_CLASSES[a["cls"]]["kind"],
               "icon": ASSET_CLASSES[a["cls"]]["icon"],
               "clsName": ASSET_CLASSES[a["cls"]]["name"],
               "price": prices.get(a["symbol"])} for a in GAME_CATALOG]
    return {"classes": ASSET_CLASSES, "assets": assets, "quizzes": QUIZZES}


@app.get("/api/game/quotes")
def game_quotes(_: str = Depends(auth)):
    """Current prices used by the browser to resolve pending predictions."""
    return _latest_prices([a["symbol"] for a in GAME_CATALOG])


SAVE_DIR = pathlib.Path(__file__).resolve().parent / "game_saves"
GAME_DB_NAME = os.getenv("GAME_DB_NAME", "money_world")
_mongo_lock = threading.Lock()
_mongo_col = None
_mongo_tried = False


def _profiles():
    """Mongo collection for player profiles, or None if unreachable.

    Connected lazily and only once: a dead network must never stop the game
    loading, so every caller falls back to a local file if this returns None.
    """
    global _mongo_col, _mongo_tried
    if _mongo_col is not None or _mongo_tried:
        return _mongo_col
    with _mongo_lock:
        if _mongo_tried:
            return _mongo_col
        _mongo_tried = True
        uri = os.getenv("MONGODB_URI")
        if not uri:
            return None
        try:
            import certifi
            from pymongo import MongoClient
            # macOS python ships without a usable CA bundle, so point TLS at certifi.
            # (Never disable verification here - that would expose the connection.)
            cli = MongoClient(uri, serverSelectionTimeoutMS=6000,
                              connectTimeoutMS=6000, socketTimeoutMS=8000,
                              tlsCAFile=certifi.where())
            cli.admin.command("ping")
            col = cli[GAME_DB_NAME]["profiles"]
            col.create_index("user", unique=True)
            _mongo_col = col
            print(f"[game] profiles -> mongo {GAME_DB_NAME}.profiles")
        except Exception as e:
            print(f"[game] mongo unavailable ({type(e).__name__}), using local files")
            _mongo_col = None
        return _mongo_col


def _save_path(user: str) -> pathlib.Path:
    """One save file per dashboard user. Name is sanitised, never user-controlled path."""
    safe = "".join(c for c in user if c.isalnum() or c in "-_") or "player"
    return SAVE_DIR / f"{safe}.json"


def _file_load(user: str) -> dict:
    p = _save_path(user)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _file_save(user: str, data: dict) -> None:
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    p = _save_path(user)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(p)                      # atomic, so a crash mid-write can't corrupt a save


@app.get("/api/game/profile")
def game_profile_get(user: str = Depends(auth)):
    """The player's whole profile: progress, wealth, badges, vault, purchases."""
    col = _profiles()
    if col is not None:
        try:
            doc = col.find_one({"user": user}, {"_id": 0, "user": 0})
            if doc:
                return doc
        except Exception:
            pass                        # fall through to the file copy
    return _file_load(user)


@app.post("/api/game/profile")
async def game_profile_post(req: Request, user: str = Depends(auth)):
    """Last-writer-wins by revision number, so a stale tab can't clobber progress."""
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "bad json")
    if not isinstance(data, dict):
        raise HTTPException(400, "expected object")
    data.pop("_id", None)
    rev = int(data.get("rev", 0) or 0)
    col = _profiles()
    if col is not None:
        try:
            cur = col.find_one({"user": user}, {"rev": 1})
            if cur and int(cur.get("rev", 0) or 0) > rev:
                return {"ok": False, "stale": True}
            col.replace_one({"user": user}, {"user": user, **data}, upsert=True)
            _file_save(user, data)      # local mirror, so a Mongo outage is survivable
            return {"ok": True, "rev": rev, "store": "mongo"}
        except Exception as e:
            print(f"[game] mongo write failed ({type(e).__name__}), writing file")
    old = _file_load(user)
    if old and int(old.get("rev", 0) or 0) > rev:
        return {"ok": False, "stale": True}
    _file_save(user, data)
    return {"ok": True, "rev": rev, "store": "file"}


@app.get("/game", response_class=HTMLResponse)
def game(_: str = Depends(auth)):
    # never cache the game page - a stale tab silently hides every new build
    return HTMLResponse(GAME_PAGE, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })


@app.get("/", response_class=HTMLResponse)
def index(_: str = Depends(auth)):
    return PAGE


PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Trading Bot Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<style>
:root{--bg:#0b0e14;--card:#151a23;--line:#222b38;--txt:#e6edf3;--mut:#8b98a9;--grn:#3fb950;--red:#f85149;--acc:#388bfd}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 2px}.sub{color:var(--mut);font-size:13px;margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.card .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:26px;font-weight:600;margin-top:6px}
.grn{color:var(--grn)}.red{color:var(--red)}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:20px}
.panel h2{font-size:14px;margin:0 0 12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:right;padding:8px 10px;border-bottom:1px solid var(--line)}
th:first-child,td:first-child{text-align:left}th{color:var(--mut);font-weight:500;font-size:12px}
.empty{color:var(--mut);padding:14px;text-align:center}
.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button{background:var(--card);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
button:hover{border-color:var(--acc)}button.danger:hover{border-color:var(--red);color:var(--red)}
.tag{font-size:11px;padding:2px 8px;border-radius:20px;background:#1f2733;color:var(--mut)}
.upd{color:var(--mut);font-size:12px;margin-left:auto}
canvas{max-height:260px}
</style></head><body><div class=wrap>
<div class=bar><div><h1>Trading Bot Dashboard</h1><div class=sub id=acct>loading…</div></div>
<a href="/game" style="margin-left:auto;text-decoration:none"><button style="border-color:var(--acc);color:var(--acc)">🎓 Trading Academy →</button></a></div>
<div class=bar style=margin-bottom:16px><span class=upd id=upd></span></div>
<div class=cards id=cards></div>
<div class=panel><h2>What the bot is thinking today</h2><div id=regime class=sub></div><div id=signals></div></div>
<div class=panel><h2>Equity — last 30 days</h2><canvas id=chart></canvas></div>
<div class=panel><h2>How the bot decides — flow</h2>
<pre class="mermaid">
flowchart TD
  S([Daily run 9AM]) --> ACC[Read account:<br/>equity, cash, positions]
  ACC --> CR[Crypto sleeve<br/>BTC and ETH]
  ACC --> EQ[Equities sleeve<br/>SMH GRID COPX SPY]
  CR --> CH{Holding?}
  CH -- yes --> ST{Down 5% or<br/>30d underwater?}
  ST -- yes --> SELL1[Stop-loss sell]
  ST -- no --> HOLD1[Hold]
  CH -- no --> SIG{Buy signal?<br/>Donchian / RSI}
  SIG -- no --> WAIT1[Stay in cash]
  SIG -- yes --> VETO{Regime bearish<br/>or stale?}
  VETO -- yes --> BLOCK[Veto - stay cash]
  VETO -- no --> CAP1[Size caps:<br/>25%/pos, 75% total]
  CAP1 --> BUY1[Buy]
  EQ --> EH{Holding?}
  EH -- yes --> TR{50d above 200d?}
  TR -- yes --> HOLD2[Hold the trend]
  TR -- no --> SELL2[Sell - trend broke]
  EH -- no --> UP{50d above 200d?<br/>uptrend}
  UP -- no --> WAIT2[Stay in cash]
  UP -- yes --> CAP2[Size caps]
  CAP2 --> BUY2[Buy]
</pre></div>
<div class=panel><h2>Open Positions</h2><div id=pos></div></div>
<div class=panel><h2>Recent Orders</h2><div id=ord></div></div>
<div class=panel><h2>Controls</h2><div class=bar>
<button class=danger onclick=flatten()>Flatten all positions</button>
<button class=danger onclick=cancelOrders()>Cancel all orders</button>
<button onclick=loadAll()>Refresh</button>
<span class=upd>auto-refresh 30s</span></div></div>
</div><script>
mermaid.initialize({startOnLoad:true,theme:'dark',themeVariables:{fontSize:'12px'}});
const $=id=>document.getElementById(id);
const money=n=>'$'+Number(n).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2});
const cls=n=>n>0?'grn':n<0?'red':'';const sign=n=>(n>=0?'+':'')+money(n);
async function j(u,o){const r=await fetch(u,o);if(!r.ok)throw new Error(await r.text());return r.json()}
let chart;
async function loadAll(){try{
 const s=await j('/api/summary');
 $('acct').textContent=`${s.account_number} · ${s.paper?'PAPER':'LIVE'} · ${s.status}`;
 $('cards').innerHTML=[
  ['Equity',money(s.equity),''],
  ['Cash',money(s.cash),''],
  ["Today's P/L",sign(s.day_pl),cls(s.day_pl)],
  ["Today %",(s.day_pl_pct>=0?'+':'')+s.day_pl_pct.toFixed(2)+'%',cls(s.day_pl)],
 ].map(([k,v,c])=>`<div class=card><div class=k>${k}</div><div class="v ${c}">${v}</div></div>`).join('');
 const sg=await j('/api/signals');
 $('regime').textContent=sg.regime?`Market regime — Fear & Greed ${sg.regime.value} (${sg.regime.label}). The bot vetoes new crypto buys while bearish.`:'';
 const badge=s=>`<span class="tag ${s==='buy'?'grn':s==='sell'?'red':''}">${s.toUpperCase()}</span>`;
 $('signals').innerHTML=`<table><tr><th>Symbol</th><th>Sleeve</th><th>Strategy</th><th>Signal</th><th style=text-align:left>What it sees</th><th>Holding</th></tr>`+
  sg.signals.map(s=>`<tr><td>${s.symbol}</td><td>${s.sleeve}</td><td>${s.strategy}</td><td>${badge(s.signal)}</td>
   <td style=text-align:left>${s.reason}</td><td>${s.holding?'✓':'—'}</td></tr>`).join('')+'</table>';
 const h=await j('/api/history');
 const labels=h.points.map(p=>new Date(p.t).toLocaleDateString(undefined,{month:'short',day:'numeric'}));
 const vals=h.points.map(p=>p.equity);
 $('chart').parentElement.querySelector('.cnote')?.remove();
 if(!vals.length){const n=document.createElement('div');n.className='cnote empty';
   n.textContent='No equity history yet — it fills in as the account runs.';$('chart').after(n);}
 if(chart)chart.destroy();
 chart=new Chart($('chart'),{type:'line',data:{labels,datasets:[{data:vals,borderColor:'#388bfd',
   backgroundColor:'rgba(56,139,253,.1)',fill:true,tension:.25,pointRadius:0,borderWidth:2}]},
   options:{plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>money(c.parsed.y)}}},
   scales:{x:{grid:{color:'#1c2430'},ticks:{color:'#8b98a9',maxTicksLimit:8}},
   y:{grid:{color:'#1c2430'},ticks:{color:'#8b98a9',callback:v=>'$'+(v/1000).toFixed(0)+'k'}}}}});
 const ps=await j('/api/positions');
 $('pos').innerHTML=ps.length?`<table><tr><th>Symbol</th><th>Qty</th><th>Avg</th><th>Price</th><th>Value</th><th>Unrl P/L</th><th>%</th></tr>`+
  ps.map(p=>`<tr><td>${p.symbol}</td><td>${p.qty}</td><td>${money(p.avg_entry)}</td><td>${money(p.price)}</td><td>${money(p.value)}</td>
   <td class=${cls(p.pl)}>${sign(p.pl)}</td><td class=${cls(p.pl)}>${p.pl_pct.toFixed(1)}%</td></tr>`).join('')+'</table>'
  :'<div class=empty>No open positions — all cash.</div>';
 const os=await j('/api/orders');
 $('ord').innerHTML=os.length?`<table><tr><th>Time</th><th>Symbol</th><th>Side</th><th>Size</th><th>Status</th><th>Fill</th></tr>`+
  os.map(o=>`<tr><td>${o.submitted}</td><td>${o.symbol}</td><td>${o.side}</td>
   <td>${o.notional?money(o.notional):(o.qty||'')}</td><td><span class=tag>${o.status}</span></td>
   <td>${o.filled_avg?money(o.filled_avg):'—'}</td></tr>`).join('')+'</table>'
  :'<div class=empty>No recent orders.</div>';
 $('upd').textContent='updated '+new Date().toLocaleTimeString();
}catch(e){$('upd').textContent='error: '+e.message}}
async function flatten(){if(!confirm('Close ALL positions at market? This is real (paper) money.'))return;
 await j('/api/flatten',{method:'POST'});loadAll()}
async function cancelOrders(){if(!confirm('Cancel ALL open orders?'))return;
 await j('/api/cancel',{method:'POST'});loadAll()}
loadAll();setInterval(loadAll,30000);
</script></body></html>"""


GAME_PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,user-scalable=no">
<title>Money World — Trading Academy</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<style>
*{box-sizing:border-box;-webkit-user-select:none;user-select:none;-webkit-tap-highlight-color:transparent}
html,body{margin:0;height:100%;background:#0a0d16;overflow:hidden;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#e9eef5}
#stage{position:relative;width:100vw;height:100vh;display:flex;align-items:center;justify-content:center}
#menu{position:fixed;right:8px;top:52px;z-index:45;display:none;flex-direction:column;gap:2px;
 background:linear-gradient(180deg,rgba(20,30,50,.98),rgba(12,19,33,.98));border:1px solid #2b3654;
 border-radius:14px;padding:7px;box-shadow:0 10px 34px rgba(0,0,0,.6);min-width:216px;max-height:78vh;overflow:auto}
#menu.show{display:flex}
.mrow{display:block;padding:9px 11px;border-radius:9px;color:#dce7f7;font-size:14px;font-weight:700;
 white-space:nowrap;text-decoration:none}
.mrow i{font-style:normal;font-weight:600;font-size:11px;color:#7fb4ff;margin-left:5px}
.mrow b{color:#f0b429}
.mrow.clk{cursor:pointer}
.mrow.clk:hover{background:#1e2c48}
.msep{height:1px;background:#2b3654;margin:4px 6px}
@media(max-width:700px){#menu{min-width:190px;right:6px}.mrow{font-size:13px;padding:8px 9px}
 #hdate{display:none}
 #hud .hpill{font-size:12px;padding:5px 9px}
 #hmenu span.lbl{display:none}}
@media(max-width:400px){#hud .hpill{font-size:11px;padding:4px 7px}}
body.bigtext .p-teach,body.bigtext .gd{font-size:17px;line-height:1.55}
body.bigtext .opt{font-size:18px;padding:15px 14px;font-weight:800}
body.bigtext .p-q{font-size:21px}
body.bigtext .p-title{font-size:25px}
body.bigtext #quest .qt{font-size:17px}
body.bigtext #quest .qw{font-size:14px}
.readbtn{display:inline-block;margin:6px 0 4px;padding:9px 14px;border-radius:10px;background:#2a3f68;
 border:1px solid #3d8bff;color:#dce7f7;font-weight:800;font-size:14px;cursor:pointer}
#quest{position:fixed;left:10px;top:64px;z-index:30;max-width:290px;background:linear-gradient(180deg,rgba(22,34,58,.97),rgba(14,22,38,.97));
 border:2px solid #3d8bff;border-radius:14px;padding:11px 13px;color:#eaf1ff;box-shadow:0 6px 22px rgba(0,0,0,.5);display:none}
#quest.show{display:block}
#quest .qh{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:#7fb4ff;font-weight:800;margin-bottom:3px}
#quest .qt{font-size:14.5px;font-weight:800;line-height:1.32}
#quest .qw{font-size:12.5px;color:#a8bcd8;margin-top:5px;line-height:1.4}
#quest .qs{margin-top:8px;font-size:11.5px;color:#6b7c96;cursor:pointer;text-decoration:underline}
#quest .qp{margin-top:7px;height:5px;background:#0d1420;border-radius:4px;overflow:hidden}
#quest .qp i{display:block;height:100%;background:linear-gradient(90deg,#3d8bff,#3fb950)}
@media(max-width:700px){#quest{max-width:210px;font-size:12px;top:58px}#quest .qt{font-size:13px}#quest .qw{font-size:11px}}
#web{position:fixed;inset:0;z-index:80;background:#0a0f18;display:none;flex-direction:column}
#web.show{display:flex}
#webbar{flex:0 0 auto;display:flex;align-items:center;gap:10px;padding:9px 12px;background:linear-gradient(180deg,#16223a,#0e1626);border-bottom:2px solid #3d8bff;box-shadow:0 3px 14px rgba(0,0,0,.5)}
#webbar button{background:#3d8bff;color:#fff;border:none;border-radius:9px;padding:11px 18px;font-weight:800;font-size:15px;cursor:pointer;white-space:nowrap}
#webbar button:hover{background:#5a9dff}
#webtitle{color:#cfe0ff;font-weight:700;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
#webbar a{color:#7fb4ff;font-weight:700;font-size:13px;text-decoration:none;white-space:nowrap}
#webframe{flex:1 1 auto;width:100%;border:0;background:#fff}
#webnote{padding:26px;color:#cfe0ff;font-size:15px;line-height:1.6;max-width:640px;margin:0 auto}
#game{background:#204a2e;max-width:100%;max-height:100%;touch-action:none;display:block;border-radius:6px}
#hud{position:absolute;top:10px;left:0;right:0;display:flex;gap:8px;justify-content:center;pointer-events:none;z-index:5;flex-wrap:wrap;padding:0 8px}
.hpill{background:rgba(12,18,34,.82);border:1px solid #2b3654;border-radius:20px;padding:6px 13px;font-size:13px;font-weight:800;backdrop-filter:blur(4px)}
.hpill b{color:#f0b429}.hpill.clk{pointer-events:auto;cursor:pointer}
#hint{position:absolute;left:0;right:0;bottom:120px;text-align:center;font-weight:800;font-size:15px;color:#fff;text-shadow:0 2px 6px #000;z-index:5;pointer-events:none;opacity:0;transition:.2s}
#hint.show{opacity:1;animation:bh 1s infinite}@keyframes bh{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}
#wbanner{position:absolute;left:0;right:0;top:40%;text-align:center;z-index:8;pointer-events:none;opacity:0;transition:.35s;transform:scale(.9)}
#wbanner.show{opacity:1;transform:scale(1)}
#wbanner .wt{font-size:13px;font-weight:800;letter-spacing:3px;color:#f0b429}#wbanner .wn{font-size:30px;font-weight:900;text-shadow:0 3px 12px #000}
#hsense{position:absolute;top:46px;left:0;right:0;text-align:center;z-index:5;pointer-events:none;font-weight:800;font-size:14px;color:#fff;text-shadow:0 2px 6px #000}
#mini{position:absolute;right:12px;bottom:92px;width:120px;height:120px;border-radius:50%;border:2px solid #2b3654;background:rgba(10,16,30,.4);z-index:5;pointer-events:none}
#pad{position:absolute;bottom:14px;left:0;right:0;display:flex;justify-content:space-between;align-items:flex-end;padding:0 16px;z-index:6}
.dpad{display:grid;grid-template-columns:repeat(3,52px);grid-template-rows:repeat(3,52px);gap:4px}
.dpad .gbtn{width:52px;height:52px}
.dU{grid-column:2;grid-row:1}.dL{grid-column:1;grid-row:2}.dR{grid-column:3;grid-row:2}.dD{grid-column:2;grid-row:3}
.gbtn{border-radius:14px;background:rgba(20,28,50,.82);border:1px solid #33456a;color:#fff;font-size:22px;font-weight:800;display:flex;align-items:center;justify-content:center;touch-action:none}
.gbtn:active{background:rgba(61,139,255,.5)}
.gbtn.enter{width:auto;height:56px;padding:0 22px;border-radius:30px;border-color:#3d8bff;color:#7fb4ff;font-size:16px;display:none}
.gbtn.enter.on{display:flex;animation:pE 1s infinite}@keyframes pE{0%,100%{transform:scale(1)}50%{transform:scale(1.08)}}
.ov{position:absolute;inset:0;background:rgba(6,9,16,.86);display:none;align-items:center;justify-content:center;z-index:20;padding:16px}
.ov.show{display:flex}
.panel{background:linear-gradient(160deg,#1a2340,#12172a);border:1px solid #3d8bff;border-radius:22px;padding:20px;max-width:460px;width:100%;text-align:center;max-height:94vh;overflow:auto;animation:pin .4s cubic-bezier(.2,1.4,.4,1);position:relative}
.panel.boss{border-color:#f0b429}
@keyframes pin{from{transform:scale(.82);opacity:0}to{transform:none;opacity:1}}
.p-badge{width:74px;height:74px;margin:0 auto 6px;border-radius:22px;display:flex;align-items:center;justify-content:center;font-size:38px;background:linear-gradient(160deg,#3d8bff,#a371f7);box-shadow:0 8px 24px rgba(61,139,255,.4)}
.p-world{color:#7fb4ff;font-weight:800;font-size:11px;letter-spacing:1.2px;text-transform:uppercase}
.p-title{font-size:21px;font-weight:800;margin:2px 0 8px}
.p-teach{color:#a7b6cc;font-size:14px;line-height:1.55;margin:0 0 14px;text-align:left;background:#0e162699;border:1px solid #22304e;border-radius:12px;padding:11px 13px}
.p-tag{display:inline-block;font-size:10px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:#0a0d16;background:#7fb4ff;border-radius:6px;padding:2px 8px;margin-bottom:8px}
.p-tag.diff1{background:#3fb950}.p-tag.diff2{background:#7fb4ff}.p-tag.diff3{background:#f0b429}.p-tag.diff4{background:#f0864a}.p-tag.diff5{background:#f85149;color:#fff}
.p-q{font-size:16px;font-weight:800;margin:6px 0 10px}
.vword{font-size:30px;font-weight:900;margin:4px 0 12px;background:linear-gradient(90deg,#3d8bff,#a371f7);-webkit-background-clip:text;background-clip:text;color:transparent}
.opt{display:block;width:100%;margin:8px 0;text-align:left;background:#0e1626;color:#e9eef5;border:1px solid #2b3654;border-radius:12px;padding:12px 14px;font-size:14px;font-weight:600}
.opt:active{background:#122038;border-color:#3d8bff}
.fillin{width:100%;background:#0e1626;border:1px solid #2b3654;border-radius:12px;padding:12px 14px;font-size:16px;color:#fff;text-align:center;margin:4px 0 10px}
.fillin:focus{outline:none;border-color:#3d8bff}
.a-px{font-size:32px;font-weight:800;margin:6px 0}
.hz{display:flex;gap:6px;justify-content:center;margin:6px 0 12px;flex-wrap:wrap}
.hz button{padding:5px 11px;font-size:12px;font-weight:800;background:#0e1626;color:#93a1b5;border:1px solid #2b3654;border-radius:10px}
.hz button.on{border-color:#3d8bff;color:#7fb4ff;background:#122038}
.calls{display:flex;gap:10px}
.calls button{flex:1;padding:15px;font-size:15px;font-weight:800;border-radius:14px;border:1px solid #2b3654;background:#0e1626}
.up{color:#3fb950}.up:active{background:rgba(63,185,80,.18)}.down{color:#f85149}.down:active{background:rgba(248,81,73,.18)}
.arena{background:radial-gradient(circle at 50% 30%,#3a2130,#160f1e);border:1px solid #55304a;border-radius:16px;padding:14px 10px 10px;margin-bottom:10px}
.enemy{font-size:60px;line-height:1;display:inline-block;filter:drop-shadow(0 6px 10px rgba(0,0,0,.5))}
.enemy.hit{animation:ehit .35s}.enemy.atk{animation:eatk .4s}
@keyframes ehit{0%{transform:scale(1)}30%{transform:scale(1.2) rotate(6deg);filter:brightness(2)}100%{transform:scale(1)}}
@keyframes eatk{0%,100%{transform:translateX(0)}20%{transform:translateX(-10px) scale(1.1)}40%{transform:translateX(10px)}60%{transform:translateX(-7px)}80%{transform:translateX(7px)}}
.ename{font-weight:800;font-size:14px;margin-top:4px;color:#ffd98a}
.hpwrap{display:flex;gap:4px;justify-content:center;margin:8px 0 2px}
.hpseg{flex:1;max-width:34px;height:10px;border-radius:4px;background:#3fb950;border:1px solid #0a0d16;transition:.3s}
.hpseg.gone{background:#2a1622}
.hplbl{font-size:11px;color:#f0864a;font-weight:800}
.panel.shake{animation:pshake .4s}@keyframes pshake{0%,100%{transform:none}25%{transform:translateX(-8px)}50%{transform:translateX(8px)}75%{transform:translateX(-5px)}}
.bossp{font-weight:800;margin:4px 0 10px;color:#f0b429}
.pbtn{margin-top:4px;padding:12px 22px;font-weight:800;border-radius:14px;border:1px solid #3d8bff;background:#122038;color:#fff;font-size:15px}
.p-note{color:#93a1b5;font-size:12px;margin-top:8px}
.tclose{position:absolute;top:12px;right:14px;font-size:22px;color:#93a1b5;background:none;border:none}
.p-burst{font-size:44px;animation:fl 1.1s infinite}@keyframes fl{0%,100%{transform:scale(1) rotate(-5deg)}50%{transform:scale(1.2) rotate(5deg)}}
.trow{display:flex;align-items:center;gap:8px;background:#0e1626;border:1px solid #2b3654;border-radius:12px;padding:9px;margin:6px 0;text-align:left}
.trow .ti{font-size:19px}.trow .tn{font-weight:700;font-size:13px}.trow .tr{margin-left:auto;font-weight:800;font-size:12px}
.gloss{text-align:left;background:#0e1626;border:1px solid #2b3654;border-radius:12px;padding:10px;margin:6px 0}
.gloss b{color:#7fb4ff}.gloss .gd{color:#a7b6cc;font-size:13px}
.bgs{display:grid;grid-template-columns:repeat(auto-fill,minmax(84px,1fr));gap:7px;margin-top:6px}
.bg{background:#0e1626;border:1px solid #2b3654;border-radius:12px;padding:8px 4px;text-align:center}.bg.off{opacity:.28;filter:grayscale(1)}.bg .i{font-size:22px}.bg .n{font-size:10px;font-weight:700;margin-top:2px}
.conf{position:fixed;top:-14px;width:10px;height:14px;border-radius:2px;z-index:60;pointer-events:none;animation:fall 1.9s linear forwards}
@keyframes fall{to{transform:translateY(110vh) rotate(680deg);opacity:.85}}
.toast{position:absolute;left:50%;top:58px;transform:translateX(-50%) translateY(-10px);background:#1c2436;border:1px solid #3d8bff;border-radius:12px;padding:10px 18px;font-size:13px;font-weight:700;max-width:92vw;text-align:center;opacity:0;transition:.3s;z-index:30;pointer-events:none}
.toast.show{opacity:1;transform:translateX(-50%)}
</style></head><body><div id=stage>
<canvas id=game width=800 height=450></canvas>
<div id=hud><span class=hpill>Lvl <b id=hlvl>1</b>/6</span><span class="hpill clk" id=hwealth>💰 $<b id=hnw>0</b></span><span class=hpill id=hfree title="How close you are to financial freedom">🗽 0%</span><span class=hpill style="font-variant-numeric:tabular-nums"><b id=hclock>08:00</b><span id=hdate> · Mon 1 Jan · Yr 1</span></span><span class="hpill clk" id=hmenu>☰<span class=lbl> Menu</span></span></div>
<div id=menu>
 <span class="mrow clk" id=hprof>👤 Profile &amp; badges</span>
 <span class="mrow clk" id=hmkt>📈 Market Desk <i>real prices</i></span>
 <span class="mrow clk" id=hact>⏳ Spend your day</span>
 <span class="mrow clk" id=hshop>🛒 Shop</span>
 <span class="mrow clk" id=hhome>🏠 Home / Outside</span>
 <span class=msep></span>
 <span class="mrow clk" id=hvault>📚 Vault <b id=hvn>0</b></span>
 <span class="mrow clk" id=hgloss>📖 Word bank <b id=hwords>0</b></span>
 <span class="mrow clk" id=htrophy>🏆 Trophies</span>
 <span class="mrow" id=hwp>💪 Willpower <b id=hwpn>0</b></span>
 <span class=msep></span>
 <span class="mrow clk" id=hview>👁 Overhead</span>
 <span class="mrow clk" id=htool>👊 Bare Hands</span>
 <span class="mrow clk" id=hnarr>🔇 Read aloud: OFF</span>
 <span class="mrow clk" id=hhelp>❔ How to play</span>
 <span class="mrow" id=hsave style="opacity:.4">☁ Saved</span>
 <a class="mrow clk" id=hdash href="/" style=color:inherit>📊 Trading dashboard</a>
</div>
<div id=hsense></div>
<div id=hint>Press ↵ ENTER to go in</div>
<div id=wbanner><div class=wt id=wbt>LEVEL 1</div><div class=wn id=wbn>Piggy Bank Park</div></div>
<div id=pad>
 <div class=dpad><button class="gbtn dU" id=bU>▲</button><button class="gbtn dL" id=bL>◀</button><button class="gbtn dR" id=bR>▶</button><button class="gbtn dD" id=bD>▼</button></div>
 <button class=gbtn id=bJ2 style=margin-right:8px>⤴</button><button class="gbtn enter" id=bE>↵ ENTER</button></div>
<canvas id=mini width=120 height=120></canvas>
<div class=toast id=toast></div>
<div class=ov id=profile><div class=panel><button class=tclose onclick="hide('profile')">✕</button><div id=profbody></div></div></div>
<div class=ov id=market><div class=panel><button class=tclose onclick="hide('market')">✕</button><div id=marketbody></div></div></div>
<div id=quest><div class=qh>Your next step</div><div class=qt id=qtext></div><div class=qw id=qwhy></div><div class=qp><i id=qbar style=width:0%></i></div><div class=qs onclick="skipTutorial()">Skip the walkthrough</div></div>
<div id=web><div id=webbar><button onclick="closeWeb()">← Back to Money World</button><span id=webtitle></span><a id=weblink href="#" target=_blank rel=noopener>Open in new tab ↗</a></div><iframe id=webframe title="Resource"></iframe><div id=webnote style="display:none"></div></div>
<div class=ov id=shop><div class=panel><button class=tclose onclick="hide('shop')">✕</button><div id=shopbody></div></div></div>
<div class=ov id=mine><div class=panel><div id=minebody></div></div></div>
<div class=ov id=npc><div class=panel><button class=tclose onclick="hide('npc')">✕</button><div id=npcbody></div></div></div>
<div class=ov id=tempt><div class=panel style=border-color:#f85149><div id=tbody></div></div></div>
<div class=ov id=challenge><div class=panel id=cpanel><button class=tclose onclick=closeChallenge()>✕</button><div id=cbody></div></div></div>
<div class=ov id=cleared><div class=panel><div class=p-burst id=clburst>⭐</div><div class=p-world id=clw>Room Cleared</div>
 <div class=p-title id=clt>Complete!</div><div class=p-teach id=cls style=text-align:center></div><button class=pbtn onclick=closeCleared()>Continue →</button></div></div>
<div class=ov id=trophies><div class=panel><button class=tclose onclick="hide('trophies')">✕</button>
 <div class=p-title>🏆 Trophy Room</div><div class=p-world style=margin-bottom:4px>Investor Credentials</div><div id=creds></div>
 <div class=p-world style=margin:12px_0_4px>Badges</div><div class=bgs id=badges></div>
 <div class=p-note>Ranks are in-game knowledge levels, not the legal financial terms.</div>
 <div style=margin-top:10px><a href="/" style=color:#7fb4ff;font-weight:700>← Live account dashboard</a></div></div></div>
<div class=ov id=wealth><div class=panel><button class=tclose onclick="hide('wealth')">✕</button><div id=wbody></div></div></div>
<div class=ov id=help><div class=panel style="text-align:center">
 <div class=p-badge style="font-size:64px">🐷</div>
 <div class=p-title style="font-size:30px">Money World</div>
 <div class=p-world style="margin-bottom:14px">Smash stuff. Get paid. Get rich.</div>
 <button class=pbtn style="font-size:22px;padding:16px" onclick="startGame()">▶ PLAY</button>
 <div class=readbtn style="margin-top:12px" onclick="toggleNarrate();this.textContent=G.narrate?'🔊 Read aloud: ON':'🔇 Read aloud: OFF'">🔇 Read aloud: OFF</div>
 <div class=p-note style="margin-top:4px">turn this on for young players</div>
 <div class=p-note style="margin-top:10px;cursor:pointer" onclick="document.getElementById('ctrls').style.display='block';this.style.display='none'">controls ↓</div>
 <div id=ctrls style="display:none;text-align:left;margin-top:8px" class=p-teach>
  <b>Move</b> arrows / WASD or the pad &nbsp; <b>Jump</b> SPACE &nbsp; <b>Do it</b> ENTER<br>
  <b>Smash</b> walk into things &nbsp; <b>Look</b> C changes the camera<br>
  Walls: beat them down, climb them, or go round. Push crates. Climb mountains.
 </div>
</div></div>
<div class=ov id=secret><div class=panel style=border-color:#f0b429><button class=tclose onclick="hide('secret')">✕</button><div id=secbody></div></div></div>
<div class=ov id=vault><div class=panel><button class=tclose onclick="hide('vault')">✕</button><div id=vbody></div></div></div>
<div class=ov id=glossary><div class=panel><button class=tclose onclick="hide('glossary')">✕</button>
 <div class=p-title>📖 Word Bank</div><div class=p-world style=margin-bottom:8px>The language of investing — your superpower</div><div id=glist></div></div></div>
</div><script>
const KEY='money_world_3';
const HORIZONS=[{h:24,l:'1 day'},{h:72,l:'3 days'},{h:168,l:'1 week'}];
const WORLDS=[
 {name:'Piggy Bank Park',ground:'#2f7d46',tint:'#3fa35a',prop:'🌳'},
 {name:'Compound Canyon',ground:'#6a5a2e',tint:'#8a7a3a',prop:'🌵'},
 {name:'Market Street',ground:'#4a5060',tint:'#5a6072',prop:'🏙️'},
 {name:'Asset Islands',ground:'#1f6a70',tint:'#2a8a86',prop:'🌊'},
 {name:'Millionaire Mountain',ground:'#6a6a72',tint:'#8a8a92',prop:'⛰️'},
 {name:'Dev Valley',ground:'#1b2740',tint:'#2b3a5c',prop:'💻'},
];
const LEVELS=[
 {world:0,diff:1,rooms:[
   {type:'vocab',ic:'🐷',title:'Word: Saving',term:'SAVING',choices:['Money you keep now to use later','Money you owe the bank','A kind of tax','Spending on toys'],a:0,word:{t:'Saving',d:'Money you set aside now to use later instead of spending it.'}},
   {type:'scenario',ic:'🍬',title:'The Patience Test',setup:'A wizard offers you 1 marshmallow NOW, or 2 if you wait 10 minutes. Choose the mindset every investor needs.',options:[{label:'🍬 Grab 1 now',ok:false,outcome:'Yummy! But waiting DOUBLES the treat. That superpower is delayed gratification.'},{label:'⏳ Wait for 2',ok:true}],word:{t:'Delayed Gratification',d:'Giving up a small reward now for a bigger reward later.'}},
   {type:'mc',ic:'🧺',title:'Needs vs Wants',teach:'A NEED keeps you alive (food, a home). A WANT is nice to have (a new game). Cover needs first.',q:'Which is a NEED?',choices:['A place to live','New sneakers','A candy bar','A video game'],a:0},
 {type:'tf',ic:'🪙',title:'Save or Spend',teach:'Saving means keeping some money for later instead of spending it all right now.',q:'Saving part of your money is a smart habit.',a:true}],boss:{name:'The Impulse Spender',enemy:'🧟',intro:'A goblin who blows every dollar on candy. Beat him with smart-money answers!',questions:[
   {q:'You get $10. The smartest first move?',choices:['Save some of it','Spend it all on candy','Lose it on purpose','Ignore it'],a:0},
   {q:'Waiting for a bigger reward later is called...',choices:['Delayed gratification','Being bored','A tax','A loss'],a:0},
   {q:'Which is a NEED, not a want?',choices:['Healthy food','A new toy','Extra candy','A fancy game'],a:0}]}},
 {world:1,diff:2,rooms:[
   {type:'mc',ic:'⛄',title:'The Snowball',teach:'Compound interest = your money earns money, and THAT money earns money too. It snowballs the longer you leave it.',q:'Why is compound interest like a snowball?',choices:['Growth builds on past growth','Because it is cold','It melts away','It rolls off a cliff'],a:0,word:{t:'Compound Interest',d:'Earning growth on your growth — money makes money, then that makes money too.'}},
   {type:'fill',ic:'⏳',title:'Time is Power',teach:'The earlier you start, the more TIME your money has to multiply.',prompt:'Finish it: the earlier you start, the more time your money has to ____.',answer:'grow',accept:['grow','multiply','compound']},
   {type:'tf',ic:'💵',title:'A Dollar Today',teach:'Money can grow over time, so a dollar now can become more than a dollar later.',q:'A dollar today is worth MORE than a dollar in 10 years.',a:true,word:{t:'Time Value of Money',d:'Money now is worth more than the same amount later, because it can grow.'}},
 {type:'mc',ic:'🌱',title:'Grow It',teach:'Money you invest can grow year after year — even while you sleep.',q:'Invested money grows mainly through...',choices:['Compounding over time','Pure luck','Spending it fast','Hiding it'],a:0}],boss:{name:'Father Time',enemy:'⏳',intro:'The keeper of the clock tests whether you respect the power of time.',questions:[
   {q:'Compound interest means your money earns money, and then...',choices:['That money earns money too','It stops growing','It shrinks','Nothing happens'],a:0},
   {q:'Who likely ends up richer?',choices:['Someone who starts investing at 20','Someone who starts at 40','They tie exactly','Neither ever wins'],a:0},
   {q:'A dollar today vs a dollar in 10 years?',choices:['Today is worth more','Later is worth more','Always equal','Impossible to say'],a:0},
   {q:'The magic ingredient compounding needs MOST is...',choices:['Time','Luck','A huge salary','A hot tip'],a:0}]}},
 {world:2,diff:3,rooms:[
   {type:'vocab',ic:'🏢',title:'Word: Stock',term:'STOCK',choices:['A small piece of ownership in a company','A loan to the government','A savings account','A store shelf'],a:0,word:{t:'Stock',d:'A share of ownership in a company. Own it and you own a slice of the business.'}},
   {type:'read',ic:'📖',title:'One Basket',tag:'Reading',passage:'An ETF is a basket that holds many stocks at once. Buy one share and you instantly own a little of everything inside — easy diversification, so a single bad company cannot sink you.',q:'What is the main benefit of an ETF?',choices:['Instant diversification across many stocks','You bet on one company','It is a bank loan','It avoids all risk'],a:0,word:{t:'Diversification',d:'Spreading money across many investments so one loser cannot sink you.'}},
   {type:'predict',ic:'🎯',title:'Your First Call',asset:'spy',teach:'Read a REAL market. Will the S&P 500 (500 biggest US companies) be higher or lower in your window?'},
 {type:'tf',ic:'📊',title:'Own a Piece',teach:'When you buy a share of stock, you literally become a part-owner of that company.',q:'Owning a stock means you own a piece of a real company.',a:true}],boss:{name:'The Bear',enemy:'🐻',intro:'A grumpy bear who thinks you do not know your stock words. Prove him wrong!',questions:[
   {q:'Owning a stock means you own...',choices:['A piece of the company','A government loan','A physical house','Nothing at all'],a:0},
   {q:'An ETF is best described as...',choices:['A basket of many stocks','One single stock','A bank branch','A type of bond'],a:0},
   {q:'A dividend is...',choices:['A share of profit paid to owners','A late penalty','A sales tax','A kind of loan'],a:0},
   {q:'Spreading money across many investments is...',choices:['Diversification','Volatility','Saving','A dividend'],a:0}]}},
 {world:3,diff:4,rooms:[
   {type:'mc',ic:'🪙',title:'Wild Rides',teach:'Crypto trades 24/7 and is very volatile — prices swing up and down sharply and fast. Keep positions small.',q:'"Volatile" means prices...',choices:['Swing a lot and fast','Never move','Only go up','Are guaranteed'],a:0,word:{t:'Volatility',d:'How much and how fast a price swings. High volatility = big, quick moves.'}},
   {type:'predict',ic:'⚡',title:'Crypto Call',asset:'btc',teach:'Bitcoin runs on crowd fear and greed. Make your call: higher or lower from here?'},
   {type:'mc',ic:'🏠',title:'Owning Property',teach:'A REIT is a company that owns rental property and trades like a stock, paying you rent income without a down payment.',q:'A REIT lets you invest in...',choices:['Real estate','Only tech stocks','Gold bars','Nothing real'],a:0,word:{t:'REIT',d:'A company that owns income property and trades like a stock, sharing the rent.'}},
 {type:'mc',ic:'⚖️',title:'Risk Check',teach:'Investments that can pay the most can also lose the most. Reward and risk travel together.',q:'Higher potential reward usually comes with...',choices:['Higher risk','No risk at all','Guaranteed money','Lower risk'],a:0}],boss:{name:'The Volatility Kraken',enemy:'🌊',intro:'A sea beast of wild swings. Stay calm and answer to tame the storm.',questions:[
   {q:'Volatility means...',choices:['Big fast price swings','Steady flat prices','Guaranteed gains','Zero risk'],a:0},
   {q:'A REIT lets you invest in...',choices:['Real estate','Only crypto','Only gold','Only bonds'],a:0},
   {q:'When interest rates RISE, bond prices usually...',choices:['Fall','Rise','Stay flat','Double'],a:0,word:{t:'Bond',d:'A loan to a government or company that pays you interest over time.'}},
   {q:'Gold is best known as a...',choices:['Safe haven in fearful times','Guaranteed money-doubler','High-interest bond','Meme coin'],a:0},
   {q:'Higher potential reward usually comes with...',choices:['Higher risk','No risk at all','Lower risk','A guarantee'],a:0,word:{t:'Risk vs Reward',d:'The bigger the possible reward, the bigger the possible loss. They travel together.'}}]}},
 {world:4,diff:5,rooms:[
   {type:'read',ic:'🧭',title:'When to Invest',tag:'Reading',passage:'WHEN to invest: money you will not need for years. WHEN NOT to: money you need next month, or money you would panic-sell the second prices dip. Great investors stay calm and think long term.',q:'Which money is BEST to invest?',choices:['Money you will not need for years','Next months rent','Money you might panic-sell','Tomorrows lunch money'],a:0},
   {type:'scenario',ic:'📉',title:'The Crash',setup:'The market suddenly drops 30% and the news is scary. You are invested for the long term. What is the wise move?',options:[{label:'😱 Panic-sell everything',ok:false,outcome:'That locks in your losses. Crashes are temporary for patient long-term investors.'},{label:'🧘 Stay calm and keep investing',ok:true}],word:{t:'Time in the Market',d:'Staying invested for the long run usually beats jumping in and out.'}},
   {type:'mc',ic:'📜',title:'The Recipe',teach:'The millionaire recipe: SAVE regularly, INVEST early, DIVERSIFY, and be PATIENT for years.',q:'Which is NOT part of the recipe?',choices:['Panic-sell when scared','Save regularly','Invest early','Diversify'],a:0},
 {type:'mc',ic:'🧠',title:'The Real Superpower',teach:'The wealthy rarely get rich fast. They get rich slowly — by staying patient and consistent for years.',q:'Most wealthy investors got there by being...',choices:['Patient and consistent','Lucky just once','Flashy spenders','In a big hurry'],a:0}],boss:{name:'The Market Dragon',enemy:'🐉',intro:'The final boss guards the summit. Speak the full language of money to defeat it!',questions:[
   {q:'A share of ownership in a company is a...',choices:['Stock','Bond','Deductible','Receipt'],a:0},
   {q:'Money that grows on its own past growth is...',choices:['Compound interest','A want','A penalty','A refund'],a:0},
   {q:'Spreading money across many investments is...',choices:['Diversification','Volatility','A dividend','A tax'],a:0},
   {q:'The best time to START investing is...',choices:['As early as possible','Never','Only when old','Only when rich'],a:0},
   {q:'A safe haven that often rises when investors panic is...',choices:['Gold','A meme coin','A new want','A late fee'],a:0},
   {q:'Time IN the market usually beats...',choices:['Timing the market','Saving money','Diversifying','Being patient'],a:0}]}},
 {world:5,diff:5,rooms:[
   {type:'vocab',ic:'🧠',title:'Word: Human Capital',term:'HUMAN CAPITAL',
    choices:['Your skills and earning power — the biggest asset you own when young','Money a company borrows from staff','The cash in your bank account','A tax on wages'],a:0,
    word:{t:'Human Capital',d:'Your skills, knowledge and earning power. Early on it is worth more than your portfolio — and it is the one asset you can grow fastest.'}},
   {type:'mc',ic:'📈',title:'The Fastest Lever',
    teach:'Cutting coffee saves you maybe $1,500 a year. Learning a skill that raises your pay can add $20,000+ a year, every year, forever. Both matter — one is far bigger.',
    q:'Early in your career, which moves the needle most?',
    choices:['Raising your income with a valuable skill','Clipping coupons harder','Finding a slightly better savings rate','Trading stocks more often'],a:0,
    word:{t:'Earning Power',d:'How much you can earn per hour of work. Raising it is usually the single biggest financial move available to you.'}},
   {type:'mc',ic:'🤖',title:'Leverage, Not Hours',
    teach:'A developer with AI tools can ship what used to take a whole team. That is LEVERAGE — output that is no longer tied to hours worked.',
    q:'Why is leverage the key to getting rich?',
    choices:['Your output stops being limited by hours in a day','It guarantees you never fail','It removes all risk','It makes work free'],a:0,
    word:{t:'Leverage',d:'Getting more output from the same effort — through code, tools, media, other people or capital. Wealth comes from leverage, not extra hours.'}},
   {type:'mc',ic:'🛡️',title:'The Security Lab',
    teach:'A pen tester gets paid to break in BEFORE criminals do. Same idea protects your money: a stolen login can drain an account faster than any bad investment.',
    q:'What protects your accounts the most?',
    choices:['Unique passwords plus two-factor authentication','Checking your balance often','Keeping cash under the mattress','Using the same strong password everywhere'],a:0,
    word:{t:'Two-Factor Authentication',d:'A second proof of identity beyond a password. The cheapest insurance in finance — free, and it stops most account theft.'}},
   {type:'scenario',ic:'💼',title:'Salary or Freelance?',
    setup:'You can code. A company offers a steady salary. A client offers contract work at a higher rate but no benefits and you handle your own taxes.',
    options:[
      {label:'💰 Chase the highest headline rate',ok:false,outcome:'Careful — as a contractor you pay both halves of Social Security and Medicare (about 15.3%) plus your own health cover. A higher rate is not automatically more money.'},
      {label:'🧮 Work out take-home after taxes and benefits',ok:true}],
    word:{t:'Self-Employment Tax',d:'Contractors pay roughly 15.3% for Social Security and Medicare — both the employee AND employer halves. Always compare offers after tax, not before.'}},
   {type:'mc',ic:'🌙',title:'Money While You Sleep',
    teach:'Selling hours caps you — there are only so many. An app, a course, a product or a portfolio keeps earning after the work is finished.',
    q:'What actually makes income "passive"?',
    choices:['It keeps paying after the work is already done','It arrives with no work at all, ever','It is guaranteed by the government','It is money from a savings account only'],a:0,
    word:{t:'Passive Income',d:'Income that keeps arriving after the work is done — products, royalties, dividends, rent. Building it is how you stop trading time for money.'}}],
  boss:{name:'The Freedom Number',enemy:'🗽',
   intro:'The last boss is not a monster — it is a number. Work out what financial freedom actually costs, and you beat the game.',questions:[
   {q:'Financial freedom means...',choices:['Your investments cover your living costs without you working','Owning expensive things','Never spending money again','Earning a very high salary'],a:0},
   {q:'The 4% rule says you can retire on roughly...',choices:['25 times your yearly spending','5 times your yearly spending','100 times your monthly rent','Whatever is in your checking account'],a:0},
   {q:'If you spend $40,000 a year, your freedom number is about...',choices:['$1,000,000','$40,000','$400,000','$4,000,000'],a:0},
   {q:'The fastest way to LOWER your freedom number is to...',choices:['Spend less each year, so you need a smaller pot','Earn more and spend it all','Take bigger risks','Retire later'],a:0},
   {q:'An employer 401(k) match is best described as...',choices:['An instant, guaranteed return on your own money','A loan you repay later','A tax penalty','A type of stock'],a:0},
   {q:'Money you have not spent is really...',choices:['Future freedom, measured in time','Money wasted','Always better in cash','Only useful in retirement'],a:0}]}}

];
const STAGES=[];
LEVELS.forEach((L,li)=>{L.rooms.forEach((r,ri)=>STAGES.push(Object.assign({},r,{wi:L.world,level:li,room:ri,diff:L.diff,isBoss:false})));
 STAGES.push({type:'boss',wi:L.world,level:li,diff:L.diff,isBoss:true,ic:'🏰',title:L.boss.name,boss:L.boss})});
// --- Question overhaul -------------------------------------------------
// Two problems: every correct answer sat in slot A, and the wrong answers were
// jokes you could eliminate without knowing anything. Both fixed here.
// Distractors are now REAL confusions: a bond mistaken for a stock, an emergency
// fund mistaken for investable money, trading mistaken for compounding.
const HARDER={
 'SAVING':['Money you keep now to use later','Money you borrow and pay back with interest','The interest a bank pays you each year','Money already invested in the stock market'],
 'Which is a NEED?':['A place to live','A streaming subscription','A gym membership','An upgraded phone'],
 'Why is compound interest like a snowball?':['Growth builds on top of past growth','You earn the same fixed amount every year','It only works if you start with a lot','The bank adds a yearly bonus'],
 'Invested money grows mainly through...':['Compounding over long periods','Trading often to catch the swings','Picking the one best stock','Buying at the bottom and selling at the top'],
 'STOCK':['A small piece of ownership in a company','A loan you make to a company','A guaranteed yearly payout','A basket holding many companies'],
 'What is the main benefit of an ETF?':['Instant diversification across many companies','A guarantee you cannot lose money','Higher returns than any single stock','It charges no fees at all'],
 '"Volatile" means prices...':['Swing up and down a lot, and fast','Climb steadily over time','Are set by the government','Only move during a recession'],
 'A REIT lets you invest in...':['Real estate','Government bonds','Foreign currency','Gold and commodities'],
 'Higher potential reward usually comes with...':['Higher risk','A longer lock-up, but no extra risk','Government protection','Lower taxes'],
 'Which money is BEST to invest?':['Money you will not need for many years','The cash in your emergency fund','Money set aside for next months rent','Money you borrowed at a low rate'],
 'Which is NOT part of the recipe?':['Panic-selling whenever it drops','Saving regularly','Starting early','Spreading it around'],
 'Most wealthy investors got there by being...':['Patient and consistent for decades','Excellent at timing the market','Willing to make huge single bets','First into every new trend'],
};
// True/False was 3-for-3 "true" — you could just hammer True. Now it is mixed,
// and two of them hinge on a distinction that actually matters.
const TF_FIX=[
 {q:'Saving part of every dollar you earn is a smart habit.',a:true},
 {q:'A dollar today is worth LESS than a dollar ten years from now.',a:false},
 {q:'Owning a stock means you have lent money to that company.',a:false},
];
(function(){
 // 1. upgrade the wrong answers
 STAGES.forEach(s=>{const key=s.q||s.term;
  if(key&&HARDER[key]&&s.choices){s.choices=HARDER[key].slice();s.a=0}});
 // 2. rewrite true/false so it is not all "true"
 let ti=0;STAGES.forEach(s=>{if(s.type==='tf'&&ti<TF_FIX.length){s.q=TF_FIX[ti].q;s.a=TF_FIX[ti].a;ti++}});
 // 3. place the correct answer on an even, non-repeating cycle across EVERY
 //    question in the game, so no slot is ever the safe guess.
 const SLOT=[2,0,3,1,3,2,0,1,1,3,0,2];let k=0;
 function place(ch,a){const n=ch.length,t=SLOT[k++%SLOT.length]%n;
  const arr=ch.slice(),correct=arr.splice(a,1)[0];arr.splice(t,0,correct);return{choices:arr,a:t}}
 STAGES.forEach(s=>{
  if(s.choices&&typeof s.a==='number'){const r=place(s.choices,s.a);s.choices=r.choices;s.a=r.a}
  if(s.options&&s.options.length){const ok=s.options.findIndex(o=>o.ok);
   if(ok>=0){const r=place(s.options,ok);s.options=r.choices}}
  if(s.type==='tf')s.tfFlip=(k++%2===0);
  if(s.boss&&s.boss.questions)s.boss.questions.forEach(q=>{
   if(q.choices&&typeof q.a==='number'){const r=place(q.choices,q.a);q.choices=r.choices;q.a=r.a}})});
})();
const TIERS=[{n:'Retail',ic:'🐣',c:'#93a1b5'},{n:'Educated',ic:'📚',c:'#3fb950'},{n:'Accredited',ic:'🎓',c:'#3d8bff'},{n:'Sophisticated',ic:'💼',c:'#a371f7'},{n:'Institutional',ic:'🏛️',c:'#f0b429'}];
const TIER_NEXT=['Finish the lesson or make 3 calls','Finish the lesson + 6 calls','15 calls at 55%+ accuracy','30 calls at 65%+ accuracy','Top rank — mastery 🏆'];
const BADGES=[
 {id:'first',ic:'🐷',n:'Saver',test:g=>Object.keys(g.done).length>=1},
 {id:'words5',ic:'📖',n:'Wordsmith',test:g=>Object.keys(g.glossary||{}).length>=5},
 {id:'boss1',ic:'🧟',n:'Spender Slayer',test:g=>bossDone(0)},
 {id:'boss3',ic:'🐻',n:'Bear Tamer',test:g=>bossDone(2)},
 {id:'call',ic:'🎯',n:'First Call',test:g=>g.predictions.length>=1},
 {id:'streak5',ic:'🔥',n:'On Fire',test:g=>g.bestStreak>=5},
 {id:'dragon',ic:'🐉',n:'Dragon Slayer',test:g=>bossDone(4)},
 {id:'grad',ic:'🎓',n:'Money Master',test:g=>Object.keys(g.done).length>=STAGES.length},
 {id:'will3',ic:'💪',n:'Iron Will',test:g=>(g.willpower||0)>=3},
 {id:'will6',ic:'🧘',n:'Unshakeable',test:g=>(g.willpower||0)>=6},
 {id:'vault3',ic:'🗝',n:'Secret Keeper',test:g=>Object.keys(g.secrets||{}).length>=3},
 {id:'coins10',ic:'🪙',n:'Coin Collector',test:g=>(g.coinCount||0)>=10},
 {id:'bike',ic:'🚲',n:'Bike Money',test:g=>(g.wealth||0)>=2500},
 {id:'car',ic:'🚗',n:'Car Money',test:g=>(g.wealth||0)>=18000},
 {id:'home',ic:'🏡',n:'Down Payment',test:g=>(g.wealth||0)>=60000},
 {id:'mill',ic:'🏰',n:'Millionaire',test:g=>(g.wealth||0)>=1000000},
 {id:'dev',ic:'💻',n:'The Developer',test:g=>bossDone(5)},
 {id:'free',ic:'🗽',n:'Financially Free',test:g=>bossDone(5)&&Object.keys(g.glossary||{}).length>=14},
];
let CAT=null;
const $=id=>document.getElementById(id);
const money=n=>n==null?'—':'$'+Number(n).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2});
async function j(u,o){const r=await fetch(u,o);if(!r.ok)throw new Error(await r.text());return r.json()}
function load(){try{return JSON.parse(localStorage.getItem(KEY))||null}catch(e){return null}}
function fresh(){return{xp:0,streak:0,bestStreak:0,done:{},predictions:[],glossary:{},hz:72,coins:{}}}
let G=load()||fresh();if(!G.mines)G.mines={};if(!G.opps)G.opps={};if(!G.owned)G.owned={};if(!G.met)G.met={};
if(!G.furn)G.furn={};if(!G.home)G.home='parents';if(G.equity==null)G.equity=0;if(G.month==null)G.month=0;
if(G.tmin==null)G.tmin=0;if(G.lastMonth==null)G.lastMonth=0;if(G.lastYear==null)G.lastYear=1;
if(G.skill==null)G.skill=0;if(G.projects==null)G.projects=0;if(G.wasted==null)G.wasted=0;if(G.buildPts==null)G.buildPts=0;if(G.tut==null)G.tut=0;if(!G.acts)G.acts={};if(G.smashed==null)G.smashed=0;if(G.narrate==null)G.narrate=0;if(!G.glossary)G.glossary={};if(G.wealth==null)G.wealth=0;
let _pushT=null,_actedBeforeLoad=false;
function save(){G.rev=(G.rev||0)+1;_actedBeforeLoad=true;localStorage.setItem(KEY,JSON.stringify(G));
 clearTimeout(_pushT);_pushT=setTimeout(pushProfile,1200)}
function pushProfile(){fetch('/api/game/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(G)})
 .then(r=>r.json()).then(r=>{const el=$('hsave');if(!el)return;
  el.textContent=(r&&r.ok)?'☁ Saved':'☁ …';el.style.opacity='1';
  clearTimeout(el._t);el._t=setTimeout(()=>{el.style.opacity='.3'},1600)}).catch(()=>{})}
function normalizeG(){const f=fresh();for(const k in f)if(G[k]==null)G[k]=f[k];
 ['glossary','coins','secrets','tempts','qclaim','found','mines','opps','owned','met'].forEach(k=>{if(!G[k]||typeof G[k]!=='object')G[k]={}});
 if(!Array.isArray(G.tools))G.tools=['fist'];if(!Array.isArray(G.predictions))G.predictions=[];
 if(G.wealth==null)G.wealth=0;if(G.willpower==null)G.willpower=0}
const unlocked=i=>i===0||!!G.done[i-1];
const POSSESSIONS=[{min:0,e:'🙂',n:'Just starting out'},{min:300,e:'🎒',n:'JanSport backpack'},{min:900,e:'🎧',n:'AirPods Pro'},{min:2500,e:'🚲',n:'Trek mountain bike'},{min:7000,e:'💻',n:'MacBook Air'},{min:18000,e:'🚗',n:'Used Honda Civic'},{min:60000,e:'🏡',n:'Down payment on a first home'},{min:250000,e:'🏖',n:'Rental property'},{min:1000000,e:'🏰',n:'Paid-off home — Millionaire!'}];
const IDEAS=['💡 Lemonade stand: buy lemons cheap, sell cups for more — that gap is profit.','💡 Mow lawns or walk dogs: trade a little time for money, then invest it.','💡 Sell old toys and games instead of tossing them.','💡 Learn a skill (art, code, baking) and get paid for it.','💡 Start small, reinvest your earnings, and let compounding grow them.','💡 A business solves a problem people will pay to fix. What bugs you?'];
function topPoss(){let p=POSSESSIONS[0];for(const q of POSSESSIONS)if(G.wealth>=q.min)p=q;return p}
function nextPoss(){for(const q of POSSESSIONS)if(G.wealth<q.min)return q;return null}
function addWealth(n){const b=topPoss();G.wealth=(G.wealth||0)+n;const a=topPoss();if(a.min>b.min){confetti();toast('🎉 New reward: '+a.e+' '+a.n+'!')}save();renderHUD()}
function bossIndex(li){let n=-1;STAGES.forEach((s,i)=>{if(s.isBoss&&s.level===li)n=i});return n}
function bossDone(li){const i=bossIndex(li);return i>=0&&!!G.done[i]}
// A 7-year-old can play a game but cannot read "diversification".
// The browser can talk - free, offline, no library. So it reads to them.
function speak(t){
 if(!G.narrate||!t)return;
 try{
  const sy=window.speechSynthesis;if(!sy)return;
  sy.cancel();
  const clean=String(t).replace(/[^ -~]/g,' ').replace(/ +/g,' ').trim();
  if(!clean)return;
  const u=new SpeechSynthesisUtterance(clean);
  u.rate=0.98;u.pitch=1.06;u.volume=1;
  const vs=sy.getVoices();
  const v=vs.find(x=>/samantha|female/i.test(x.name))||vs.find(x=>x.lang&&x.lang.startsWith('en'));
  if(v)u.voice=v;
  sy.speak(u);
 }catch(e){}}
function stopSpeak(){try{window.speechSynthesis&&window.speechSynthesis.cancel()}catch(e){}}
function toggleNarrate(){
 G.narrate=G.narrate?0:1;save();
 const el=$('hnarr');if(el)el.textContent=G.narrate?'🔊 Read aloud: ON':'🔇 Read aloud: OFF';
 document.body.classList.toggle('bigtext',!!G.narrate);
 if(G.narrate)speak('Read aloud is on. I will read everything to you.');else stopSpeak();}
function readChallenge(){
 const b=$('cbody');if(!b)return;
 const title=(b.querySelector('.p-title')||{}).textContent||'';
 const teach=(b.querySelector('.p-teach')||{}).textContent||'';
 const q=(b.querySelector('.p-q')||{}).textContent||'';
 const opts=[...b.querySelectorAll('.opt')].map(o=>o.textContent.trim());
 speak([title,teach,q].filter(Boolean).join('. ')+'. '+opts.join('. '));}
function toast(m){const t=$('toast');t.textContent=m;t.classList.add('show');clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('show'),2600)}
function confetti(){const c=['#3fb950','#3d8bff','#a371f7','#f0b429','#f85149'];for(let k=0;k<44;k++){const p=document.createElement('div');p.className='conf';p.style.left=(Math.random()*100)+'vw';p.style.background=c[k%c.length];p.style.animationDelay=(Math.random()*.35)+'s';document.body.appendChild(p);setTimeout(()=>p.remove(),2300)}}

/* ===== Roblox-style 3D world (Three.js) — one world at a time, hidden blocks, tools, secrets ===== */
const cv=$('game');
let scene,camera,renderer,hero,heroLegs=[],heroArms=[],possSprite=null,worldGroup=null,beacon=null;
let heading=0,pos={x:0,z:0},walkPhase=0,camMode=0,curLevel=0,pendingWorld=null;
let paused=false,nearGate=-1,shownWorld=-1;
let blocks=[],curSecrets=[],coins=[],tempts=[],walls=[],npcs=[],dayT=0,nearNPC=null,curTempt=null,curWi=0;
let BND={x0:-42,x1:42,z0:-42,z1:42},roomCells=[],gateSpots=[],mines=[],opps=[],ambLight=null,sunLight=null,lampLight=null;
let atHome=false,homeDoor=null,bigGround=null,homeBed=null,_lastT=0,homeSmash=null,_pigCool=0;
let heroY=0,heroVY=0,onGround=true;
const DOORS=STAGES.map((s,i)=>({i,s}));
if(!G.tools)G.tools=['fist'];if(!G.secrets)G.secrets={};if(!G.found)G.found={};if(!G.tempts)G.tempts={};if(G.willpower==null)G.willpower=0;if(G.coinCount==null)G.coinCount=0;if(!G.qclaim)G.qclaim={};
const SKY=[0x8ecbff,0xe8b06a,0xaec8e8,0x66c7d6,0xdfeaf6,0x2a3a5e];
const WCOL=[0x3f9a54,0x8a7a3a,0x5a6272,0x2a9a92,0x8a8a92,0x2b3a5c];
const WACC=[0x2f7d3a,0x6a5a2e,0x455170,0x1f6a70,0x6a6a72,0x1b2740];
const BSTATE={done:0xf0b429,open:0x3d8bff,boss:0xf05a4a,lock:0x59647c};
const CAMNAMES=['Overhead','3rd Person','1st Person','Cinematic'];
const TOOLS=[{id:'fist',e:'👊',n:'Bare Hands',dmg:1},{id:'pick',e:'⛏️',n:'Pickaxe',dmg:2},{id:'hammer',e:'🔨',n:'Sledgehammer',dmg:3},{id:'drill',e:'🛠️',n:'Power Drill',dmg:5},{id:'tnt',e:'🧨',n:'Dynamite',dmg:9}];
const SECRETS=[
 {id:'invgov',world:0,e:'🧮',name:'The Free Compounding Calculator',insight:'The U.S. government hosts a FREE compound-interest calculator. Watch a little money snowball into a fortune.',url:'https://www.investor.gov/financial-tools-calculators/calculators/compound-interest-calculator'},
 {id:'babylon',world:0,e:'📜',name:'The Richest Man in Babylon',insight:'A 100-year-old classic with one golden rule: pay yourself first — save at least 10% of everything you earn.',url:'https://en.wikipedia.org/wiki/The_Richest_Man_in_Babylon'},
 {id:'rule72',world:1,e:'🔢',name:'The Rule of 72',insight:'Divide 72 by your return rate to see how many years money takes to DOUBLE. 72 / 8% = 9 years.',url:'https://www.investopedia.com/terms/r/ruleof72.asp'},
 {id:'khan',world:1,e:'🎓',name:'Khan Academy: Money',insight:'A free, world-class personal-finance course the wealthy quietly use to teach their own kids.',url:'https://www.khanacademy.org/college-careers-more/personal-finance'},
 {id:'bogle',world:2,e:'🐷',name:'The Bogleheads',insight:'A free community of everyday millionaires who share exactly how they invest in low-cost index funds.',url:'https://www.bogleheads.org/wiki/Getting_started'},
 {id:'buffett',world:2,e:'💌',name:'Warren Buffett Letters',insight:'Decades of the greatest investor writing plainly about money — all free to read.',url:'https://www.berkshirehathaway.com/letters/letters.html'},
 {id:'fred',world:3,e:'📈',name:'FRED Economic Data',insight:'The exact free data the pros watch — inflation, interest rates, and more.',url:'https://fred.stlouisfed.org'},
 {id:'investopedia',world:3,e:'📚',name:'Investopedia Dictionary',insight:'Look up ANY money word ever invented, explained simply — free.',url:'https://www.investopedia.com/financial-term-dictionary-4769738'},
 {id:'psych',world:4,e:'🧠',name:'The Psychology of Money',insight:'The rich know wealth is more about behavior than math. This explains why patience beats brains.',url:'https://en.wikipedia.org/wiki/The_Psychology_of_Money'},
 {id:'match',world:5,e:'🎁',name:'The Employer Match',insight:'If your job matches 401(k) contributions, that is an instant 50-100% return on your own money — the highest guaranteed return in all of finance. Most people leave it on the table.',url:'https://www.investor.gov/introduction-investing/investing-basics/employer-sponsored-plans'},
 {id:'roth',world:5,e:'🌱',name:'Roth IRA & HSA',insight:'A Roth IRA grows TAX-FREE forever. An HSA is the only account with a triple tax break — deductible going in, growing tax-free, tax-free coming out for medical costs. These are the legal loopholes hiding in plain sight.',url:'https://www.investor.gov/introduction-investing/investing-basics/glossary/roth-iras'},
 {id:'capgains',world:5,e:'⚖️',name:'Why the Rich Own Things',insight:'Wages are taxed at up to 37%. Long-term capital gains are taxed at 0-20%. That gap is the single biggest structural reason wealthy people OWN assets instead of only earning a paycheck.',url:'https://www.irs.gov/taxtopics/tc409'},
 {id:'fees',world:5,e:'🪙',name:'The Fee Trap',insight:'A 1% yearly fee sounds tiny. Over 40 years it can quietly eat roughly a quarter of your final balance. Low-cost index funds exist precisely because of this maths.',url:'https://www.investor.gov/financial-tools-calculators/calculators/mutual-fund-analyzer'},
 {id:'sec',world:4,e:'🏛️',name:'investor.gov (SEC)',insight:'The official free government site to check any investment and dodge scams before you put in a dime.',url:'https://www.investor.gov'},
];
const NPCS=[
 {world:0,name:'Grandma Penny',e:'👵',lines:['Save a little from every dollar, sweetie — future you will thank you.','A penny saved is a penny earned. Start young!','Needs first, wants later — that is the whole secret.'],quest:{t:'Resist a temptation to build your willpower.',chk:()=>(G.willpower||0)>=1,reward:300}},
 {world:1,name:'Professor Owl',e:'🦉',lines:['Compound interest is the eighth wonder of the world. Time is your friend.','Money left alone grows on its own growth — like a snowball!','The best day to start was yesterday. The next best is today.'],quest:{t:'Collect 5 shiny coins scattered around this world.',chk:()=>(G.coinCount||0)>=5,reward:600}},
 {world:5,name:'Ada the Builder',e:'👩‍💻',lines:['Your skills are an asset. Unlike a stock, nobody can take them from you.','I stopped selling hours and started selling what I built. That changed everything.','Learn something valuable, use leverage, then let the money you make go buy assets.'],quest:{t:'Reach a Net Worth of $25,000 — enough to prove the engine works.',chk:()=>(G.wealth||0)>=25000,reward:6000}},
 {world:2,name:'Broker Bea',e:'💼',lines:['A stock is a slice of a real business. Own great ones and be patient.','Do not put all your eggs in one basket — diversify.','Time IN the market beats timing the market.'],quest:{t:'Uncover a hidden Secret of the Rich in this world.',chk:()=>SECRETS.some(s=>s.world===2&&G.secrets[s.id]),reward:900}},
 {world:3,name:'Captain Cash',e:'⚓',lines:['Spread your treasure across many seas — stocks, bonds, gold.','Higher reward means higher risk. Size your bets wisely.','Calm sailors survive the storm — never panic-sell.'],quest:{t:'Defeat the boss of this world.',chk:()=>bossDone(3),reward:1500}},
 {world:4,name:'The Oracle',e:'🧙',lines:['Wealth is more about patience than genius.','Save, invest early, diversify, and wait. That is the game.','The rich buy assets. The poor buy liabilities. Choose assets.'],quest:{t:'Reach a Net Worth of $8,000.',chk:()=>(G.wealth||0)>=8000,reward:3000}},
];
const EXTRA_NPCS=[
 {e:'🧒',name:'Timmy',lines:['I saved my allowance for a whole month and bought it myself!','My mom says a want can wait, but a need cannot.']},
 {e:'👷',name:'Builder Bob',lines:['Wealth is built brick by brick — one good habit at a time.','Slow and steady finishes the house.']},
 {e:'🧓',name:'Old Sam',lines:['I wish I had started investing at your age. Time is the secret.','Compound interest turned my small savings into a nest egg.']},
 {e:'🧑‍🚒',name:'Firefighter Fay',lines:['An emergency fund is your safety net — build it first.','Never invest money you might need in a hurry.']},
 {e:'🧑‍🎓',name:'Student Sky',lines:['Owning stocks means owning real companies — how cool is that?','Do not bet it all on one thing. Diversify!']},
 {e:'👩‍🍳',name:'Chef Maria',lines:['A budget is like a recipe — measure before you spend.','Cooking at home saved me enough to start investing.']},
];
const TEMPTS=[
 {world:0,e:'🧃',name:'a Stanley tumbler',price:45,lesson:'A $45 cup holds water. $45 invested at 8% is about $470 in 30 years.'},
 {world:0,e:'🃏',name:'a Pokemon booster box',price:180,lesson:'Cards MIGHT go up. Index funds have gone up ~10%/yr for a century.'},
 {world:1,e:'🎮',name:'a PlayStation 5 Pro',price:700,lesson:'You will still own it in 5 years — worth about $200. Invested, that $700 becomes ~$1,030.'},
 {world:1,e:'🍔',name:'a month of DoorDash',price:220,lesson:'$220/mo delivered = $2,640/yr. That one habit is a vacation, or a Roth IRA contribution.'},
 {world:2,e:'👟',name:'Air Jordan 1 Retro (limited)',price:400,lesson:'Resale MIGHT beat retail. Owning Nike stock pays you whether or not the shoes sell out.'},
 {world:2,e:'🎧',name:'AirPods Max',price:550,lesson:'Great sound. Also 2 shares of an S&P 500 fund that pay you forever.'},
 {world:3,e:'🎲',name:'a night of sports betting',price:400,lesson:'Sportsbooks keep a ~5-10% edge on every bet. The market has paid investors ~10%/yr.'},
 {world:3,e:'🎫',name:'floor seats to a playoff game',price:900,lesson:'A great night. Just know it costs a full year of maxing an HSA.'},
 {world:4,e:'📱',name:'an iPhone 17 Pro Max',price:1400,lesson:'Trade-in value in 3 years: ~$400. Invested instead: ~$1,760.'},
 {world:4,e:'⌚',name:'an Apple Watch Ultra',price:800,lesson:'It tracks your time. Investing buys you time — years of it, later.'},
];
function updateWP(){const el=$('hwpn');if(el)el.textContent=G.willpower||0}
function levelStages(li){const a=[];STAGES.forEach((s,i)=>{if(s.level===li)a.push(i)});return a}
function firstOpen(){let i=0;while(i<STAGES.length&&G.done[i])i++;return Math.min(i,STAGES.length-1)}
function doorState(d){return G.done[d.i]?'done':unlocked(d.i)?'open':'lock'}
function bestTool(){let b=TOOLS[0];for(const t of TOOLS)if(G.tools.includes(t.id)&&t.dmg>b.dmg)b=t;return b}
function toolDmg(){return bestTool().dmg}
function updateTool(){const t=bestTool();$('htool').textContent=t.e+' '+t.n}
function grantToolFor(s){if(!s.isBoss)return;const nt=TOOLS[s.level+1];if(nt&&!G.tools.includes(nt.id)){G.tools.push(nt.id);save();updateTool();setTimeout(()=>{sfx('tool');toast('🎁 TOOL UNLOCKED: '+nt.e+' '+nt.n+' — blocks break faster now!')},950)}}
function updateVaultCount(){$('hvn').textContent=Object.keys(G.secrets).length+SHOP.filter(i=>i.url&&owns(i.id)).length}
let actx;function sfx(type){try{if(!actx)actx=new(window.AudioContext||window.webkitAudioContext)();const o=actx.createOscillator(),g=actx.createGain();o.connect(g);g.connect(actx.destination);const now=actx.currentTime;
 let f=440,d=0.12,ty='square';if(type==='hit'){f=170;d=0.07}else if(type==='break'){f=500;d=0.16;ty='triangle'}else if(type==='secret'){f=880;d=0.42;ty='sine'}else if(type==='tool'){f=620;d=0.3;ty='sawtooth'}else if(type==='win'){f=700;d=0.55;ty='triangle'}
 o.type=ty;o.frequency.setValueAtTime(f,now);if(type==='secret'||type==='win'||type==='break')o.frequency.exponentialRampToValueAtTime(f*2,now+d);
 g.gain.setValueAtTime(0.16,now);g.gain.exponentialRampToValueAtTime(0.001,now+d);o.start(now);o.stop(now+d)}catch(e){}}
function startGame(){$('help').classList.remove('show');paused=false;document.body.classList.toggle('bigtext',!!G.narrate);if($('hnarr'))$('hnarr').textContent=G.narrate?'🔊 Read aloud: ON':'🔇 Read aloud: OFF';if(typeof renderQuest==='function')renderQuest();try{if(!actx)actx=new(window.AudioContext||window.webkitAudioContext)()}catch(e){}}
function showHelp(){paused=true;$('help').classList.add('show')}

function box(w,h,dp,col){return new THREE.Mesh(new THREE.BoxGeometry(w,h,dp),new THREE.MeshLambertMaterial({color:col}))}
function makeLabel(txt,emoji){const c=document.createElement('canvas');c.width=256;c.height=140;const g=c.getContext('2d');g.textAlign='center';
 if(emoji){g.font='78px serif';g.fillText(emoji,128,66)}
 if(txt){g.font='bold 30px system-ui';g.lineWidth=5;g.strokeStyle='#000';g.strokeText(txt,128,120);g.fillStyle='#fff';g.fillText(txt,128,120)}
 const tex=new THREE.CanvasTexture(c);const s=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,depthTest:false,transparent:true}));s.scale.set(3.4,1.9,1);return s}
function addTree(x,z,leaf,par){const t=new THREE.Group();const tr=box(0.5,1.5,0.5,0x6b4a2a);tr.position.y=0.75;t.add(tr);const lf=box(2,2,2,leaf);lf.position.y=2.4;t.add(lf);t.position.set(x,0,z);par.add(t)}
function cone(r,h,col){return new THREE.Mesh(new THREE.ConeGeometry(r,h,6),new THREE.MeshLambertMaterial({color:col}))}
function spawnBiome(wi,par){function put(fn,n){let c=0,g=0;while(c<n&&g<n*5){g++;const x=(Math.random()-0.5)*78,z=(Math.random()-0.5)*78;if(Math.hypot(x,z)<12)continue;fn(x,z);c++}}
 if(wi===0){put((x,z)=>addTree(x,z,0x2f7d3a,par),18);put((x,z)=>{const f=box(0.4,0.5,0.4,[0xff7ab0,0xffd54a,0xff5a5a][Math.floor(Math.random()*3)]);f.position.set(x,0.3,z);par.add(f)},16)}
 else if(wi===1){put((x,z)=>{const r=box(1.4,0.7+Math.random()*1.2,1.4,0x8a6a3a);r.position.y=r.geometry.parameters.height/2;r.position.x=x;r.position.z=z;par.add(r)},16);put((x,z)=>{const c=box(0.6,2.4,0.6,0x3f8a4a);c.position.set(x,1.3,z);par.add(c)},10)}
 else if(wi===2){put((x,z)=>{const h=5+Math.random()*10;const b=box(3,h,3,[0x5a6272,0x475066,0x6a7284][Math.floor(Math.random()*3)]);b.position.set(x,h/2,z);par.add(b);const w=box(3.05,h,0.1,0xffe066);w.position.set(x,h/2,z+1.5);w.material.opacity=0.25;w.material.transparent=true;par.add(w)},18)}
 else if(wi===3){put((x,z)=>{const w=new THREE.Mesh(new THREE.PlaneGeometry(7,7),new THREE.MeshLambertMaterial({color:0x2a8ad0}));w.rotation.x=-Math.PI/2;w.position.set(x,0.04,z);par.add(w)},9);put((x,z)=>{const t=box(0.4,2,0.4,0x6b4a2a);t.position.set(x,1,z);par.add(t);const l=box(1.8,0.5,1.8,0x2f8a4a);l.position.set(x,2.2,z);par.add(l)},12)}
 else{put((x,z)=>{const m=box(2+Math.random()*3,1.6,2+Math.random()*3,0xf0f4ff);m.position.set(x,0.8,z);par.add(m)},16);put((x,z)=>{const c=cone(1,2.6,0x2a5a3a);c.position.set(x,1.3,z);par.add(c);const snow=cone(0.6,0.8,0xffffff);snow.position.set(x,2.4,z);par.add(snow)},10)}
}
function disposeGroup(g){g.traverse(o=>{if(o.geometry)o.geometry.dispose();if(o.material){if(o.material.map)o.material.map.dispose();o.material.dispose()}})}

function buildBlock(d){const g=new THREE.Group();const boss=d.s.isBoss;const st=doorState(d);
 d.maxhp=boss?(5+d.s.level*2):(1+d.s.level);d.hp=d.maxhp;
 const sz=boss?(3.4+d.s.level*0.5):(2+d.s.level*0.35);d.sz=sz;const col=st==='done'?BSTATE.done:st==='lock'?BSTATE.lock:boss?BSTATE.boss:BSTATE.open;
 const cube=box(sz,sz,sz,col);cube.position.y=sz/2+0.5;g.add(cube);d.cube=cube;d.base=cube.position.y;
 const q=makeLabel('',st==='done'?'⭐':st==='lock'?'🔒':boss?'👑':'❓');q.scale.set(sz*0.9,sz*0.9,1);q.position.y=cube.position.y;q.material.depthTest=true;g.add(q);d.qface=q;
 const lab=makeLabel(boss?('LEVEL '+(d.s.level+1)+' BOSS'):('Level '+(d.s.level+1)),boss?d.s.boss.enemy:d.s.ic);
 lab.position.y=cube.position.y+sz*0.7+0.8;g.add(lab);d.label=lab;
 g.position.set(d.px,0,d.pz);g.userData.d=d;g.visible=!!(G.done[d.i]||G.found[d.i]||(unlocked(d.i)&&!G.done[d.i]));d._st=st;return g}
function refreshGates(){for(const w of walls){if(w.gateFor==null||w.broken)continue;
 if(G.done[w.gateFor]){w.broken=true;if(w.mesh)worldGroup.remove(w.mesh);if(w.cap)worldGroup.remove(w.cap);
  burst(w.x,3,w.z,0xf0b429);sfx('break');toast('🚪 The door swings open — the way ahead is clear!')}}}
function refreshBlocks(){for(const b of blocks){const d=b.userData.d,st=doorState(d);if(d._st===st)continue;d._st=st;const boss=d.s.isBoss;
 d.cube.material.color.setHex(st==='done'?BSTATE.done:st==='lock'?BSTATE.lock:boss?BSTATE.boss:BSTATE.open);
 const face=st==='done'?'⭐':st==='lock'?'🔒':boss?'👑':'❓';const nq=makeLabel('',face);nq.scale.copy(d.qface.scale);nq.position.copy(d.qface.position);nq.material.depthTest=true;b.remove(d.qface);d.qface.material.map.dispose();d.qface.material.dispose();b.add(nq);d.qface=nq}}

function buildHero(){const g=new THREE.Group();
 const torso=box(1.1,1.3,0.6,0x3d8bff);torso.position.y=1.75;g.add(torso);
 const head=box(0.82,0.82,0.82,0xf1c9a5);head.position.y=2.85;g.add(head);
 const eL=box(0.13,0.13,0.06,0x22303a);eL.position.set(-0.18,2.9,0.42);g.add(eL);const eR=eL.clone();eR.position.x=0.18;g.add(eR);
 const cap=box(0.94,0.32,0.94,0x2f7d3a);cap.position.y=3.28;g.add(cap);
 const legL=box(0.42,1.15,0.5,0x2a3a5a);legL.position.set(-0.28,0.58,0);g.add(legL);heroLegs.push(legL);
 const legR=legL.clone();legR.position.x=0.28;g.add(legR);heroLegs.push(legR);
 const armL=box(0.32,1.15,0.45,0x2f6fd0);armL.position.set(-0.73,1.75,0);g.add(armL);heroArms.push(armL);
 const armR=armL.clone();armR.position.x=0.73;g.add(armR);heroArms.push(armR);
 possSprite=makeLabel('','');possSprite.position.y=4.1;possSprite.scale.set(1.4,1.4,1);g.add(possSprite);return g}
function updatePoss(){const tp=topPoss();const face=tp.min>0?tp.e:'';if(possSprite._f===face)return;possSprite._f=face;
 const c=document.createElement('canvas');c.width=128;c.height=128;const g=c.getContext('2d');if(face){g.font='90px serif';g.textAlign='center';g.fillText(face,64,86)}
 if(possSprite.material.map)possSprite.material.map.dispose();possSprite.material.map=new THREE.CanvasTexture(c);possSprite.material.needsUpdate=true}

const parts=[];
function burst(x,y,z,col){for(let k=0;k<14;k++){const m=box(0.3,0.3,0.3,col);m.position.set(x,y,z);scene.add(m);parts.push({m,vx:(Math.random()-0.5)*0.4,vy:Math.random()*0.4+0.1,vz:(Math.random()-0.5)*0.4,life:1})}}
function spawnSecret(s,par){const o=new THREE.Mesh(new THREE.SphereGeometry(0.55,14,14),new THREE.MeshBasicMaterial({color:0xffd54a}));o.position.set(s.x,1.4,s.z);par.add(o);s.orb=o;const sp=makeLabel('','✨');sp.position.set(s.x,2.5,s.z);sp.scale.set(1.2,1.2,1);par.add(sp);s.spr=sp}

const keys={};function sk(k,v){keys[k]=v}
addEventListener('keydown',e=>{const k=e.key.toLowerCase();if(['arrowup','arrowdown','arrowleft','arrowright',' '].includes(k))e.preventDefault();
 if(k==='arrowup'||k==='w')sk('F',1);if(k==='arrowdown'||k==='s')sk('B',1);if(k==='arrowleft'||k==='a')sk('TL',1);if(k==='arrowright'||k==='d')sk('TR',1);
 if(k===' ')sk('JUMP',1);if(k==='c')setView(camMode+1);if(e.key==='Enter')interact()});
addEventListener('keyup',e=>{const k=e.key.toLowerCase();if(k==='arrowup'||k==='w')sk('F',0);if(k==='arrowdown'||k==='s')sk('B',0);if(k==='arrowleft'||k==='a')sk('TL',0);if(k==='arrowright'||k==='d')sk('TR',0);if(k===' ')sk('JUMP',0)});
function bindHold(el,key){el.addEventListener('touchstart',e=>{e.preventDefault();sk(key,1)},{passive:false});el.addEventListener('touchend',e=>{e.preventDefault();sk(key,0)},{passive:false});el.addEventListener('mousedown',()=>sk(key,1));el.addEventListener('mouseup',()=>sk(key,0));el.addEventListener('mouseleave',()=>sk(key,0))}
bindHold($('bU'),'F');bindHold($('bD'),'B');bindHold($('bL'),'TL');bindHold($('bR'),'TR');bindHold($('bJ2'),'JUMP');
$('bE').addEventListener('click',interact);$('bE').addEventListener('touchstart',e=>{e.preventDefault();interact()},{passive:false});
$('htrophy').addEventListener('click',openTrophies);$('hgloss').addEventListener('click',openGlossary);$('hwealth').addEventListener('click',openWealth);
$('hview').addEventListener('click',()=>setView(camMode+1));$('hvault').addEventListener('click',openVault);$('hshop').addEventListener('click',openShop);
$('hhome').addEventListener('click',()=>{if(atHome)goOutside();else goHome()});
$('hact').addEventListener('click',openActions);
$('hmkt').addEventListener('click',openMarket);
$('hprof').addEventListener('click',openProfile);$('hhelp').addEventListener('click',showHelp);
$('hnarr').addEventListener('click',toggleNarrate);
// collapse the menu: it had grown to 13 pills and was wrapping over the game
$('hmenu').addEventListener('click',e=>{e.stopPropagation();$('menu').classList.toggle('show')});
document.querySelectorAll('#menu .clk').forEach(el=>el.addEventListener('click',()=>$('menu').classList.remove('show')));
document.addEventListener('click',e=>{const m=$('menu');
 if(m.classList.contains('show')&&!m.contains(e.target)&&e.target!==$('hmenu'))m.classList.remove('show')});
addEventListener('keydown',e=>{if(e.key==='Escape')$('menu').classList.remove('show')});$('htool').addEventListener('click',()=>toast('Your tool: '+bestTool().e+' '+bestTool().n+' — beat bosses to unlock stronger ones!'));
function setView(m){camMode=((m%4)+4)%4;$('hview').textContent='👁 '+CAMNAMES[camMode]}

let hitCool=0;
function hitBlock(d){if(!d)return;if(d.hp<=0){if(!G.done[d.i])openChallenge(d.i);return}const dmg=toolDmg();d.hp-=dmg;
 burst(d.px,d.base,d.pz,d.s.isBoss?0xf05a4a:0x3d8bff);if(d.cube)d.cube.userData.shake=8;
 if(d.hp<=0){sfx('break');toast('💥 Block smashed open!');const i=d.i;setTimeout(()=>openChallenge(i),170)}
 else{sfx('hit');toast('⛏️ '+d.hp+' more hit'+(d.hp>1?'s':'')+' to crack it open! (a better tool helps)')}}
function addWall(par,x,z,w,d,top){const m=box(w,top,d,0x8a6a4a);m.position.set(x,top/2,z);par.add(m);
 const cap=box(w+0.1,0.25,d+0.1,0x6b4f36);cap.position.set(x,top,z);par.add(cap);
 walls.push({mesh:m,cap,x,z,hw:w/2,hd:d/2,top,hp:Math.round(top*3),maxhp:Math.round(top*3),broken:false})}
function spawnWalls(wi,par){walls=[];const gap=(Math.random()-0.5)*22;
 addWall(par,gap-20,-9,26,1.6,1.4);addWall(par,gap+20,-9,26,1.6,1.4);        // low barrier row (jump it, break it, or use the gap)
 let made=0,g=0;while(made<3&&g<24){g++;const x=(Math.random()-0.5)*50,z=(Math.random()*24)-3;if(Math.hypot(x,z+18)<10)continue;addWall(par,x,z,6,2.5,3.8);made++}}
// how high you can step up unaided; a rope ladder makes you a proper climber
function stepReach(){return owns('ladder')?3.2:1.45}
let _stepT=0;
function stepFX(w){if(_stepT>0)return;_stepT=10;sfx('hit');burst(pos.x,heroY,pos.z,0xd8c8a8)}
let _shoveT=0;
function pushFX(w){if(_shoveT>0){_shoveT--;return}_shoveT=26;sfx('hit');
 burst(w.x,0.4,w.z,0xc8a06a);toast('📦 You shoved it aside — some things move if you lean on them.')}
function blockedAt(nx,nz,y){for(const w of walls){if(w.broken)continue;if(y>=w.top-0.25)continue;if(Math.abs(nx-w.x)<w.hw+0.55&&Math.abs(nz-w.z)<w.hd+0.55)return w}return null}
function shakeWall(w){w._sh=10}
function armSwing(){_swing=12}
let _swing=0;
function ram(w){if(!w)return;armSwing();
 if(w.kind==='piggy'){hitPiggy();return}
 if(w.solid){shakeWall(w);sfx('hit');
  toast(w.kind==='mountain'?'⛰️ A mountain. You do not move this — you climb it. Walk up the tiers.'
   :w.immovable?'🪨 Immovable. Not everything gives way. Climb it or go around.'
   :'🪨 Solid — climb it (⤴ SPACE) or go around.');return}
 if(w.broken)return;
 if(w.gateFor!=null){toast('🚪 This door is locked — clear the challenge in this room to open it!');return}
 shakeWall(w);burst(w.x,Math.min(w.top,2.2),w.z,0xb08a5a);
 w._c=(w._c||0)-1;
 if(w._c<=0){w._c=4;w.hp-=toolDmg();
  if(w.hp<=0){breakWall(w)}
  else{sfx('hit');const pct=Math.max(0,Math.round(w.hp/w.maxhp*100));
   toast('🧱 CRACK! '+'█'.repeat(Math.ceil(pct/10))+'░'.repeat(10-Math.ceil(pct/10))+'  '+Math.max(0,w.hp)+' HP left — keep hitting ↵')}}
 else{sfx('hit');toast('🔨 You swing... '+Math.max(0,w.hp)+' HP left. Keep pressing ↵ — it IS working.')}}
function breakWall(w){w.broken=true;if(w.mesh)worldGroup.remove(w.mesh);if(w.cap)worldGroup.remove(w.cap);sfx('break');burst(w.x,w.top,w.z,0xb08a5a);toast('🧱 Wall smashed — the path opens up!')}
function interact(){if(paused)return;
 // TALKING WINS. rooms are walled now, so a wall is almost always within arm's
 // reach - checking walls first made every NPC impossible to speak to.
 // (you smash walls just by walking into them anyway.)
 if(atHome&&homeSmash&&!G.smashed&&Math.hypot(homeSmash.x-pos.x,homeSmash.z-pos.z)<3.2){_pigCool=0;hitPiggy();return}
 if(atHome&&homeBed&&Math.hypot(homeBed.x-pos.x,homeBed.z-pos.z)<2.6){sleepTilMorning();return}
 if(nearNPC){talkNPC();$('npc').classList.add('show');return}
 if(nearGate>=0){hitBlock(DOORS[nearGate]);return}
 let bw=null,bd=1e9;for(const w of walls){if(w.broken)continue;const dd=Math.hypot(w.x-pos.x,w.z-pos.z)-Math.max(w.hw,w.hd);if(dd<1.8&&dd<bd){bd=dd;bw=w}}
 if(bw){ram(bw);return}
 armSwing();sfx('hit');toast('🤜 You swing at the air — get closer to a wall, a block, or someone to talk to.')}

function scatterPos(used){for(let tries=0;tries<40;tries++){const x=(Math.random()-0.5)*38,z=(Math.random()-0.5)*30;if(Math.hypot(x,z+18)<8)continue;let ok=true;for(const u of used)if(Math.hypot(u.x-x,u.z-z)<7){ok=false;break}if(ok){used.push({x,z});return{x,z}}}const x=(Math.random()-0.5)*38,z=(Math.random()-0.5)*30;used.push({x,z});return{x,z}}
function cornerPos(used){const cs=[{x:-26,z:-22},{x:26,z:-22},{x:-26,z:22},{x:26,z:22},{x:0,z:26},{x:0,z:-26}];const c=cs[used.length%cs.length];used.push(c);return c}

function loadWorld(li){if(worldGroup){scene.remove(worldGroup);disposeGroup(worldGroup)}
 worldGroup=new THREE.Group();scene.add(worldGroup);curLevel=li;const wi=LEVELS[li].world;curWi=wi;
 const stages=levelStages(li),N=stages.length;
 const ROOM=36,HR=ROOM/2,WT=1.6,GAP=9;
 const cols=(N<=4?2:3),rows=Math.ceil(N/cols);
 const CX=c=>(c-(cols-1)/2)*ROOM, CZ=r=>r*ROOM;
 // serpentine path: row 0 left->right, row 1 right->left, ...
 roomCells=[];
 for(let i=0;i<N;i++){const r=Math.floor(i/cols);let c=i%cols;if(r%2===1)c=cols-1-c;
  roomCells.push({i,si:stages[i],c,r,x:CX(c),z:CZ(r),sub:SUBB[(li*3+i)%SUBB.length]})}
 const X0=CX(0)-HR,X1=CX(cols-1)+HR,Z0=-HR,Z1=CZ(rows-1)+HR;
 BND={x0:X0-26,x1:X1+26,z0:Z0-26,z1:Z1+26};
 walls=[];gateSpots=[];
 // one big open plain — no perimeter box, the horizon just fades into fog
 const gw=(X1-X0)+96,gd=(Z1-Z0)+96,mx=(X0+X1)/2,mz=(Z0+Z1)/2;
 const ground=new THREE.Mesh(new THREE.PlaneGeometry(gw,gd),new THREE.MeshLambertMaterial({color:WCOL[wi]}));
 ground.rotation.x=-Math.PI/2;ground.position.set(mx,0,mz);worldGroup.add(ground);
 // each room is its own biome: tinted floor + its own flora
 roomCells.forEach(rc=>{
  const f=new THREE.Mesh(new THREE.PlaneGeometry(ROOM-2,ROOM-2),new THREE.MeshLambertMaterial({color:rc.sub.g}));
  f.rotation.x=-Math.PI/2;f.position.set(rc.x,0.03,rc.z);worldGroup.add(f);
  for(let k=0;k<10;k++){const a=Math.random()*6.283,d=6.5+Math.random()*(HR-5);
   rc.sub.f(rc.x+Math.cos(a)*d,rc.z+Math.sin(a)*d,worldGroup)}});
 // EVERY room is a real room: 4 walls, each with a doorway.
 // the doorway onto the next room is the locked one; the other three stay open,
 // so you can always wander out a side door and go the long way round.
 const WCOLR=ROOMWALL[wi]||0xb08a5a, seg=(ROOM-GAP)/2;
 const edges=new Map();
 const EK=(k,c,r)=>k+':'+c+':'+r;
 roomCells.forEach(rc=>{
  edges.set(EK('v',rc.c-1,rc.r),{k:'v',c:rc.c-1,r:rc.r});   // west wall
  edges.set(EK('v',rc.c,rc.r),  {k:'v',c:rc.c,  r:rc.r});   // east wall
  edges.set(EK('h',rc.c,rc.r-1),{k:'h',c:rc.c,  r:rc.r-1}); // north wall
  edges.set(EK('h',rc.c,rc.r),  {k:'h',c:rc.c,  r:rc.r});   // south wall
 });
 // the doorway on the path between room i and room i+1 is the one that locks
 const gateOn=new Map();
 for(let i=0;i<N-1;i++){const A=roomCells[i],B=roomCells[i+1];
  const key=(A.r===B.r)?EK('v',Math.min(A.c,B.c),A.r):EK('h',A.c,Math.min(A.r,B.r));
  gateOn.set(key,A.si)}
 edges.forEach((e,key)=>{
  const gf=gateOn.has(key)?gateOn.get(key):null;
  if(e.k==='v'){const x=CX(e.c)+HR,zc=CZ(e.r);
   bigWall(x,zc-(GAP/2+seg/2),WT,seg,{solid:1,col:WCOLR});
   bigWall(x,zc+(GAP/2+seg/2),WT,seg,{solid:1,col:WCOLR});
   if(gf!=null){bigWall(x,zc,WT,GAP,{gateFor:gf});gateSpots.push({x:x,z:zc,dir:'v'})}
   else {doorFrame(x,zc,'v',WT,GAP);gateSpots.push({x:x,z:zc})}
  }else{const z=CZ(e.r)+HR,xc=CX(e.c);
   bigWall(xc-(GAP/2+seg/2),z,seg,WT,{solid:1,col:WCOLR});
   bigWall(xc+(GAP/2+seg/2),z,seg,WT,{solid:1,col:WCOLR});
   if(gf!=null){bigWall(xc,z,GAP,WT,{gateFor:gf});gateSpots.push({x:xc,z:z,dir:'h'})}
   else {doorFrame(xc,z,'h',WT,GAP);gateSpots.push({x:xc,z:z})}
  }});
 // a climb route beside the first locked door — over the wall is always an option
 // stairs beside the first locked door, offset so they never block the doorway
 {const g0=gateSpots.find(g=>g.dir);
  if(g0){if(g0.dir==='v')climbSteps(g0.x,g0.z+GAP+2,-1,0);else climbSteps(g0.x+GAP+2,g0.z,0,-1)}}
 // name every room after somewhere real
 const VN=VENUE[wi]||VENUE[0];
 roomCells.forEach((rc,ri)=>{const nm=VN.rooms[ri%VN.rooms.length];rc.name=nm;
  const sign=makeLabel(nm,'🚪');sign.position.set(rc.x,7.2,rc.z-HR+0.6);
  sign.scale.set(6,3.2,1);worldGroup.add(sign)})
 // obstacles: rubble to smash, barricades, boulders + ledges to climb
 const KINDS=['rubble','rubble','barricade','boulder','ledge','tower','crate','crate','barrel','bedrock'];
 roomCells.forEach((rc,idx)=>{const cnt=3+Math.min(4,li+(idx%3));
  for(let k=0;k<cnt;k++){const a=Math.random()*6.283,d=7.5+Math.random()*(HR-6);
   const x=rc.x+Math.cos(a)*d,z=rc.z+Math.sin(a)*d;
   if(nearGateSpot(x,z,9))continue;                      // never plug a doorway
   obstacle(KINDS[Math.floor(Math.random()*KINDS.length)],x,z,li)}});
 // an opportunity perched on top of a ledge in most rooms - climb, then jump
 opps=[];let oi=0;
 walls.filter(w=>w.kind==='ledge').forEach(l=>{const id='o'+li+'-'+(oi++);
  if(G.opps[id])return;
  const o={id,x:l.x,y:l.top+1.0,z:l.z,reward:250+li*150};spawnOpp(o,worldGroup);opps.push(o)});
 // signpost the climbing route so the mechanic is discoverable
 walls.filter(w=>w.kind==='step'&&w.top<3).forEach(st=>{
  const sp=makeLabel('CLIMB  ⤴ SPACE','🪜');sp.position.set(st.x,st.top+1.9,st.z);sp.scale.set(6,3,1);worldGroup.add(sp)});
 // scatter the minefield: hidden until you learn to spot them
 mines=[];let mi=0;
 roomCells.forEach((rc,ri)=>{if(ri===0)return;              // room 1 is a safe place to learn
  const cnt=1+Math.min(2,Math.floor(li/2)+(ri%2));
  for(let k=0;k<cnt;k++){const id='m'+li+'-'+(mi++);if(G.mines[id])continue;
   const a=Math.random()*6.283,d=6+Math.random()*(HR-6);
   const x=rc.x+Math.cos(a)*d,z=rc.z+Math.sin(a)*d;
   if(nearGateSpot(x,z,7))continue;                          // not in a doorway
   const base=MINES[(li*3+mi)%MINES.length];
   const m=Object.assign({},base,{id,x,z});spawnMine(m,worldGroup);mines.push(m)}});
 // mountains: one per level in the far corner, plus one mid-map you can summit
 {const mx1=X0+14,mz1=Z1-14;buildMountain(mx1,mz1,worldGroup,1.0);
  if(rows>1){const mx2=X1-14,mz2=Z0+14;buildMountain(mx2,mz2,worldGroup,0.8)}}
 // distant treeline so the edge of the world reads as landscape, not a wall
 for(let k=0;k<80;k++){const a=k/80*6.283;
  const rx=mx+Math.cos(a)*((X1-X0)/2+34)+(Math.random()-0.5)*10;
  const rz=mz+Math.sin(a)*((Z1-Z0)/2+34)+(Math.random()-0.5)*10;
  biomeItem(wi,rx,rz,worldGroup)}
 // one challenge block at the heart of each room
 blocks=[];roomCells.forEach(rc=>{const d=DOORS[rc.si];d.px=rc.x;d.pz=rc.z;
  const g=buildBlock(d);g.visible=true;worldGroup.add(g);blocks.push(g)});
 // coins
 coins=[];let ci=0;
 roomCells.forEach(rc=>{for(let k=0;k<3;k++){const id='c'+li+'-'+(ci++);if(G.coins[id])continue;
  const a=Math.random()*6.283,d=5+Math.random()*(HR-5);
  const x=rc.x+Math.cos(a)*d,z=rc.z+Math.sin(a)*d;
  const m=box(0.55,0.55,0.14,0xf0c419);m.position.set(x,0.9,z);worldGroup.add(m);coins.push({mesh:m,x,z,id})}});
 // hidden secrets, tucked in the far corners of later rooms
 curSecrets=SECRETS.filter(s=>s.world===wi);
 curSecrets.forEach((s,idx)=>{if(G.secrets[s.id])return;const rc=roomCells[Math.min(roomCells.length-1,1+idx)];
  s.x=rc.x+(idx%2?1:-1)*(HR-4);s.z=rc.z+(HR-5);spawnSecret(s,worldGroup)});
 // temptations
 tempts=[];TEMPTS.filter(tm=>tm.world===wi).forEach((tm,idx)=>{const id='t'+wi+'-'+idx;const o=Object.assign({},tm,{id});
  if(!G.tempts[id]){const rc=roomCells[Math.min(roomCells.length-1,idx+1)];
   o.x=rc.x+(idx%2?-1:1)*7;o.z=rc.z+6;
   const sp=makeLabel('',tm.e);sp.position.set(o.x,1.5,o.z);sp.scale.set(1.7,1.7,1);worldGroup.add(sp);o.spr=sp}
  tempts.push(o)});
 // mentor in the first room, travellers scattered through the rest
 npcs=[];const nd=NPCS.find(n=>n.world===wi);
 if(nd){const r0=roomCells[0],x=r0.x-7,z=r0.z-7;const g=buildNPC(nd,0x8a5cff);g.position.set(x,0,z);worldGroup.add(g);
  npcs.push(Object.assign({},nd,{x,z,mesh:g}))}
 // the menagerie — helpers and predators, mixed together on purpose
 roomCells.forEach((rc,ri)=>{const f=FAUNA[(li*5+ri*3)%FAUNA.length];
  const id='f'+li+'-'+ri;
  const nd={e:f.e,name:f.n,lines:f.lines,deal:f.deal,id:id,good:f.good,obvious:f.obvious};
  const g=buildNPC({e:f.e,name:f.n,quest:null,marker:faunaMarker(f)},f.col);
  const x=rc.x+(ri%2?-1:1)*(HR-7),z=rc.z+(ri%2?7:-7);
  g.position.set(x,0,z);worldGroup.add(g);
  npcs.push(Object.assign(nd,{x,z,mesh:g}))});
 for(let ri=1;ri<roomCells.length;ri++){if(Math.random()<0.75){const rc=roomCells[ri];
  const ex=EXTRA_NPCS[(li*3+ri)%EXTRA_NPCS.length];const g=buildNPC(ex,0x3fa35a);
  const x=rc.x+(ri%2?1:-1)*7,z=rc.z+(Math.random()-0.5)*10;
  g.position.set(x,0,z);worldGroup.add(g);npcs.push(Object.assign({},ex,{x,z,mesh:g}))}}
 const st=roomCells[0];pos={x:st.x,z:st.z-HR+4};heading=0;heroY=0;heroVY=0;onGround=true;
 hero.position.set(pos.x,0,pos.z);shownWorld=-1}
function goOutside(){atHome=false;if(bigGround)bigGround.visible=true;loadWorld(curLevel);toast('🚪 Out into the world you go.')}
function goHome(){loadHome();toast('🏠 Home. Everything you own is right here.')}
// A kid should be hitting something before they read a single word.
// This sits two paces in front of where you wake up.
function spawnPiggy(px,pz){
 if(G.smashed){homeSmash=null;return}
 const g=new THREE.Group();
 const body=box(1.7,1.4,1.2,0xff8fb0);body.position.y=0.95;g.add(body);
 const snout=box(0.55,0.42,0.32,0xff6f9c);snout.position.set(0,0.9,0.68);g.add(snout);
 [[-0.55,-0.38],[0.55,-0.38],[-0.55,0.38],[0.55,0.38]].forEach(p=>{
  const l=box(0.32,0.42,0.32,0xff6f9c);l.position.set(p[0],0.21,p[1]);g.add(l)});
 const slot=box(0.9,0.09,0.18,0xd8577f);slot.position.set(0,1.66,0);g.add(slot);
 const lbl=makeLabel('SMASH IT!','🐷');lbl.position.y=3.0;lbl.scale.set(7,3.4,1);g.add(lbl);
 g.position.set(px,0,pz);worldGroup.add(g);
 // a real collider - you bump into it instead of walking through it
 const col={mesh:null,cap:null,x:px,z:pz,hw:1.05,hd:0.85,top:1.7,hp:999,maxhp:999,
  broken:false,solid:true,immovable:true,gateFor:null,kind:'piggy',movable:false};
 walls.push(col);
 homeSmash={x:px,z:pz,g,hp:3,lbl,col};}
function hitPiggy(){
 if(!homeSmash||G.smashed)return;
 if(_pigCool>0){_pigCool--;return}
 _pigCool=7;homeSmash.hp--;
 sfx('hit');burst(homeSmash.x,1.2,homeSmash.z,0xff8fb0);
 if(homeSmash.g){homeSmash.g.scale.setScalar(0.7+0.3*(homeSmash.hp/3));homeSmash.g.rotation.z=0.25}
 if(homeSmash.hp<=0){
  G.smashed=1;save();
  if(homeSmash.g)worldGroup.remove(homeSmash.g);
  if(homeSmash.col)homeSmash.col.broken=true;
  for(let q=0;q<6;q++)burst(homeSmash.x+(Math.random()-0.5)*2.4,1,homeSmash.z+(Math.random()-0.5)*2.4,0xf0c419);
  confetti();sfx('secret');addWealth(50);
  homeSmash=null;
  toast('💰 $50! That is yours. Now go turn it into more.');
  checkQuest();
 } else toast('🐷 CRACK! Hit it again');}
function loadHome(){
 if(worldGroup){scene.remove(worldGroup);disposeGroup(worldGroup)}
 worldGroup=new THREE.Group();scene.add(worldGroup);atHome=true;
 const H=curHome(),W=H.w,D=H.d,WT=1.2,WALLH=6;
 blocks=[];coins=[];mines=[];opps=[];npcs=[];curSecrets=[];tempts=[];walls=[];gateSpots=[];roomCells=[];
 BND={x0:-W/2+1,x1:W/2-1,z0:-D/2+1,z1:D/2-1};
 if(bigGround)bigGround.visible=false;                 // stops z-fighting with the outdoor ground
 const floor=new THREE.Mesh(new THREE.PlaneGeometry(W,D),new THREE.MeshLambertMaterial({color:0x9a7a52}));
 floor.rotation.x=-Math.PI/2;floor.position.y=0.06;worldGroup.add(floor);
 // skirting board, so the join reads like a room and not a rug on a lawn
 [[0,-D/2,W,0.3],[0,D/2,W,0.3],[-W/2,0,0.3,D],[W/2,0,0.3,D]].forEach(b=>{
  const sk=box(b[2],0.45,b[3],0xbfae94);sk.position.set(b[0],0.22,b[1]);worldGroup.add(sk)});
 const ceil=new THREE.Mesh(new THREE.PlaneGeometry(W,D),new THREE.MeshLambertMaterial({color:0xe8e4dc}));
 ceil.rotation.x=Math.PI/2;ceil.position.y=WALLH;worldGroup.add(ceil);
 // four walls, with a doorway out on the south side
 const DOORW=4,seg=(W-DOORW)/2;
 bigWall(-W/2-WT/2,0,WT,D,{solid:1,h:WALLH,col:0xd8cdb8,cap:0xbfae94});
 bigWall(W/2+WT/2,0,WT,D,{solid:1,h:WALLH,col:0xd8cdb8,cap:0xbfae94});
 bigWall(0,-D/2-WT/2,W+WT*2,WT,{solid:1,h:WALLH,col:0xd8cdb8,cap:0xbfae94});
 bigWall(-(DOORW/2+seg/2),D/2+WT/2,seg,WT,{solid:1,h:WALLH,col:0xd8cdb8,cap:0xbfae94});
 bigWall(DOORW/2+seg/2,D/2+WT/2,seg,WT,{solid:1,h:WALLH,col:0xd8cdb8,cap:0xbfae94});
 doorFrame(0,D/2+WT/2,'h',WT,DOORW);
 homeDoor={x:0,z:D/2};
 const sign=makeLabel('GO OUTSIDE','🚪');sign.position.set(0,4.2,D/2-0.4);sign.scale.set(7,3.4,1);worldGroup.add(sign);
 const nm=makeLabel(H.n,H.e);nm.position.set(0,5.0,-D/2+0.6);nm.scale.set(8,3.6,1);worldGroup.add(nm);
 // window on the back wall so it reads like a room
 const win=new THREE.Mesh(new THREE.PlaneGeometry(4,2.4),new THREE.MeshBasicMaterial({color:0x8ecbff}));
 win.position.set(-W/4,3,-D/2+0.05);worldGroup.add(win);
 // your stuff, arranged round the edges
 const spots=[[-W/2+2.6,-D/2+3.4],[W/2-2.6,-D/2+3.2],[-W/2+2.4,0],[W/2-2.4,0],
              [-W/2+2.6,D/2-4],[W/2-2.6,D/2-4],[0,-D/2+2.2],[-W/4,D/2-3],
              [W/4,D/2-3],[0,0],[-W/4,-D/2+2.4],[W/4,-D/2+2.4],
              [-W/2+3,-2.5],[W/2-3,-2.5],[-W/2+3,2.5],[W/2-3,2.5]];
 let si=0;
 homeBed=null;
 FURN.forEach(f=>{if(!ownsF(f.id))return;const sp=spots[si++%spots.length];fBuild(f.b,sp[0],sp[1],worldGroup);
  if(f.id==='bed'){homeBed={x:sp[0],z:sp[1]};
   const zz=makeLabel('SLEEP','😴');zz.position.set(sp[0],2.6,sp[1]);zz.scale.set(4.5,2.4,1);worldGroup.add(zz)}});
 pos={x:0,z:D/2-3};heading=Math.PI;heroY=0;heroVY=0;onGround=true;hero.position.set(pos.x,0,pos.z);
 spawnPiggy(0,D/2-8);
 shownWorld=-1;renderHUD()}
function maybeAdvanceWorld(){if(pendingWorld!=null){const w=pendingWorld;pendingWorld=null;if(w<LEVELS.length)loadWorld(w)}}

function initWorld(){scene=new THREE.Scene();scene.background=new THREE.Color(0x8ecbff);scene.fog=new THREE.Fog(0x8ecbff,95,360);
 camera=new THREE.PerspectiveCamera(70,innerWidth/innerHeight,0.1,900);
 renderer=new THREE.WebGLRenderer({canvas:cv,antialias:true});renderer.setPixelRatio(Math.min(2,window.devicePixelRatio||1));renderer.setSize(innerWidth,innerHeight);
 ambLight=new THREE.AmbientLight(0xffffff,0.82);scene.add(ambLight);const sun=new THREE.DirectionalLight(0xffffff,0.68);sun.position.set(20,40,12);scene.add(sun);sunLight=sun;
 const grd=new THREE.Mesh(new THREE.PlaneGeometry(900,900),new THREE.MeshLambertMaterial({color:0x2e7d46}));grd.rotation.x=-Math.PI/2;scene.add(grd);bigGround=grd;
 hero=buildHero();scene.add(hero);
 beacon=new THREE.Mesh(new THREE.CylinderGeometry(0.16,0.16,22,8),new THREE.MeshBasicMaterial({color:0xffe066,transparent:true,opacity:0.32}));beacon.visible=false;scene.add(beacon);
 setView(0);updateTool();updateVaultCount();updateWP();
 loadWorld(LEVELS[STAGES[firstOpen()].level]?STAGES[firstOpen()].level:0)}

function updateCamera(t){if(!hero)return;const P=hero.position,fx=Math.sin(heading),fz=Math.cos(heading);
 if(camMode===0){camera.position.set(P.x-fx*5,30,P.z-fz*5);camera.lookAt(P.x+fx*0.5,0.6,P.z+fz*0.5)}
 else if(camMode===1){camera.position.set(P.x-fx*9,6,P.z-fz*9);camera.lookAt(P.x+fx*2,2.4,P.z+fz*2)}
 else if(camMode===2){camera.position.set(P.x+fx*0.2,2.9,P.z+fz*0.2);camera.lookAt(P.x+fx*8,2.7,P.z+fz*8)}
 else{const a=t*0.0003;camera.position.set(P.x+Math.cos(a)*15,11,P.z+Math.sin(a)*15);camera.lookAt(P.x,2,P.z)}}

function update(t){if(!renderer)return;
 if(!paused){if(keys.TL)heading+=0.052;if(keys.TR)heading-=0.052;
  const mv=(keys.F?1:0)-(keys.B?1:0),fx=Math.sin(heading),fz=Math.cos(heading);
  if(mv){const dx=fx*0.18*mv,dz=fz*0.18*mv;
   // auto-step: if the thing in your way is a short hop up, just climb it.
   // (a rope ladder raises how high you can step.)
   const reach=stepReach();
   let w=blockedAt(pos.x+dx,pos.z,heroY);
   if(w&&onGround&&(w.top-heroY)<=reach&&(w.top-heroY)>0){heroY=w.top+0.01;heroVY=0;onGround=true;pos.x+=dx;stepFX(w)}
   else if(w&&w.movable&&onGround){if(pushWall(w,Math.sign(dx),0)){pos.x+=dx;pushFX(w)}else ram(w)}
   else if(!w)pos.x+=dx;else ram(w);
   w=blockedAt(pos.x,pos.z+dz,heroY);
   if(w&&onGround&&(w.top-heroY)<=reach&&(w.top-heroY)>0){heroY=w.top+0.01;heroVY=0;onGround=true;pos.z+=dz;stepFX(w)}
   else if(w&&w.movable&&onGround){if(pushWall(w,0,Math.sign(dz))){pos.z+=dz;pushFX(w)}else ram(w)}
   else if(!w)pos.z+=dz;else ram(w);
   walkPhase+=0.3}
  if(keys.JUMP&&onGround){heroVY=0.42;onGround=false;sfx('hit')}
  heroVY-=0.028;heroY+=heroVY;onGround=false;if(heroY<=0){heroY=0;heroVY=0;onGround=true}
  for(const w of walls){if(w.broken)continue;if(Math.abs(pos.x-w.x)<w.hw&&Math.abs(pos.z-w.z)<w.hd&&heroVY<=0&&heroY<=w.top+0.05&&heroY>=w.top-0.9){heroY=w.top;heroVY=0;onGround=true}}
  pos.x=Math.max(BND.x0,Math.min(BND.x1,pos.x));pos.z=Math.max(BND.z0,Math.min(BND.z1,pos.z));
  hero.position.set(pos.x,heroY,pos.z);hero.rotation.y=heading;
  const sw=mv?Math.sin(walkPhase)*0.7:0;if(heroLegs[0]){heroLegs[0].rotation.x=sw;heroLegs[1].rotation.x=-sw;heroArms[0].rotation.x=-sw;heroArms[1].rotation.x=sw}
  updatePoss();
  // reveal: the current target is always shown; other hidden blocks reveal when you get close
  for(const b of blocks){const d=b.userData.d;if(b.visible)continue;const isTarget=unlocked(d.i)&&!G.done[d.i];
   if(G.done[d.i]||isTarget){b.visible=true}
   else if(Math.hypot(d.px-pos.x,d.pz-pos.z)<12){b.visible=true;if(!G.found[d.i]){G.found[d.i]=1;save();burst(d.px,d.base,d.pz,0xf0d060);sfx('secret');toast('✨ You uncovered a hidden block!')}}}
  // secrets
  for(const s of curSecrets){if(G.secrets[s.id]||!s.orb)continue;if(Math.hypot(s.x-pos.x,s.z-pos.z)<2.9)revealSecret(s)}
  // nearest interactable
  nearGate=-1;let best=1e9;for(const b of blocks){const d=b.userData.d;if(G.done[d.i]||!unlocked(d.i)||!b.visible)continue;const dd=Math.hypot(d.px-pos.x,d.pz-pos.z);if(dd<4.6&&dd<best){best=dd;nearGate=d.i}}
  // tell the player how to climb when they're standing at something climbable
  if(nearGate<0&&!nearNPC){let cl=null,cd=1e9;
   for(const w of walls){if(w.broken)continue;if(w.kind!=='step'&&w.kind!=='ledge')continue;
    const dd=Math.hypot(w.x-pos.x,w.z-pos.z);if(dd<6&&dd<cd){cd=dd;cl=w}}
   if(cl&&heroY<cl.top-0.3){$('hint').textContent='⤴ Press SPACE to jump up — climb the ledges to get over the wall';$('hint').classList.add('show')}}
  const near=nearGate>=0;$('hint').classList.toggle('show',near);$('bE').classList.toggle('on',near);
  if(near)$('hint').textContent=(DOORS[nearGate].s.isBoss?'⚔️ BOSS block':'Run into it or press ↵ to SMASH')+' — '+DOORS[nearGate].hp+' HP left';
  // auto-smash whenever you're near — walk into a block and it keeps cracking on its own
  if(near){const d=DOORS[nearGate];if(Math.hypot(d.px-pos.x,d.pz-pos.z)<(2.6+(d.sz||2)*0.6)){if(hitCool>0)hitCool--;else{hitCool=9;hitBlock(d)}}else hitCool=0}
  // treasure sense + light beacon over the current target
  let td=1e9,tgt=null;for(const b of blocks){const d=b.userData.d;if(G.done[d.i]||!unlocked(d.i))continue;const dd=Math.hypot(d.px-pos.x,d.pz-pos.z);if(dd<td){td=dd;tgt=d}}
  if(beacon){if(tgt){beacon.visible=true;beacon.position.set(tgt.px,11,tgt.pz);beacon.material.opacity=0.2+0.16*Math.abs(Math.sin(t*0.004))}else beacon.visible=false}
  $('hsense').textContent=tgt?(td<5?'🔥🔥 RIGHT HERE — press ENTER to smash!':td<12?'🔥 Getting hot!':td<22?'🙂 Warm — follow the beam of light':'❄️ Cold — head toward the beam of light'):'🏆 World cleared!';
  if(!atHome){const cw=LEVELS[curLevel].world;if(cw!==shownWorld){shownWorld=cw;showBanner(cw)}}
 }
 for(const b of blocks){const d=b.userData.d;if(!b.visible||!d.cube)continue;d.cube.rotation.y+=0.008;let yy=d.base+Math.sin(t*0.002+d.i)*0.18;if(d.cube.userData.shake>0){d.cube.userData.shake--;yy+=Math.sin(d.cube.userData.shake*3)*0.12}d.cube.position.y=yy;const f=d.hp/d.maxhp;d.cube.scale.setScalar(0.6+0.4*f)}
 if(_stepT>0)_stepT--;
 if(!paused&&(t|0)%17===0)checkQuest();
 {const fp=$('hfree');if(fp){const fn=freedomNumber();
   fp.textContent='🗽 '+Math.min(999,Math.round(Math.max(0,netWorth())/fn*1000)/10)+'%'}}
 if(_swing>0){_swing--;if(heroArms[0]){heroArms[0].rotation.x=-1.6*Math.sin((12-_swing)/12*Math.PI)}}
 for(const w of walls){if(!w.mesh)continue;
  if(w._sh>0){w._sh--;w.mesh.position.x=w.x+Math.sin(w._sh*2.1)*0.16;w.mesh.position.z=w.z+Math.cos(w._sh*1.7)*0.1;
   if(w.cap){w.cap.position.x=w.mesh.position.x;w.cap.position.z=w.mesh.position.z}}
  else if(w.mesh.position.x!==w.x){w.mesh.position.x=w.x;w.mesh.position.z=w.z;
   if(w.cap){w.cap.position.x=w.x;w.cap.position.z=w.z}}}
 for(const s of curSecrets){if(s.orb&&s.orb.visible){s.orb.rotation.y+=0.03;s.orb.position.y=1.4+Math.sin(t*0.003+s.x)*0.25}}
 for(let k=parts.length-1;k>=0;k--){const p=parts[k];p.m.position.x+=p.vx;p.m.position.y+=p.vy;p.m.position.z+=p.vz;p.vy-=0.03;p.life-=0.02;p.m.rotation.x+=0.3;if(p.life<=0){scene.remove(p.m);parts.splice(k,1)}}
 updateExtras(t);updateCamera(t)}
function showBanner(w){$('wbt').textContent='LEVEL '+(w+1);$('wbn').textContent=WORLDS[w].name;const b=$('wbanner');b.classList.add('show');clearTimeout(b._t);b._t=setTimeout(()=>b.classList.remove('show'),1900)}

function revealSecret(s){G.secrets[s.id]=1;save();if(s.orb)s.orb.visible=false;if(s.spr)s.spr.visible=false;updateVaultCount();confetti();sfx('secret');paused=true;
 $('secbody').innerHTML='<div class=p-badge>'+s.e+'</div><div class=p-world>🤫 Secret of the Rich</div><div class=p-title>'+s.name+'</div><p class=p-teach>'+s.insight+'</p><button class=pbtn onclick="hide(&#39;secret&#39;);openResource(&#39;'+s.url+'&#39;,&#39;'+s.name.replace(/'/g,"")+'&#39;)">Open this resource ↗</button><button class=pbtn style="background:#1b2740;border-color:#2b3654" onclick="hide(&#39;secret&#39;)">Keep exploring</button><div class=p-note>Opens with a big Back to Money World button always on screen. Saved to your Wealth Vault 📚</div>';
 $('secret').classList.add('show')}
function openVault(){paused=true;$('vbody').innerHTML='<div class=p-title>📚 Wealth Vault</div><div class=p-world style=margin-bottom:8px>Hidden knowledge of the rich — found by exploring</div>'+SECRETS.map(s=>G.secrets[s.id]?('<div class=gloss><b>'+s.e+' '+s.name+'</b><div class=gd>'+s.insight+'</div><button class=pbtn style="margin-top:6px" onclick="hide(&#39;vault&#39;);openResource(&#39;'+s.url+'&#39;,&#39;'+s.name.replace(/'/g,"")+'&#39;)">Open resource ↗</button></div>'):'<div class=gloss style=opacity:.55><b>🔒 Hidden Secret</b><div class=gd>Out in the far corners of one of the worlds... explore to uncover it.</div></div>').join('')+SHOP.filter(i=>i.url&&owns(i.id)).map(i=>'<div class=gloss><b>'+i.e+' '+i.n+'</b><div class=gd>Bought from the Shop — yours for good.</div><button class=pbtn style="margin-top:6px" onclick="hide(&#39;vault&#39;);openResource(&#39;'+i.url+'&#39;,&#39;'+i.n.replace(/'/g,"")+'&#39;)">Open resource ↗</button></div>').join('')
  +'<button class=pbtn style="margin-top:10px" onclick="hide(&#39;vault&#39;)">← Back to Money World</button><div class=p-note>Resources open in a new tab — your game keeps running here.</div>';$('vault').classList.add('show')}

function buildNPC(nd,col){const g=new THREE.Group();const robe=box(1.3,1.7,0.7,col||0x8a5cff);robe.position.y=0.9;g.add(robe);const head=box(0.82,0.82,0.82,0xf1c9a5);head.position.y=2.1;g.add(head);const face=makeLabel('',nd.e);face.position.y=2.1;face.scale.set(1.1,1.1,1);face.material.depthTest=true;g.add(face);const nm=makeLabel(nd.name,nd.marker||(nd.quest?'❗':'💬'));nm.position.y=3.1;g.add(nm);return g}
function bigWall(x,z,w,d,opts){opts=opts||{};const H=opts.h||6,gate=(opts.gateFor!=null);
 const m=box(w,H,d,gate?0x9a5a3a:(opts.col||0x726052));m.position.set(x,H/2,z);worldGroup.add(m);
 const cap=box(w+0.15,0.3,d+0.15,opts.cap||0x554637);cap.position.set(x,H,z);worldGroup.add(cap);
 const hp=opts.solid?999:(opts.hp||999);
 const wall={mesh:m,cap,x,z,hw:w/2,hd:d/2,top:H,hp,maxhp:hp,broken:false,solid:!!opts.solid,gateFor:(gate?opts.gateFor:null),kind:opts.kind||'wall',movable:!!opts.movable,immovable:!!opts.immovable};
 if(wall.gateFor!=null&&G.done[wall.gateFor]){wall.broken=true;worldGroup.remove(m);worldGroup.remove(cap)}
 walls.push(wall);return wall}
// rooms you actually walk through — a home, a school, a store, an office, a bank
const ROOMWALL=[0xc9a878,0xcbb98a,0x9aa6ba,0x86b3ad,0xb2adc4,0x4a5a80];
const VENUE=[
 {v:'Home',   rooms:['Bedroom','Kitchen','Living Room','Garage','Back Yard','Attic','Basement']},
 {v:'School', rooms:['Classroom','Library','Cafeteria','Gym','Science Lab','Hallway','Auditorium']},
 {v:'Store',  rooms:['Front Aisle','Stock Room','Checkout','Loading Dock','Break Room','Office','Warehouse']},
 {v:'Office', rooms:['Lobby','Cubicles','Meeting Room','Server Room','Corner Office','Break Room','Rooftop']},
 {v:'Bank',   rooms:['Teller Line','Vault','Trading Floor','Board Room','Archive','Atrium','Executive Suite']},
 {v:'Studio', rooms:['Bootcamp','Code Lab','Design Studio','Security Lab','AI Lab','Launch Pad','Server Room']},
];
// a doorway you can see through — posts + lintel, no collision
function doorFrame(x,z,dir,WT,GAP){const H=6,col=0x6b5238;
 const l=(dir==='v')?box(WT+0.3,0.9,GAP+0.4,col):box(GAP+0.4,0.9,WT+0.3,col);
 l.position.set(x,H-0.45,z);worldGroup.add(l);
 const pa=(dir==='v')?[[0,-GAP/2],[0,GAP/2]]:[[-GAP/2,0],[GAP/2,0]];
 pa.forEach(o=>{const p=box(WT+0.4,H,WT+0.4,col);p.position.set(x+o[0],H/2,z+o[1]);worldGroup.add(p)})}
// --- the minefield. life throws these at everyone. ---
const MINES=[
 {e:'🚗',t:'Surprise car repair',cost:400,lesson:'The transmission goes out on a Tuesday. This is the exact thing an emergency fund is for.'},
 {e:'🏥',t:'Emergency room visit',cost:600,lesson:'One bad fall can wipe out a year of saving. Insurance plus cash reserves absorb the hit.'},
 {e:'📉',t:'You panic-sold in a crash',cost:500,lesson:'The market dropped 20% and you sold at the bottom. Staying the course beats reacting every time.'},
 {e:'💼',t:'Laid off with no warning',cost:800,lesson:'3-6 months of expenses saved turns a catastrophe into an inconvenience.'},
 {e:'🦷',t:'Emergency dental work',cost:350,lesson:'Unplanned, unavoidable, and always at the worst possible time.'},
 {e:'📱',t:'Phone smashed on the sidewalk',cost:250,lesson:'Small disasters add up. Budget a line for "things break", because they will.'},
 {e:'🏠',t:'Water heater burst',cost:900,lesson:'Owning things costs money. Set aside about 1% of a home value every year.'},
 {e:'💳',t:'Credit card interest caught up',cost:450,lesson:'At 24% APR, compounding runs in reverse — against you, every single month.'},
];
// how far ahead you can spot trouble: grows with willpower + rooms cleared
function mineSense(){return 3+(G.willpower||0)*2.2+Object.keys(G.done).length*0.7}
// your emergency fund softens the blow; enough of one defuses it entirely
function mineDamage(c){return Math.max(0,Math.round(c-(G.willpower||0)*120-Object.keys(G.done).length*25))}
function spawnMine(m,par){const d=new THREE.Mesh(new THREE.CylinderGeometry(0.75,0.75,0.18,12),new THREE.MeshLambertMaterial({color:0x3a2a2a}));
 d.position.set(m.x,0.09,m.z);par.add(d);m.disc=d;
 const sp=makeLabel('','⚠️');sp.position.set(m.x,1.5,m.z);sp.scale.set(1.5,1.5,1);par.add(sp);m.spr=sp;
 d.visible=false;sp.visible=false}
const OPPS=[
 {t:'You started the business you kept putting off',l:'The layoff freed you. Severance plus your emergency fund became startup capital.'},
 {t:'You bought while everyone else panicked',l:'Crashes are sales for people with cash. You had cash, so the crash paid YOU.'},
 {t:'You negotiated the bill down to nothing',l:'Because you could pay, you had leverage to ask. Broke people cannot negotiate.'},
 {t:'You fixed it yourself and learned a trade',l:'A setback taught you a skill you will use for life. Constraint is a teacher.'},
 {t:'The setback became your best story',l:'Preparation turns a disaster into an anecdote — and often into an opening.'},
];
function hitMine(m){if(G.mines[m.id])return;G.mines[m.id]=1;
 const dmg=mineDamage(m.cost);
 if(dmg===0){                                   // prepared -> the setback flips into an opportunity
  const o=OPPS[Math.abs(m.id.split('-')[1]|0)%OPPS.length],rw=Math.round(m.cost*1.5);
  addWealth(rw);if(m.disc)m.disc.visible=false;if(m.spr)m.spr.visible=false;
  burst(m.x,1.4,m.z,0x3fb950);sfx('secret');confetti();paused=true;
  $('minebody').innerHTML='<div class=p-badge>🚪</div>'
   +'<div class=p-world>An opportunity in disguise</div>'
   +'<div class=p-title>'+o.t+'</div>'
   +'<p class=p-teach>What looked like <b>'+m.t.toLowerCase()+'</b> turned into something better. '+o.l+'</p>'
   +'<p class=p-teach style="border-color:#3fb950">Your emergency fund covered the whole hit — so instead of losing money, you gained <b>+$'+rw.toLocaleString()+'</b>.</p>'
   +'<div class=p-note>Setbacks and opportunities often arrive wearing the same coat. Being prepared is what tells them apart.</div>'
   +'<button class=pbtn onclick="hide(&#39;mine&#39;)">Keep going →</button>';
  $('mine').classList.add('show');return}
 G.wealth=Math.max(0,(G.wealth||0)-dmg);save();renderHUD();
 if(m.disc)m.disc.visible=false;if(m.spr)m.spr.visible=false;
 burst(m.x,1,m.z,0xff5a3a);sfx('hit');
 // knock the player back the way they came
 pos.x-=Math.sin(heading)*3.2;pos.z-=Math.cos(heading)*3.2;
 paused=true;
 const safe=false;
 $('minebody').innerHTML='<div class=p-badge>💥</div>'
  +'<div class=p-world>💥 LANDMINE</div>'
  +'<div class=p-title>'+m.t+'</div>'
  +'<p class=p-teach>'+m.lesson+'</p>'
  +(safe?'<p class=p-teach style="border-color:#3fb950">Your emergency fund covered it completely. <b>Cost to you: $0.</b> This is what staying the course buys you.</p>'
        :'<p class=p-teach style="border-color:#f85149">Cost: <b>-$'+dmg.toLocaleString()+'</b>'+((G.willpower||0)>0?' (your emergency fund absorbed $'+(m.cost-dmg).toLocaleString()+')':'')+'</p>')
  +'<div class=p-note>Resist temptations to build willpower 💪 — every point softens the next hit, and you start spotting them sooner.</div>'
  +'<button class=pbtn onclick="hide(&#39;mine&#39;)">Keep going →</button>';
 $('mine').classList.add('show')}
// chances sitting just out of reach — you have to climb and jump to take them
function spawnOpp(o,par){const m=box(1.1,1.1,1.1,0xf0c419);m.position.set(o.x,o.y,o.z);par.add(m);o.mesh=m;
 const sp=makeLabel('JUMP FOR IT','⤴');sp.position.set(o.x,o.y+1.5,o.z);sp.scale.set(5,2.6,1);par.add(sp);o.spr=sp}
function takeOpp(o){if(G.opps[o.id])return;G.opps[o.id]=1;save();
 if(o.mesh)worldGroup.remove(o.mesh);if(o.spr)worldGroup.remove(o.spr);
 addWealth(o.reward);burst(o.x,o.y,o.z,0xf0c419);sfx('secret');confetti();
 toast('⤴ You reached for it and got it — +$'+o.reward.toLocaleString()+'. Opportunities go to whoever jumps.')}
// Things worth BUYING. Spending isn't the enemy — spending on things that
// pay you back is how you get ahead. Every item here earns its price.
// The menagerie. Market folklore is full of animals for a reason —
// bulls, bears, wolves, sharks, sheep and pigs are all real behaviour patterns.
// Some help you. Some eat you. A few of each are not what they look like.
const FAUNA=[
 {e:'🐂',n:'The Bull',good:1,obvious:1,col:0x3fa35a,
  lines:['Markets go up over time. Not every day — over TIME.','Optimism plus patience has beaten pessimism for 100 years straight.']},
 {e:'🦉',n:'Owl the Researcher',good:1,obvious:1,col:0x8a6a3a,
  lines:['Before you buy anything, read what it actually is. Boring? Yes. Rich? Also yes.','If you cannot explain it to a 10-year-old, do not put money in it.']},
 {e:'🦁',n:'Lion',good:1,obvious:1,col:0xd6a13a,
  lines:['Own the big, boring, profitable companies. Let them do the roaring.','You do not need to be clever. You need to be consistent.']},
 {e:'🐴',n:'Workhorse',good:1,obvious:1,col:0x8a6a52,
  lines:['I put the same amount in every single month. That is the whole trick.','Slow money is the only money that stays.']},
 {e:'🦅',n:'Eagle',good:1,obvious:1,col:0x6a5a48,
  lines:['I look 30 years out. From up here, the crashes are tiny little dips.','Zoom out. Almost every scary chart looks fine from far enough away.']},
 {e:'🐭',n:'Field Mouse',good:1,obvious:0,col:0x9a9a9a,
  lines:['I know I am small. I still save a little every week, and it adds up.','Nobody starts big. Starting at all is the hard part.']},
 {e:'🐙',n:'Octopus',good:1,obvious:0,col:0x8a5cff,
  lines:['Eight arms, eight different baskets. That is diversification.','If one arm gets bitten, I still have seven. Never put it all in one place.']},
 {e:'🦈',n:'Loan Shark',good:0,obvious:1,col:0x5a6272,deal:{
   pitch:'Cash right now, friend. No credit check. Just a small weekly fee.',
   cost:700,take:'You took the fast cash. The "small weekly fee" was 300% a year.',
   walk:'You walked away. Fast money always costs the most.',
   lesson:'Payday loans and "no credit check" offers run 200-400% APR. The cost is hidden in the speed.'}},
 {e:'🐻',n:'The Bear',good:0,obvious:1,col:0x6a4a32,deal:{
   pitch:'It is ALL going to crash. Sell everything and hide in cash. Today.',
   cost:500,take:'You panic-sold everything. The market recovered without you.',
   walk:'You stayed the course. The dip passed, like they all do.',
   lesson:'Missing just the 10 best days of a decade cuts your return roughly in half. Time in beats timing.'}},
 {e:'🐺',n:'Wolf in a Suit',good:0,obvious:0,col:0x7a7a86,deal:{
   pitch:'I have a hot pick. Guaranteed 10x. My clients are all getting rich. In or out?',
   cost:900,take:'You bought his "sure thing". He sold his shares into your money.',
   walk:'You said no. Nobody with a guaranteed 10x needs YOUR money.',
   lesson:'"Guaranteed returns" is the oldest lie in finance. Guaranteed and high-return never appear together.'}},
 {e:'🐑',n:'The Herd',good:0,obvious:0,col:0xd8d8d0,deal:{
   pitch:'EVERYONE is buying this one. You are going to be the only one left out!',
   cost:600,take:'You followed the crowd in at the top. The crowd left before you did.',
   walk:'You let them run past. Crowded trades are usually late trades.',
   lesson:'By the time something is on every feed, the easy money already left. FOMO is not research.'}},
 {e:'🐷',n:'Piggy',good:0,obvious:0,col:0xf0a0b0,deal:{
   pitch:'Why settle for 10% a year? Put it ALL on this. Go big or go home!',
   cost:800,take:'You bet everything on one thing. One thing went wrong.',
   walk:'You kept your position sensible. Greed is the expensive one.',
   lesson:'Bulls make money, bears make money, pigs get slaughtered. Position size is survival.'}},
 {e:'🐯',n:'Tiger Fund',good:0,obvious:0,col:0xe08a3a,deal:{
   pitch:'Aggressive growth, 40% a year, small management fee of just 2% and 20% of profits.',
   cost:650,take:'You paid the fees. The fees showed up every year. The 40% did not.',
   walk:'You checked the fees first and passed.',
   lesson:'A 2% annual fee eats roughly 40% of your lifetime gains. Fees are certain; returns are not.'}},
];
function faunaMarker(f){if(f.good)return f.obvious?'💬':'💬';
 return (f.obvious||streetSmarts()>=4)?'⚠️':'💬'}
const SHOP=[
 {id:'lantern',e:'🔦',n:'Lantern',price:250,cat:'Tool',
  d:'Night stops being a problem. Explore after dark.',
  why:'A tool that lets you keep working is not an expense — it buys you capacity.'},
 {id:'ladder',e:'🪜',n:'Rope Ladder',price:400,cat:'Tool',
  d:'Climb almost anything just by walking into it.',
  why:'Buying the right tool turns a wall you cannot pass into a step. That is what good equipment does.'},
 {id:'boots',e:'🥾',n:'Sturdy Boots',price:350,cat:'Tool',
  d:'Landmines hurt you far less.',
  why:'Paying to reduce a risk you cannot avoid is insurance, and insurance is smart money.'},
 {id:'map',e:'🗺️',n:'Detailed Map',price:450,cat:'Tool',
  d:'Spot landmines from much further away.',
  why:'Information bought before you need it is always cheaper than the mistake.'},
 {id:'babylon',e:'📕',n:'The Richest Man in Babylon',price:300,cat:'Book',wp:1,
  d:'+1 willpower, forever. Adds the book to your Vault.',
  why:'A book is the cheapest way to buy decades of somebody else’s experience.',
  url:'https://en.wikipedia.org/wiki/The_Richest_Man_in_Babylon'},
 {id:'psych',e:'📗',n:'The Psychology of Money',price:500,cat:'Book',wp:1,
  d:'+1 willpower, forever. Adds the book to your Vault.',
  why:'Wealth is behaviour more than maths. This one teaches the behaviour.',
  url:'https://en.wikipedia.org/wiki/The_Psychology_of_Money'},
 {id:'jlcollins',e:'📘',n:'The Simple Path to Wealth',price:600,cat:'Book',wp:1,
  d:'+1 willpower, forever. Adds the book to your Vault.',
  why:'One boring index fund, held for decades, beats almost every clever plan.',
  url:'https://www.bogleheads.org/wiki/Getting_started'},
 {id:'khan',e:'🎓',n:'Khan Academy course',price:200,cat:'Knowledge',
  d:'A free, world-class personal-finance course, saved to your Vault.',
  why:'You are paying for the time to sit down and learn. That is always worth it.',
  url:'https://www.khanacademy.org/college-careers-more/personal-finance'},
 {id:'fred',e:'📈',n:'FRED economic data',price:400,cat:'Knowledge',
  d:'The real data the professionals watch, saved to your Vault.',
  why:'Opinions are free and mostly wrong. Data costs something and is mostly right.'},
 {id:'advisor',e:'🧑‍💼',n:'Fee-only advisor session',price:900,cat:'Knowledge',
  d:'An hour with someone paid by YOU, not by commissions.',
  why:'A fee-only advisor has no reason to sell you junk. How someone is paid tells you who they serve.',
  url:'https://www.napfa.org'},
];
// Sites we can legally embed. The rest send X-Frame-Options: SAMEORIGIN and
// simply refuse to load in a frame - for those we open a tab and keep a big
// obvious way back on screen. (We cannot put our button on someone else's site.)
const EMBEDDABLE=[/(^|[.])investor[.]gov$/i,/(^|[.])wikipedia[.]org$/i,/(^|[.])khanacademy[.]org$/i];
function canEmbed(u){try{return EMBEDDABLE.some(r=>r.test(new URL(u).hostname))}catch(e){return false}}
function openResource(url,title){
 paused=true;
 $('webtitle').textContent=title||url;
 $('weblink').href=url;
 const fr=$('webframe'),note=$('webnote');
 if(canEmbed(url)){note.style.display='none';fr.style.display='';fr.src=url}
 else{fr.style.display='none';fr.removeAttribute('src');note.style.display='';
  note.innerHTML='<h2 style="margin:0 0 10px">'+(title||'Resource')+'</h2>'
   +'<p>This site does not allow itself to be opened inside another page, so it opened in a <b>new tab</b>.</p>'
   +'<p>Your game is still running right here — come back to this tab, or hit the big blue button above, any time.</p>'
   +'<p><a href="'+url+'" target=_blank rel=noopener style="color:#7fb4ff;font-weight:800">Open it again ↗</a></p>';
  window.open(url,'_blank','noopener')}
 $('web').classList.add('show')}
function closeWeb(){const fr=$('webframe');fr.removeAttribute('src');$('web').classList.remove('show');paused=false}
function owns(id){return !!(G.owned&&G.owned[id])}
function ownedBooks(){return SHOP.filter(i=>i.cat==='Book'&&owns(i.id)).length}
// how good you are at spotting a bad actor - grows as you read and clear rooms
function streetSmarts(){return ownedBooks()*2+Object.keys(G.done).length*0.5+(G.willpower||0)*0.4+(owns('advisor')?2:0)+(G.skill||0)*0.6}
function buyItem(id){const it=SHOP.find(x=>x.id===id);if(!it||owns(id))return;
 if((G.wealth||0)<it.price){toast('Not enough money yet — clear rooms and collect coins first.');return}
 G.wealth-=it.price;G.owned[id]=1;if(it.wp)G.willpower=(G.willpower||0)+it.wp;
 save();renderHUD();updateWP();updateVaultCount();sfx('secret');confetti();
 toast('✅ Bought '+it.e+' '+it.n+' — '+(it.wp?'+1 willpower. ':'')+'This one pays you back.');
 openShop()}
// A month passes each time you clear a room. Rent comes out. This is the
// whole game in one function: what is left over is what compounds.
function passMonth(){
 const H=curHome();G.month=(G.month||0)+1;const _p=tParts();
 const inc=passiveIncome();
 if(inc>0){G.wealth=(G.wealth||0)+inc;
  setTimeout(()=>toast('🚀 Your '+projectsDone()+' side project(s) paid $'+inc.toLocaleString()+' — you worked zero hours for it.'),1400)}
 // life costs money even when rent is $0
 const live=livingCost();
 G.wealth=(G.wealth||0)-live;
 if(H.monthly>0){
  G.wealth=(G.wealth||0)-H.monthly;
  if(H.own&&H.equity)G.equity=(G.equity||0)+H.equity;
  const eq=H.own&&H.equity?(' · $'+H.equity.toLocaleString()+' of it became equity you keep'):'';
  toast('🏠 1st of '+MONTHS[_p.month]+': '+H.n+' $'+H.monthly.toLocaleString()+' + living $'+live.toLocaleString()+eq)}
 else toast('🏠 1st of '+MONTHS[_p.month]+': rent $0, living costs $'+live.toLocaleString()+'. Rent-free is the head start.');
 // cannot pay? you move back down the ladder. this is how it works in real life.
 if((G.wealth||0)<0){
  const i=homeIdx();
  if(i>0){G.home=HOMES[i-1].id;G.wealth=0;
   setTimeout(()=>{sfx('hit');toast('📦 You could not cover the bills and had to move back to '+curHome().n+'.')},1800)}
  else {G.wealth=0;setTimeout(()=>toast('😬 Bills ate everything. You are at $0 — no cushion at all.'),1800)}}
 save();renderHUD();}
function birthday(p){paused=true;sfx('tool');confetti();
 const yearsLeft=Math.max(0,65-p.age);const fn=freedomNumber();
 const seed=Math.max(0,netWorth());
 const at65=Math.round(seed*Math.pow(1.08,yearsLeft));
 $('minebody').innerHTML='<div class=p-badge>🎂</div><div class=p-world>A year just went by</div>'
  +'<div class=p-title>You are '+p.age+'</div>'
  +'<p class=p-teach>Another year gone. You got exactly the same 24 hours a day as everybody else — '
  +'8,760 hours. What you did with them is the only thing that was ever different.</p>'
  +'<p class=p-teach style="border-color:#3fb950">Net worth today: <b>'+money(seed)+'</b>.<br>'
  +'Left alone at 8% a year for the '+yearsLeft+' years to 65, that alone becomes <b>'+money(at65)+'</b>.</p>'
  +'<p class=p-teach style="border-color:#f0b429">You burn <b>'+money(monthlyBurn())+'</b> a month, so freedom costs <b>'+money(fn)+'</b>. '
  +'You are <b>'+Math.round(Math.max(0,netWorth())/fn*1000)/10+'%</b> of the way there.</p>'
  +'<div class=p-note>Every year you wait, that number shrinks. Time is the ingredient you cannot buy back.</div>'
  +'<button class=pbtn onclick="hide(&#39;mine&#39;)">Another year →</button>';
 $('mine').classList.add('show')}
function netWorth(){return (G.wealth||0)+(G.equity||0)}
function buyFurn(id){const f=FURN.find(x=>x.id===id);if(!f||ownsF(id))return;
 if((G.wealth||0)<f.price){toast('Not enough money — clear rooms and collect coins first.');return}
 G.wealth-=f.price;G.furn[id]=1;save();renderHUD();sfx('secret');
 if(atHome)loadHome();
 toast(f.e+' '+f.n+' delivered! '+(f.cat==='bad'?'It is yours — and it starts losing value today.':'Nice.'));
 openShop()}
function buyHome(id){const i=HOMES.findIndex(h=>h.id===id),H=HOMES[i];if(i<0||i<=homeIdx())return;
 if((G.wealth||0)<H.buy){toast('You cannot afford the move-in cost yet.');return}
 G.wealth-=H.buy;G.home=id;save();renderHUD();sfx('tool');confetti();
 if(atHome)loadHome();
 paused=true;
 $('minebody').innerHTML='<div class=p-badge>'+H.e+'</div><div class=p-world>You moved in</div><div class=p-title>'+H.n+'</div>'
  +'<p class=p-teach>'+H.note+'</p>'
  +'<p class=p-teach style="border-color:'+(H.monthly>1500?'#f0b429':'#3fb950')+'">Your monthly cost is now <b>$'+H.monthly.toLocaleString()+'</b>'
  +(H.own&&H.equity?(', of which $'+H.equity.toLocaleString()+' builds equity you keep.'):', all of which is gone each month.')+'</p>'
  +'<p class=p-teach style="border-color:#7fb4ff"><b>The catch nobody mentions:</b> at $'+H.monthly.toLocaleString()+'/month, your freedom number just went up by about <b>$'
  +(H.monthly*12*25).toLocaleString()+'</b>. Every upgrade moves the finish line further away.</p>'
  +'<button class=pbtn onclick="hide(&#39;mine&#39;)">Got it →</button>';
 $('mine').classList.add('show')}
// Real money, real prices, no real risk. This is the part nothing else has.
function pCallFree(id,dir){
 const a=CAT&&CAT.assets.find(x=>x.id===id);
 if(!a||a.price==null){toast('No live price right now — try again in a moment.');return}
 G.predictions.unshift({id:'p'+Date.now(),symbol:a.symbol,name:a.name,cls:a.cls,dir,price:a.price,
  ts:Date.now(),due:Date.now()+G.hz*3600*1000,horizon:G.hz,status:'pending'});
 save();sfx('secret');
 toast('🔒 Call locked: '+a.name+' '+(dir==='up'?'HIGHER':'LOWER')+' within '+G.hz+'h. Real prices decide this one.');
 openMarket()}
function setHzFree(h){G.hz=h;save();openMarket()}
function predStats(){const ps=G.predictions||[],res=ps.filter(p=>p.status!=='pending');
 const right=res.filter(p=>p.status==='correct').length;
 return{total:ps.length,open:ps.filter(p=>p.status==='pending').length,resolved:res.length,right,
  acc:res.length?Math.round(right/res.length*100):null}}
function openMarket(){
 paused=true;
 if(!CAT){$('marketbody').innerHTML='<div class=p-title>📈 Market Desk</div><p class=p-teach>Live prices have not loaded yet. Close this and try again in a moment.</p><button class=pbtn onclick="hide(&#39;market&#39;)">← Back</button>';$('market').classList.add('show');return}
 const st=predStats();
 const hz=HORIZONS.map(h=>'<button class="'+(h.h===G.hz?'on':'')+'" onclick="setHzFree('+h.h+')">'+h.l+'</button>').join('');
 const byCls={};CAT.assets.forEach(a=>{(byCls[a.cls]=byCls[a.cls]||[]).push(a)});
 let rows='';
 Object.keys(byCls).forEach(c=>{
  const cl=CAT.classes[c];if(!cl||cl.kind==='concept'||cl.kind==='soon')return;
  const {t}=tierFor(c),tr=TIERS[t];
  rows+='<div class=p-title style="font-size:16px;margin-top:12px">'+cl.icon+' '+cl.name
   +' <span class=p-note style="color:'+tr.c+'">· '+tr.ic+' '+tr.n+'</span></div>';
  byCls[c].slice(0,4).forEach(a=>{
   rows+='<div class=gloss><b>'+a.name+'</b> <span class=p-note>'+a.symbol+'</span>'
    +'<div class=a-px style="font-size:20px;margin:2px 0">'+(a.price==null?'—':money(a.price))+'</div>'
    +'<div class=calls><button class=up onclick="pCallFree(&#39;'+a.id+'&#39;,&#39;up&#39;)">▲ Higher</button>'
    +'<button class=down onclick="pCallFree(&#39;'+a.id+'&#39;,&#39;down&#39;)">▼ Lower</button></div></div>'})});
 const open=(G.predictions||[]).filter(p=>p.status==='pending').slice(0,8).map(p=>{
  const hrs=Math.max(0,Math.round((p.due-Date.now())/3600000));
  return '<div class=gloss><b>'+(p.dir==='up'?'▲':'▼')+' '+p.name+'</b>'
   +'<div class=gd>Called at '+money(p.price)+' · resolves in '+hrs+'h from real market data</div></div>'}).join('');
 const hist=(G.predictions||[]).filter(p=>p.status!=='pending').slice(0,6).map(p=>
  '<div class=gloss style="border-color:'+(p.status==='correct'?'#3fb950':'#f85149')+'">'
  +'<b>'+(p.status==='correct'?'✅':'❌')+' '+p.name+' '+(p.dir==='up'?'higher':'lower')+'</b>'
  +'<div class=gd>'+money(p.price)+' → '+money(p.resolved)+'</div></div>').join('');
 $('marketbody').innerHTML='<div class=p-title>📈 Market Desk</div>'
  +'<div class=p-world style=margin-bottom:8px>Real prices. Real markets. None of your money at risk.</div>'
  +'<p class=p-teach>Call a direction and the <b>actual market</b> settles it later — no simulation, no made-up numbers. '
  +'This is how you find out whether you can read a market before it costs you anything.</p>'
  +'<div class=p-teach style="border-color:'+(st.acc==null?'#2b3654':st.acc>=55?'#3fb950':'#f0b429')+'">'
  +'<b>Your record:</b> '+(st.resolved?(st.right+' of '+st.resolved+' right · '+st.acc+'% accurate'):'no calls settled yet')
  +(st.open?(' · '+st.open+' still open'):'')+'</div>'
  +'<div class=hz style="margin:10px 0">Window: '+hz+'</div>'
  +(open?('<div class=p-title style="font-size:16px;margin-top:12px">⏳ Open calls</div>'+open):'')
  +(hist?('<div class=p-title style="font-size:16px;margin-top:12px">📜 Settled</div>'+hist):'')
  +rows
  +'<button class=pbtn style="margin-top:12px" onclick="hide(&#39;market&#39;)">← Back to Money World</button>';
 $('market').classList.add('show')}
// Everything you are, in one place. Who you became, what you learned,
// what you own, and how close you actually are to being free.
function hoursSpent(){const a=G.acts||{};let h=0;
 ACTIONS.forEach(x=>{h+=(a[x.id]||0)*x.hours});return h}
function openProfile(){
 paused=true;
 const p=tParts(),tier=wageTier(),st=predStats(),fn=freedomNumber(),nw=netWorth();
 const pct=Math.max(0,Math.min(999,Math.round(nw/fn*1000)/10));
 const earned=BADGES.filter(b=>{try{return b.test(G)}catch(e){return false}});
 const locked=BADGES.filter(b=>!earned.includes(b));
 const a=G.acts||{};
 const rooms=Object.keys(G.done||{}).length;
 const stat=(l,v,c)=>'<div style="flex:1 1 44%;min-width:130px;background:#0d1420;border:1px solid #2b3654;border-radius:10px;padding:9px 11px">'
   +'<div style="font-size:11px;color:#7b8aa3;text-transform:uppercase;letter-spacing:.06em">'+l+'</div>'
   +'<div style="font-size:19px;font-weight:800;color:'+(c||'#eaf1ff')+'">'+v+'</div></div>';
 const invTiers=CAT?Object.keys(CAT.classes).map(c=>{const cl=CAT.classes[c],{t}=tierFor(c),tr=TIERS[t];
   return '<div class=trow><span class=ti>'+cl.icon+'</span><span class=tn>'+cl.name+'</span>'
     +'<span class=tr style=color:'+tr.c+'>'+tr.ic+' '+tr.n+'</span></div>'}).join(''):'';
 const vault=SECRETS.filter(x=>G.secrets[x.id]).map(x=>x.e+' '+x.name)
   .concat(SHOP.filter(x=>x.url&&owns(x.id)).map(x=>x.e+' '+x.n));
 $('profbody').innerHTML=
  '<div class=p-badge>'+curHome().e+'</div>'
  +'<div class=p-world>Your life so far</div>'
  +'<div class=p-title>'+tier.n+' · age '+p.age+'</div>'
  +'<div class=p-note style="margin-bottom:10px">'+dateStr()+' · day '+(p.totalDays+1)+' of the story</div>'

  +'<div class=p-teach style="border-color:'+(pct>=100?'#3fb950':pct>=25?'#f0b429':'#3d8bff')+'">'
  +'<b>Financial freedom: '+pct+'%</b><div class=qp style="margin-top:6px;height:8px"><i style="width:'+Math.min(100,pct)+'%"></i></div>'
  +'<div class=gd style="margin-top:6px">You burn '+money(monthlyBurn())+' a month, so freedom costs '+money(fn)+'. '
  +(pct>=100?'You are already there — your money covers your life.':'You need '+money(Math.max(0,fn-nw))+' more.')+'</div></div>'

  +'<div class=p-title style="font-size:16px;margin-top:14px">💰 Money</div>'
  +'<div style="display:flex;flex-wrap:wrap;gap:7px">'
  +stat('Net worth',money(nw),'#3fb950')+stat('Cash',money(G.wealth||0))
  +stat('Home equity',money(G.equity||0))+stat('Monthly burn',money(monthlyBurn()),'#f0b429')
  +stat('Passive income',money(passiveIncome()),passiveIncome()>0?'#3fb950':'#7b8aa3')
  +stat('A shift pays',money(wage()))+'</div>'

  +'<div class=p-title style="font-size:16px;margin-top:14px">🧠 What you know</div>'
  +'<div style="display:flex;flex-wrap:wrap;gap:7px">'
  +stat('Skill',(G.skill||0)+' / '+SKILL_CAP)+stat('Wage tier',tier.n,'#3d8bff')
  +stat('Rooms cleared',rooms+' / '+STAGES.length)+stat('Words learned',Object.keys(G.glossary||{}).length)
  +stat('Willpower',(G.willpower||0)+' 💪')+stat('Street smarts',Math.round(streetSmarts()*10)/10)+'</div>'

  +'<div class=p-title style="font-size:16px;margin-top:14px">⏳ Where the hours went</div>'
  +'<div style="display:flex;flex-wrap:wrap;gap:7px">'
  +stat('Shifts worked',(a.work||0))+stat('Study sessions',(a.study||0))
  +stat('Projects finished',projectsDone())+stat('Hours scrolled away',(G.wasted||0),(G.wasted||0)>12?'#f85149':'#7b8aa3')
  +'</div>'

  +'<div class=p-title style="font-size:16px;margin-top:14px">🏠 Home</div>'
  +'<div class=gloss><b>'+curHome().e+' '+curHome().n+'</b><div class=gd>'+curHome().note+'</div>'
  +'<div class=gd>Furniture: '+(Object.keys(G.furn||{}).length?FURN.filter(f=>ownsF(f.id)).map(f=>f.e).join(' '):'nothing yet')+'</div></div>'

  +'<div class=p-title style="font-size:16px;margin-top:14px">📈 Market record</div>'
  +'<div class=gloss><b>'+(st.resolved?(st.right+' of '+st.resolved+' calls right · '+st.acc+'% accurate'):'No calls settled yet')+'</b>'
  +(st.open?'<div class=gd>'+st.open+' still open</div>':'')+'</div>'+invTiers

  +'<div class=p-title style="font-size:16px;margin-top:14px">🏆 Accomplishments <span class=p-note>· '+earned.length+' of '+BADGES.length+'</span></div>'
  +'<div class=badges>'+earned.map(b=>'<div class=bg><div class=i>'+b.ic+'</div><div class=n>'+b.n+'</div></div>').join('')
  +locked.map(b=>'<div class="bg off"><div class=i>'+b.ic+'</div><div class=n>'+b.n+'</div></div>').join('')+'</div>'

  +'<div class=p-title style="font-size:16px;margin-top:14px">📚 Vault <span class=p-note>· '+vault.length+'</span></div>'
  +(vault.length?vault.map(v=>'<div class=gloss><b>'+v+'</b></div>').join(''):'<div class=p-note>Nothing found yet — explore the far corners.</div>')

  +'<button class=pbtn style="margin-top:12px" onclick="hide(&#39;profile&#39;)">← Back to Money World</button>';
 $('profile').classList.add('show')}
function openShop(){paused=true;
 const rows=SHOP.map(it=>{const has=owns(it.id),afford=(G.wealth||0)>=it.price;
  return '<div class=gloss style="'+(has?'border-color:#3fb950':'')+'">'
   +'<b>'+it.e+' '+it.n+'</b> <span class=p-note>· '+it.cat+'</span>'
   +'<div class=gd>'+it.d+'</div>'
   +'<div class=gd style="color:#7fb4ff">'+it.why+'</div>'
   +(has?'<div style="color:#3fb950;font-weight:700;margin-top:4px">✓ Owned</div>'
        :'<button class=pbtn style="margin-top:6px'+(afford?'':';opacity:.5')+'" onclick="buyItem(&#39;'+it.id+'&#39;)">Buy · $'+it.price.toLocaleString()+'</button>')
   +'</div>'}).join('');
 const CATC={need:'#93a1b5',asset:'#3fb950',fun:'#a371f7',bad:'#f85149'};
 const CATN={need:'Need',asset:'Asset — pays you back',fun:'Fun — costs you, and that is OK',bad:'Liability — loses value'};
 const frows=FURN.map(f=>{const has=ownsF(f.id),afford=(G.wealth||0)>=f.price;
  return '<div class=gloss style="'+(has?'border-color:#3fb950':'')+'">'
   +'<b>'+f.e+' '+f.n+'</b> <span class=p-note style="color:'+CATC[f.cat]+'">· '+CATN[f.cat]+'</span>'
   +'<div class=gd>'+f.lesson+'</div>'
   +(has?'<div style="color:#3fb950;font-weight:700;margin-top:4px">✓ In your room</div>'
        :'<button class=pbtn style="margin-top:6px'+(afford?'':';opacity:.5')+'" onclick="buyFurn(&#39;'+f.id+'&#39;)">Buy · $'+f.price.toLocaleString()+'</button>')
   +'</div>'}).join('');
 const ci=homeIdx();
 const hrows=HOMES.map((h,i)=>{const cur=i===ci,past=i<ci,afford=(G.wealth||0)>=h.buy;
  return '<div class=gloss style="'+(cur?'border-color:#3d8bff':'')+(past?';opacity:.45':'')+'">'
   +'<b>'+h.e+' '+h.n+'</b>'+(cur?' <span class=p-note style="color:#3d8bff">· where you live now</span>':'')
   +'<div class=gd>'+h.note+'</div>'
   +'<div class=gd>Move-in $'+h.buy.toLocaleString()+' · monthly <b>$'+h.monthly.toLocaleString()+'</b>'
   +(h.own&&h.equity?(' · $'+h.equity.toLocaleString()+' of that is equity you keep'):'')+'</div>'
   +((!cur&&!past)?'<button class=pbtn style="margin-top:6px'+(afford?'':';opacity:.5')+'" onclick="buyHome(&#39;'+h.id+'&#39;)">Move in · $'+h.buy.toLocaleString()+'</button>':'')
   +'</div>'}).join('');
 const H=curHome();
 $('shopbody').innerHTML='<div class=p-title>🛒 The Shop</div>'
  +'<div class=p-world style=margin-bottom:8px>Cash '+money(G.wealth||0)+((G.equity||0)>0?(' · Equity '+money(G.equity)):'')+' · Net worth '+money(netWorth())+'</div>'
  +'<p class=p-teach>Not every purchase is a bad purchase. Junk loses value the second you buy it. '
  +'Some things give back — light, safety, knowledge, a place to work. That is the difference between <b>spending</b> and <b>investing in yourself</b>.</p>'
  +'<div class=p-title style="font-size:17px;margin-top:14px">🎒 Gear & Knowledge</div>'+rows
  +'<div class=p-title style="font-size:17px;margin-top:14px">🛋️ Furniture for your room</div>'
  +'<div class=p-note style="margin-bottom:6px">Everything here shows up in your actual room at home.</div>'+frows
  +'<div class=p-title style="font-size:17px;margin-top:14px">🏠 Where you live</div>'
  +'<div class=p-note style="margin-bottom:6px">You pay this every single month. It is the biggest number in most peoples lives.</div>'+hrows
  +'<button class=pbtn style="margin-top:10px" onclick="hide(&#39;shop&#39;)">← Back to Money World</button>';
 $('shop').classList.add('show')}

// ============ HOME ============
// You always start here. Housing is most people's single biggest expense,
// so the ladder below is the real lesson: every upgrade buys comfort AND
// raises the bar you have to clear to be free.
// ============ TIME ============
// Everybody on earth gets the same 24 hours. Not 16, not 30. What separates
// people is what those hours get spent on — so the game runs a real clock.
const MIN_PER_SEC=8;                 // 1 real second = 8 game minutes -> a day is 3 real minutes
const MIN_PER_DAY=1440, DAYS_PER_MONTH=30, MONTHS_PER_YEAR=12, START_AGE=18;
const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const DAYNAMES=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
function tParts(){
 const t=(G.tmin||0)+8*60;           // everyone starts at 08:00 on day 1
 const totalDays=Math.floor(t/MIN_PER_DAY), mins=Math.floor(t%MIN_PER_DAY);
 const totalMonths=Math.floor(totalDays/DAYS_PER_MONTH);
 return {hour:Math.floor(mins/60),minute:mins%60,
  dayOfMonth:(totalDays%DAYS_PER_MONTH)+1,
  weekOfMonth:Math.floor((totalDays%DAYS_PER_MONTH)/7)+1,
  dayName:DAYNAMES[totalDays%7],
  month:(totalMonths%MONTHS_PER_YEAR),
  year:Math.floor(totalMonths/MONTHS_PER_YEAR)+1,
  totalDays,totalMonths,
  age:START_AGE+Math.floor(totalMonths/MONTHS_PER_YEAR)};}
function clockStr(){const p=tParts();
 return String(p.hour).padStart(2,'0')+':'+String(p.minute).padStart(2,'0');}
function dateStr(){const p=tParts();
 return p.dayName+' '+p.dayOfMonth+' '+MONTHS[p.month]+' · Yr '+p.year;}
// 0 = midnight, 1 = noon. Drives the sky, the fog and how far you can see.
function daylight(){const p=tParts(),h=p.hour+p.minute/60;
 return Math.max(0,Math.min(1,(Math.sin((h-6)/24*2*Math.PI)+1)/2));}
function isNight(){const h=tParts().hour;return h<6||h>=20}
// Sleeping skips to 7am - but only if you own a bed. Everything costs something.
function sleepTilMorning(){
 if(!ownsF('bed')){toast('😴 You have no bed yet. Buy one in the shop — sleep is not a luxury.');return}
 const p=tParts();const mins=((24-p.hour+7)%24)*60-p.minute;
 G.tmin=(G.tmin||0)+(mins<=0?mins+1440:mins);save();
 sfx('secret');toast('😴 You slept. It is '+clockStr()+' on '+dateStr()+'.')}
// ============ WHAT YOU DO WITH THE HOURS ============
// Every action costs time. Some pay today, some pay in 20 years, some never pay.
// Choosing between them IS the game.
// Your wage is not a constant. Every skill you pick up moves you up a tier,
// and the tier is what pays. This is the whole thesis of the game, so it has
// to be true in the numbers, not just in the text.
const WAGE_TIERS=[
 {s:0, w:140,n:'Entry level'},{s:5, w:200,n:'Junior'},{s:12,w:300,n:'Skilled'},
 {s:22,w:450,n:'Senior'},   {s:35,w:650,n:'Expert'},{s:50,w:900,n:'In demand'}];
const SKILL_CAP=50;
function wageTier(){let t=WAGE_TIERS[0];for(const x of WAGE_TIERS)if((G.skill||0)>=x.s)t=x;return t}
function wage(){return wageTier().w}
function nextTier(){return WAGE_TIERS.find(x=>x.s>(G.skill||0))||null}
// A side project takes real, repeated effort - 10 sessions - before it pays anything.
const BUILD_PER_PROJECT=10;
function projectsDone(){return Math.floor((G.buildPts||0)/BUILD_PER_PROJECT)}
function passiveIncome(){return projectsDone()*120}
// Life costs money even with no rent: food, phone, transport.
function livingCost(){return 700+homeIdx()*150}
function monthlyBurn(){return curHome().monthly+livingCost()}
function freedomNumber(){return monthlyBurn()*12*25}
// ============ FIRST FIVE MINUTES ============
// Everything in here already worked, but a new player landed in a bedroom with
// eleven buttons and no idea what any of it was for. This is the thread that
// connects them, in the order that teaches the thesis fastest.
const TUTORIAL=[
 {t:'🐷 SMASH the piggy bank',      w:'Walk straight into it.',                       chk:()=>!!G.smashed},
 {t:'💼 Work a shift → get paid',  w:'☰ Menu → Spend your day.',                   chk:()=>((G.acts&&G.acts.work)||0)>=1},
 {t:'📚 Study once',                w:'It pays $0 today. Watch what happens anyway.', chk:()=>(G.skill||0)>=1},
 {t:'📈 Study until your pay JUMPS', w:'5 sessions = Junior = $200 a shift.',          chk:()=>(G.skill||0)>=5},
 {t:'🚪 Get outside',               w:'Door at the bottom of your room.',             chk:()=>!atHome},
 {t:'⛏️ Smash a glowing block',        w:'Follow the beam of light.',                    chk:()=>Object.keys(G.done||{}).length>=1},
 {t:'🐺 Talk to an animal',         w:'Some help you. Some rob you.',                 chk:()=>!!G._talked},
 {t:'🛒 Buy something',             w:'Some things pay you back. Most do not.',       chk:()=>Object.keys(G.owned||{}).length+Object.keys(G.furn||{}).length>=1},
 {t:'📈 Call a REAL market',        w:'☰ Menu → Market Desk. Live prices.',          chk:()=>(G.predictions||[]).length>=1},
 {t:'🗽 Now go get rich',           w:'Freedom = 25x what you spend in a year.',      chk:()=>false},
];
function tutStep(){return TUTORIAL[Math.min(G.tut||0,TUTORIAL.length-1)]}
function renderQuest(){
 const q=$('quest');if(!q)return;
 if(G.tutSkipped){q.classList.remove('show');return}
 const i=Math.min(G.tut||0,TUTORIAL.length-1),st=TUTORIAL[i];
 const changed=($('qtext').textContent!==st.t);
 $('qtext').textContent=st.t;$('qwhy').textContent=st.w;
 if(changed)speak(st.t+'. '+st.w);
 $('qbar').style.width=Math.round(i/(TUTORIAL.length-1)*100)+'%';
 q.classList.add('show')}
function checkQuest(){
 if(G.tutSkipped)return;
 const i=G.tut||0;if(i>=TUTORIAL.length-1){renderQuest();return}
 let guard=0;
 while((G.tut||0)<TUTORIAL.length-1&&TUTORIAL[G.tut||0].chk()&&guard++<10){
  G.tut=(G.tut||0)+1;save();sfx('secret');confetti();
  toast('✅ '+TUTORIAL[G.tut-1].t.replace(/^[A-Z]/,c=>c)+' — done!')}
 renderQuest()}
function skipTutorial(){G.tutSkipped=1;save();$('quest').classList.remove('show');
 toast('Walkthrough hidden. Press ❔ any time for the controls.')}
const ACTIONS=[
 {id:'work',e:'💼',n:'Work a shift',hours:8,pay:'wage',
  d:'Reliable money, today.',
  lesson:'Trading hours for money works — but you only ever have 24 of them. This has a hard ceiling built in.'},
 {id:'overtime',e:'🌙',n:'Pick up overtime',hours:4,pay:'ot',
  d:'More money. Less of everything else.',
  lesson:'Overtime pays better per hour. It also eats exactly the hours you would use to build something that pays forever.'},
 {id:'study',e:'📚',n:'Study a skill',hours:4,pay:0,skill:1,
  d:'Pays $0 today.',
  lesson:'This is the one almost everyone skips, because it pays nothing today. It is also the one that changes your income for the rest of your life.'},
 {id:'build',e:'🛠️',n:'Build a side project',hours:6,pay:0,proj:1,
  d:'Pays $0 today. May pay every month, forever.',
  lesson:'Assets get built in the hours AFTER the work is done. That is the whole secret, and it is why it stays rare.'},
 {id:'gym',e:'🏋️',n:'Train',hours:2,pay:0,wp:1,
  d:'No money. More willpower.',
  lesson:'Discipline transfers. People who keep promises to themselves in the gym tend to keep them with money too.'},
 {id:'rest',e:'🎮',n:'Rest and play',hours:3,pay:0,
  d:'Pure recovery.',
  lesson:'Rest is not laziness. Burning out costs far more than the hours it saved.'},
 {id:'scroll',e:'📱',n:'Doomscroll',hours:3,pay:0,waste:1,
  d:'Three hours. Gone.',
  lesson:'The average person spends about 3 hours a day here. Over 40 years that is roughly 5 years of waking life, traded for nothing.'},
];
function doAction(id){const a=ACTIONS.find(x=>x.id===id);if(!a)return;
 G.tmin=(G.tmin||0)+a.hours*60;
 G.acts=G.acts||{};G.acts[a.id]=(G.acts[a.id]||0)+1;
 const payNow=a.pay==='wage'?wage():a.pay==='ot'?Math.round(wage()*0.75):(a.pay||0);
 if(payNow)G.wealth=(G.wealth||0)+payNow;
 if(a.skill)G.skill=Math.min(SKILL_CAP,(G.skill||0)+1);
 if(a.proj)G.buildPts=(G.buildPts||0)+1;
 if(a.wp)G.willpower=(G.willpower||0)+1;
 if(a.waste)G.wasted=(G.wasted||0)+a.hours;
 if(a.skill){const t=wageTier();if(G._tier!==t.n){G._tier=t.n;
   setTimeout(()=>{confetti();toast('📈 You are now '+t.n+' — every shift pays $'+t.w.toLocaleString()+' instead of $'+WAGE_TIERS[0].w+'.')},700)}}
 save();renderHUD();updateWP();sfx(payNow?'hit':'secret');
 const bits=[a.hours+'h gone'];
 if(payNow)bits.push('+$'+payNow.toLocaleString());
 if(a.skill)bits.push('+1 skill');
 if(a.wp)bits.push('+1 willpower');
 if(a.skill){const nt=nextTier();bits.push(nt?('skill '+G.skill+'/'+nt.s+' to '+nt.n):('skill maxed · '+wageTier().n))}
 if(a.proj){const inP=(G.buildPts||0)%BUILD_PER_PROJECT;
  bits.push('project '+(inP===0?'FINISHED':inP+'/'+BUILD_PER_PROJECT))}
 if(a.proj&&(G.buildPts||0)%BUILD_PER_PROJECT===0)setTimeout(()=>{confetti();
  toast('🚀 Side project #'+projectsDone()+' finished — it now pays you $120 every month, forever.')},800);
 toast(a.e+' '+bits.join(' · ')+' — it is now '+clockStr());
 openActions()}
function openActions(){paused=true;
 const p=tParts();
 const rows=ACTIONS.map(a=>{
  const col=a.pay?'#3fb950':(a.skill||a.proj)?'#3d8bff':a.waste?'#f85149':'#a371f7';
  const tag=a.pay?('Pays $'+a.pay+' now'):(a.skill||a.proj)?'Pays later':a.waste?'Never pays':'Pays in rest';
  return '<div class=gloss>'
   +'<b>'+a.e+' '+a.n+'</b> <span class=p-note style="color:'+col+'">· '+a.hours+' hours · '+tag+'</span>'
   +'<div class=gd>'+a.d+'</div><div class=gd style="color:#7fb4ff">'+a.lesson+'</div>'
   +'<button class=pbtn style="margin-top:6px" onclick="doAction(&#39;'+a.id+'&#39;)">Spend '+a.hours+' hours</button></div>'}).join('');
 $('shopbody').innerHTML='<div class=p-title>⏳ How will you spend the day?</div>'
  +'<div class=p-world style=margin-bottom:8px>'+clockStr()+' · '+dateStr()+' · you are '+p.age+'</div>'
  +'<p class=p-teach style="border-color:#3fb950"><b>'+wageTier().n+'</b> — a shift pays you <b>'+money(wage())+'</b>.'
  +(nextTier()?(' '+((nextTier().s)-(G.skill||0))+' more study sessions and it becomes '+money(nextTier().w)+'.'):' You have maxed your skill.')
  +'<br>Monthly burn <b>'+money(monthlyBurn())+'</b> · passive income <b>'+money(passiveIncome())+'</b> · freedom costs <b>'+money(freedomNumber())+'</b>.</p>'
  +'<p class=p-teach>Nobody gets 30 hours. Nobody gets 16. Everyone alive gets the same <b>24</b>. '
  +'The only difference between people is which of these they picked, over and over, for years.</p>'
  +(projectsDone()>0?'<p class=p-teach style="border-color:#3fb950">🚀 '+projectsDone()+' finished side project(s) pay you '+money(passiveIncome())+' every month — whether you show up or not.</p>':'')
  +((G.wasted||0)>=12?'<p class=p-teach style="border-color:#f85149">You have scrolled away <b>'+G.wasted+' hours</b> so far. That is '+Math.round(G.wasted/8)+' full working days.</p>':'')
  +rows+'<button class=pbtn style="margin-top:10px" onclick="hide(&#39;shop&#39;)">← Back to Money World</button>';
 $('shop').classList.add('show')}
const HOMES=[
 {id:'parents',n:"Mom & Dad's House",e:'🏠',buy:0,monthly:0,own:false,slots:5,w:16,d:14,
  note:'Rent-free. Boring, maybe. But every month here is a month of full savings — this is the biggest head start there is.'},
 {id:'dorm',n:'Dorm Room',e:'🛏️',buy:600,monthly:450,own:false,slots:6,w:18,d:15,
  note:'Small and cheap. Low expenses early is worth more than square footage.'},
 {id:'apartment',n:'Apartment',e:'🏢',buy:1800,monthly:1100,own:false,slots:8,w:22,d:18,
  note:'Your own place. Rent buys freedom of choice, but builds you no equity at all.'},
 {id:'condo',n:'Condo',e:'🏘️',buy:9000,monthly:1600,equity:500,own:true,slots:10,w:26,d:20,
  note:'You own it. About a third of the payment now builds EQUITY instead of vanishing.'},
 {id:'house',n:'House',e:'🏡',buy:26000,monthly:2200,equity:800,own:true,slots:13,w:30,d:24,
  note:'A real home. Bigger payment, bigger equity — and a bigger freedom number.'},
 {id:'bighouse',n:'The Big House',e:'🏰',buy:70000,monthly:3400,equity:1200,own:true,slots:16,w:36,d:28,
  note:'The dream house. Ask yourself honestly whether it is buying you freedom or costing it.'},
];
function homeIdx(){const i=HOMES.findIndex(h=>h.id===(G.home||'parents'));return i<0?0:i}
function curHome(){return HOMES[homeIdx()]}
// Furniture. Some of it helps you. Most of it just loses value quietly.
const FURN=[
 {id:'bed',e:'🛏️',n:'Bed',price:250,cat:'need',b:'bed',
  lesson:'A need. Sleep is not optional, and a cheap good bed beats an expensive bad one.'},
 {id:'desk',e:'🪑',n:'Desk & Chair',price:200,cat:'asset',b:'desk',
  lesson:'An ASSET in disguise — somewhere to study or work is where your earning power gets built.'},
 {id:'shelf',e:'📚',n:'Bookshelf',price:180,cat:'asset',b:'shelf',
  lesson:'Books you actually read pay for themselves hundreds of times over.'},
 {id:'lamp',e:'💡',n:'Lamp',price:60,cat:'need',b:'lamp',lesson:'Cheap, useful, done. Not everything has to be a decision.'},
 {id:'rug',e:'🟦',n:'Rug',price:120,cat:'fun',b:'rug',lesson:'Makes the place yours. Costs a little, returns nothing. That is fine — just know which is which.'},
 {id:'plant',e:'🪴',n:'Plant',price:40,cat:'fun',b:'plant',lesson:'Small joy, small price. Good trade.'},
 {id:'dresser',e:'🗄️',n:'Dresser',price:220,cat:'need',b:'dresser',lesson:'Storage. Useful, boring, holds its value better than anything with a screen.'},
 {id:'tv',e:'📺',n:'Big TV',price:900,cat:'bad',b:'tv',
  lesson:'Worth about $300 in three years. A TV is a liability that also eats the hours you could earn in.'},
 {id:'console',e:'🎮',n:'Game Console',price:600,cat:'bad',b:'console',
  lesson:'Fun is allowed! Just buy it with money you already have, never on a payment plan.'},
 {id:'beanbag',e:'🫘',n:'Bean Bag',price:150,cat:'fun',b:'beanbag',lesson:'Comfort is not a crime. Budget for it on purpose and enjoy it guilt-free.'},
 {id:'toys',e:'🧸',n:'Toys & Games',price:130,cat:'fun',b:'toys',lesson:'Things you love are part of a good life. The trap is buying them to feel better after a bad day.'},
 {id:'poster',e:'🖼️',n:'Posters',price:50,cat:'fun',b:'poster',lesson:'Cheap personality. Best value in the whole shop.'},
];
function ownsF(id){return !!(G.furn&&G.furn[id])}
// ---- furniture meshes (blocky, to match everything else) ----
function fBuild(kind,x,z,par){const g=new THREE.Group();g.position.set(x,0,z);
 if(kind==='bed'){const f=box(2.6,0.45,4.4,0x6b4a2a);f.position.y=0.35;g.add(f);
  const m=box(2.4,0.4,4.0,0xeae2d0);m.position.y=0.72;g.add(m);
  const p=box(1.6,0.28,0.7,0xffffff);p.position.set(0,0.98,-1.5);g.add(p);
  const q=box(2.42,0.16,2.6,0x3d6bb5);q.position.set(0,0.96,0.7);g.add(q)}
 else if(kind==='tv'){const st=box(2.6,0.6,0.7,0x4a3a2a);st.position.y=0.3;g.add(st);
  const sc=box(3.4,1.9,0.16,0x11151c);sc.position.y=1.6;g.add(sc);
  const gl=box(3.1,1.6,0.04,0x2b4a7a);gl.position.set(0,1.6,0.11);g.add(gl)}
 else if(kind==='dresser'){const b=box(2.2,1.5,0.9,0x8a6a44);b.position.y=0.75;g.add(b);
  [0.45,1.05].forEach(y=>{const d=box(1.9,0.42,0.06,0x6b5030);d.position.set(0,y,0.48);g.add(d)})}
 else if(kind==='desk'){const t=box(2.4,0.14,1.1,0x9a7a52);t.position.y=1.0;g.add(t);
  [[-1.05,-0.45],[1.05,-0.45],[-1.05,0.45],[1.05,0.45]].forEach(p=>{const l=box(0.14,1.0,0.14,0x6b5030);l.position.set(p[0],0.5,p[1]);g.add(l)});
  const ch=box(0.9,0.12,0.9,0x3a4a6a);ch.position.set(0,0.6,1.2);g.add(ch);
  const bk=box(0.9,0.9,0.12,0x3a4a6a);bk.position.set(0,1.05,1.6);g.add(bk)}
 else if(kind==='shelf'){const b=box(1.9,2.4,0.5,0x7a5a38);b.position.y=1.2;g.add(b);
  [0.6,1.2,1.8].forEach((y,i)=>{const sh=box(1.8,0.09,0.46,0x5a4028);sh.position.set(0,y,0.02);g.add(sh);
   for(let k=0;k<5;k++){const bk=box(0.16,0.42,0.3,[0xd64f6a,0x3fb950,0x3d8bff,0xf0b429,0xa371f7][k%5]);
    bk.position.set(-0.7+k*0.32,y+0.26,0.06);g.add(bk)}})}
 else if(kind==='beanbag'){const b=new THREE.Mesh(new THREE.SphereGeometry(0.85,12,10),new THREE.MeshLambertMaterial({color:0xd64f6a}));
  b.scale.set(1,0.62,1);b.position.y=0.5;g.add(b)}
 else if(kind==='console'){const b=box(0.9,0.22,0.6,0x1b2230);b.position.y=0.72;g.add(b);
  const c1=box(0.3,0.12,0.22,0x3d8bff);c1.position.set(-0.6,0.68,0.4);g.add(c1);
  const c2=box(0.3,0.12,0.22,0xd64f6a);c2.position.set(0.6,0.68,0.4);g.add(c2);
  const t=box(1.4,0.6,0.7,0x4a3a2a);t.position.y=0.3;g.add(t)}
 else if(kind==='toys'){for(let k=0;k<7;k++){const c=box(0.32,0.32,0.32,[0xf0b429,0x3fb950,0x3d8bff,0xd64f6a,0xa371f7][k%5]);
  c.position.set((Math.random()-0.5)*2.2,0.16+(k%2)*0.34,(Math.random()-0.5)*1.6);g.add(c)}
  const bear=box(0.5,0.7,0.4,0xb08a5a);bear.position.set(0.7,0.35,0.4);g.add(bear)}
 else if(kind==='rug'){const r=new THREE.Mesh(new THREE.PlaneGeometry(5,4),new THREE.MeshLambertMaterial({color:0x3a5a8a}));
  r.rotation.x=-Math.PI/2;r.position.y=0.03;g.add(r)}
 else if(kind==='lamp'){const p=box(0.14,2.0,0.14,0x6a6a72);p.position.y=1.0;g.add(p);
  const sh=cone(0.55,0.7,0xffe9a8);sh.position.y=2.2;g.add(sh)}
 else if(kind==='plant'){const p=box(0.5,0.5,0.5,0xb0653a);p.position.y=0.25;g.add(p);
  const l=box(0.9,1.2,0.9,0x2f8a4a);l.position.y=1.1;g.add(l)}
 else if(kind==='poster'){const q=new THREE.Mesh(new THREE.PlaneGeometry(1.6,2.1),new THREE.MeshLambertMaterial({color:0xf0b429}));
  q.position.set(0,2.6,0);g.add(q)}
 par.add(g);return g}
const SUBB=[
 {n:'Meadow',g:0x4a9a58,f:(x,z,p)=>{addTree(x,z,0x2f7d3a,p)}},
 {n:'Rocky Flats',g:0x8a8272,f:(x,z,p)=>{const h=1+Math.random()*1.7;const b=box(1.7,h,1.7,0x77716a);b.position.set(x,h/2,z);p.add(b)}},
 {n:'Ruins',g:0x9a9484,f:(x,z,p)=>{const h=2+Math.random()*2.4;const c=box(1,h,1,0xc8c0ac);c.position.set(x,h/2,z);p.add(c);const t=box(1.35,0.3,1.35,0xb0a894);t.position.set(x,h,z);p.add(t)}},
 {n:'Oasis',g:0x3f8f7a,f:(x,z,p)=>{const w=new THREE.Mesh(new THREE.PlaneGeometry(5,5),new THREE.MeshLambertMaterial({color:0x2a8ad0}));w.rotation.x=-Math.PI/2;w.position.set(x,0.05,z);p.add(w);const t=box(0.4,2.4,0.4,0x6b4a2a);t.position.set(x+2.6,1.2,z);p.add(t);const l=box(2,0.4,2,0x2f8a4a);l.position.set(x+2.6,2.5,z);p.add(l)}},
 {n:'Crystal Hollow',g:0x5a4a8a,f:(x,z,p)=>{const c=cone(0.8,2.6+Math.random()*1.7,0x9a7aff);c.position.set(x,1.6,z);p.add(c)}},
 {n:'Dunes',g:0xc8a86a,f:(x,z,p)=>{const c=box(0.7,2.2,0.7,0x3f8a4a);c.position.set(x,1.1,z);p.add(c);const a=box(1.8,0.6,0.6,0x3f8a4a);a.position.set(x,1.6,z);p.add(a)}},
 {n:'Frostfield',g:0xdfe9f5,f:(x,z,p)=>{const c=cone(1,2.8,0x2a5a3a);c.position.set(x,1.4,z);p.add(c);const s=cone(0.62,0.9,0xffffff);s.position.set(x,2.6,z);p.add(s)}},
 {n:'Emberwaste',g:0x6a3a30,f:(x,z,p)=>{const b=box(1.8,1.2,1.8,0x3a2a26);b.position.set(x,0.6,z);p.add(b);const l=new THREE.Mesh(new THREE.PlaneGeometry(3,3),new THREE.MeshBasicMaterial({color:0xff6a3a}));l.rotation.x=-Math.PI/2;l.position.set(x,0.06,z);p.add(l)}},
 {n:'Mushroom Grove',g:0x4a6a4a,f:(x,z,p)=>{const st=box(0.5,1.6,0.5,0xe8dcc0);st.position.set(x,0.8,z);p.add(st);const cp=cone(1.5,1.4,0xd64f6a);cp.position.set(x,2.2,z);p.add(cp)}},
 {n:'Marsh',g:0x4a6a58,f:(x,z,p)=>{const w=new THREE.Mesh(new THREE.PlaneGeometry(6,6),new THREE.MeshLambertMaterial({color:0x3a6a5a}));w.rotation.x=-Math.PI/2;w.position.set(x,0.05,z);p.add(w);for(let k=0;k<4;k++){const r=box(0.16,1.8,0.16,0x6a8a4a);r.position.set(x+(Math.random()-0.5)*4,0.9,z+(Math.random()-0.5)*4);p.add(r)}}}
];
// obstacle kit — break it, climb it, or go around it
// Some things in your way you can shove aside. Some you never will —
// you go over them, or you go around. Knowing which is which is the skill.
function pushWall(w,dx,dz){
 if(!w||!w.movable||w.broken)return false;
 const step=0.22,nx=w.x+dx*step,nz=w.z+dz*step;
 if(nx<BND.x0+2||nx>BND.x1-2||nz<BND.z0+2||nz>BND.z1-2)return false;
 for(const o of walls){if(o===w||o.broken)continue;
  if(Math.abs(nx-o.x)<w.hw+o.hw-0.05&&Math.abs(nz-o.z)<w.hd+o.hd-0.05)return false}
 w.x=nx;w.z=nz;
 if(w.mesh)w.mesh.position.set(nx,w.mesh.position.y,nz);
 if(w.cap)w.cap.position.set(nx,w.cap.position.y,nz);
 if(w.spr)w.spr.position.set(nx,w.spr.position.y,nz);
 return true}
// A mountain: stacked tiers, each a walk-up step. Big enough to see the whole
// level from the top, and impossible to move.
function buildMountain(x,z,par,scale){
 const S=scale||1,tiers=[[13*S,1.4],[10*S,2.8],[7.4*S,4.2],[5*S,5.6],[2.8*S,7.0]];
 tiers.forEach((t,k)=>{
  const w=bigWall(x,z,t[0],t[0],{h:t[1],solid:1,immovable:1,
   col:k<2?0x6a7280:k<4?0x7b8290:0xe8eef6,cap:k<4?0x4a515e:0xffffff,kind:'mountain'})});
 const flag=makeLabel('SUMMIT','⛰️');flag.position.set(x,8.6,z);flag.scale.set(6,3,1);par.add(flag)}
function obstacle(kind,x,z,lv){
 if(kind==='crate')   return bigWall(x,z,2.6,2.6,{h:2.2,solid:1,movable:1,col:0xa8814e,cap:0x7a5c34,kind:'crate'});
 if(kind==='barrel')  return bigWall(x,z,2.2,2.2,{h:2.4,solid:1,movable:1,col:0x8a6a3a,cap:0x5f4726,kind:'barrel'});
 if(kind==='bedrock') return bigWall(x,z,4.2,4.2,{h:5.2,solid:1,immovable:1,col:0x3f4652,cap:0x2a3038,kind:'bedrock'});
 if(kind==='rubble')   return bigWall(x,z,2.4,2.4,{h:1.6,hp:2+lv,col:0x8a7a6a,cap:0x6a5a4a,kind:'rubble'});
 if(kind==='barricade')return bigWall(x,z,6,1.4,{h:2.7,hp:4+lv*2,col:0x7a5a3a,cap:0x5a4028,kind:'barricade'});
 if(kind==='boulder')  return bigWall(x,z,3,3,{h:3.2,solid:1,col:0x6a6a72,cap:0x4a4a52,kind:'boulder'});
 if(kind==='ledge')    return bigWall(x,z,4.6,4.6,{h:2.0,solid:1,col:0x7a6a58,cap:0x5a4a3a,kind:'ledge'});
 if(kind==='tower')    return bigWall(x,z,2.2,2.2,{h:5.5,solid:1,col:0x5a5a66,cap:0x3a3a46,kind:'tower'});
 return null}
// a two-step staircase — hop 0->2->4 then jump the 6-high rampart
function climbSteps(x,z,dx,dz){
 // (dx,dz) points AWAY from the wall, into the room. Tallest step sits against
 // the wall, shortest is furthest out - so walking toward the wall you go
 // 1.3 -> 2.6 -> 3.9 -> 5.2 -> and auto-step straight onto the 6-high rampart.
 [5.2,3.9,2.6,1.3].forEach((h,k)=>{const d=2.6+k*3.0;
  bigWall(x+dx*d,z+dz*d,3.4,3.4,{h,solid:1,col:k%2?0x6a5a48:0x7a6a58,cap:0x4a3a2a,kind:'step'})});}
function nearGateSpot(x,z,r){for(const g of gateSpots)if(Math.hypot(g.x-x,g.z-z)<r)return true;return false}

function biomeItem(wi,x,z,par){if(wi===0)addTree(x,z,0x2f7d3a,par);else if(wi===1){const r=box(1.4,1,1.4,0x8a6a3a);r.position.set(x,0.5,z);par.add(r)}else if(wi===2){const h=3+Math.random()*3;const b=box(1.4,h,1.4,0x5a6272);b.position.set(x,h/2,z);par.add(b)}else if(wi===3){const t=box(0.4,2,0.4,0x6b4a2a);t.position.set(x,1,z);par.add(t);const l=box(1.6,0.5,1.6,0x2f8a4a);l.position.set(x,2.1,z);par.add(l)}else{const c=cone(0.9,2.2,0x2a5a3a);c.position.set(x,1.1,z);par.add(c)}}
function closeNPC(){$('npc').classList.remove('show');paused=false}
function claimQuest(w){const q=NPCS.find(n=>n.world===w).quest;if(!q||G.qclaim[w])return;G.qclaim[w]=1;addWealth(q.reward);sfx('tool');closeNPC();toast('🎁 Quest complete! +$'+q.reward.toLocaleString())}
function takeDeal(){const n=nearNPC;if(!n||!n.deal||G.met[n.id])return;G.met[n.id]=1;
 const d=n.deal;G.wealth=Math.max(0,(G.wealth||0)-d.cost);save();renderHUD();sfx('hit');
 $('npcbody').innerHTML='<div class=p-badge>'+n.e+'</div><div class=p-world>💸 That cost you</div><div class=p-title>'+n.name+'</div>'
  +'<p class=p-teach>'+d.take+'</p>'
  +'<p class=p-teach style="border-color:#f85149">-$'+d.cost.toLocaleString()+'</p>'
  +'<p class=p-teach style="border-color:#7fb4ff"><b>The lesson:</b> '+d.lesson+'</p>'
  +'<button class=pbtn onclick="closeNPC()">Noted →</button>'}
function walkAway(){const n=nearNPC;if(!n||!n.deal||G.met[n.id])return;G.met[n.id]=1;
 const d=n.deal;G.willpower=(G.willpower||0)+1;updateWP();save();sfx('secret');confetti();
 $('npcbody').innerHTML='<div class=p-badge>🛡️</div><div class=p-world>You saw through it</div><div class=p-title>'+n.name+'</div>'
  +'<p class=p-teach>'+d.walk+'</p>'
  +'<p class=p-teach style="border-color:#3fb950">+1 willpower 💪</p>'
  +'<p class=p-teach style="border-color:#7fb4ff"><b>The lesson:</b> '+d.lesson+'</p>'
  +'<button class=pbtn onclick="closeNPC()">Keep going →</button>'}
function talkNPC(){const n=nearNPC;if(!n)return;G._talked=1;
 if(n.deal){paused=true;
  const seen=!!G.met[n.id],smart=streetSmarts()>=4,warn=(n.obvious||smart);
  $('npcbody').innerHTML='<div class=p-badge>'+n.e+'</div>'
   +'<div class=p-world>'+(warn?'⚠️ Something is off about this one':'A friendly stranger')+'</div>'
   +'<div class=p-title>'+n.name+'</div>'
   +'<p class=p-teach>&ldquo;'+n.deal.pitch+'&rdquo;</p>'
   +(warn&&!n.obvious?'<div class=p-note>Your reading paid off — you can tell this is a bad deal. Keep learning and more of them light up.</div>':'')
   +(seen?'<p class=p-teach style="border-color:#3fb950">You already know how this one ends.</p><button class=pbtn onclick="closeNPC()">Move along →</button>'
         :'<button class=pbtn style="background:#3a1f1f;border-color:#6a2a2a" onclick="takeDeal()">Take the deal · -$'+n.deal.cost.toLocaleString()+'</button>'
          +'<button class=pbtn onclick="walkAway()">Walk away 🚶</button>');
  return}
 if(!n.lines)return;paused=true;const l=n.lines[Math.floor(Math.random()*n.lines.length)];const q=n.quest,done=q?!!q.chk():false,claimed=q?!!G.qclaim[n.world]:false;
 const qbox=q?('<div class=p-teach style="text-align:left;border-color:#f0b429"><b>📜 Quest:</b> '+q.t+'<br>'+(claimed?'<span style=color:#3fb950>✓ Completed &amp; claimed</span>':done?'<span style=color:#3fb950>✓ Done! Claim your reward below.</span>':'⏳ In progress — reward: $'+q.reward.toLocaleString())+'</div>'):'';
 const btn=(q&&done&&!claimed)?'<button class=pbtn onclick=claimQuest('+n.world+')>🎁 Claim $'+q.reward.toLocaleString()+'</button>':'<button class=pbtn onclick=closeNPC()>Thanks! 🙏</button>';
 $('npcbody').innerHTML='<div class=p-badge>'+n.e+'</div><div class=p-world>'+(q?'Your Mentor':'A Traveller')+'</div><div class=p-title>'+n.name+'</div><p class=p-teach>&ldquo;'+l+'&rdquo;</p>'+qbox+btn}
function openTempt(tm){paused=true;curTempt=tm;
 $('tbody').innerHTML='<div class=p-badge>'+tm.e+'</div><div class=p-world>💸 Temptation!</div><div class=p-title>'+tm.name+'</div><p class=p-teach>A shiny '+tm.name+' for $'+tm.price.toLocaleString()+'. Buy it now for a quick thrill... or keep saving and let your money grow?</p><div class=calls><button class=down onclick=buyTempt()>Buy it (-$'+tm.price.toLocaleString()+')</button><button class=up onclick=resistTempt()>Resist &amp; save 💪</button></div>';
 $('tempt').classList.add('show')}
function buyTempt(){const tm=curTempt;G.tempts[tm.id]=1;G.wealth=Math.max(0,(G.wealth||0)-tm.price);save();renderHUD();sfx('hit');$('tempt').classList.remove('show');paused=false;if(tm.spr){worldGroup.remove(tm.spr);tm.spr=null}toast('💸 You spent $'+tm.price.toLocaleString()+'. '+tm.lesson)}
function resistTempt(){const tm=curTempt;G.tempts[tm.id]=1;G.willpower=(G.willpower||0)+1;updateWP();save();sfx('secret');confetti();$('tempt').classList.remove('show');paused=false;if(tm.spr){worldGroup.remove(tm.spr);tm.spr=null}toast('💪 Willpower +1! You kept your money working. Delayed gratification wins.')}
function updateExtras(t){
 // run the clock (paused time does not count)
 if(!paused){const now=t;if(!_lastT)_lastT=now;
  const dt=Math.min(0.2,(now-_lastT)/1000);_lastT=now;
  G.tmin=(G.tmin||0)+dt*MIN_PER_SEC;
  const p=tParts();
  if(p.totalMonths>(G.lastMonth||0)){G.lastMonth=p.totalMonths;passMonth();}
  if(p.year>(G.lastYear||1)){G.lastYear=p.year;birthday(p);}
  const cl=$('hclock');if(cl)cl.textContent=clockStr();
  const dEl=$('hdate');if(dEl)dEl.textContent=' · '+dateStr();
 } else {_lastT=0}
 const k=daylight();
 if(scene){const c=new THREE.Color(SKY[curWi]||0x8ecbff).lerp(new THREE.Color(0x243a66),(1-k)*0.85);scene.background=c;if(scene.fog)scene.fog.color=c}
 // nights get genuinely dark — unless you bought a lantern
 if(ambLight&&atHome){ambLight.intensity=0.95;if(sunLight)sunLight.intensity=0.5}
 else if(ambLight){const dark=1-k,lamp=owns('lantern');
  ambLight.intensity=lamp?0.88:(0.82-dark*0.46);
  if(sunLight)sunLight.intensity=0.68-dark*0.4;
  if(lamp&&!lampLight){lampLight=new THREE.PointLight(0xffd9a0,1.15,26);scene.add(lampLight)}
  if(lampLight&&hero)lampLight.position.set(hero.position.x,3.2,hero.position.z)}
 if(!paused){
  for(let i=coins.length-1;i>=0;i--){const c=coins[i];c.mesh.rotation.y+=0.09;c.mesh.position.y=0.9+Math.sin(t*0.004+c.x)*0.16;if(Math.hypot(c.x-pos.x,c.z-pos.z)<1.7){worldGroup.remove(c.mesh);coins.splice(i,1);G.coins[c.id]=1;G.coinCount=(G.coinCount||0)+1;addWealth(50);sfx('hit')}}
  for(const tm of tempts){if(G.tempts[tm.id]||tm.x==null)continue;if(tm.spr)tm.spr.position.y=1.5+Math.sin(t*0.003+tm.x)*0.2;if(Math.hypot(tm.x-pos.x,tm.z-pos.z)<2.5){openTempt(tm);break}}
  // the piggy bank: walk into it and it breaks. no reading required.
  if(atHome&&homeSmash&&!G.smashed){
   const g=homeSmash.g;g.rotation.y=Math.sin(t*0.003)*0.25;
   g.position.y=Math.abs(Math.sin(t*0.004))*0.18;
   if(_pigCool>0)_pigCool--;
   if(Math.hypot(homeSmash.x-pos.x,homeSmash.z-pos.z)<3.2){
    $('hint').classList.add('show');$('hint').textContent='🐷 Walk into it! Or press ↵ ENTER';$('bE').classList.add('on')}}
  // step through the front door and you are out in the world
  if(atHome&&homeBed&&Math.hypot(homeBed.x-pos.x,homeBed.z-pos.z)<2.6&&nearGate<0){
   $('hint').classList.add('show');$('hint').textContent='😴 Press ↵ ENTER to sleep until morning';$('bE').classList.add('on')}
  if(atHome&&homeDoor&&Math.hypot(homeDoor.x-pos.x,homeDoor.z-pos.z)<2.4){goOutside();return}
  // opportunities: only reachable if you climbed up to them
  for(const o of opps){if(G.opps[o.id])continue;
   if(o.mesh){o.mesh.rotation.y+=0.03;o.mesh.position.y=o.y+Math.sin(t*0.004+o.x)*0.15}
   if(Math.hypot(o.x-pos.x,o.z-pos.z)<1.9&&heroY>o.y-1.7)takeOpp(o)}
  // minefield: reveal what you've learned to see, and set off what you step on
  {const sense=mineSense();
   for(const m of mines){if(G.mines[m.id])continue;
    const dd=Math.hypot(m.x-pos.x,m.z-pos.z);
    const vis=dd<sense;if(m.disc)m.disc.visible=vis;if(m.spr){m.spr.visible=vis;m.spr.position.y=1.5+Math.sin(t*0.005+m.x)*0.15}
    if(dd<1.5){hitMine(m);break}}}
  nearNPC=null;{let bd=3.8;for(const n of npcs){const dd=Math.hypot(n.x-pos.x,n.z-pos.z);if(dd<bd){bd=dd;nearNPC=n}}}
  if(nearNPC){$('hint').classList.add('show');
   $('hint').textContent=(nearNPC.deal?'💬 Press ↵ ENTER to hear out '+nearNPC.name:'💬 Press ↵ ENTER to talk to '+nearNPC.name);
   $('bE').classList.add('on')}
 }
 for(const n of npcs){if(n.mesh)n.mesh.rotation.y=Math.sin(t*0.001+(n.x||0)*0.1)*0.3}
 drawMini()}
function drawMini(){const mc=$('mini');if(!mc)return;const g=mc.getContext('2d'),S=mc.width;g.clearRect(0,0,S,S);g.fillStyle='rgba(10,16,30,.55)';g.beginPath();g.arc(S/2,S/2,S/2,0,7);g.fill();
 const _w=Math.max(70,Math.max(BND.x1-BND.x0,BND.z1-BND.z0)+10),sc=S/_w,_ox=(BND.x0+BND.x1)/2,_oz=(BND.z0+BND.z1)/2;
 function P(x,z){return[S/2+(x-_ox)*sc,S/2+(z-_oz)*sc]}
 for(const b of blocks){const d=b.userData.d;if(!b.visible)continue;const st=doorState(d);g.fillStyle=st==='done'?'#f0b429':d.s.isBoss?'#f05a4a':'#3d8bff';const p=P(d.px,d.pz);g.fillRect(p[0]-2,p[1]-2,4,4)}
 g.fillStyle='#ffd54a';for(const s of curSecrets){if(G.secrets[s.id])continue;const p=P(s.x,s.z);g.beginPath();g.arc(p[0],p[1],2,0,7);g.fill()}
 g.fillStyle='#f5d76e';for(const c of coins){const p=P(c.x,c.z);g.fillRect(p[0]-1,p[1]-1,2,2)}
 g.fillStyle='#ff7a3a';{const sense=mineSense();for(const m of mines){if(G.mines[m.id])continue;
   if(Math.hypot(m.x-pos.x,m.z-pos.z)>sense)continue;const p=P(m.x,m.z);g.fillRect(p[0]-1.5,p[1]-1.5,3,3)}}
 g.fillStyle='#f85149';for(const tm of tempts){if(G.tempts[tm.id]||tm.x==null)continue;const p=P(tm.x,tm.z);g.beginPath();g.arc(p[0],p[1],2,0,7);g.fill()}
 for(const n of npcs){const p=P(n.x,n.z);
   g.fillStyle=n.quest?'#b18aff':(n.deal?((n.obvious||streetSmarts()>=4)?'#f85149':'#6fd3a0'):'#6fd3a0');g.beginPath();g.arc(p[0],p[1],n.quest?2.8:2,0,7);g.fill()}
 const pp=P(pos.x,pos.z);g.fillStyle='#43d17a';g.beginPath();g.arc(pp[0],pp[1],3,0,7);g.fill();g.strokeStyle='#43d17a';g.lineWidth=1.5;g.beginPath();g.moveTo(pp[0],pp[1]);g.lineTo(pp[0]+Math.sin(heading)*8,pp[1]+Math.cos(heading)*8);g.stroke()}
function loop(){const t=performance.now();update(t);if(renderer)renderer.render(scene,camera);requestAnimationFrame(loop)}
if(window.THREE){initWorld();if(typeof loadHome==='function')loadHome();paused=true;$('help').classList.add('show')}else{setTimeout(()=>toast('3D engine did not load — check internet and refresh'),400)}

/* ===== challenges (shared engine) ===== */
let bossQ=0;
function tryEnter(){if(paused||nearGate<0)return;openChallenge(nearGate)}
function opts(arr,fn,i){return arr.map((c,k)=>`<button class=opt onclick="${fn}(${i},${k})">${String.fromCharCode(65+k)}.  ${c}</button>`).join('')}
function hdr(s){return `<div class=p-badge>${s.isBoss?s.boss.enemy:s.ic}</div><div class=p-world>Level ${s.level+1} · ${WORLDS[s.wi].name}${s.isBoss?' · BOSS':''}</div><div class=p-title>${s.isBoss?s.boss.name:s.title}</div><div class="p-tag diff${s.diff}">Difficulty ${s.diff}/5</div>`}
function openChallenge(i){paused=true;G.cur=i;bossQ=0;const s=STAGES[i];$('cpanel').classList.toggle('boss',!!s.isBoss);
 let b=hdr(s);
 if(s.type==='vocab'){b+=`<div class=p-teach style=text-align:center>What does this word mean?</div><div class=vword>${s.term}</div>`+opts(s.choices,'pick',i)}
 else if(s.type==='mc'){b+=`<p class=p-teach>${s.teach}</p><div class=p-q>${s.q}</div>`+opts(s.choices,'pick',i)}
 else if(s.type==='read'){b+=`<p class=p-teach>${s.passage}</p><div class=p-q>${s.q}</div>`+opts(s.choices,'pick',i)}
 else if(s.type==='tf'){if(s.teach)b+=`<p class=p-teach>${s.teach}</p>`;
  const bT=`<button class=up onclick="tfAns(${i},1)">✓ True</button>`,bF=`<button class=down onclick="tfAns(${i},0)">✗ False</button>`;
  b+=`<div class=p-q>${s.q}</div><div class=calls>${s.tfFlip?bF+bT:bT+bF}</div>`}
 else if(s.type==='fill'){if(s.teach)b+=`<p class=p-teach>${s.teach}</p>`;b+=`<div class=p-q>${s.prompt}</div><input id=fillin class=fillin autocomplete=off placeholder="type your answer" onkeydown="if(event.key==='Enter'){event.stopPropagation();fillAns(${i})}"><button class=pbtn onclick="fillAns(${i})">Submit</button>`}
 else if(s.type==='scenario'){b+=`<p class=p-teach>${s.setup}</p>`+s.options.map((o,k)=>`<button class=opt onclick="scenAns(${i},${k})">${o.label}</button>`).join('')}
 else if(s.type==='predict'){const a=CAT.assets.find(x=>x.id===s.asset);b+=`<p class=p-teach>${s.teach}</p>`+assetCard(a)}
 else if(s.type==='boss'){b+=`<p class=p-teach>${s.boss.intro}</p><div id=bosswrap></div>`}
 $('cbody').innerHTML=b;
 if(G.narrate){const rb=document.createElement('div');rb.className='readbtn';rb.textContent='🔊 Read it to me';
  rb.onclick=readChallenge;$('cbody').insertBefore(rb,$('cbody').firstChild);setTimeout(readChallenge,250)}
 $('challenge').classList.add('show');
 if(s.type==='fill')setTimeout(()=>{const el=$('fillin');if(el)el.focus()},60);
 if(s.type==='boss')renderBossQ()}
function closeChallenge(){stopSpeak();$('challenge').classList.remove('show');paused=false}
function pick(i,k){if(k!==STAGES[i].a){toast('Not quite — read the clue again and retry.');return}complete(i)}
function tfAns(i,v){if((!!v)!==(!!STAGES[i].a)){toast('Not quite — think it through and retry.');return}complete(i)}
function norm(s){return (s||'').toLowerCase().trim().replace(/[^a-z0-9 ]/g,'')}
function fillAns(i){const s=STAGES[i];const v=norm(($('fillin')||{}).value);const ok=[s.answer].concat(s.accept||[]).some(a=>norm(a)===v);if(!ok){toast('Close! Re-read the hint and try again.');return}complete(i)}
function scenAns(i,k){const o=STAGES[i].options[k];if(!o.ok){toast(o.outcome||'Try another choice.');return}complete(i)}
function renderBossQ(){const s=STAGES[G.cur],B=s.boss,total=B.questions.length,remain=total-bossQ,q=B.questions[bossQ];
 const hp=Array.from({length:total},(_,k)=>`<div class="hpseg ${k>=remain?'gone':''}"></div>`).join('');
 $('bosswrap').innerHTML=`<div class=arena><div class=enemy id=enemy>${B.enemy}</div><div class=ename>${B.name}</div><div class=hpwrap>${hp}</div><div class=hplbl>HP ${remain}/${total}</div></div><div class=bossp>Attack ${bossQ+1} of ${total} — answer to strike!</div><div class=p-q>${q.q}</div>`+q.choices.map((c,k)=>`<button class=opt onclick="bossPick(${k})">${String.fromCharCode(65+k)}.  ${c}</button>`).join('')}
function bossPick(k){const s=STAGES[G.cur],B=s.boss,q=B.questions[bossQ];const en=$('enemy');
 if(k!==q.a){if(en){en.classList.remove('atk');void en.offsetWidth;en.classList.add('atk')}$('cpanel').classList.remove('shake');void $('cpanel').offsetWidth;$('cpanel').classList.add('shake');toast('💥 '+B.name+' strikes back! Try again.');return}
 if(q.word&&!G.glossary[q.word.t])G.glossary[q.word.t]=q.word.d;
 if(en){en.classList.remove('hit');void en.offsetWidth;en.classList.add('hit')}confetti();
 bossQ++;if(bossQ<B.questions.length)renderBossQ();else complete(G.cur)}
function assetCard(a){const hz=HORIZONS.map(h=>`<button class="${h.h===G.hz?'on':''}" onclick="setHz(${h.h})">${h.l}</button>`).join('');
 return `<div class=a-px>${money(a.price)}</div><div class=p-note style=margin:0>${a.name} · ${a.clsName}</div><div class=hz>Window: ${hz}</div><div class=calls><button class=up onclick="pCall('${a.id}','up')">▲ Higher</button><button class=down onclick="pCall('${a.id}','down')">▼ Lower</button></div><div class=p-note>Your call resolves from real prices later — clearing the room just needs you to make it.</div>`}
function setHz(h){G.hz=h;save();openChallenge(G.cur)}
function pCall(id,dir){const a=CAT.assets.find(x=>x.id===id);if(!a||a.price==null){toast('No live price — try again shortly.');return}
 G.predictions.unshift({id:'p'+Date.now(),symbol:a.symbol,name:a.name,cls:a.cls,dir,price:a.price,ts:Date.now(),due:Date.now()+G.hz*3600*1000,horizon:G.hz,status:'pending'});save();toast('🔒 '+a.name+' '+(dir==='up'?'HIGHER':'LOWER'));complete(G.cur)}
function complete(i){const s=STAGES[i];if(s.word&&!G.glossary[s.word.t]){G.glossary[s.word.t]=s.word.d;toast('📖 New word: '+s.word.t+'!')}
 const xp=s.isBoss?80:s.type==='predict'?25:20;const first=!G.done[i];
 if(first){G.done[i]=1;G.xp+=xp;addWealth(s.isBoss?5000:s.type==='predict'?800:600);
  // What you learn in here is what you are worth out there. Rooms raise your wage.
  const gain=s.isBoss?3:1,before=wageTier().n;
  G.skill=Math.min(SKILL_CAP,(G.skill||0)+gain);
  if(wageTier().n!==before)setTimeout(()=>{confetti();
   toast('📈 What you just learned made you '+wageTier().n+' — every shift now pays '+money(wage())+'.')},1200)}save();renderHUD();if(typeof refreshBlocks==='function')refreshBlocks();if(typeof refreshGates==='function')refreshGates();
 if(first&&s.isBoss){if(typeof grantToolFor==='function')grantToolFor(s);if(s.level+1<LEVELS.length)pendingWorld=s.level+1}
 if(typeof sfx==='function')sfx(s.isBoss?'win':'break');confetti();
 $('challenge').classList.remove('show');$('clburst').textContent=s.isBoss?'🏆':'⭐';
 $('clw').textContent=s.isBoss?('LEVEL '+(s.level+1)+' COMPLETE'):('Level '+(s.level+1)+' · Room '+(s.room+1));
 $('clt').textContent=s.isBoss?(s.boss.name+' defeated!'):(s.title+' — Cleared!');
 let sub=first?('+'+xp+' 💎  ·  +'+(s.isBoss?3:1)+' skill → '+wageTier().n+' ('+money(wage())+'/shift)'):'Reviewed — nice!';
 if(s.isBoss)sub+=(s.level+1<LEVELS.length)?('  ·  Level '+(s.level+2)+' unlocked!'):'  ·  🎓 You beat Money World!';else sub+='  ·  next room unlocked';
 if(s.word)sub+='<br><span style="color:#7fb4ff">📖 '+s.word.t+':</span> '+s.word.d;
 $('cls').innerHTML=sub;$('cleared').classList.add('show')}
function closeCleared(){$('cleared').classList.remove('show');paused=false;if(typeof maybeAdvanceWorld==='function')maybeAdvanceWorld()}

function hasLesson(cls){const map={stocks:['Stock','Dividend','Diversification'],crypto:['Volatility'],realestate:['REIT'],bonds:['Bond'],commodities:[],insurance:[]};return (map[cls]||[]).some(w=>G.glossary[w])||G.predictions.some(p=>p.cls===cls)}
function catStats(cls){const ps=G.predictions.filter(p=>p.cls===cls);const res=ps.filter(p=>p.status!=='pending');const correct=res.filter(p=>p.status==='correct').length;return{calls:ps.length,resolved:res.length,correct,acc:res.length?correct/res.length:0,lesson:hasLesson(cls)}}
function tierFor(cls){if(!CAT)return{t:0,s:{}};const kind=CAT.classes[cls].kind,s=catStats(cls);if(kind==='concept'||kind==='soon')return{t:s.lesson?1:0,s};let t=0;if(s.lesson||s.calls>=3)t=1;if(s.lesson&&s.calls>=6)t=2;if(s.lesson&&s.calls>=15&&s.resolved>=8&&s.acc>=.55)t=3;if(s.lesson&&s.calls>=30&&s.resolved>=15&&s.acc>=.65)t=4;return{t,s}}
function openTrophies(){paused=true;$('creds').innerHTML=Object.keys(CAT.classes).map(c=>{const cl=CAT.classes[c],{t}=tierFor(c),tr=TIERS[t];const pips=TIERS.map((_,k)=>`<span style="width:13px;height:6px;border-radius:4px;display:inline-block;background:${k<=t?'#3d8bff':'#0d1420'};border:1px solid #2b3654"></span>`).join(' ');return `<div class=trow><span class=ti>${cl.icon}</span><span class=tn>${cl.name}</span><span class=tr style=color:${tr.c}>${tr.ic} ${tr.n}</span></div><div style=margin:-2px_0_6px;padding-left:2px>${pips} <span class=p-note>${t<4?TIER_NEXT[t]:'max'}</span></div>`}).join('');
 $('badges').innerHTML=BADGES.map(b=>{let g=false;try{g=b.test(G)}catch(e){}return `<div class="bg ${g?'':'off'}"><div class=i>${b.ic}</div><div class=n>${b.n}</div></div>`}).join('');$('trophies').classList.add('show')}
function openGlossary(){paused=true;const ks=Object.keys(G.glossary);$('glist').innerHTML=ks.length?ks.map(k=>`<div class=gloss><b>${k}</b><div class=gd>${G.glossary[k]}</div></div>`).join(''):'<div class=p-note>No words yet — clear rooms to fill your Word Bank!</div>';$('glossary').classList.add('show')}
function openWealth(){paused=true;const tp=topPoss(),np=nextPoss();
 const items=POSSESSIONS.map(q=>`<div class=trow><span class=ti>${q.e}</span><span class=tn>${q.n}</span><span class=tr style=color:${G.wealth>=q.min?'#3fb950':'#93a1b5'}>${G.wealth>=q.min?'OWNED':'$'+q.min.toLocaleString()}</span></div>`).join('');
 const prog=np?Math.min(100,(G.wealth-tp.min)/(np.min-tp.min)*100):100;
 $('wbody').innerHTML=`<div style=font-size:44px>${tp.e}</div><div class=p-title>Net Worth $${(G.wealth||0).toLocaleString()}</div>
  <div class=p-world>${np?('Next reward: '+np.e+' '+np.n+' at $'+np.min.toLocaleString()):'You are a MILLIONAIRE! 🏰'}</div>
  <div style="height:12px;background:#0d1420;border:1px solid #2b3654;border-radius:8px;overflow:hidden;margin:10px 0"><div style="height:100%;width:${prog}%;background:linear-gradient(90deg,#3d8bff,#3fb950)"></div></div>
  ${items}<div class=p-teach style=margin-top:12px>${IDEAS[Object.keys(G.done).length%IDEAS.length]}</div>`;
 $('wealth').classList.add('show')}
function hide(id){$(id).classList.remove('show');paused=false}
function renderHUD(){$('hnw').textContent=(typeof netWorth==='function'?netWorth():(G.wealth||0)).toLocaleString();$('hwords').textContent=Object.keys(G.glossary).length;let i=0;while(i<STAGES.length&&G.done[i])i++;$('hlvl').textContent=(i>=STAGES.length?LEVELS.length:STAGES[i].level+1)}
async function resolve(){const due=G.predictions.filter(p=>p.status==='pending'&&Date.now()>=p.due);if(!due.length)return;let q={};try{q=await j('/api/game/quotes')}catch(e){return}
 for(const p of due){const now=q[p.symbol];if(now==null)continue;p.resolved=now;const win=(p.dir==='up'&&now>p.price)||(p.dir==='down'&&now<p.price);p.status=win?'correct':'wrong';if(win){G.streak++;G.bestStreak=Math.max(G.bestStreak,G.streak);addWealth(1500);
  const before=wageTier().n;G.skill=Math.min(SKILL_CAP,(G.skill||0)+1);
  toast('✅ Your '+p.name+' call came true! +$1,500 · +1 skill');
  if(wageTier().n!==before)setTimeout(()=>{confetti();toast('📈 Reading markets made you '+wageTier().n+' — '+money(wage())+'/shift.')},1400)}else{G.streak=0;G.xp+=5}}save();renderHUD()}
async function boot(){
 // profile lives on the server now — pull it before anything reads progress
 try{const srv=await j('/api/game/profile');
  // never clobber something the player already did while the fetch was in flight
  if(srv&&typeof srv==='object'&&Object.keys(srv).length&&!_actedBeforeLoad&&(srv.rev||0)>=(G.rev||0)){
   G=srv;normalizeG();localStorage.setItem(KEY,JSON.stringify(G));
   if($('hnarr'))$('hnarr').textContent=G.narrate?'🔊 Read aloud: ON':'🔇 Read aloud: OFF';
   document.body.classList.toggle('bigtext',!!G.narrate);
   if(typeof loadHome==='function'&&window.THREE){loadHome();updateTool();updateVaultCount();updateWP()}
   toast('☁ Profile loaded — welcome back!')}
  else{normalizeG();pushProfile()}
 }catch(e){normalizeG()}
 // reflect the read-aloud setting however we got here
 if($('hnarr'))$('hnarr').textContent=G.narrate?'🔊 Read aloud: ON':'🔇 Read aloud: OFF';
 document.body.classList.toggle('bigtext',!!G.narrate);
 try{CAT=await j('/api/game/catalog')}catch(e){document.body.innerHTML='<div style=color:#fff;padding:30px>Could not load market data: '+e.message+'</div>';return}
 await resolve();renderHUD();requestAnimationFrame(loop);setInterval(async()=>{try{CAT=await j('/api/game/catalog')}catch(e){}await resolve()},60000)}
function fit(){if(renderer){renderer.setSize(innerWidth,innerHeight);camera.aspect=innerWidth/innerHeight;camera.updateProjectionMatrix()}}
addEventListener('resize',fit);fit();boot();
</script></body></html>"""
