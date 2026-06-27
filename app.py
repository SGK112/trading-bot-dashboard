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
import secrets
import requests
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from dotenv import load_dotenv

load_dotenv()

KEY = os.getenv("APCA_API_KEY_ID")
SECRET = os.getenv("APCA_API_SECRET_KEY")
BASE = os.getenv("APCA_BASE_URL", "https://paper-api.alpaca.markets")
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


@app.get("/", response_class=HTMLResponse)
def index(_: str = Depends(auth)):
    return PAGE


PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Trading Bot Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
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
<span class=upd id=upd></span></div>
<div class=cards id=cards></div>
<div class=panel><h2>Equity — last 30 days</h2><canvas id=chart></canvas></div>
<div class=panel><h2>Open Positions</h2><div id=pos></div></div>
<div class=panel><h2>Recent Orders</h2><div id=ord></div></div>
<div class=panel><h2>Controls</h2><div class=bar>
<button class=danger onclick=flatten()>Flatten all positions</button>
<button class=danger onclick=cancelOrders()>Cancel all orders</button>
<button onclick=loadAll()>Refresh</button>
<span class=upd>auto-refresh 30s</span></div></div>
</div><script>
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
 const h=await j('/api/history');
 const pts=h.points.map(p=>({x:p.t,y:p.equity}));
 if(chart)chart.destroy();
 chart=new Chart($('chart'),{type:'line',data:{datasets:[{data:pts,borderColor:'#388bfd',
   backgroundColor:'rgba(56,139,253,.1)',fill:true,tension:.25,pointRadius:0,borderWidth:2}]},
   options:{plugins:{legend:{display:false}},scales:{x:{type:'time',time:{unit:'day'},grid:{color:'#1c2430'},ticks:{color:'#8b98a9'}},
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
