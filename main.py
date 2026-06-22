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

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import os
import time

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
def recommend(goal: str = "diversified", risk: str = "neutral", tickers: str = ""):
    """
    goal: growth | dividend | diversified
    risk: conservative | neutral | aggressive
    tickers: 콤마구분. 비우면 전체 풀 대상.
    """
    w = compute_weights(goal, risk)

    if tickers.strip():
        wanted = [t.strip().upper() for t in tickers.split(",") if t.strip().upper() in POOL_BY_TICKER]
    else:
        wanted = [e["ticker"] for e in ETF_POOL]

    rows = []
    sources = set()
    for t in wanted:
        m = fetch_metrics(t)
        sources.add(m["source"])
        sc = sub_scores(m)
        score = w["R"] * sc["R"] + w["D"] * sc["D"] + w["S"] * sc["S"]
        meta = POOL_BY_TICKER[t]
        rows.append({
            "ticker": t,
            "name": meta["name"],
            "cat": meta["cat"],
            "ret1y": m["ret1y"],
            "vol": m["vol"],
            "yield": m["yield"],
            "price": m["price"],
            "source": m["source"],
            "scores": sc,
            "score": round(score, 1),
            "reason": make_reason(meta["cat"], sc, w),
        })

    rows.sort(key=lambda r: r["score"], reverse=True)
    overall_source = "yfinance" if sources == {"yfinance"} else ("fallback" if sources == {"fallback"} else "mixed")
    return {
        "goal": goal,
        "risk": risk,
        "weights": w,
        "source": overall_source,
        "results": rows,
        "disclaimer": "교육·참고용입니다. 세금·매매수수료·환율은 반영하지 않습니다. 투자 권유가 아닙니다.",
    }


# 정적 파일 (프론트)
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(path):
        return FileResponse(path)
    return JSONResponse({"error": "static/index.html 이(가) 없습니다."}, status_code=404)


if __name__ == "__main__":
    import uvicorn
    # 클라우드 배포 시 호스트가 PORT 환경변수를 주입한다. 없으면 로컬 기본값 8000.
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
