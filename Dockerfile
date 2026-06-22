# ETF 추천·분석 — NAS 등에서 실행하기 위한 컨테이너 이미지
FROM python:3.11-slim

WORKDIR /app

# 의존성 먼저 설치 (캐시 활용)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 앱 소스 복사
COPY . .

# 데이터(SQLite DB·세션키)는 /data 에 저장 → 컨테이너 밖 볼륨으로 마운트해 영구 보관
ENV DATA_DIR=/data
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
