FROM python:3.11-slim

WORKDIR /app

# 安裝系統依賴
RUN apt-get update && apt-get install -y \
    gcc \
    libexpat1 \
    curl \
    fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

# 複製requirements並安裝Python依賴
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# 複製應用程式碼
COPY . .

# 建立logs目錄
RUN mkdir -p /app/logs

# 設定環境變數
ENV PYTHONPATH=/app
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# 暴露端口
EXPOSE 5000

# 啟動命令
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
