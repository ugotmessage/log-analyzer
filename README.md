# Log Analyzer 🔍

一個輕量級的Apache/Nginx LOG分析工具，使用Python開發並透過Docker Compose部署。

[![Docker](https://img.shields.io/badge/Docker-支持-blue)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-green)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-red)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## 功能特色

- 🔍 **自動解析** Apache/Nginx Common Log Format
- 📊 **統計分析** 請求數、IP分布、狀態碼等
- ⏰ **時間分析** 每小時流量分布
- 🚨 **異常檢測** 高頻IP、錯誤請求、大檔案請求
- 📈 **視覺化圖表** 自動生成統計圖表
- 🌐 **Web API** RESTful API介面
- 🐳 **Docker化** 一鍵部署

## 快速開始

### 1. 準備LOG檔案
將您的LOG檔案放入 `logs/` 目錄中：
```bash
cp your_log_file.log logs/
```

### 2. 啟動服務
```bash
docker-compose up -d
```

### 3. 存取Web介面
開啟瀏覽器前往：http://localhost:5000

## API端點

| 方法 | 端點 | 說明 |
|------|------|------|
| GET | `/api/stats` | 取得基本統計 |
| GET | `/api/hourly` | 取得每小時流量 |
| GET | `/api/anomalies` | 取得異常檢測結果 |
| POST | `/api/analyze` | 執行完整分析 |
| GET | `/api/logs/list` | 列出可用LOG檔案 |
| GET | `/health` | 健康檢查 |

## 目錄結構

```
log_ana/
├── logs/                 # LOG檔案目錄 (掛載點)
├── output/              # 分析結果輸出目錄
├── log_analyzer.py      # 核心分析模組
├── app.py              # Flask Web應用
├── requirements.txt    # Python依賴
├── Dockerfile         # Docker映像檔
├── docker-compose.yml # Docker Compose配置
└── README.md          # 說明文件
```

## 使用範例

### 分析特定LOG檔案
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"filename": "access.log"}'
```

### 取得基本統計
```bash
curl http://localhost:5000/api/stats
```

### 取得異常檢測結果
```bash
curl http://localhost:5000/api/anomalies
```

## 配置說明

### Docker Compose配置
- **端口映射**: 5000:5000
- **LOG目錄掛載**: `./logs:/app/logs:ro` (唯讀)
- **輸出目錄掛載**: `./output:/app/output`
- **健康檢查**: 每30秒檢查一次

### 環境變數
- `LOG_DIR`: LOG檔案目錄 (預設: /app/logs)
- `OUTPUT_DIR`: 輸出目錄 (預設: /app/output)
- `FLASK_ENV`: Flask環境 (production)

## 支援的LOG格式

目前支援Apache/Nginx Common Log Format：
```
IP - - [timestamp] "method url protocol" status_code response_size "referer" "user_agent"
```

範例：
```
172.70.207.38 - - [24/Sep/2025:09:35:41 +0800] "POST /wp-cron.php HTTP/1.1" 499 0 "-" "WordPress/6.8.2"
```

## 故障排除

### 檢查容器狀態
```bash
docker-compose ps
```

### 查看容器日誌
```bash
docker-compose logs -f log-analyzer
```

### 重新建置
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## 擴展功能

可以透過修改 `log_analyzer.py` 來：
- 支援其他LOG格式
- 新增更多統計指標
- 實作即時監控
- 整合資料庫儲存

## 授權

MIT License
