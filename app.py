from flask import Flask, jsonify, request, send_file, render_template_string
import os
import json
from log_analyzer import LogAnalyzer
from datetime import datetime
import pytz

app = Flask(__name__)

# 初始化LOG分析器
analyzer = LogAnalyzer()

# 設定版本時間（台北時間）- 每次上版時更新
taipei_tz = pytz.timezone('Asia/Taipei')
VERSION_TIME = datetime.now(taipei_tz).strftime('%Y-%m-%d %H:%M')

# HTML模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>LOG分析儀</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f6fa; 
            color: #2c3e50;
            line-height: 1.6;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 20px;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            border-radius: 12px;
            margin-bottom: 25px;
            position: relative;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .header h1 { 
            font-size: 2.2rem; 
            margin-bottom: 8px;
            font-weight: 300;
        }
        
        .header p { 
            font-size: 1.1rem; 
            opacity: 0.9;
        }
        
        .version-info {
            position: absolute;
            top: 20px;
            right: 30px;
            background: rgba(255, 255, 255, 0.2);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
            backdrop-filter: blur(10px);
        }
        
        /* Stats Section */
        .stats-section {
            margin-bottom: 25px;
        }
        
        /* Info Cards Grid */
        .info-cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }
        
        /* Cards */
        .card { 
            background: white; 
            border-radius: 12px; 
            padding: 20px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            border: 1px solid #e8ecf0;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        
        .card:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 4px 20px rgba(0,0,0,0.12);
        }
        
        .card-header { 
            display: flex; 
            align-items: center; 
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f1f3f4;
        }
        
        .card-icon { 
            font-size: 1.5rem; 
            margin-right: 10px;
        }
        
        .card-title { 
            font-size: 1.1rem; 
            font-weight: 600; 
            color: #2c3e50;
        }
        
        /* Stats Grid */
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin-bottom: 20px;
        }
        
        .stat-item { 
            background: white; 
            padding: 20px; 
            border-radius: 10px; 
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            border-left: 4px solid #667eea;
        }
        
        .stat-value { 
            font-size: 2rem; 
            font-weight: 700; 
            color: #2c3e50; 
            margin-bottom: 5px;
        }
        
        .stat-label { 
            font-size: 0.9rem; 
            color: #7f8c8d; 
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Filter Section */
        .filter-section { 
            background: white; 
            border-radius: 12px; 
            padding: 25px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            margin-bottom: 25px;
        }
        
        .filter-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 20px;
        }
        
        .filter-group { 
            display: flex; 
            flex-direction: column;
        }
        
        .filter-group label { 
            font-weight: 600; 
            margin-bottom: 8px; 
            color: #2c3e50;
            font-size: 0.9rem;
        }
        
        .filter-group input, .filter-group select { 
            padding: 12px 15px; 
            border: 2px solid #e8ecf0; 
            border-radius: 8px; 
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        .filter-group input:focus, .filter-group select:focus { 
            outline: none; 
            border-color: #667eea;
        }
        
        .filter-actions { 
            display: flex; 
            gap: 12px; 
            flex-wrap: wrap;
        }
        
        .btn { 
            padding: 12px 24px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 14px; 
            font-weight: 600;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .btn-primary { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-secondary { 
            background: #6c757d; 
            color: white;
        }
        
        .btn-success { 
            background: #28a745; 
            color: white;
        }
        
        .btn:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        
        /* Charts */
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-bottom: 25px;
        }
        
        .chart-container { 
            background: white; 
            border-radius: 12px; 
            padding: 25px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            margin-bottom: 25px;
        }
        
        .chart-half {
            margin-bottom: 0;
        }
        
        .chart-full {
            width: 100%;
        }
        
        .chart img { 
            max-width: 100%; 
            height: auto; 
            border-radius: 8px;
            width: 100%;
            object-fit: contain;
        }
        
        .chart-container {
            overflow: hidden;
        }
        
        /* Log Viewer */
        .log-viewer { 
            background: white; 
            border-radius: 12px; 
            padding: 25px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        .log-viewer-full {
            width: 100%;
        }
        
        .log-controls { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .log-search { 
            display: flex; 
            gap: 10px; 
            align-items: center;
            flex: 1;
            min-width: 300px;
        }
        
        .log-search input { 
            flex: 1; 
            padding: 10px 15px; 
            border: 2px solid #e8ecf0; 
            border-radius: 8px; 
            font-size: 14px;
        }
        
        .log-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 15px;
            font-size: 13px;
        }
        
        .log-table th { 
            background: #f8f9fa; 
            padding: 12px 8px; 
            text-align: left; 
            font-weight: 600; 
            color: #2c3e50;
            border-bottom: 2px solid #e8ecf0;
        }
        
        .log-table td { 
            padding: 10px 8px; 
            border-bottom: 1px solid #f1f3f4;
            word-break: break-all;
        }
        
        .log-table tr:hover { 
            background: #f8f9fa;
        }
        
        .pagination { 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            gap: 10px; 
            margin-top: 20px;
        }
        
        .pagination button { 
            padding: 8px 12px; 
            border: 1px solid #e8ecf0; 
            background: white; 
            border-radius: 6px; 
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .pagination button:hover:not(:disabled) { 
            background: #667eea; 
            color: white; 
            border-color: #667eea;
        }
        
        .pagination button:disabled { 
            opacity: 0.5; 
            cursor: not-allowed;
        }
        
        .pagination .current-page { 
            background: #667eea; 
            color: white; 
            border-color: #667eea;
        }
        
        /* API Section */
        .api-section { 
            background: white; 
            border-radius: 12px; 
            padding: 25px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        .endpoint { 
            margin: 12px 0; 
            padding: 15px; 
            background: #f8f9fa; 
            border-radius: 8px; 
            border-left: 4px solid #667eea;
        }
        
        .method { 
            font-weight: bold; 
            color: #667eea; 
            margin-right: 10px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .info-cards-grid {
                grid-template-columns: 1fr;
            }
            
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .chart-half {
                margin-bottom: 25px;
            }
            
            .stats-grid { 
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
            }
            
            .filter-grid { 
                grid-template-columns: 1fr; 
            }
            
            .log-controls { 
                flex-direction: column; 
                align-items: stretch;
            }
            
            .log-search { 
                min-width: auto;
            }
            
            .version-info { 
                position: static; 
                margin-top: 15px; 
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔍 LOG分析儀</h1>
            <p>輕量級Apache/Nginx LOG分析工具</p>
            <div class="version-info">
                <span>版本: {{ current_time }}</span>
            </div>
        </div>
        
        <!-- Filter Section -->
        <div class="filter-section">
            <div class="card-header">
                <span class="card-icon">🔍</span>
                <span class="card-title">過濾條件</span>
            </div>
            <form id="filterForm">
                <div class="filter-grid">
                    <div class="filter-group">
                        <label for="filename">LOG檔案</label>
                        <select id="filename" name="filename">
                            <option value="">所有檔案</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="start_time">開始時間</label>
                        <input type="datetime-local" id="start_time" name="start_time">
                    </div>
                    <div class="filter-group">
                        <label for="end_time">結束時間</label>
                        <input type="datetime-local" id="end_time" name="end_time">
                    </div>
                    <div class="filter-group">
                        <label for="domain">網域過濾</label>
                        <input type="text" id="domain" name="domain" placeholder="例如: example.com">
                    </div>
                </div>
                <div class="filter-actions">
                    <button type="button" class="btn btn-primary" onclick="applyFilters()">套用過濾</button>
                    <button type="button" class="btn btn-secondary" onclick="clearFilters()">清除過濾</button>
                    <button type="button" class="btn btn-success" onclick="runAnalysis()">執行分析</button>
                </div>
            </form>
        </div>
        
        <!-- Stats Section -->
        <div class="stats-section">
            <div class="card">
                <div class="card-header">
                    <span class="card-icon">📊</span>
                    <span class="card-title">基本統計</span>
                </div>
                <div class="stats-grid" id="basic-stats">
                    <div class="stat-item">
                        <div class="stat-value">{{ stats.get('total_requests', 0) }}</div>
                        <div class="stat-label">總請求數</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{{ stats.get('unique_ips', 0) }}</div>
                        <div class="stat-label">唯一IP數</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{{ "%.1f"|format(stats.get('total_bytes', 0)/1024/1024) }}</div>
                        <div class="stat-label">總流量 (MB)</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{{ "%.0f"|format(stats.get('avg_response_size', 0)) }}</div>
                        <div class="stat-label">平均回應 (bytes)</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Info Cards Section -->
        <div class="info-cards-grid">
            <!-- Time Range -->
            <div class="card" id="time-range">
                <div class="card-header">
                    <span class="card-icon">⏰</span>
                    <span class="card-title">時間範圍</span>
                </div>
                <div id="time-content">
                    {% if stats.get('time_range') %}
                    <div style="padding: 10px 0;">
                        <div style="margin-bottom: 10px;">
                            <strong>開始時間:</strong><br>
                            <span style="color: #667eea;">{{ stats.time_range.start }}</span>
                        </div>
                        <div>
                            <strong>結束時間:</strong><br>
                            <span style="color: #667eea;">{{ stats.time_range.end }}</span>
                        </div>
                    </div>
                    {% else %}
                    <p style="color: #7f8c8d; text-align: center; padding: 20px;">暫無時間資料</p>
                    {% endif %}
                </div>
            </div>
            
            <!-- Top URLs -->
            <div class="card" id="top-urls">
                <div class="card-header">
                    <span class="card-icon">🔗</span>
                    <span class="card-title">熱門URL</span>
                </div>
                <div id="urls-content">
                    {% if stats.get('top_urls') %}
                    {% for url, count in stats.top_urls.items() %}
                    <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f1f3f4;">
                        <span title="{{ url }}" style="flex: 1; margin-right: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ url[:50] }}{% if url|length > 50 %}...{% endif %}</span>
                        <span style="color: #667eea; font-weight: 600; flex-shrink: 0;">{{ count }}</span>
                    </div>
                    {% endfor %}
                    {% else %}
                    <p style="color: #7f8c8d; text-align: center; padding: 20px;">暫無URL資料</p>
                    {% endif %}
                </div>
            </div>
            
            <!-- Top IPs -->
            <div class="card" id="top-ips">
                <div class="card-header">
                    <span class="card-icon">🌐</span>
                    <span class="card-title">熱門IP</span>
                </div>
                <div id="ips-content">
                    {% if stats.get('top_ips') %}
                    {% for ip, count in stats.top_ips.items() %}
                    <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f1f3f4;">
                        <span><strong>{{ ip }}</strong></span>
                        <span style="color: #667eea; font-weight: 600;">{{ count }}</span>
                    </div>
                    {% endfor %}
                    {% else %}
                    <p style="color: #7f8c8d; text-align: center; padding: 20px;">暫無IP資料</p>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <!-- Log Viewer Section -->
        <div class="log-viewer log-viewer-full">
            <div class="card-header">
                <span class="card-icon">📋</span>
                <span class="card-title">LOG查看器</span>
            </div>
            <div class="log-controls">
                <div class="log-search">
                    <input type="text" id="logSearch" placeholder="搜尋關鍵字..." onkeyup="searchLogs()">
                    <button class="btn btn-primary" onclick="searchLogs()">搜尋</button>
                </div>
                <div>
                    <span style="color: #7f8c8d; font-size: 14px;">每頁顯示: </span>
                    <select id="pageSize" onchange="loadLogs()" style="padding: 5px; border: 1px solid #e8ecf0; border-radius: 4px;">
                        <option value="10" selected>10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </div>
            </div>
            <div id="logTableContainer">
                <table class="log-table" id="logTable">
                    <thead>
                        <tr>
                            <th>時間</th>
                            <th>IP</th>
                            <th>方法</th>
                            <th>URL</th>
                            <th>狀態</th>
                            <th>大小</th>
                        </tr>
                    </thead>
                    <tbody id="logTableBody">
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 40px; color: #7f8c8d;">
                                請選擇LOG檔案並執行分析
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="pagination" id="pagination">
                <!-- Pagination will be generated by JavaScript -->
            </div>
        </div>
        
        <!-- Charts Section -->
        <div class="charts-grid">
            <div class="chart-container chart-half">
                <div class="card-header">
                    <span class="card-icon">📈</span>
                    <span class="card-title">流量趨勢</span>
                    <div style="margin-left: auto; display: flex; gap: 10px; align-items: center;">
                        <span style="color: #7f8c8d; font-size: 14px;">時間級距:</span>
                        <select id="timeInterval" onchange="updateTimeInterval()" style="padding: 5px; border: 1px solid #e8ecf0; border-radius: 4px;">
                            <option value="hourly">每小時</option>
                            <option value="daily" selected>每日</option>
                            <option value="weekly">每週</option>
                            <option value="monthly">每月</option>
                        </select>
                    </div>
                </div>
                <img src="/chart/traffic_trend.png" alt="Traffic Trend Chart" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                <p style="display:none; color:#666; text-align: center; padding: 40px;">暫無圖表資料，請先執行分析</p>
            </div>
            
            <div class="chart-container chart-half">
                <div class="card-header">
                    <span class="card-icon">🌐</span>
                    <span class="card-title">熱門IP分布</span>
                </div>
                <img src="/chart/top_ips.png" alt="Top IPs Chart" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                <p style="display:none; color:#666; text-align: center; padding: 40px;">暫無圖表資料，請先執行分析</p>
            </div>
        </div>
        
        <div class="chart-container chart-full">
            <div class="card-header">
                <span class="card-icon">🔗</span>
                <span class="card-title">熱門URL分布</span>
            </div>
            <img src="/chart/top_urls.png" alt="Top URLs Chart" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
            <p style="display:none; color:#666; text-align: center; padding: 40px;">暫無圖表資料，請先執行分析</p>
        </div>
        
        <!-- API Section -->
        <div class="api-section">
            <div class="card-header">
                <span class="card-icon">🔌</span>
                <span class="card-title">API端點</span>
            </div>
            <div class="endpoint">
                <span class="method">GET</span> /api/stats - 取得基本統計
            </div>
            <div class="endpoint">
                <span class="method">GET</span> /api/hourly - 取得每小時流量
            </div>
            <div class="endpoint">
                <span class="method">GET</span> /api/anomalies - 取得異常檢測結果
            </div>
            <div class="endpoint">
                <span class="method">POST</span> /api/analyze - 執行完整分析
            </div>
            <div class="endpoint">
                <span class="method">GET</span> /api/logs - 取得LOG資料
            </div>
            <div class="endpoint">
                <span class="method">GET</span> /health - 健康檢查
            </div>
        </div>
    </div>
    
    <script>
        // 全域變數
        let currentLogs = [];
        let filteredLogs = [];
        let currentPage = 1;
        let pageSize = 10;
        let searchKeyword = '';
        let timeInterval = 'daily';
        
        // 載入LOG檔案列表
        async function loadLogFiles() {
            try {
                const response = await fetch('/api/logs/list');
                const data = await response.json();
                const select = document.getElementById('filename');
                
                // 清空現有選項
                select.innerHTML = '<option value="">所有檔案</option>';
                
                // 添加LOG檔案選項
                data.log_files.forEach(file => {
                    const option = document.createElement('option');
                    option.value = file.filename;
                    option.textContent = `${file.filename} (${(file.size / 1024).toFixed(1)}KB)`;
                    select.appendChild(option);
                });
            } catch (error) {
                console.error('載入LOG檔案列表失敗:', error);
            }
        }
        
        // 載入LOG資料
        async function loadLogs() {
            try {
                const form = document.getElementById('filterForm');
                const formData = new FormData(form);
                const params = new URLSearchParams();
                
                for (let [key, value] of formData.entries()) {
                    if (value) {
                        params.append(key, value);
                    }
                }
                
                // 添加分頁參數
                params.append('page', currentPage);
                params.append('page_size', pageSize);
                if (searchKeyword) {
                    params.append('search', searchKeyword);
                }
                
                const response = await fetch(`/api/logs?${params}`);
                const data = await response.json();
                
                if (data.success) {
                    currentLogs = data.logs;
                    filteredLogs = data.logs;
                    updateLogTable();
                    updatePagination(data.total, data.total_pages);
                } else {
                    console.error('載入LOG資料失敗:', data.error);
                    showLogMessage('載入LOG資料失敗: ' + data.error);
                }
            } catch (error) {
                console.error('載入LOG資料失敗:', error);
                showLogMessage('載入LOG資料失敗: ' + error.message);
            }
        }
        
        // 更新LOG表格
        function updateLogTable() {
            const tbody = document.getElementById('logTableBody');
            
            if (!filteredLogs || filteredLogs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px; color: #7f8c8d;">暫無LOG資料</td></tr>';
                return;
            }
            
            tbody.innerHTML = filteredLogs.map(log => `
                <tr>
                    <td title="${log.timestamp}">${formatTimestamp(log.timestamp)}</td>
                    <td>${log.ip}</td>
                    <td><span style="background: #e3f2fd; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600;">${log.method}</span></td>
                    <td title="${log.url}">${truncateText(log.url, 50)}</td>
                    <td><span style="color: ${getStatusColor(log.status_code)}; font-weight: 600;">${log.status_code}</span></td>
                    <td>${formatBytes(log.response_size)}</td>
                </tr>
            `).join('');
        }
        
        // 更新分頁
        function updatePagination(total, totalPages) {
            const pagination = document.getElementById('pagination');
            
            if (totalPages <= 1) {
                pagination.innerHTML = '';
                return;
            }
            
            let html = '';
            
            // 上一頁按鈕
            html += `<button ${currentPage === 1 ? 'disabled' : ''} onclick="changePage(${currentPage - 1})">上一頁</button>`;
            
            // 頁碼按鈕
            const startPage = Math.max(1, currentPage - 2);
            const endPage = Math.min(totalPages, currentPage + 2);
            
            if (startPage > 1) {
                html += `<button onclick="changePage(1)">1</button>`;
                if (startPage > 2) {
                    html += `<span>...</span>`;
                }
            }
            
            for (let i = startPage; i <= endPage; i++) {
                html += `<button class="${i === currentPage ? 'current-page' : ''}" onclick="changePage(${i})">${i}</button>`;
            }
            
            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    html += `<span>...</span>`;
                }
                html += `<button onclick="changePage(${totalPages})">${totalPages}</button>`;
            }
            
            // 下一頁按鈕
            html += `<button ${currentPage === totalPages ? 'disabled' : ''} onclick="changePage(${currentPage + 1})">下一頁</button>`;
            
            pagination.innerHTML = html;
        }
        
        // 換頁
        function changePage(page) {
            currentPage = page;
            loadLogs();
        }
        
        // 搜尋LOG
        function searchLogs() {
            searchKeyword = document.getElementById('logSearch').value.trim();
            currentPage = 1;
            loadLogs();
        }
        
        // 顯示LOG訊息
        function showLogMessage(message) {
            const tbody = document.getElementById('logTableBody');
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 40px; color: #e74c3c;">${message}</td></tr>`;
        }
        
        // 格式化時間戳記
        function formatTimestamp(timestamp) {
            try {
                const date = new Date(timestamp);
                return date.toLocaleString('zh-TW', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                });
            } catch (error) {
                return timestamp;
            }
        }
        
        // 截斷文字
        function truncateText(text, maxLength) {
            if (text.length <= maxLength) return text;
            return text.substring(0, maxLength) + '...';
        }
        
        // 取得狀態碼顏色
        function getStatusColor(statusCode) {
            if (statusCode >= 200 && statusCode < 300) return '#27ae60';
            if (statusCode >= 300 && statusCode < 400) return '#f39c12';
            if (statusCode >= 400 && statusCode < 500) return '#e67e22';
            if (statusCode >= 500) return '#e74c3c';
            return '#7f8c8d';
        }
        
        // 格式化位元組
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }
        
        // 更新時間級距
        function updateTimeInterval() {
            timeInterval = document.getElementById('timeInterval').value;
            updateCharts();
        }
        
        // 套用過濾條件
        async function applyFilters() {
            const form = document.getElementById('filterForm');
            const formData = new FormData(form);
            const params = new URLSearchParams();
            
            for (let [key, value] of formData.entries()) {
                if (value) {
                    params.append(key, value);
                }
            }
            
            try {
                console.log('正在套用過濾條件...');
                // 更新統計資料
                const statsResponse = await fetch(`/api/stats?${params}`);
                
                if (!statsResponse.ok) {
                    throw new Error(`HTTP ${statsResponse.status}: ${statsResponse.statusText}`);
                }
                
                const stats = await statsResponse.json();
                console.log('收到統計資料:', stats);
                
                // 更新頁面顯示
                updateStatsDisplay(stats);
                
                // 更新圖表
                updateCharts();
                
                // 載入LOG資料
                loadLogs();
                
                console.log('過濾條件套用成功');
                
            } catch (error) {
                console.error('套用過濾失敗:', error);
                alert('套用過濾失敗: ' + error.message);
            }
        }
        
        // 清除過濾條件
        function clearFilters() {
            document.getElementById('filterForm').reset();
            applyFilters(); // 重新載入所有資料
        }
        
        // 執行完整分析
        async function runAnalysis() {
            console.log('開始執行分析...');
            
            // 檢查必需的元素是否存在
            const requiredElements = ['basic-stats', 'time-range', 'top-urls', 'top-ips'];
            const missingElements = requiredElements.filter(id => !document.getElementById(id));
            
            if (missingElements.length > 0) {
                console.error('缺少必需的元素:', missingElements);
                alert('頁面元素未完全加載，請稍後再試');
                return;
            }
            
            const form = document.getElementById('filterForm');
            if (!form) {
                console.error('找不到過濾表單');
                alert('找不到過濾表單');
                return;
            }
            
            const formData = new FormData(form);
            const data = {};
            
            for (let [key, value] of formData.entries()) {
                if (value) {
                    data[key] = value;
                }
            }
            
            // 添加時間級距
            data.time_interval = timeInterval;
            
            try {
                console.log('發送分析請求:', data);
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                console.log('收到分析結果:', result);
                
                if (result.success) {
                    // 更新統計資料
                    updateStatsDisplay(result.stats);
                    
                    // 更新圖表
                    updateCharts();
                    
                    // 載入LOG資料
                    loadLogs();
                    
                    alert('分析完成！');
                } else {
                    alert('分析失敗: ' + result.error);
                }
            } catch (error) {
                console.error('執行分析失敗:', error);
                alert('執行分析失敗: ' + error.message);
            }
        }
        
        // 安全更新DOM元素
        function safeUpdateElement(selector, content) {
            try {
                const element = document.querySelector(selector);
                if (element) {
                    element.innerHTML = content;
                    console.log(`成功更新元素: ${selector}`);
                    return true;
                } else {
                    console.warn(`找不到元素: ${selector}`);
                    return false;
                }
            } catch (error) {
                console.error(`更新元素失敗: ${selector}`, error);
                return false;
            }
        }
        
        // 更新統計顯示 - 強健版本
        function updateStatsDisplay(stats) {
            console.log('開始更新統計顯示...', stats);
            
            // 等待DOM完全準備好
            if (document.readyState !== 'complete') {
                console.log('等待DOM完全加載...');
                setTimeout(() => updateStatsDisplay(stats), 100);
                return;
            }
            
            // 檢查所有必需元素
            const elements = {
                basicStats: document.getElementById('basic-stats'),
                timeRange: document.getElementById('time-range'),
                topUrls: document.getElementById('top-urls'),
                topIps: document.getElementById('top-ips')
            };
            
            // 檢查是否有任何元素缺失
            const missingElements = Object.entries(elements)
                .filter(([name, element]) => !element)
                .map(([name]) => name);
            
            if (missingElements.length > 0) {
                console.error('缺少必需的元素:', missingElements);
                console.log('頁面HTML結構:', document.body.innerHTML.substring(0, 500));
                alert('頁面元素未完全加載，請重新整理頁面後再試');
                return;
            }
            
            try {
                // 更新基本統計
                if (elements.basicStats) {
                    elements.basicStats.innerHTML = `
                        <h3>📊 基本統計</h3>
                        <p><strong>總請求數:</strong> ${stats.total_requests || 0}</p>
                        <p><strong>唯一IP數:</strong> ${stats.unique_ips || 0}</p>
                        <p><strong>總流量:</strong> ${((stats.total_bytes || 0) / 1024 / 1024).toFixed(2)} MB</p>
                        <p><strong>平均回應大小:</strong> ${(stats.avg_response_size || 0).toFixed(0)} bytes</p>
                    `;
                    console.log('基本統計更新成功');
                }
                
                // 更新時間範圍
                if (elements.timeRange) {
                    elements.timeRange.innerHTML = stats.time_range ? `
                        <h3>⏰ 時間範圍</h3>
                        <p><strong>開始時間:</strong> ${stats.time_range.start}</p>
                        <p><strong>結束時間:</strong> ${stats.time_range.end}</p>
                    ` : `
                        <h3>⏰ 時間範圍</h3>
                        <p>暫無時間資料</p>
                    `;
                    console.log('時間範圍更新成功');
                }
                
                // 更新熱門URL
                if (elements.topUrls) {
                    let urlsHtml = '';
                    if (stats.top_urls && Object.keys(stats.top_urls).length > 0) {
                        for (let [url, count] of Object.entries(stats.top_urls)) {
                            const displayUrl = url.length > 50 ? url.substring(0, 50) + '...' : url;
                            urlsHtml += `
                                <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f1f3f4;">
                                    <span title="${url}" style="flex: 1; margin-right: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${displayUrl}</span>
                                    <span style="color: #667eea; font-weight: 600; flex-shrink: 0;">${count}</span>
                                </div>
                            `;
                        }
                    } else {
                        urlsHtml = '<p style="color: #7f8c8d; text-align: center; padding: 20px;">暫無URL資料</p>';
                    }
                    elements.topUrls.querySelector('#urls-content').innerHTML = urlsHtml;
                    console.log('熱門URL更新成功');
                }
                
                // 更新熱門IP
                if (elements.topIps) {
                    let ipsHtml = '';
                    if (stats.top_ips && Object.keys(stats.top_ips).length > 0) {
                        for (let [ip, count] of Object.entries(stats.top_ips)) {
                            ipsHtml += `
                                <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f1f3f4;">
                                    <span><strong>${ip}</strong></span>
                                    <span style="color: #667eea; font-weight: 600;">${count}</span>
                                </div>
                            `;
                        }
                    } else {
                        ipsHtml = '<p style="color: #7f8c8d; text-align: center; padding: 20px;">暫無IP資料</p>';
                    }
                    elements.topIps.querySelector('#ips-content').innerHTML = ipsHtml;
                    console.log('熱門IP更新成功');
                }
                
                console.log('統計顯示更新完成');
            } catch (error) {
                console.error('更新統計顯示時發生錯誤:', error);
                console.error('錯誤堆疊:', error.stack);
            }
        }
        
        // 更新圖表
        function updateCharts() {
            const charts = document.querySelectorAll('.chart-container img');
            charts.forEach(img => {
                const baseSrc = img.src.split('?')[0];
                img.src = baseSrc + '?t=' + new Date().getTime() + '&interval=' + timeInterval;
            });
        }
        
        // 頁面載入時初始化
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM已加載，開始初始化...');
            loadLogFiles();
        });
        
        // 確保頁面完全加載後再執行
        window.addEventListener('load', function() {
            console.log('頁面完全加載完成');
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """主頁面"""
    try:
        # 載入最新分析結果
        results_file = os.path.join(analyzer.output_dir, 'analysis_results.json')
        if os.path.exists(results_file):
            with open(results_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                stats = data.get('basic_stats', {})
        else:
            stats = {}
        
        return render_template_string(HTML_TEMPLATE, stats=stats, current_time=VERSION_TIME)
    except Exception as e:
        return f"錯誤: {str(e)}", 500

@app.route('/api/stats')
def get_stats():
    """取得基本統計"""
    try:
        # 取得查詢參數
        filename = request.args.get('filename')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        domain = request.args.get('domain')
        
        logs = analyzer.load_logs(filename, start_time, end_time, domain)
        stats = analyzer.get_basic_stats(logs)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hourly')
def get_hourly():
    """取得每小時流量"""
    try:
        # 取得查詢參數
        filename = request.args.get('filename')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        domain = request.args.get('domain')
        
        logs = analyzer.load_logs(filename, start_time, end_time, domain)
        hourly = analyzer.analyze_hourly_traffic(logs)
        return jsonify(hourly)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/anomalies')
def get_anomalies():
    """取得異常檢測結果"""
    try:
        # 取得查詢參數
        filename = request.args.get('filename')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        domain = request.args.get('domain')
        
        logs = analyzer.load_logs(filename, start_time, end_time, domain)
        anomalies = analyzer.detect_anomalies(logs)
        return jsonify(anomalies)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def run_analysis():
    """執行完整分析"""
    try:
        data = request.get_json() or {}
        log_filename = data.get('filename')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        domain = data.get('domain')
        time_interval = data.get('time_interval', 'daily')
        
        result = analyzer.run_full_analysis(log_filename, start_time, end_time, domain, time_interval)
        
        if result:
            return jsonify({
                'success': True,
                'message': '分析完成',
                'stats': result['stats'],
                'charts': result['charts'],
                'results_file': result['results_file'],
                'filters': result['filters']
            })
        else:
            return jsonify({'error': '分析失敗'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chart/<filename>')
def get_chart(filename):
    """取得圖表檔案"""
    try:
        chart_path = os.path.join(analyzer.output_dir, filename)
        if os.path.exists(chart_path):
            return send_file(chart_path)
        else:
            return "圖表不存在", 404
    except Exception as e:
        return f"錯誤: {str(e)}", 500

@app.route('/health')
def health_check():
    """健康檢查"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'log_dir': analyzer.log_dir,
        'output_dir': analyzer.output_dir
    })

@app.route('/api/logs/list')
def list_log_files():
    """列出可用的LOG檔案"""
    try:
        log_files = []
        if os.path.exists(analyzer.log_dir):
            for file in os.listdir(analyzer.log_dir):
                if file.endswith('.log'):
                    file_path = os.path.join(analyzer.log_dir, file)
                    stat = os.stat(file_path)
                    log_files.append({
                        'filename': file,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
        
        return jsonify({'log_files': log_files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """取得LOG資料，支援分頁和搜尋"""
    try:
        # 取得查詢參數
        filename = request.args.get('filename')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        domain = request.args.get('domain')
        search = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 50))
        
        # 載入LOG資料
        logs = analyzer.load_logs(filename, start_time, end_time, domain)
        
        # 應用搜尋過濾
        if search:
            search_lower = search.lower()
            logs = [log for log in logs if 
                   search_lower in log.get('ip', '').lower() or
                   search_lower in log.get('url', '').lower() or
                   search_lower in log.get('method', '').lower() or
                   search_lower in str(log.get('status_code', '')).lower() or
                   search_lower in log.get('user_agent', '').lower()]
        
        # 計算分頁
        total = len(logs)
        total_pages = (total + page_size - 1) // page_size
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_logs = logs[start_idx:end_idx]
        
        return jsonify({
            'success': True,
            'logs': paginated_logs,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': total_pages
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
