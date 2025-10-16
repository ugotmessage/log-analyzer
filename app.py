from flask import Flask, jsonify, request, send_file, render_template_string
import os
import json
from log_analyzer import LogAnalyzer
from datetime import datetime

app = Flask(__name__)

# 初始化LOG分析器
analyzer = LogAnalyzer()

# HTML模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>LOG分析儀</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .stat-card { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
        .chart { text-align: center; margin: 20px 0; }
        .chart img { max-width: 100%; height: auto; }
        .api-section { margin-top: 40px; padding: 20px; background: #f5f5f5; border-radius: 8px; }
        .endpoint { margin: 10px 0; padding: 10px; background: white; border-radius: 4px; }
        .method { font-weight: bold; color: #007bff; }
        .filter-section { margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border: 1px solid #dee2e6; }
        .filter-form { margin-top: 15px; }
        .filter-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px; }
        .filter-group { display: flex; flex-direction: column; }
        .filter-group label { font-weight: bold; margin-bottom: 5px; color: #495057; }
        .filter-group input, .filter-group select { padding: 8px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; }
        .filter-actions { display: flex; gap: 10px; margin-top: 15px; }
        .filter-actions button { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .filter-actions button:nth-child(1) { background: #007bff; color: white; }
        .filter-actions button:nth-child(2) { background: #6c757d; color: white; }
        .filter-actions button:nth-child(3) { background: #28a745; color: white; }
        .filter-actions button:hover { opacity: 0.8; }
        
        /* 版本信息樣式 */
        .version-info {
            position: absolute;
            top: 10px;
            right: 20px;
            background: rgba(0, 0, 0, 0.1);
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            color: #666;
            border: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .header {
            position: relative;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 LOG分析儀</h1>
            <p>輕量級Apache/Nginx LOG分析工具</p>
            <div class="version-info">
                <span>版本: 2025-10-16 19:15</span>
            </div>
        </div>
        
        <!-- 過濾表單 -->
        <div class="filter-section">
            <h3>🔍 過濾條件</h3>
            <form id="filterForm" class="filter-form">
                <div class="filter-row">
                    <div class="filter-group">
                        <label for="filename">LOG檔案:</label>
                        <select id="filename" name="filename">
                            <option value="">所有檔案</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="start_time">開始時間:</label>
                        <input type="datetime-local" id="start_time" name="start_time">
                    </div>
                    <div class="filter-group">
                        <label for="end_time">結束時間:</label>
                        <input type="datetime-local" id="end_time" name="end_time">
                    </div>
                    <div class="filter-group">
                        <label for="domain">網域過濾:</label>
                        <input type="text" id="domain" name="domain" placeholder="例如: example.com">
                    </div>
                </div>
                <div class="filter-actions">
                    <button type="button" onclick="applyFilters()">套用過濾</button>
                    <button type="button" onclick="clearFilters()">清除過濾</button>
                    <button type="button" onclick="runAnalysis()">執行分析</button>
                </div>
            </form>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card" id="basic-stats">
                <h3>📊 基本統計</h3>
                <p><strong>總請求數:</strong> {{ stats.get('total_requests', 0) }}</p>
                <p><strong>唯一IP數:</strong> {{ stats.get('unique_ips', 0) }}</p>
                <p><strong>總流量:</strong> {{ "%.2f"|format(stats.get('total_bytes', 0)/1024/1024) }} MB</p>
                <p><strong>平均回應大小:</strong> {{ "%.0f"|format(stats.get('avg_response_size', 0)) }} bytes</p>
            </div>
            
            <div class="stat-card" id="time-range">
                <h3>⏰ 時間範圍</h3>
                {% if stats.get('time_range') %}
                <p><strong>開始時間:</strong> {{ stats.time_range.start }}</p>
                <p><strong>結束時間:</strong> {{ stats.time_range.end }}</p>
                {% else %}
                <p>暫無時間資料</p>
                {% endif %}
            </div>
            
            <div class="stat-card" id="http-methods">
                <h3>🌐 HTTP方法</h3>
                {% if stats.get('methods') %}
                {% for method, count in stats.methods.items() %}
                <p><strong>{{ method }}:</strong> {{ count }}</p>
                {% endfor %}
                {% else %}
                <p>暫無方法資料</p>
                {% endif %}
            </div>
            
            <div class="stat-card" id="status-codes">
                <h3>📈 狀態碼</h3>
                {% if stats.get('status_codes') %}
                {% for code, count in stats.status_codes.items() %}
                <p><strong>{{ code }}:</strong> {{ count }}</p>
                {% endfor %}
                {% else %}
                <p>暫無狀態碼資料</p>
                {% endif %}
            </div>
        </div>
        
        <div class="chart">
            <h3>📊 狀態碼分布</h3>
            <img src="/chart/status_codes.png" alt="Status Codes Chart" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
            <p style="display:none; color:#666;">暫無圖表資料，請先執行分析</p>
        </div>
        
        <div class="chart">
            <h3>⏰ 每小時流量</h3>
            <img src="/chart/hourly_traffic.png" alt="Hourly Traffic Chart" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
            <p style="display:none; color:#666;">暫無圖表資料，請先執行分析</p>
        </div>
        
        <div class="chart">
            <h3>🔝 Top IPs</h3>
            <img src="/chart/top_ips.png" alt="Top IPs Chart" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
            <p style="display:none; color:#666;">暫無圖表資料，請先執行分析</p>
        </div>
        
        <div class="api-section">
            <h3>🔌 API端點</h3>
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
                <span class="method">GET</span> /health - 健康檢查
            </div>
        </div>
    </div>
    
    <script>
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
            const requiredElements = ['basic-stats', 'time-range', 'http-methods', 'status-codes'];
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
                httpMethods: document.getElementById('http-methods'),
                statusCodes: document.getElementById('status-codes')
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
                
                // 更新HTTP方法
                if (elements.httpMethods) {
                    let methodsHtml = '<h3>🌐 HTTP方法</h3>';
                    if (stats.methods && Object.keys(stats.methods).length > 0) {
                        for (let [method, count] of Object.entries(stats.methods)) {
                            methodsHtml += `<p><strong>${method}:</strong> ${count}</p>`;
                        }
                    } else {
                        methodsHtml += '<p>暫無方法資料</p>';
                    }
                    elements.httpMethods.innerHTML = methodsHtml;
                    console.log('HTTP方法更新成功');
                }
                
                // 更新狀態碼
                if (elements.statusCodes) {
                    let statusHtml = '<h3>📈 狀態碼</h3>';
                    if (stats.status_codes && Object.keys(stats.status_codes).length > 0) {
                        for (let [code, count] of Object.entries(stats.status_codes)) {
                            statusHtml += `<p><strong>${code}:</strong> ${count}</p>`;
                        }
                    } else {
                        statusHtml += '<p>暫無狀態碼資料</p>';
                    }
                    elements.statusCodes.innerHTML = statusHtml;
                    console.log('狀態碼更新成功');
                }
                
                console.log('統計顯示更新完成');
            } catch (error) {
                console.error('更新統計顯示時發生錯誤:', error);
                console.error('錯誤堆疊:', error.stack);
            }
        }
        
        // 更新圖表
        function updateCharts() {
            const charts = document.querySelectorAll('.chart img');
            charts.forEach(img => {
                img.src = img.src + '?t=' + new Date().getTime();
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
        
        return render_template_string(HTML_TEMPLATE, stats=stats)
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
        
        result = analyzer.run_full_analysis(log_filename, start_time, end_time, domain)
        
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
