from flask import Flask, render_template, request, jsonify, send_file
import traceback
import os
import json
from datetime import datetime
import pytz
from log_analyzer import LogAnalyzer

app = Flask(__name__, template_folder='templates', static_folder='static')

# 初始化LOG分析器
analyzer = LogAnalyzer()

# 設定版本時間（台北時間）- 每次上版時更新
taipei_tz = pytz.timezone('Asia/Taipei')
VERSION_TIME = datetime.now(taipei_tz).strftime('%Y-%m-%d %H:%M')

@app.route('/')
def index():
    """主頁面"""
    try:
        # 載入最新分析結果
        results_file = os.path.join(analyzer.output_dir, 'analysis_results.json')
        if os.path.exists(results_file):
            with open(results_file, 'r', encoding='utf-8') as f:
                stats = json.load(f)
        else:
            stats = {}
        
        return render_template('base.html', stats=stats, current_time=VERSION_TIME)
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
        
        # 執行分析
        stats = analyzer.get_basic_stats(filename, start_time, end_time, domain)
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
        
        # 執行分析
        hourly_data = analyzer.get_hourly_traffic(filename, start_time, end_time)
        return jsonify(hourly_data)
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
        
        # 執行分析
        anomalies = analyzer.detect_anomalies(filename, start_time, end_time)
        return jsonify(anomalies)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def run_analysis():
    """執行完整分析"""
    try:
        data = request.get_json() or {}
        log_filename = data.get('filename')
        
        # 如果 filename 是 list，取第一個元素
        if isinstance(log_filename, list):
            log_filename = log_filename[0] if log_filename else None
            
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        domain = data.get('domain')
        time_interval = data.get('time_interval', 'daily')
        
        # 執行完整分析
        results = analyzer.run_full_analysis(
            log_filename=log_filename,
            start_time=start_time,
            end_time=end_time,
            domain=domain,
            time_interval=time_interval
        )
        
        return jsonify({
            'success': True,
            'stats': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'trace': traceback.format_exc()}), 500

@app.route('/api/chart/<filename>')
def get_chart(filename):
    """取得圖表檔案"""
    try:
        chart_path = os.path.join(analyzer.output_dir, filename)
        if os.path.exists(chart_path):
            return send_file(chart_path)
        else:
            return "圖表檔案不存在", 404
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

@app.route('/api/logs/files')
def list_log_files():
    """列出可用的LOG檔案"""
    try:
        log_files = []
        if os.path.exists(analyzer.log_dir):
            for file in os.listdir(analyzer.log_dir):
                if file.endswith('.log') or file.endswith('.error.log') or file.endswith('.err') or file.endswith('.error'):
                    file_path = os.path.join(analyzer.log_dir, file)
                    file_size = os.path.getsize(file_path)
                    # 依副檔名粗略判斷類型
                    f_lower = file.lower()
                    ftype = 'error' if (f_lower.endswith('.error.log') or f_lower.endswith('.err') or f_lower.endswith('.error')) else 'access'
                    log_files.append({
                        'filename': file,
                        'size': file_size,
                        'type': ftype
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
        search = request.args.get('search', '')
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 10))
        
        # 執行分析
        logs_data = analyzer.get_logs(
            filename=filename,
            start_time=start_time,
            end_time=end_time,
            domain=domain,
            search=search,
            page=page,
            page_size=page_size,
            log_type=request.args.get('log_type')
        )
        
        return jsonify({
            'success': True,
            'logs': logs_data.get('logs', []),
            'total': logs_data.get('total', 0),
            'total_pages': logs_data.get('total_pages', 0),
            'current_page': page
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5566, debug=True)
