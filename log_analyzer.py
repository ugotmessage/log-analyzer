import re
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict, Any
import json


class LogAnalyzer:
    """Apache/Nginx LOG分析器"""
    
    def __init__(self, log_dir: str = "/app/logs", output_dir: str = "/app/output"):
        self.log_dir = log_dir
        self.output_dir = output_dir
        self.log_pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) ([^"]+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        
        # 確保輸出目錄存在
        os.makedirs(output_dir, exist_ok=True)
        
    def parse_log_line(self, line: str) -> Dict[str, Any]:
        """解析單行log"""
        match = re.match(self.log_pattern, line.strip())
        if not match:
            return None
            
        groups = match.groups()
        return {
            'ip': groups[0],
            'timestamp': groups[1],
            'method': groups[2],
            'url': groups[3],
            'protocol': groups[4],
            'status_code': int(groups[5]),
            'response_size': int(groups[6]),
            'referer': groups[7],
            'user_agent': groups[8]
        }
    
    def load_logs(self, filename: str = None, start_time: str = None, end_time: str = None, domain: str = None) -> List[Dict[str, Any]]:
        """載入並解析log檔案，支援時間範圍和網域過濾"""
        logs = []
        
        if filename:
            file_path = os.path.join(self.log_dir, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        parsed = self.parse_log_line(line)
                        if parsed:
                            logs.append(parsed)
        else:
            # 載入所有log檔案
            for file in os.listdir(self.log_dir):
                if file.endswith('.log'):
                    file_path = os.path.join(self.log_dir, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            parsed = self.parse_log_line(line)
                            if parsed:
                                logs.append(parsed)
        
        # 應用過濾條件
        filtered_logs = self._apply_filters(logs, start_time, end_time, domain)
        return filtered_logs
    
    def _apply_filters(self, logs: List[Dict[str, Any]], start_time: str = None, end_time: str = None, domain: str = None) -> List[Dict[str, Any]]:
        """應用時間範圍和網域過濾"""
        filtered_logs = logs.copy()
        
        # 時間範圍過濾
        if start_time or end_time:
            filtered_logs = self._filter_by_time_range(filtered_logs, start_time, end_time)
        
        # 網域過濾
        if domain:
            filtered_logs = self._filter_by_domain(filtered_logs, domain)
        
        return filtered_logs
    
    def _filter_by_time_range(self, logs: List[Dict[str, Any]], start_time: str = None, end_time: str = None) -> List[Dict[str, Any]]:
        """根據時間範圍過濾logs"""
        filtered_logs = []
        
        for log in logs:
            try:
                # 解析時間戳記
                log_time = pd.to_datetime(log['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
                
                # 檢查時間範圍
                if start_time:
                    start_dt = pd.to_datetime(start_time)
                    if log_time < start_dt:
                        continue
                
                if end_time:
                    end_dt = pd.to_datetime(end_time)
                    if log_time > end_dt:
                        continue
                
                filtered_logs.append(log)
            except Exception as e:
                # 如果時間解析失敗，跳過這條記錄
                continue
        
        return filtered_logs
    
    def _filter_by_domain(self, logs: List[Dict[str, Any]], domain: str) -> List[Dict[str, Any]]:
        """根據網域過濾logs"""
        filtered_logs = []
        
        for log in logs:
            # 檢查URL是否包含指定網域
            if domain.lower() in log['url'].lower() or domain.lower() in log['referer'].lower():
                filtered_logs.append(log)
        
        return filtered_logs
    
    def get_basic_stats(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """取得基本統計資訊"""
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        
        # 轉換時間戳記
        df['datetime'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        
        stats = {
            'total_requests': int(len(logs)),
            'unique_ips': int(df['ip'].nunique()),
            'status_codes': {str(k): int(v) for k, v in df['status_code'].value_counts().to_dict().items()},
            'top_ips': {str(k): int(v) for k, v in df['ip'].value_counts().head(10).to_dict().items()},
            'top_urls': {str(k): int(v) for k, v in df['url'].value_counts().head(10).to_dict().items()},
            'methods': {str(k): int(v) for k, v in df['method'].value_counts().to_dict().items()},
            'time_range': {
                'start': df['datetime'].min().isoformat(),
                'end': df['datetime'].max().isoformat()
            },
            'total_bytes': int(df['response_size'].sum()),
            'avg_response_size': float(df['response_size'].mean())
        }
        
        return stats
    
    def analyze_hourly_traffic(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析每小時流量"""
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        df['datetime'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        df['hour'] = df['datetime'].dt.hour
        
        hourly_stats = df.groupby('hour').agg({
            'ip': 'count',
            'response_size': 'sum'
        }).rename(columns={'ip': 'requests', 'response_size': 'bytes'})
        
        # 轉換為可序列化的格式
        result = {}
        for hour, row in hourly_stats.iterrows():
            result[str(hour)] = {
                'requests': int(row['requests']),
                'bytes': int(row['bytes'])
            }
        
        return result
    
    def detect_anomalies(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """檢測異常行為"""
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        
        anomalies = {
            'high_frequency_ips': [],
            'error_requests': [],
            'large_requests': []
        }
        
        # 高頻率IP
        ip_counts = df['ip'].value_counts()
        high_freq_threshold = ip_counts.mean() + 2 * ip_counts.std()
        anomalies['high_frequency_ips'] = ip_counts[ip_counts > high_freq_threshold].to_dict()
        
        # 錯誤請求
        error_codes = df[df['status_code'] >= 400]
        anomalies['error_requests'] = error_codes.groupby('status_code').size().to_dict()
        
        # 大檔案請求
        large_requests = df[df['response_size'] > df['response_size'].quantile(0.95)]
        anomalies['large_requests'] = large_requests[['ip', 'url', 'response_size']].to_dict('records')
        
        return anomalies
    
    def generate_charts(self, logs: List[Dict[str, Any]]) -> List[str]:
        """生成圖表"""
        if not logs:
            return []
            
        df = pd.DataFrame(logs)
        df['datetime'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        
        chart_files = []
        
        # 設定中文字體
        plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False
        
        # 1. 狀態碼分布
        plt.figure(figsize=(10, 6))
        df['status_code'].value_counts().plot(kind='bar')
        plt.title('HTTP Status Code Distribution')
        plt.xlabel('Status Code')
        plt.ylabel('Count')
        plt.tight_layout()
        status_chart = os.path.join(self.output_dir, 'status_codes.png')
        plt.savefig(status_chart)
        plt.close()
        chart_files.append(status_chart)
        
        # 2. 每小時流量
        plt.figure(figsize=(12, 6))
        df['hour'] = df['datetime'].dt.hour
        hourly_counts = df.groupby('hour').size()
        hourly_counts.plot(kind='line', marker='o')
        plt.title('Hourly Traffic Distribution')
        plt.xlabel('Hour')
        plt.ylabel('Requests')
        plt.grid(True)
        plt.tight_layout()
        hourly_chart = os.path.join(self.output_dir, 'hourly_traffic.png')
        plt.savefig(hourly_chart)
        plt.close()
        chart_files.append(hourly_chart)
        
        # 3. Top IPs
        plt.figure(figsize=(12, 6))
        top_ips = df['ip'].value_counts().head(10)
        top_ips.plot(kind='bar')
        plt.title('Top 10 IP Addresses')
        plt.xlabel('IP Address')
        plt.ylabel('Requests')
        plt.xticks(rotation=45)
        plt.tight_layout()
        ips_chart = os.path.join(self.output_dir, 'top_ips.png')
        plt.savefig(ips_chart)
        plt.close()
        chart_files.append(ips_chart)
        
        return chart_files
    
    def export_results(self, logs: List[Dict[str, Any]], filename: str = "analysis_results.json"):
        """匯出分析結果"""
        stats = self.get_basic_stats(logs)
        hourly = self.analyze_hourly_traffic(logs)
        anomalies = self.detect_anomalies(logs)
        
        results = {
            'basic_stats': stats,
            'hourly_traffic': hourly,
            'anomalies': anomalies,
            'generated_at': datetime.now().isoformat()
        }
        
        output_file = os.path.join(self.output_dir, filename)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        return output_file
    
    def run_full_analysis(self, log_filename: str = None, start_time: str = None, end_time: str = None, domain: str = None):
        """執行完整分析，支援時間範圍和網域過濾"""
        print("開始載入LOG檔案...")
        logs = self.load_logs(log_filename, start_time, end_time, domain)
        
        if not logs:
            print("未找到有效的LOG資料")
            return None
        
        print(f"載入了 {len(logs)} 筆LOG記錄")
        
        # 如果有過濾條件，顯示過濾資訊
        filter_info = []
        if start_time:
            filter_info.append(f"開始時間: {start_time}")
        if end_time:
            filter_info.append(f"結束時間: {end_time}")
        if domain:
            filter_info.append(f"網域: {domain}")
        
        if filter_info:
            print(f"過濾條件: {', '.join(filter_info)}")
        
        print("生成基本統計...")
        stats = self.get_basic_stats(logs)
        
        print("分析每小時流量...")
        hourly = self.analyze_hourly_traffic(logs)
        
        print("檢測異常行為...")
        anomalies = self.detect_anomalies(logs)
        
        print("生成圖表...")
        charts = self.generate_charts(logs)
        
        print("匯出結果...")
        results_file = self.export_results(logs)
        
        print(f"分析完成！結果已儲存至: {results_file}")
        print(f"圖表檔案: {', '.join(charts)}")
        
        return {
            'stats': stats,
            'hourly': hourly,
            'anomalies': anomalies,
            'charts': charts,
            'results_file': results_file,
            'filters': {
                'start_time': start_time,
                'end_time': end_time,
                'domain': domain
            }
        }
