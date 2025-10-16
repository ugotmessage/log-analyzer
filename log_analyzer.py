import re
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import List, Dict, Any
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
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
    
    def generate_charts(self, logs: List[Dict[str, Any]], time_interval: str = 'daily') -> List[str]:
        """生成圖表（使用plotly）"""
        if not logs:
            return []

        df = pd.DataFrame(logs)
        df['datetime'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

        chart_files = []

        # 1. 流量趨勢圖（支援動態時間級距）
        if time_interval == 'hourly':
            df['time_group'] = df['datetime'].dt.floor('H')
            group_col = 'time_group'
            title = '每小時流量趨勢'
        elif time_interval == 'daily':
            df['time_group'] = df['datetime'].dt.date
            group_col = 'time_group'
            title = '每日流量趨勢'
        elif time_interval == 'weekly':
            df['time_group'] = df['datetime'].dt.to_period('W').dt.start_time
            group_col = 'time_group'
            title = '每週流量趨勢'
        elif time_interval == 'monthly':
            df['time_group'] = df['datetime'].dt.to_period('M').dt.start_time
            group_col = 'time_group'
            title = '每月流量趨勢'
        else:
            df['time_group'] = df['datetime'].dt.date
            group_col = 'time_group'
            title = '每日流量趨勢'

        # 計算流量統計
        traffic_stats = df.groupby(group_col).agg({
            'ip': 'count',
            'response_size': 'sum'
        }).rename(columns={'ip': 'requests', 'response_size': 'bytes'}).reset_index()

        # 創建雙軸圖表
        fig = make_subplots(specs=[[{"secondary_y": True}]])

        # 添加請求數線圖
        fig.add_trace(
            go.Scatter(
                x=traffic_stats[group_col],
                y=traffic_stats['requests'],
                name='請求數',
                line=dict(color='#667eea', width=3),
                mode='lines+markers',
                marker=dict(size=6)
            ),
            secondary_y=False
        )

        # 添加流量線圖
        fig.add_trace(
            go.Scatter(
                x=traffic_stats[group_col],
                y=traffic_stats['bytes'] / 1024 / 1024,
                name='流量 (MB)',
                line=dict(color='#f39c12', width=3),
                mode='lines+markers',
                marker=dict(size=6)
            ),
            secondary_y=True
        )

        # 更新佈局
        fig.update_layout(
            title=dict(
                text=title,
                font=dict(size=16, family='Arial, sans-serif'),
                x=0.5
            ),
            xaxis=dict(
                title=dict(text='時間', font=dict(size=12, family='Arial, sans-serif')),
                tickfont=dict(size=10, family='Arial, sans-serif'),
                tickangle=45
            ),
            yaxis=dict(
                title=dict(text='請求數', font=dict(size=12, family='Arial, sans-serif')),
                tickfont=dict(size=10, family='Arial, sans-serif')
            ),
            yaxis2=dict(
                title=dict(text='流量 (MB)', font=dict(size=12, family='Arial, sans-serif')),
                tickfont=dict(size=10, family='Arial, sans-serif')
            ),
            legend=dict(
                font=dict(size=12, family='Arial, sans-serif')
            ),
            height=400,
            width=600,
            margin=dict(l=60, r=60, t=80, b=80)
        )

        # 儲存圖表
        traffic_chart = os.path.join(self.output_dir, 'traffic_trend.png')
        fig.write_image(traffic_chart, format='png', engine='kaleido', scale=2)
        chart_files.append(traffic_chart)

        # 2. Top IPs 分布圖
        top_ips = df['ip'].value_counts().head(10).reset_index()
        top_ips.columns = ['ip', 'count']

        fig_ip = go.Figure()
        fig_ip.add_trace(
            go.Bar(
                y=top_ips['ip'],
                x=top_ips['count'],
                orientation='h',
                marker=dict(color='#667eea'),
                text=top_ips['count'],
                textposition='outside',
                textfont=dict(size=10, family='Arial, sans-serif')
            )
        )

        fig_ip.update_layout(
            title=dict(
                text='熱門IP分布 (Top 10)',
                font=dict(size=16, family='Arial, sans-serif'),
                x=0.5
            ),
            xaxis=dict(
                title=dict(text='請求數', font=dict(size=12, family='Arial, sans-serif')),
                tickfont=dict(size=10, family='Arial, sans-serif')
            ),
            yaxis=dict(
                tickfont=dict(size=10, family='Arial, sans-serif')
            ),
            height=400,
            width=500,
            margin=dict(l=100, r=60, t=80, b=60)
        )

        ips_chart = os.path.join(self.output_dir, 'top_ips.png')
        fig_ip.write_image(ips_chart, format='png', engine='kaleido', scale=2)
        chart_files.append(ips_chart)

        # 3. Top URLs 分布圖
        top_urls = df['url'].value_counts().head(12).reset_index()
        top_urls.columns = ['url', 'count']

        # 截斷過長的URL
        top_urls['display_url'] = top_urls['url'].apply(lambda x: x[:40] + '...' if len(x) > 40 else x)

        fig_url = go.Figure()
        fig_url.add_trace(
            go.Bar(
                y=top_urls['display_url'],
                x=top_urls['count'],
                orientation='h',
                marker=dict(color='#27ae60'),
                text=top_urls['count'],
                textposition='outside',
                textfont=dict(size=10, family='Arial, sans-serif')
            )
        )

        fig_url.update_layout(
            title=dict(
                text='熱門URL分布 (Top 12)',
                font=dict(size=16, family='Arial, sans-serif'),
                x=0.5
            ),
            xaxis=dict(
                title=dict(text='請求數', font=dict(size=12, family='Arial, sans-serif')),
                tickfont=dict(size=10, family='Arial, sans-serif')
            ),
            yaxis=dict(
                tickfont=dict(size=9, family='Arial, sans-serif')
            ),
            height=500,
            width=800,
            margin=dict(l=200, r=60, t=80, b=60)
        )

        urls_chart = os.path.join(self.output_dir, 'top_urls.png')
        fig_url.write_image(urls_chart, format='png', engine='kaleido', scale=2)
        chart_files.append(urls_chart)

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
    
    def run_full_analysis(self, log_filename: str = None, start_time: str = None, end_time: str = None, domain: str = None, time_interval: str = 'daily'):
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
        
        print(f"生成圖表 (時間級距: {time_interval})...")
        charts = self.generate_charts(logs, time_interval)
        
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
                'domain': domain,
                'time_interval': time_interval
            }
        }
