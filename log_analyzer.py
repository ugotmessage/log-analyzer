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
        # Nginx 與 Apache error log（寬鬆匹配）
        self.error_pattern_nginx = (
            r'(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] [^:]*: ?(?P<message>.*?)(?:, client: (?P<client>[^,]+))?(?:, server: (?P<server>[^,]+))?(?:, request: "(?P<request>[^\"]*)")?(?:, upstream: "(?P<upstream>[^\"]*)")?(?:, host: "(?P<host>[^\"]*)")?'
        )
        self.error_pattern_apache = (
            r'\[(?P<time>[^\]]+)\] \[(?P<module>[^:]+):(?P<level>\w+)\] (?:\[pid (?P<pid>\d+):tid (?P<tid>\d+)\] )?(?:\[client (?P<client>[^\]]+)\] )?(?P<message>.*)'
        )
        
        # 確保輸出目錄存在
        os.makedirs(output_dir, exist_ok=True)
        
    def parse_log_line(self, line: str) -> Dict[str, Any]:
        """解析單行log：先嘗試 access，再嘗試 error（nginx/apache）"""
        text = line.strip()
        # 1) Access log
        match = re.match(self.log_pattern, text)
        if match:
            groups = match.groups()
            return {
                'log_type': 'access',
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

        # 2) Nginx error log
        m_ng = re.match(self.error_pattern_nginx, text)
        if m_ng:
            gd = m_ng.groupdict()
            method = None
            url = None
            req = gd.get('request')
            if not req:
                m_req = re.search(r'request: "([^"]+)"', text)
                if m_req:
                    req = m_req.group(1)
            if req:
                parts = req.split()
                if len(parts) >= 2:
                    method = parts[0]
                    url = parts[1]
            # 訊息：從冒號後到第一個已知欄位（client/server/request/upstream/host）之前
            msg = (gd.get('message') or '').strip()
            if not msg:
                m2 = re.search(r":\s(?P<msg>.+?)(?:,\s(?:client|server|request|upstream|host):|$)", text)
                if m2:
                    msg = (m2.group('msg') or '').strip()
            if not msg:
                msg = text
            # 解析 client IP（正則群組缺時用全文擷取）
            client_ip_raw = (gd.get('client') or '')
            if not client_ip_raw:
                m_client = re.search(r", client: ([^,]+)", text)
                if m_client:
                    client_ip_raw = m_client.group(1)

            return {
                'log_type': 'error',
                'timestamp': gd.get('time'),
                'ip': (client_ip_raw or '').split(':')[0],
                'method': method,
                'url': url or gd.get('upstream') or gd.get('host') or gd.get('server'),
                'protocol': None,
                'status_code': None,
                'response_size': None,
                'referer': None,
                'user_agent': None,
                'level': gd.get('level'),
                'message': msg
            }

        # 3) Apache error log
        m_ap = re.match(self.error_pattern_apache, text)
        if m_ap:
            gd = m_ap.groupdict()
            method = None
            url = None
            msg = gd.get('message') or ''
            req_m = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^\s\"]+)[^\"]*"', msg)
            if req_m:
                method = req_m.group(1)
                url = req_m.group(2)
            if not msg:
                m2 = re.search(r"\] (?P<msg>.+)$", text)
                if m2:
                    msg = (m2.group('msg') or '').strip()
            if not msg:
                msg = text
            client = gd.get('client')
            client_ip = client.split(':')[0] if client else None
            return {
                'log_type': 'error',
                'timestamp': gd.get('time'),
                'ip': client_ip,
                'method': method,
                'url': url,
                'protocol': None,
                'status_code': None,
                'response_size': None,
                'referer': None,
                'user_agent': None,
                'level': gd.get('level'),
                'message': msg
            }

        # 4) 其他未知格式
        return None
    
    def load_logs(self, filename: str = None, start_time: str = None, end_time: str = None, domain: str = None) -> List[Dict[str, Any]]:
        """載入並解析log檔案，支援時間範圍和網域過濾"""
        logs = []
        
        if filename:
            # 防呆：若 filename 來自表單可能是 list/tuple（甚至巢狀），取第一個有效字串
            while isinstance(filename, (list, tuple)):
                filename = filename[0] if filename else None
                if filename is None:
                    break
            file_path = os.path.join(self.log_dir, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        parsed = self.parse_log_line(line)
                        if parsed:
                            logs.append(parsed)
        else:
            # 載入所有log檔案（同時包含 access 與常見 error 副檔名）
            for file in os.listdir(self.log_dir):
                if file.endswith('.log') or file.endswith('.error.log') or file.endswith('.err') or file.endswith('.error'):
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
                # 解析時間戳記（同時支援 access 與 nginx error 常見格式）
                ts = log.get('timestamp')
                log_time = None
                for fmt in ('%d/%b/%Y:%H:%M:%S %z', '%Y/%m/%d %H:%M:%S', '%a %b %d %H:%M:%S.%f %Y'):
                    try:
                        log_time = pd.to_datetime(ts, format=fmt)
                        break
                    except Exception:
                        continue
                if log_time is None:
                    # 最後嘗試自動解析
                    log_time = pd.to_datetime(ts, errors='coerce')
                if pd.isna(log_time):
                    continue
                
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
            # 檢查URL/Referer 是否包含指定網域
            url = str(log.get('url', '')).lower()
            ref = str(log.get('referer', '')).lower()
            if domain.lower() in url or domain.lower() in ref:
                filtered_logs.append(log)
        
        return filtered_logs
    
    def get_basic_stats(self, filename: str = None, start_time: str = None, end_time: str = None, domain: str = None) -> Dict[str, Any]:
        """取得基本統計資訊"""
        logs = self.load_logs(filename, start_time, end_time, domain)
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        
        # 轉換時間戳記（統一為無時區 datetime64[ns]）
        df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%Y/%m/%d %H:%M:%S', errors='coerce')
        # 去除時區並強制為 datetime64[ns]
        try:
            df['datetime'] = df['datetime'].dt.tz_convert(None)
        except Exception:
            try:
                df['datetime'] = df['datetime'].dt.tz_localize(None)
            except Exception:
                pass
        df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        
        # 數值欄位清洗，避免 NaN 造成 int 轉換錯誤
        df['response_size'] = pd.to_numeric(df.get('response_size', 0), errors='coerce').fillna(0).astype('int64')
        df['status_code'] = pd.to_numeric(df.get('status_code', 0), errors='coerce').fillna(0).astype('int64')

        # 產出熱門IP/URL為陣列以相容前端 slice/map
        top_ips_counts = df['ip'].value_counts().head(10)
        top_ips_list = [{ 'ip': str(ip), 'count': int(cnt) } for ip, cnt in top_ips_counts.items()]
        top_urls_counts = df['url'].value_counts().head(10)
        top_urls_list = [{ 'url': str(url), 'count': int(cnt) } for url, cnt in top_urls_counts.items()]

        stats = {
            'total_requests': int(len(logs)),
            'unique_ips': int(df['ip'].nunique()),
            'status_codes': {str(k): int(v) for k, v in df['status_code'].value_counts().to_dict().items()},
            'top_ips': top_ips_list,
            'top_urls': top_urls_list,
            'methods': {str(k): int(v) for k, v in df['method'].value_counts().to_dict().items()},
            'time_range': {
                'start': df['datetime'].min().isoformat(),
                'end': df['datetime'].max().isoformat()
            },
            'total_bytes': int(df['response_size'].sum()),
            'avg_response_size': int(df['response_size'].mean())
        }
        
        return stats
    
    def get_basic_stats_from_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """從logs列表取得基本統計資訊（內部方法）"""
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        
        # 轉換時間戳記（統一為無時區 datetime64[ns]）
        df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%Y/%m/%d %H:%M:%S', errors='coerce')
        try:
            df['datetime'] = df['datetime'].dt.tz_convert(None)
        except Exception:
            try:
                df['datetime'] = df['datetime'].dt.tz_localize(None)
            except Exception:
                pass
        df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        
        # 數值欄位清洗
        df['response_size'] = pd.to_numeric(df.get('response_size', 0), errors='coerce').fillna(0).astype('int64')
        df['status_code'] = pd.to_numeric(df.get('status_code', 0), errors='coerce').fillna(0).astype('int64')

        top_ips_counts = df['ip'].value_counts().head(10)
        top_ips_list = [{ 'ip': str(ip), 'count': int(cnt) } for ip, cnt in top_ips_counts.items()]
        top_urls_counts = df['url'].value_counts().head(10)
        top_urls_list = [{ 'url': str(url), 'count': int(cnt) } for url, cnt in top_urls_counts.items()]
        
        stats = {
            'total_requests': int(len(logs)),
            'unique_ips': int(df['ip'].nunique()),
            'status_codes': {str(k): int(v) for k, v in df['status_code'].value_counts().to_dict().items()},
            'top_ips': top_ips_list,
            'top_urls': top_urls_list,
            'methods': {str(k): int(v) for k, v in df['method'].value_counts().to_dict().items()},
            'time_range': {
                'start': df['datetime'].min().isoformat(),
                'end': df['datetime'].max().isoformat()
            },
            'total_bytes': int(df['response_size'].sum()),
            'avg_response_size': int(df['response_size'].mean())
        }
        
        return stats
    
    def get_hourly_traffic(self, filename: str = None, start_time: str = None, end_time: str = None) -> Dict[str, Any]:
        """分析每小時流量"""
        logs = self.load_logs(filename, start_time, end_time)
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%Y/%m/%d %H:%M:%S', errors='coerce')
        try:
            df['datetime'] = df['datetime'].dt.tz_convert(None)
        except Exception:
            try:
                df['datetime'] = df['datetime'].dt.tz_localize(None)
            except Exception:
                pass
        df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        # 移除無法解析的列，避免 .dt 錯誤
        df = df.dropna(subset=['datetime'])
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
    
    def analyze_hourly_traffic_from_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """從logs列表分析每小時流量（內部方法）"""
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%Y/%m/%d %H:%M:%S', errors='coerce')
        try:
            df['datetime'] = df['datetime'].dt.tz_convert(None)
        except Exception:
            try:
                df['datetime'] = df['datetime'].dt.tz_localize(None)
            except Exception:
                pass
        df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        df = df.dropna(subset=['datetime'])
        df['hour'] = df['datetime'].dt.hour
        
        hourly_stats = df.groupby('hour').agg({
            'ip': 'count',
            'response_size': 'sum'
        }).rename(columns={'ip': 'requests', 'response_size': 'bytes'})
        
        result = {}
        for hour, row in hourly_stats.iterrows():
            result[str(hour)] = {
                'requests': int(row['requests']),
                'bytes': int(row['bytes'])
            }
        
        return result
    
    def detect_anomalies_from_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """從logs列表檢測異常行為（內部方法）"""
        if not logs:
            return {}
            
        df = pd.DataFrame(logs)
        
        anomalies = {
            'high_frequency_ips': [],
            'error_requests': [],
            'large_requests': []
        }
        
        # 高頻率IP檢測
        ip_counts = df['ip'].value_counts()
        high_freq_threshold = ip_counts.mean() + 2 * ip_counts.std()
        high_freq_ips = ip_counts[ip_counts > high_freq_threshold]
        
        for ip, count in high_freq_ips.items():
            anomalies['high_frequency_ips'].append({
                'ip': ip,
                'count': int(count),
                'reason': 'High request frequency'
            })
        
        # 錯誤請求檢測
        error_logs = df[df['status_code'] >= 400]
        for _, log in error_logs.iterrows():
            anomalies['error_requests'].append({
                'ip': log['ip'],
                'url': log['url'],
                'status_code': int(log['status_code']),
                'timestamp': log['timestamp']
            })
        
        # 大請求檢測
        large_requests = df[df['response_size'] > df['response_size'].quantile(0.95)]
        for _, log in large_requests.iterrows():
            anomalies['large_requests'].append({
                'ip': log['ip'],
                'url': log['url'],
                'size': int(log['response_size']),
                'timestamp': log['timestamp']
            })
        
        return anomalies
    
    def get_logs(self, filename: str = None, start_time: str = None, end_time: str = None, 
                 domain: str = None, search: str = None, page: int = 1, page_size: int = 10, log_type: str = None) -> Dict[str, Any]:
        """取得LOG資料，支援分頁和搜尋"""
        logs = self.load_logs(filename, start_time, end_time, domain)
        
        # 依 log_type 過濾（'access' 或 'error'）
        if log_type in ('access', 'error', 'raw'):
            logs = [l for l in logs if l.get('log_type') == log_type]
        
        # 應用搜尋過濾
        if search:
            search_lower = str(search).lower()
            def s(val):
                return str(val or '').lower()
            logs = [log for log in logs if 
                   search_lower in s(log.get('ip')) or
                   search_lower in s(log.get('url')) or
                   search_lower in s(log.get('method')) or
                   search_lower in s(log.get('status_code')) or
                   search_lower in s(log.get('user_agent')) or
                   search_lower in s(log.get('message'))]
        
        # 計算分頁
        total = len(logs)
        total_pages = (total + page_size - 1) // page_size
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_logs = logs[start_idx:end_idx]
        
        return {
            'logs': paginated_logs,
            'total': total,
            'total_pages': total_pages,
            'current_page': page
        }
    
    def detect_anomalies(self, filename: str = None, start_time: str = None, end_time: str = None) -> Dict[str, Any]:
        """檢測異常行為"""
        logs = self.load_logs(filename, start_time, end_time)
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
        # 圖表也改為寬鬆解析（先自動，其次 access，再 nginx error）
        df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce', utc=True)
        mask_na = df['datetime'].isna()
        if mask_na.any():
            df.loc[mask_na, 'datetime'] = pd.to_datetime(df.loc[mask_na, 'timestamp'], format='%Y/%m/%d %H:%M:%S', errors='coerce')
        try:
            df['datetime'] = df['datetime'].dt.tz_convert(None)
        except Exception:
            try:
                df['datetime'] = df['datetime'].dt.tz_localize(None)
            except Exception:
                pass
        df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        df = df.dropna(subset=['datetime'])
        
        chart_files = []
        
        # 1. Traffic trend (supports dynamic time interval)
        if time_interval == 'hourly':
            df['time_group'] = df['datetime'].dt.floor('H')
            group_col = 'time_group'
            title = 'Hourly Traffic Trend'
        elif time_interval == 'daily':
            df['time_group'] = df['datetime'].dt.date
            group_col = 'time_group'
            title = 'Daily Traffic Trend'
        elif time_interval == 'weekly':
            df['time_group'] = df['datetime'].dt.to_period('W').dt.start_time
            group_col = 'time_group'
            title = 'Weekly Traffic Trend'
        elif time_interval == 'monthly':
            df['time_group'] = df['datetime'].dt.to_period('M').dt.start_time
            group_col = 'time_group'
            title = 'Monthly Traffic Trend'
        else:
            df['time_group'] = df['datetime'].dt.date
            group_col = 'time_group'
            title = 'Daily Traffic Trend'

        # 計算流量統計
        traffic_stats = df.groupby(group_col).agg({
            'ip': 'count',
            'response_size': 'sum'
        }).rename(columns={'ip': 'requests', 'response_size': 'bytes'}).reset_index()

        # Create dual-axis figure
        fig = make_subplots(specs=[[{"secondary_y": True}]])

        # Requests line
        fig.add_trace(
            go.Scatter(
                x=traffic_stats[group_col],
                y=traffic_stats['requests'],
                name='Requests',
                line=dict(color='#667eea', width=3),
                mode='lines+markers',
                marker=dict(size=6)
            ),
            secondary_y=False
        )

        # Traffic line
        fig.add_trace(
            go.Scatter(
                x=traffic_stats[group_col],
                y=traffic_stats['bytes'] / 1024 / 1024,
                name='Traffic (MB)',
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
                title=dict(text='Time', font=dict(size=12, family='Arial, sans-serif')),
                tickfont=dict(size=10, family='Arial, sans-serif'),
                tickangle=45
            ),
            yaxis=dict(
                title=dict(text='Requests', font=dict(size=12, family='Arial, sans-serif')),
                tickfont=dict(size=10, family='Arial, sans-serif')
            ),
            yaxis2=dict(
                title=dict(text='Traffic (MB)', font=dict(size=12, family='Arial, sans-serif')),
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

        # 2. Top IPs
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
                text='Top IPs (Top 10)',
                font=dict(size=16, family='Arial, sans-serif'),
                x=0.5
            ),
            xaxis=dict(
                title=dict(text='Requests', font=dict(size=12, family='Arial, sans-serif')),
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

        # 3. Top URLs
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
                text='Top URLs (Top 12)',
                font=dict(size=16, family='Arial, sans-serif'),
                x=0.5
            ),
            xaxis=dict(
                title=dict(text='Requests', font=dict(size=12, family='Arial, sans-serif')),
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
        stats = self.get_basic_stats_from_logs(logs)
        hourly = self.analyze_hourly_traffic_from_logs(logs)
        anomalies = self.detect_anomalies_from_logs(logs)
        
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
        # 防呆 normalize
        while isinstance(log_filename, (list, tuple)):
            log_filename = log_filename[0] if log_filename else None
            if log_filename is None:
                break
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
        stats = self.get_basic_stats_from_logs(logs)
        
        print("分析每小時流量...")
        hourly = self.analyze_hourly_traffic_from_logs(logs)
        
        print("檢測異常行為...")
        anomalies = self.detect_anomalies_from_logs(logs)
        
        print(f"生成圖表 (時間級距: {time_interval})...")
        charts = self.generate_charts(logs, time_interval)
        
        print("匯出結果...")
        results_file = self.export_results(logs)
        
        print(f"分析完成！結果已儲存至: {results_file}")
        print(f"圖表檔案類型: {type(charts)}")
        print(f"圖表檔案內容: {charts}")
        if isinstance(charts, list):
            print(f"圖表檔案: {', '.join(charts)}")
        else:
            print(f"圖表檔案不是列表: {charts}")
        
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
