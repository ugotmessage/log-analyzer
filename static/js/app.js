// 全域變數
let currentLogs = [];
let filteredLogs = [];
let currentPage = 1;
let pageSize = 10;
let searchKeyword = '';
let timeInterval = 'daily';

// 頁面載入時初始化
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM載入完成，開始初始化...');
    loadLogFiles();
    loadStats();
    loadLogs();
    updateCharts();
    console.log('初始化完成');
});

// 載入LOG檔案列表
async function loadLogFiles() {
    try {
        const response = await fetch('/api/logs/files');
        const data = await response.json();
        const select = document.getElementById('filename');
        select.innerHTML = '<option value="">所有檔案</option>';
        if (data.log_files && Array.isArray(data.log_files)) {
            data.log_files.forEach(file => {
                const option = document.createElement('option');
                option.value = file.filename;
                option.textContent = `${file.filename} (${(file.size / 1024).toFixed(1)}KB)`;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('載入LOG檔案失敗:', error);
    }
}

// 載入統計資料
async function loadStats() {
    try {
        // 依目前過濾條件組裝查詢參數
        const form = document.getElementById('filterForm');
        const formData = form ? new FormData(form) : new FormData();
        const params = new URLSearchParams();
        const selectedFile = formData.get('filename');
        for (let [key, value] of formData.entries()) {
            if (value) params.append(key, value);
        }
        // 若未選擇檔案：不呼叫後端，直接顯示引導訊息
        if (!selectedFile) {
            const totalRequestsEl = document.getElementById('totalRequests');
            const uniqueIPsEl = document.getElementById('uniqueIPs');
            const totalBytesEl = document.getElementById('totalBytes');
            const avgResponseTimeEl = document.getElementById('avgResponseTime');
            if (totalRequestsEl) totalRequestsEl.textContent = '-';
            if (uniqueIPsEl) uniqueIPsEl.textContent = '-';
            if (totalBytesEl) totalBytesEl.textContent = '-';
            if (avgResponseTimeEl) avgResponseTimeEl.textContent = '-';
            const topUrlsContent = document.getElementById('topUrlsContent');
            const topIpsContent = document.getElementById('topIpsContent');
            if (topUrlsContent) topUrlsContent.innerHTML = '<p>請先選擇 LOG 檔案後再分析</p>';
            if (topIpsContent) topIpsContent.innerHTML = '<p>請先選擇 LOG 檔案後再分析</p>';
            const startEl = document.getElementById('startTimeDisplay');
            const endEl = document.getElementById('endTimeDisplay');
            if (startEl) startEl.textContent = '-';
            if (endEl) endEl.textContent = '-';
            return;
        }

        const response = await fetch(`/api/stats?${params.toString()}`);
        const stats = await response.json();
        
        // 更新統計卡片
        const totalRequestsEl = document.getElementById('totalRequests');
        const uniqueIPsEl = document.getElementById('uniqueIPs');
        const totalBytesEl = document.getElementById('totalBytes');
        const avgResponseTimeEl = document.getElementById('avgResponseTime');
        
        if (totalRequestsEl) totalRequestsEl.textContent = stats.total_requests || 0;
        if (uniqueIPsEl) uniqueIPsEl.textContent = stats.unique_ips || 0;
        if (totalBytesEl) totalBytesEl.textContent = ((stats.total_bytes || 0) / 1024 / 1024).toFixed(1);
        if (avgResponseTimeEl) avgResponseTimeEl.textContent = stats.avg_response_size || 0;
        
        // 更新時間範圍
        if (stats.time_range) {
            document.getElementById('startTimeDisplay').textContent = stats.time_range.start || '-';
            document.getElementById('endTimeDisplay').textContent = stats.time_range.end || '-';
        }
        
        // 更新熱門URL（後端為物件，轉為陣列再取前五）
        if (stats.top_urls) {
            const topUrlsContent = document.getElementById('topUrlsContent');
            if (!topUrlsContent) return;
            const urlArray = Array.isArray(stats.top_urls)
                ? stats.top_urls
                : Object.entries(stats.top_urls).map(([url, count]) => ({ url, count }));
            topUrlsContent.innerHTML = urlArray.slice(0, 5).map(item => 
                `<p><strong>${item.url}</strong><br><small>${item.count} 次請求</small></p>`
            ).join('');
        }
        
        // 更新熱門IP（後端為物件，轉為陣列再取前五）
        if (stats.top_ips) {
            const topIpsContent = document.getElementById('topIpsContent');
            if (!topIpsContent) return;
            const ipArray = Array.isArray(stats.top_ips)
                ? stats.top_ips
                : Object.entries(stats.top_ips).map(([ip, count]) => ({ ip, count }));
            topIpsContent.innerHTML = ipArray.slice(0, 5).map(item => 
                `<p><strong>${item.ip}</strong><br><small>${item.count} 次請求</small></p>`
            ).join('');
        }
    } catch (error) {
        console.error('載入統計資料失敗:', error);
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
            currentLogs = data.logs || [];
            filteredLogs = currentLogs;
            updateLogTable();
            updatePagination(data.total_pages || 1);
        } else {
            console.error('載入LOG資料失敗:', data.error);
            showLogMessage('載入LOG資料失敗: ' + data.error);
        }
    } catch (error) {
        console.error('載入LOG資料失敗:', error);
        showLogMessage('載入LOG資料失敗: ' + error.message);
    }
}

// 顯示LOG訊息
function showLogMessage(message) {
    const tbody = document.getElementById('logTableBody');
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 20px; color: #e74c3c;">${message}</td></tr>`;
}

// 更新LOG表格
function updateLogTable() {
    const tbody = document.getElementById('logTableBody');
    if (filteredLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px;">無資料</td></tr>';
        return;
    }
    
    tbody.innerHTML = filteredLogs.map(log => {
        try {
            return `
                <tr>
                    <td>${formatTimestamp(log.timestamp)}</td>
                    <td>${log.ip || '-'}</td>
                    <td><span class="status-code status-${Math.floor((log.status_code || 0) / 100) * 100}">${log.status_code || '-'}</span></td>
                    <td>${log.method || '-'}</td>
                    <td title="${(log.url || log.upstream || log.host || log.server || '')}">${truncateText((log.url || log.upstream || log.host || log.server || ''), 50)}</td>
                    <td>${formatBytes(log.response_size || 0)}</td>
                    <td>${log.user_agent ? truncateText(log.user_agent, 30) : '-'}</td>
                    <td>${log.message ? truncateText(log.message, 80) : '-'}</td>
                </tr>
            `;
        } catch (error) {
            console.error('處理LOG記錄時出錯:', error, log);
            return `
                <tr>
                    <td colspan="8" style="color: red;">處理記錄時出錯: ${error.message}</td>
                </tr>
            `;
        }
    }).join('');
}

// 更新分頁
function updatePagination(totalPages) {
    const pagination = document.getElementById('logPagination');
    if (totalPages <= 1) {
        pagination.innerHTML = '';
        return;
    }
    
    let html = '';
    
    // 上一頁按鈕
    html += `<button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>上一頁</button>`;
    
    // 頁碼按鈕
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);
    
    for (let i = startPage; i <= endPage; i++) {
        const isActive = i === currentPage ? 'current-page' : '';
        html += `<button class="${isActive}" onclick="changePage(${i})">${i}</button>`;
    }
    
    // 下一頁按鈕
    html += `<button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>下一頁</button>`;
    
    pagination.innerHTML = html;
}

// 換頁
function changePage(page) {
    if (page < 1) return;
    currentPage = page;
    loadLogs();
}

// 搜尋LOG
function searchLogs() {
    searchKeyword = document.getElementById('logSearch').value;
    currentPage = 1;
    loadLogs();
}

// 改變頁面大小
function changePageSize() {
    pageSize = parseInt(document.getElementById('pageSize').value);
    currentPage = 1;
    loadLogs();
}

// 顯示LOG訊息詳情
function showLogMessage(message) {
    alert(message);
}

// 格式化時間戳
function formatTimestamp(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleString('zh-TW');
}

// 截斷文字
function truncateText(text, maxLength) {
    if (!text) return '-';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

// 格式化位元組
function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

// 套用過濾條件
function applyFilters() {
    const form = document.getElementById('filterForm');
    const formData = new FormData(form);
    
    // 這裡可以根據需要處理過濾條件
    console.log('套用過濾條件:', Object.fromEntries(formData));
    
    // 重新載入資料
    loadStats();
    loadLogs();
    updateCharts();
}

// 清除過濾條件
function clearFilters() {
    document.getElementById('filterForm').reset();
    searchKeyword = '';
    currentPage = 1;
    loadStats();
    loadLogs();
    updateCharts();
}

// 執行分析
async function runAnalysis() {
    try {
        const form = document.getElementById('filterForm');
        const formData = new FormData(form);
        const data = {};
        
        for (let [key, value] of formData.entries()) {
            if (value) {
                data[key] = value;
            }
        }
        
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        const result = await response.json();
        
        if (result.success) {
            // 重新載入所有資料
            loadStats();
            loadLogs();
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

// 更新圖表
function updateCharts() {
    const timeInterval = document.getElementById('time_interval').value;
    
    // 更新流量趨勢圖
    const trafficChart = document.getElementById('trafficTrendChart');
    trafficChart.src = `/api/chart/traffic_trend.png?interval=${timeInterval}&t=${new Date().getTime()}`;
    trafficChart.style.display = 'block';
    
    // 更新熱門IP圖
    const topIpsChart = document.getElementById('topIpsChart');
    topIpsChart.src = `/api/chart/top_ips.png?t=${new Date().getTime()}`;
    topIpsChart.style.display = 'block';
    
    // 更新熱門URL圖
    const topUrlsChart = document.getElementById('topUrlsChart');
    topUrlsChart.src = `/api/chart/top_urls.png?t=${new Date().getTime()}`;
    topUrlsChart.style.display = 'block';
}

// 更新時間間隔
function updateTimeInterval() {
    timeInterval = document.getElementById('time_interval').value;
    updateCharts();
}

// 監聽視窗大小變化，並自動調整所有圖表尺寸
window.addEventListener('resize', function() {
    const chartDivs = document.querySelectorAll('.chart-container');
    chartDivs.forEach(div => {
        const img = div.querySelector('img');
        if (img) {
            const baseSrc = img.src.split('?')[0];
            img.src = baseSrc + '?t=' + new Date().getTime() + '&interval=' + timeInterval;
        }
    });
});

// 頁面載入時初始化
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM載入完成，開始初始化...');
    loadLogFiles();
    loadStats();
    loadLogs();
    updateCharts();
    console.log('初始化完成');
});
