#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EASM 掃描工具 (External Attack Surface Management Scanner)
功能：兩階段掃描（快掃全 Port + 深度掃描）+ 多執行緒 + Excel 多工作表報告
作者：資安工程師
"""

import sys
import os
import json
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

import nmap
import requests
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

# ==================== 全域設定 ====================
# 執行緒池大小（預設值為 1，可調整）
MAX_WORKERS = 1

# 歷史記錄檔案
HISTORY_FILE = 'scan_history.json'

# 線程鎖（確保線程安全）
lock = threading.Lock()

# Web 服務常用 Port
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888]


# ==================== 工具函式 ====================

def load_history():
    """載入掃描歷史記錄"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] 載入歷史記錄失敗: {e}")
            return {}
    return {}


def save_history(history_data):
    """儲存掃描歷史記錄"""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] 儲存歷史記錄失敗: {e}")


def get_geo_info(ip):
    """查詢 IP 地理位置與 ISP 資訊"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                country = data.get('country', 'N/A')
                city = data.get('city', 'N/A')
                isp = data.get('isp', 'N/A')
                return f"{country}/{city}", isp
    except Exception as e:
        print(f"[!] GeoIP 查詢失敗 ({ip}): {e}")
    return "N/A", "N/A"


def compare_with_history(ip, current_data, history):
    """比對當前掃描結果與歷史記錄"""
    if ip not in history:
        return "第一次掃測", "新增 IP"
    
    old_data = history[ip]
    changes = []
    
    # 比對 Port 狀態
    old_ports = set(old_data.get('ports', []))
    current_ports = set(current_data.get('ports', []))
    
    if old_ports != current_ports:
        added = current_ports - old_ports
        removed = old_ports - current_ports
        if added:
            changes.append(f"新增 Port: {', '.join(map(str, added))}")
        if removed:
            changes.append(f"關閉 Port: {', '.join(map(str, removed))}")
    
    # 比對服務版本
    old_services = old_data.get('services', {})
    current_services = current_data.get('services', {})
    
    service_changes = []
    for port, service_info in current_services.items():
        old_service = old_services.get(port, {})
        if old_service.get('version') != service_info.get('version'):
            service_changes.append(f"Port {port} 服務版本變更")
    
    if service_changes:
        changes.extend(service_changes)
    
    # 比對漏洞
    old_vulns = old_data.get('vulnerabilities', [])
    current_vulns = current_data.get('vulnerabilities', [])
    
    if old_vulns != current_vulns:
        added_vulns = len(current_vulns) - len(old_vulns)
        if added_vulns > 0:
            changes.append(f"新增 {added_vulns} 個漏洞風險")
        elif added_vulns < 0:
            changes.append(f"減少 {abs(added_vulns)} 個漏洞風險")
    
    if changes:
        return "有變動", "; ".join(changes)
    else:
        return "無變動", ""


# ==================== 掃描函式 ====================

def fast_scan(ip):
    """第一階段：快速全 Port 掃描"""
    try:
        nm = nmap.PortScanner()
        # 使用 -p- --open -T4 進行快速掃描
        nm.scan(ip, arguments='-p- --open -T4')
        
        open_ports = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                open_ports.extend(list(ports))
        
        return sorted(open_ports)
    except Exception as e:
        print(f"[!] 快掃失敗 ({ip}): {e}")
        return []


def deep_scan(ip, open_ports):
    """第二階段：針對性深度掃描"""
    if not open_ports:
        return {}, []
    
    try:
        nm = nmap.PortScanner()
        ports_str = ','.join(map(str, open_ports))
        
        # 判斷是否為 Web 服務 Port
        web_ports_in_list = [p for p in open_ports if p in WEB_PORTS]
        
        if web_ports_in_list:
            # Web 服務加強掃描
            arguments = f'-sV -sC -p {ports_str} --script=ssl-enum-ciphers,ssl-cert,http-security-headers,http-hsts,vuln '
            # 一般深度掃描
            arguments = f'-sV -sC -p {ports_str} --script=vuln '
        
        nm.scan(ip, arguments=arguments)
        
        services = {}
        vulnerabilities = []
        
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    port_info = nm[ip][proto][port]
                    
                    # 收集服務資訊
                    service_name = port_info.get('name', 'unknown')
                    service_product = port_info.get('product', '')
                    service_version = port_info.get('version', '')
                    
                    services[port] = {
                        'name': service_name,
                        'product': service_product,
                        'version': service_version,
                        'state': port_info.get('state', 'unknown')
                    }
                    
                    # 收集漏洞資訊
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            if 'vuln' in script_name.lower() or 'ssl' in script_name.lower():
                                vulnerabilities.append({
                                    'port': port,
                                    'type': script_name,
                                    'description': str(script_output)
                                })
        
        return services, vulnerabilities
    except Exception as e:
        print(f"[!] 深掃失敗 ({ip}): {e}")
        return {}, []


def scan_ip(ip, history, total_count, current_index):
    """掃描單一 IP（包含兩階段掃描）"""
    print(f"[+] 掃描 {ip} ({current_index}/{total_count})...")
    
    # 第一階段：快掃
    open_ports = fast_scan(ip)
    
    if not open_ports:
        print(f"[-] {ip}: 未發現開啟的 Port")
        return {
            'ip': ip,
            'ports': [],
            'services': {},
            'vulnerabilities': [],
            'geo_location': 'N/A',
            'isp': 'N/A',
            'status': '無開啟 Port'
        }
    
    print(f"[+] {ip}: 發現 {len(open_ports)} 個開啟 Port: {open_ports}")
    
    # 第二階段：深掃
    services, vulnerabilities = deep_scan(ip, open_ports)
    
    # GeoIP 查詢
    geo_location, isp = get_geo_info(ip)
    
    # 比對歷史記錄
    current_data = {
        'ports': open_ports,
        'services': services,
        'vulnerabilities': vulnerabilities
    }
    
    status, change_detail = compare_with_history(ip, current_data, history)
    
    return {
        'ip': ip,
        'ports': open_ports,
        'services': services,
        'vulnerabilities': vulnerabilities,
        'geo_location': geo_location,
        'isp': isp,
        'status': status,
        'change_detail': change_detail
    }


# ==================== Excel 報告生成 ====================

def style_header(ws):
    """美化工作表標題列"""
    header_fill = PatternFill(start_color="CCCCCC", end_color="CCCCCC", fill_type="solid")
    header_font = Font(bold=True, color="000000")
    
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
    
    # 自動調整欄寬
    for column in ws.columns:
        max_length = 0
        column_letter = get_column_letter(column[0].column)
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width


def create_executive_summary(ws, results, total_ips):
    """建立工作表 1: 掃描摘要"""
    ws.title = "掃描摘要"
    
    # 標題列
    headers = ['掃描日期', '掃描 IP 總數', '發現風險 IP 數', '異動 IP 數', '高風險漏洞總數', 'SSL/TLS 不合規數量']
    ws.append(headers)
    
    # 計算統計數據
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    risk_ips = sum(1 for r in results if r.get('vulnerabilities') or r.get('status') != '無變動')
    changed_ips = sum(1 for r in results if r.get('status') in ['有變動', '第一次掃測'])
    total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
    ssl_issues = sum(1 for r in results if any('ssl' in str(v.get('type', '')).lower() for v in r.get('vulnerabilities', [])))
    
    # 寫入數據
    ws.append([
        scan_date,
        total_ips,
        risk_ips,
        changed_ips,
        total_vulns,
        ssl_issues
    ])
    
    style_header(ws)


def create_vulnerability_list(ws, results):
    """建立工作表 2: 漏洞清單"""
    ws.title = "漏洞清單"
    
    # 標題列
    headers = ['IP Address', 'Port/Protocol', 'Service Name', '漏洞類型', '詳細描述', '修補建議']
    ws.append(headers)
    
    # 只列出有漏洞的項目
    for result in results:
        ip = result['ip']
        vulnerabilities = result.get('vulnerabilities', [])
        services = result.get('services', {})
        
        if not vulnerabilities:
            continue
        
        for vuln in vulnerabilities:
            port = vuln.get('port', 'N/A')
            vuln_type = vuln.get('type', 'N/A')
            description = vuln.get('description', 'N/A')
            
            service_name = services.get(port, {}).get('name', 'N/A')
            
            # 根據漏洞類型提供修補建議
            if 'ssl' in vuln_type.lower():
                suggestion = "更新 SSL/TLS 設定，使用現代加密協定（TLS 1.2+）"
            elif 'hsts' in vuln_type.lower():
                suggestion = "啟用 HSTS (HTTP Strict Transport Security)"
            elif 'cve' in vuln_type.lower() or 'vuln' in vuln_type.lower():
                suggestion = "更新服務版本至最新版本，修補已知漏洞"
            else:
                suggestion = "檢視詳細描述並採取相應修補措施"
            
            ws.append([
                ip,
                port,
                service_name,
                vuln_type,
                str(description)[:500],  # 限制長度
                suggestion
            ])
    
    style_header(ws)


def create_change_log(ws, results):
    """建立工作表 3: 變動比對"""
    ws.title = "變動比對"
    
    # 標題列
    headers = ['IP Address', '變動類型', '變更詳情', '漏洞風險']
    ws.append(headers)
    
    # 只列出有變動的項目
    for result in results:
        ip = result['ip']
        status = result.get('status', '')
        change_detail = result.get('change_detail', '')
        vulnerabilities = result.get('vulnerabilities', [])
        
        if status == '無變動':
            continue
        
        # 判斷變動類型
        if status == '第一次掃測':
            change_type = "新增 IP"
        elif 'Port' in change_detail:
            change_type = "Port 開啟狀態異動"
        elif '漏洞' in change_detail:
            change_type = "漏洞風險狀態異動"
        else:
            change_type = "服務異動"
        
        # 漏洞風險狀態
        if vulnerabilities:
            vuln_risk = f"發現 {len(vulnerabilities)} 個漏洞風險"
        else:
            vuln_risk = "無漏洞風險"
        
        ws.append([
            ip,
            change_type,
            change_detail if change_detail else status,
            vuln_risk
        ])
    
    style_header(ws)


def create_port_stats(ws, results):
    """建立工作表 4: Port 開啟統計"""
    ws.title = "Port 開啟統計"
    
    # 標題列
    headers = ['Port 號碼', '服務名稱', '開啟數量', '佔比 (%)']
    ws.append(headers)
    
    # 統計 Port 開啟頻率
    port_count = defaultdict(int)
    port_services = {}
    total_port_occurrences = 0
    
    for result in results:
        ports = result.get('ports', [])
        services = result.get('services', {})
        
        for port in ports:
            port_count[port] += 1
            total_port_occurrences += 1
            if port not in port_services:
                service_name = services.get(port, {}).get('name', 'unknown')
                port_services[port] = service_name
    
    # 寫入統計數據
    for port in sorted(port_count.keys()):
        count = port_count[port]
        percentage = (count / total_port_occurrences * 100) if total_port_occurrences > 0 else 0
        service_name = port_services.get(port, 'unknown')
        
        ws.append([
            port,
            service_name,
            count,
            f"{percentage:.2f}%"
        ])
    
    style_header(ws)


def create_raw_data(ws, results):
    """建立工作表 5: 詳細資料"""
    ws.title = "詳細資料"
    
    # 標題列
    headers = ['IP', '地理位置', 'ISP', 'Port 清單', 'SSL/TLS 狀態', '完整 Nmap 輸出', '掃測狀態標記', '總結建議']
    ws.append(headers)
    
    # 寫入所有掃描結果
    for result in results:
        ip = result['ip']
        geo_location = result.get('geo_location', 'N/A')
        isp = result.get('isp', 'N/A')
        ports = result.get('ports', [])
        ports_str = ', '.join(map(str, ports)) if ports else '無開啟 Port'
        
        # SSL/TLS 狀態
        ssl_status = "正常"
        vulnerabilities = result.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if 'ssl' in str(vuln.get('type', '')).lower():
                ssl_status = "不合規"
                break
        
        # 完整 Nmap 輸出（簡化版）
        services = result.get('services', {})
        nmap_output = []
        for port, service_info in services.items():
            nmap_output.append(f"Port {port}: {service_info.get('name', 'unknown')} "
                             f"({service_info.get('product', '')} {service_info.get('version', '')})")
        nmap_output_str = '; '.join(nmap_output) if nmap_output else '無服務資訊'
        
        # 掃測狀態標記
        status = result.get('status', '正常')
        
        # 總結建議
        suggestions = []
        if vulnerabilities:
            suggestions.append(f"發現 {len(vulnerabilities)} 個漏洞，建議立即修補")
        if ssl_status == "不合規":
            suggestions.append("SSL/TLS 設定不合規，建議更新加密協定")
        if not ports:
            suggestions.append("無開啟 Port，安全性良好")
        if not suggestions:
            suggestions.append("無明顯安全問題")
        
        summary = '; '.join(suggestions)
        
        ws.append([
            ip,
            geo_location,
            isp,
            ports_str,
            ssl_status,
            nmap_output_str,
            status,
            summary
        ])
    
    style_header(ws)


def generate_report(results, output_dir):
    """生成 Excel 報告"""
    wb = Workbook()
    
    # 移除預設工作表
    if 'Sheet' in wb.sheetnames:
        wb.remove(wb['Sheet'])
    
    # 建立所有工作表
    create_executive_summary(wb.create_sheet(), results, len(results))
    create_vulnerability_list(wb.create_sheet(), results)
    create_change_log(wb.create_sheet(), results)
    create_port_stats(wb.create_sheet(), results)
    create_raw_data(wb.create_sheet(), results)
    
    # 儲存檔案
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    filename = f'EASM_Report_{timestamp}.xlsx'
    filepath = os.path.join(output_dir, filename)
    
    # 確保輸出目錄存在
    os.makedirs(output_dir, exist_ok=True)
    
    wb.save(filepath)
    print(f"\n[+] Excel 報告已生成: {filepath}")
    
    return filepath


# ==================== 主程式 ====================

def main():
    """主程式入口"""
    parser = argparse.ArgumentParser(description='EASM 掃描工具')
    parser.add_argument('target_file', help='目標清單檔案路徑')
    parser.add_argument('output_dir', nargs='?', default='Report', help='報告輸出目錄（預設: Report）')
    
    args = parser.parse_args()
    
    # 讀取目標清單
    if not os.path.exists(args.target_file):
        print(f"[!] 錯誤: 找不到目標清單檔案: {args.target_file}")
        sys.exit(1)
    
    with open(args.target_file, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    if not targets:
        print("[!] 錯誤: 目標清單為空")
        sys.exit(1)
    
    print(f"[+] 載入 {len(targets)} 個目標 IP")
    
    # 載入歷史記錄
    history = load_history()
    
    # 多執行緒掃描
    results = []
    total_count = len(targets)
    
    print(f"[+] 開始掃描（執行緒數: {MAX_WORKERS}）...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有任務
        future_to_ip = {
            executor.submit(scan_ip, ip, history, total_count, idx + 1): ip
            for idx, ip in enumerate(targets)
        }
        
        # 收集結果（線程安全）
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                with lock:
                    results.append(result)
            except Exception as e:
                print(f"[!] 掃描 {ip} 時發生錯誤: {e}")
                with lock:
                    results.append({
                        'ip': ip,
                        'ports': [],
                        'services': {},
                        'vulnerabilities': [],
                        'geo_location': 'N/A',
                        'isp': 'N/A',
                        'status': '掃描失敗',
                        'change_detail': f'錯誤: {str(e)}'
                    })
    
    # 更新歷史記錄
    new_history = {}
    for result in results:
        ip = result['ip']
        new_history[ip] = {
            'ports': result.get('ports', []),
            'services': result.get('services', {}),
            'vulnerabilities': result.get('vulnerabilities', []),
            'last_scan': datetime.now().isoformat()
        }
    
    save_history(new_history)
    
    # 生成 Excel 報告
    print("\n[+] 正在生成 Excel 報告...")
    generate_report(results, args.output_dir)
    
    print("\n[+] 掃描完成！")


if __name__ == '__main__':
    main()
