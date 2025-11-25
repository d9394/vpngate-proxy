import requests
import threading
import time
import os
from datetime import datetime
import subprocess
import signal
import base64
import configparser
import re

# --- 纯 Python ICMP PING 相关的导入 ---
import struct
import select
import sys
import socket # 确保 socket 模块被导入
# -----------------------------------

# 全局变量
VPN_GATE_LIST = []
PROXY_LIST = []
LOCAL_PROXY_LIST = []
VPN_LIST_LOCK = threading.Lock()
PROXY_LIST_LOCK = threading.Lock()
OPENVPN_PROCESS = None
CURRENT_PROXY = None
DEFAULT_GW = None
config = {} # config 定义为全局变量，用于存储配置

# 文件修改时间记录
LAST_CONFIG_MOD_TIME = 0
LAST_PROXY_MOD_TIME = 0

# 调试/监控全局变量
NETWORK_FAILURE_COUNT = 0 # 连续网络失败计数

# ICMP 报文常量
ICMP_ECHO_REQUEST = 8 
ICMP_ECHO_REPLY = 0 
PACKET_SIZE = 64 # ICMP 报文主体长度

# --- 配置文件与参数 ---
CONFIG_FILE = 'vpngate.cfg'
PROXY_FILE = 'proxy.txt'
GATEWAY_FILE = 'gateway.txt'

# 默认配置
DEFAULT_CONFIG = {
    'general': {
        'vpngate_update_interval_seconds': '3600',
        'proxy_update_interval_seconds': '300',
        'network_check_interval_seconds': '300',
        'config_check_interval_seconds': '300',
        'proxy_test_url': 'https://www.google.com',
        'ping_check_ip': '8.8.8.8',
        'vpngate_url': 'http://www.vpngate.net/api/iphone/',
        'proxy_retry_count': '3',
        'proxy_retry_delay_seconds': '1',
        'proxy_max_retries': '5', 
        'debug_mode': 'no', 
        'monitor_ping_interval_seconds': '10', 
        'monitor_max_failures': '5' 
    },
    'vpngate': {
        'country_codes': 'JP,HK',
        'hostname_filter_keywords': ''
    },
    'local_proxies': {
        'enable': 'yes',
        'proxies': 'socks5h://192.168.1.1:3128'
    }
}

def log_print(message, is_debug=False):
    """
    带时间戳地打印信息。
    如果 is_debug 为 True，则只有在 config['general']['debug_mode'] 开启时才打印。
    """
    global config
    
    # 只有在 config 字典已加载时才进行判断
    if config: 
        if is_debug:
            # 检查配置中的 debug_mode 是否为 'yes' (不区分大小写)
            debug_enabled = config['general'].get('debug_mode', 'no').lower() == 'yes'
            if not debug_enabled:
                return

    timestamp = datetime.now().strftime("%Y%m%d-%H:%M:%S")
    print(f"[{timestamp}] {message}")

# --- 纯 Python ICMP Ping 实现 (替代系统 ping) ---

def checksum(source_string):
    """
    计算 ICMP 校验和。
    """
    sum_val = 0
    # ... (ICMP checksum logic remains the same)
    max_count = (len(source_string) // 2) * 2
    count = 0
    while count < max_count:
        # Python 3 compatibility: struct.unpack returns a tuple
        val = source_string[count + 1] * 256 + source_string[count]
        sum_val = sum_val + val
        sum_val = sum_val & 0xffffffff
        count += 2

    if max_count < len(source_string):
        sum_val += source_string[len(source_string) - 1]
        sum_val = sum_val & 0xffffffff

    sum_val = (sum_val >> 16) + (sum_val & 0xffff)
    sum_val = sum_val + (sum_val >> 16)
    answer = ~sum_val
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def pure_python_icmp_ping(host, timeout=1):
    """
    使用原始 socket 发送和接收 ICMP Echo 报文，测量延迟。
    注意：在 Linux/Unix 上通常需要 root 权限 (CAP_NET_RAW capability) 才能创建 raw socket。
    返回: 延迟（毫秒）或 None。
    """
    try:
        # 尝试使用 AF_INET 协议族和 IPPROTO_ICMP 协议创建 raw socket
        # 需要 root 权限
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        if e.errno == 1:
             log_print("ICMP Ping 错误：创建 raw socket 需要 root/管理员权限。请以 root 运行脚本。")
        else:
            log_print(f"ICMP Ping 错误：创建 socket 失败：{e}")
        return None
    except Exception as e:
        log_print(f"ICMP Ping 错误：{e}")
        return None
        
    icmp_socket.settimeout(timeout)
    
    my_id = os.getpid() & 0xFFFF
    my_seq = int((time.time() * 1000) % 65535)
    
    data = (PACKET_SIZE - 8) * b'Q' 
    
    header = struct.pack('!bbHHh', ICMP_ECHO_REQUEST, 0, 0, my_id, my_seq) 
    
    my_checksum = checksum(header + data)
    
    header = struct.pack('!bbHHh', ICMP_ECHO_REQUEST, 0, my_checksum, my_id, my_seq) 
    packet = header + data

    try:
        dest_addr = socket.gethostbyname(host)
        
        time_sent = time.time()
        icmp_socket.sendto(packet, (dest_addr, 1)) 
        
        ready = select.select([icmp_socket], [], [], timeout)
        time_received = time.time()
        
        if ready[0] == []:
            icmp_socket.close()
            return None
        
        rec_packet, addr = icmp_socket.recvfrom(1024)
        icmp_socket.close()

        icmp_header = rec_packet[20:28] 
        type, code, checksum_rcv, id_rcv, seq_rcv = struct.unpack('!bbHHh', icmp_header)

        if type == ICMP_ECHO_REPLY and id_rcv == my_id:
            latency = (time_received - time_sent) * 1000 # 转换为毫秒
            return latency
        else:
            return None

    except socket.gaierror as e:
        log_print(f"ICMP Ping 错误：无法解析主机名 {host}：{e}", is_debug=False)
        return None
    except Exception as e:
        log_print(f"ICMP Ping 过程中发生错误：{e}", is_debug=True)
        return None

# --- 监控线程 (Continuous Ping) ---

def vpn_monitor_thread_loop():
    # ... (function body remains the same, relies on check_network which uses ICMP)
    """
    VPN 连接状态监控线程，定期检查网络连通性。
    如果连续失败次数达到阈值，则强制终止 OpenVPN 进程。
    """
    global OPENVPN_PROCESS, NETWORK_FAILURE_COUNT, config
    
    try:
        monitor_interval = int(config['general'].get('monitor_ping_interval_seconds', '10'))
        max_failures = int(config['general'].get('monitor_max_failures', '5'))
    except ValueError:
        log_print("警告：VPN监控配置参数格式错误，使用默认值(间隔10s, 失败5次)。")
        monitor_interval = 10
        max_failures = 5

    while True:
        time.sleep(monitor_interval) 
        
        if OPENVPN_PROCESS and OPENVPN_PROCESS.poll() is None:
            log_print("VPN监控线程：正在进行连接状态检查...")
            
            if check_network(timeout=5): 
                if NETWORK_FAILURE_COUNT > 0:
                     log_print(f"VPN监控线程：网络恢复正常。")
                NETWORK_FAILURE_COUNT = 0
            else:
                NETWORK_FAILURE_COUNT += 1
                log_print(f"VPN监控线程：连接检查失败 ({NETWORK_FAILURE_COUNT}/{max_failures})！")

                if NETWORK_FAILURE_COUNT >= max_failures:
                    log_print(f"VPN监控线程：连续 {max_failures} 次检查失败，认为VPN连接已断开或失效，强制终止进程。")
                    
                    try:
                        pgid = os.getpgid(OPENVPN_PROCESS.pid)
                        os.killpg(pgid, signal.SIGKILL)
                        OPENVPN_PROCESS.wait(timeout=5)
                        log_print("VPN监控线程：已强制终止 OpenVPN 进程。")
                    except Exception as e:
                        log_print(f"VPN监控线程：强制终止进程失败: {e}")
                        
                    OPENVPN_PROCESS = None
                    NETWORK_FAILURE_COUNT = 0
        else:
            if OPENVPN_PROCESS is None and NETWORK_FAILURE_COUNT > 0:
                NETWORK_FAILURE_COUNT = 0
            
            log_print("VPN监控线程：当前无活动 OpenVPN 进程。")


# --- 网络与代理 ---

def get_current_proxy():
# ... (function body remains the same)
    """根据优先级获取当前可用的代理字典。"""
    global CURRENT_PROXY, PROXY_LIST, LOCAL_PROXY_LIST
    with PROXY_LIST_LOCK:
        if PROXY_LIST:
            CURRENT_PROXY = PROXY_LIST[0]
            return PROXY_LIST[0]
        elif LOCAL_PROXY_LIST:
            CURRENT_PROXY = LOCAL_PROXY_LIST[0]
            return LOCAL_PROXY_LIST[0]
    
    CURRENT_PROXY = None
    return None

def read_default_gateway():
# ... (function body remains the same)
    """从文件中读取默认网关IP。"""
    global DEFAULT_GW
    if os.path.exists(GATEWAY_FILE):
        with open(GATEWAY_FILE, 'r') as f:
            gw_ip = f.readline().strip()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', gw_ip):
                DEFAULT_GW = gw_ip
                log_print(f"已从 {GATEWAY_FILE} 文件中读取系统网关IP：{DEFAULT_GW}")
                return True
    
    log_print(f"错误：未找到有效的系统网关IP。请在 {GATEWAY_FILE} 文件中写入正确的IP地址。")
    return False

def add_route_for_proxy(proxy_ip):
# ... (function body remains the same)
    """为代理IP添加路由规则，通过默认网关，并检测是否成功。"""
    if not DEFAULT_GW:
        log_print("无法添加路由：系统网关IP未设置。")
        return False
    
    try:
        command = ['ip', 'route', 'add', proxy_ip, 'via', DEFAULT_GW]
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        max_checks = 3
        check_delay = 0.5
        
        for i in range(max_checks):
            route_check_command = ['ip', 'route', 'show']
            result = subprocess.run(route_check_command, capture_output=True, text=True, check=False)
            expected_route_segment = f"{proxy_ip} via {DEFAULT_GW}"

            if expected_route_segment in result.stdout:
                log_print(f"已成功为代理IP {proxy_ip} 添加路由规则并确认。")
                return True
            
            if i < max_checks - 1:
                time.sleep(check_delay)

        log_print(f"添加路由失败：已执行 'ip route add {proxy_ip} via {DEFAULT_GW}'，但路由表中未检测到该条目。")
        return False
        
    except Exception as e:
        log_print(f"添加路由时发生未知错误：{e}")
        return False

def delete_route_for_proxy(proxy_ip):
# ... (function body remains the same)
    """删除为代理IP添加的路由规则。"""
    if not DEFAULT_GW:
        log_print("无法删除路由：系统网关IP未设置。")
        return False

    try:
        command = ['ip', 'route', 'del', proxy_ip]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_print(f"已删除代理IP {proxy_ip} 的路由规则。")
        return True
    except subprocess.CalledProcessError as e:
        log_print(f"删除路由失败：{e}")
        return False
    except Exception as e:
        log_print(f"删除路由时发生未知错误：{e}")
        return False


def parse_proxy_line(line):
# ... (function body remains the same)
    """解析 proxy.txt 中的一行内容。"""
    parts = line.strip().split(',')
    if len(parts) >= 4:
        url = parts[0].strip()
        try:
            latency = float(parts[1].strip().replace("ms",""))
            retries = int(parts[2].strip())
            info = parts[3].strip()
            if url.startswith('http://') or url.startswith('socks5h://') or url.startswith('socks5://') or url.startswith('socks4://'):
                return {'url': url, 'latency': latency, 'retries': retries, 'info': info, 'raw_line': line}
        except ValueError:
            log_print(f"代理验证线程：{PROXY_FILE}内容错误：{line}。")
    return None

def format_proxy_line(proxy_data):
# ... (function body remains the same)
    """格式化代理数据为 proxy.txt 行格式。"""
    return f"{proxy_data['url']},{proxy_data['latency']:.2f},{proxy_data['retries']},{proxy_data['info']}\n"


def test_single_proxy(proxy_url, retry_count, retry_delay_seconds):
# ... (function body remains the same)
    """
    测试单个代理的可达性和延迟。
    返回: (is_success, latency_ms)
    """
    global config
    proxies = {}
    if proxy_url.startswith('socks://') or proxy_url.startswith('socks5://') or proxy_url.startswith('socks5h://'):
        proxy_url = re.sub(r'socks(5h|5)?://', 'socks5h://', proxy_url)
        proxies = {'http': proxy_url, 'https': proxy_url}
    elif proxy_url.startswith('http://') or proxy_url.startswith('socks4://'):
        proxies = {'http': proxy_url, 'https': proxy_url}
    else:
        log_print(f"代理验证线程：代理格式不支持，跳过测试：{proxy_url}", is_debug=True)
        return False, None
    
    match = re.search(r'://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', proxy_url)
    proxy_ip = match.group(1) if match else None

    if proxy_ip:
        add_route_for_proxy(proxy_ip)
    
    is_successful = False
    latency = None
    
    for attempt in range(1, retry_count + 1):
        try:
            start_time = time.time()
            response = requests.get(config['general']['proxy_test_url'], proxies=proxies, timeout=10)
            
            if response.status_code == 200:
                latency = (time.time() - start_time) * 1000 
                is_successful = True
                break
            else:
                log_print(f"代理验证线程：代理 {proxy_url} 第 {attempt} 次尝试验证失败，状态码：{response.status_code}。")
        except Exception as e:
            log_print(f"代理验证线程：代理 {proxy_url} 第 {attempt} 次尝试验证失败，错误：{e}。")
        
        if attempt < retry_count:
            time.sleep(retry_delay_seconds)

    if not is_successful and proxy_ip:
        delete_route_for_proxy(proxy_ip)
        
    return is_successful, latency

def validate_proxies():
# ... (function body remains the same)
    """
    验证 proxy.txt 和本地配置中的代理，并根据规则更新 proxy.txt 文件。
    """
    global PROXY_LIST, LOCAL_PROXY_LIST, config
    
    validated_list_from_file = []
    
    proxy_file_records = []
    seen_urls = {}
    unprocessed_lines = [] 
    
    PROXY_CONTENT_CHANGED = False 
    original_file_content = ""
    
    if os.path.exists(PROXY_FILE):
        with open(PROXY_FILE, 'r') as f:
            original_lines = f.readlines()
            original_file_content = "".join(original_lines) 
            
            for line in original_lines:
                line = line.rstrip('\n') 
                stripped_line = line.strip()

                if stripped_line.startswith('#'):
                    unprocessed_lines.append(line + '\n') 
                    continue 
                
                data = parse_proxy_line(stripped_line)
                if data:
                    data['raw_line'] = stripped_line
                    data['is_commented'] = False
                    data['original_retries'] = data['retries'] 
                    url = data['url']
                    
                    seen_urls[url] = data
                else:
                    if stripped_line: 
                         unprocessed_lines.append(line + '\n') 
                
        proxy_file_records = list(seen_urls.values())
    else :
        log_print(f"代理验证线程：{PROXY_FILE} 文件未找到。")
        
    log_print(f"代理验证线程：开始验证 {PROXY_FILE} 中的 {len(proxy_file_records)} 条有效记录，{len(unprocessed_lines)}条无效记录。")
    
    requests_retry_count = int(config['general']['proxy_retry_count'])
    retry_delay_seconds = int(config['general']['proxy_retry_delay_seconds'])
    max_retries = int(config['general'].get('proxy_max_retries', 5))
    TIMESTAMP_PATTERN = r'[#%]\d{8}-\d{2}:\d{2}:\d{2}$' 
    
    updated_proxy_records = []
    
    for record in proxy_file_records:
        original_retries = record.pop('original_retries') 
        
        is_success, latency = test_single_proxy(
            record['url'], 
            requests_retry_count, 
            retry_delay_seconds
        )
        current_time_str = datetime.now().strftime("%Y%m%d-%H:%M:%S")

        if is_success:
            if record['retries'] != 0:
                record['retries'] = 0
                PROXY_CONTENT_CHANGED = True
                
            record['latency'] = latency
            record['is_commented'] = False 
            
            if re.search(r'%\d{8}-\d{2}:\d{2}:\d{2}$', record['info']):
                 record['info'] = re.sub(TIMESTAMP_PATTERN, '', record['info'])
                 PROXY_CONTENT_CHANGED = True

            validated_list_from_file.append({'proxies': {'http': record['url'], 'https': record['url']}, 'latency': latency})
            log_print(f"代理验证线程：代理 {record['url']} 验证成功，延迟 {latency:.2f}ms。")
        else:
            if record['retries'] < max_retries:
                record['retries'] += 1
                if record['retries'] != original_retries:
                    PROXY_CONTENT_CHANGED = True
                
            
            if record['retries'] < max_retries:
                record['is_commented'] = False
                log_print(f"代理验证线程：代理 {record['url']} 验证失败，重试次数 {record['retries']}/{max_retries}，保留。")
            else:
                if original_retries < max_retries:
                    PROXY_CONTENT_CHANGED = True
                    
                    record['is_commented'] = True
                    fail_tag = f'%{current_time_str}'
                    record['info'] = re.sub(TIMESTAMP_PATTERN, '', record['info'])
                    record['info'] += fail_tag
                    
                    log_print(f"代理验证线程：代理 {record['url']} 达到最大重试次数 {max_retries}，已注释并标记失败时间 ({fail_tag})。")
                else:
                    pass

        updated_proxy_records.append(record)
    
    processed_content = ""
    for record in updated_proxy_records:
        line = format_proxy_line(record) 
        if record.get('is_commented'):
            processed_content += "#" + line
        else:
            processed_content += line
            
    file_content_to_write = processed_content + "".join(unprocessed_lines)

    if PROXY_CONTENT_CHANGED or (file_content_to_write.strip() != original_file_content.strip() and os.path.exists(PROXY_FILE)):
        try:
            with open(PROXY_FILE, 'w') as f:
                f.write(file_content_to_write)

            log_print(f"代理验证线程：{PROXY_FILE} 已更新，共 {len(updated_proxy_records)} 条有效代理记录被处理。")
        except Exception as e:
            log_print(f"错误：写入 {PROXY_FILE} 文件失败：{e}")
    else:
        log_print(f"代理验证线程：{PROXY_FILE} 内容无变化，跳过文件写入。") 

    local_proxy_list = []
    if config['local_proxies']['enable'].lower() == 'yes':
        local_proxy_list = config['local_proxies']['proxies']
    
    validated_list_from_local = []
    
    for proxy_url in local_proxy_list:
        is_success, latency = test_single_proxy(
            proxy_url, 
            requests_retry_count, 
            retry_delay_seconds
        )
        
        if is_success:
             validated_list_from_local.append({
                 'proxies': {'http': proxy_url, 'https': proxy_url}, 
                 'latency': latency
             })

    with PROXY_LIST_LOCK:
        validated_list_from_file.sort(key=lambda x: x['latency'])
        PROXY_LIST = [item['proxies'] for item in validated_list_from_file]
        
        validated_list_from_local.sort(key=lambda x: x['latency'])
        LOCAL_PROXY_LIST = [item['proxies'] for item in validated_list_from_local]
        log_print(f"代理验证线程：全局列表更新完成。共{len(PROXY_LIST)}个外部代理，{len(LOCAL_PROXY_LIST)}个本地代理")
        
# --- VPN Gate 列表 ---

def check_network(timeout=5):
    """
    使用纯 Python ICMP 报文检测网络连接是否正常。
    """
    global config
    ping_ip = config['general']['ping_check_ip']
    log_print(f"主线程：正在使用 ICMP 报文 ping {ping_ip} 检测网络连接...")
    
    latency = pure_python_icmp_ping(ping_ip, timeout=timeout) 
    
    if latency is not None:
        log_print(f"主线程：网络连接正常 (延迟: {latency:.2f}ms)。")
        return True
    else:
        log_print(f"主线程：网络连接异常，ICMP ping {ping_ip} 失败。")
        return False

def fetch_vpngate_list():
# ... (function body remains the same)
    """从 VPN Gate 获取服务器列表并格式化。"""
    global VPN_GATE_LIST, config
    url = config['general']['vpngate_url']
    try:
        proxies = None
        if config['local_proxies']['enable'].lower() == 'yes' and LOCAL_PROXY_LIST:
            proxies = LOCAL_PROXY_LIST[0]
            log_print(f"获取VPN列表线程：优先使用最快的本地代理 {proxies.get('http', '')}...")
        
        if not proxies:
            proxies = get_current_proxy()
            log_print("获取VPN列表线程：使用代理列表中的代理...")

        if not proxies:
            log_print("获取VPN列表线程：无可用代理，无法获取VPN列表。")
            return
            
        log_print("获取VPN列表线程：正在获取VPN Gate列表...")
        response = requests.get(url, proxies=proxies, timeout=30)

        if response.status_code != 200 or not response.text:
            log_print("获取VPN列表线程：获取列表失败。")
            return

        lines = response.text.split('\n')
        
        all_vpn_list = []
        filter_patterns = config['vpngate']['hostname_filter_patterns']

        for line in lines[2:-1]:
            parts = line.split(',')
            if len(parts) >= 8:
                hostname = parts[0]
                
                is_filtered = False
                for pattern in filter_patterns:
                    if pattern.search(hostname):
                        log_print(f"获取VPN列表线程：跳过VPN [{hostname}]，因其主机名匹配正则模式：'{pattern.pattern}'。")
                        is_filtered = True
                        break
                
                if not is_filtered:
                    all_vpn_list.append(parts)

        final_sorted_list = []
        country_codes = config['vpngate']['country_codes']

        for country_code in country_codes:
            country_specific_list = [vpn for vpn in all_vpn_list if vpn[6] == country_code]
            log_print(f"{country_code}共有{len(country_specific_list)}条记录")
            
            def get_ping_value(vpn_entry):
                try:
                    return int(vpn_entry[3])
                except (ValueError, IndexError):
                    return float('inf')

            country_specific_list.sort(key=get_ping_value)
            final_sorted_list.extend(country_specific_list)
        
        with VPN_LIST_LOCK:
            VPN_GATE_LIST = final_sorted_list
        
        log_print(f"获取VPN列表线程：已成功获取并更新VPN列表，共有{len(VPN_GATE_LIST)}条记录。")
        log_print("获取VPN列表线程：VPN列表已按配置文件中的国家/地区和Ping值排序。")

    except Exception as e:
        log_print(f"获取VPN列表线程：获取列表失败，错误：{e}")

# --- OpenVPN 连接逻辑 ---

def create_ovpn_file(vpn_info):
# ... (function body remains the same)
    """根据VPN列表记录生成.ovpn配置文件。"""
    try:
        base64_config = vpn_info[14]
        decoded_config = base64.b64decode(base64_config).decode('utf-8')
        
        ovpn_filename = '/app/temp_config.ovpn'
        with open(ovpn_filename, 'w') as f:
            clean_lines = []
            for line in decoded_config.split('\n'):
                line = line.strip()
                if line and not line.startswith(('#', ';')):
                    clean_lines.append(line)
            
            clean_lines.append('cipher AES-128-CBC')
            clean_lines.append('data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC')

            proxies = get_current_proxy()
            if proxies:
                proxy_addr_url = proxies.get('http') or proxies.get('https')
                match = re.search(r'://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', proxy_addr_url)
                if match:
                    ip, port = match.group(1), match.group(2)
                    log_print(f"OVPN将使用代理{proxy_addr_url}")
                    if 'socks' in proxy_addr_url:
                        clean_lines.append(f'socks-proxy {ip} {port}')
                        clean_lines.append('socks-proxy-retry')
                    elif 'http' in proxy_addr_url:
                        clean_lines.append(f'http-proxy {ip} {port}')
                        clean_lines.append('http-proxy-retry')
                else:
                    log_print("OpenVPN连接线程：无法从代理URL中解析出IP和端口。")
            
            f.write('\n'.join(clean_lines))
            
        log_print(f"OpenVPN连接线程：已生成配置文件 {ovpn_filename}")
        return ovpn_filename
    except Exception as e:
        log_print(f"OpenVPN连接线程：生成配置文件失败，错误：{e}")
        return None

def connect_openvpn():
# ... (function body remains the same)
    """OpenVPN连接线程，尝试连接列表中的VPN。"""
    global OPENVPN_PROCESS, NETWORK_FAILURE_COUNT, config
    
    with VPN_LIST_LOCK:
        current_list = VPN_GATE_LIST[:]
    
    if not current_list:
        log_print("OpenVPN连接线程：VPN列表为空，无法连接。")
        return

    log_print("OpenVPN连接线程：正在尝试连接VPN...")
    
    for i, vpn_info in enumerate(current_list):
        log_print(f"OpenVPN连接线程：尝试连接第 {i+1} 条记录 ({vpn_info[0]}, {vpn_info[6]}，原始Ping: {vpn_info[3]}ms)")
        ovpn_file = create_ovpn_file(vpn_info)
        
        if not ovpn_file:
            continue
            
        try:
            if OPENVPN_PROCESS:
                log_print("OpenVPN连接线程：正在终止旧的OpenVPN进程...")
                pgid = None
                
                try:
                    pgid = os.getpgid(OPENVPN_PROCESS.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    log_print(f"已发送 SIGTERM 到进程组 {pgid}，等待退出...")
                except ProcessLookupError:
                    log_print("旧进程已消失，无需终止。")
                except Exception as e:
                    log_print(f"终止旧进程时出现错误 (SIGTERM)：{e}")
                
                try:
                    OPENVPN_PROCESS.wait(timeout=10) 
                    log_print("旧进程已优雅退出。")
                except subprocess.TimeoutExpired:
                    log_print("旧进程超时未退出，尝试强制终止 (SIGKILL)...")
                    if pgid:
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                            OPENVPN_PROCESS.wait(timeout=5)
                        except ProcessLookupError:
                            pass 
                        except Exception as e:
                            log_print(f"强制终止旧进程时出现错误 (SIGKILL)：{e}")
                
                OPENVPN_PROCESS = None
            
            OPENVPN_PROCESS = subprocess.Popen(
                ['openvpn', '--config', ovpn_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid 
            )
            
            log_print("OpenVPN连接线程：等待 tun0 接口出现...")
            success = False
            for _ in range(60):
                if os.path.exists('/sys/class/net/tun0'):
                    success = True
                    break
                time.sleep(1)

            if not success:
                log_print("OpenVPN连接线程：60秒内未检测到 tun0 接口，连接可能失败。")
                
                if OPENVPN_PROCESS:
                    pgid = os.getpgid(OPENVPN_PROCESS.pid)
                    os.killpg(pgid, signal.SIGKILL)
                    OPENVPN_PROCESS.wait()
                    OPENVPN_PROCESS = None
                continue
            else:
                log_print("OpenVPN连接线程：tun0 接口已就绪。")

            log_print("OpenVPN连接线程：等待网络稳定和连通性（最多30秒重试）...")
            
            network_ok = False
            max_checks = 10 
            check_delay = 3
            
            for attempt in range(max_checks):
                if check_network(timeout=5): 
                    network_ok = True
                    break
                log_print(f"OpenVPN连接线程：网络检查失败 (尝试 {attempt + 1}/{max_checks})，等待 {check_delay} 秒重试...")
                time.sleep(check_delay)

            if network_ok:
                avg_latency = ping_test_average_latency(host=config['general']['ping_check_ip'], count=5)
                
                if avg_latency is not None:
                    NETWORK_FAILURE_COUNT = 0 
                    
                    log_print(f"OpenVPN连接线程：连接成功，VPN [{vpn_info[0]}] 正常工作，平均延迟：{avg_latency:.2f} ms。")
                    
                    proxy_str = "N/A"
                    
                    if os.path.exists(ovpn_file):
                        try:
                            with open(ovpn_file, 'r') as f:
                                content = f.read()
                            
                            socks_match = re.search(r'socks-proxy\s+(\S+)\s+(\S+)', content)
                            http_match = re.search(r'http-proxy\s+(\S+)\s+(\S+)', content)
                            
                            if socks_match:
                                ip, port = socks_match.groups()
                                proxy_str = f"socks://{ip}:{port}"
                            elif http_match:
                                ip, port = http_match.groups()
                                proxy_str = f"http://{ip}:{port}"
                                
                        except Exception as e:
                            log_print(f"OpenVPN连接线程：读取配置文件失败，错误：{e}")
                    
                    url_msg = f"已连接{vpn_info[0]}({vpn_info[6]}) 原始Ping:{vpn_info[3]}ms"
                    url_ping_info = f" 平均延迟:{avg_latency:.2f}ms"
                    url_proxy_info = f" 通过代理:{proxy_str}"
                    
                    full_url = f"http://192.168.1.1:81/?phone=test&msg={url_msg}{url_ping_info}{url_proxy_info}&from=VPNGATE"
                    
                    log_print(f"OpenVPN连接线程：发送连接成功通知到 {full_url}")
                    try :
                        requests.get(full_url, timeout=5)
                    except Exception as e :
                        log_print(f"发送SMS失败{e}")
                
                return 
            else:
                log_print(f"OpenVPN连接线程：VPN [{vpn_info[0]}] 连接后网络异常，尝试下一条。")
                
                if OPENVPN_PROCESS:
                    pgid = os.getpgid(OPENVPN_PROCESS.pid)
                    os.killpg(pgid, signal.SIGKILL)
                    OPENVPN_PROCESS.wait()
                    OPENVPN_PROCESS = None
                continue

        except Exception as e:
            log_print(f"OpenVPN连接线程：连接过程中出现错误：{e}")
            if OPENVPN_PROCESS:
                try:
                    pgid = os.getpgid(OPENVPN_PROCESS.pid)
                    os.killpg(pgid, signal.SIGKILL)
                    OPENVPN_PROCESS.wait()
                except:
                    pass
                OPENVPN_PROCESS = None
        finally:
            if os.path.exists(ovpn_file):
                os.remove(ovpn_file)

    log_print("OpenVPN连接线程：所有VPN记录都连接失败。")

def ping_test_average_latency(host=config['general']['ping_check_ip'], count=5):
    """
    使用纯 Python ICMP 报文执行多次 ping 并计算平均延迟（毫秒）。
    """
    log_print(f"OpenVPN连接线程：正在使用 ICMP 报文 ping {host} 获取平均延迟 ({count}次)...")
    
    latencies = []
    
    for i in range(count):
        latency = pure_python_icmp_ping(host, timeout=5)
        if latency is not None:
            latencies.append(latency)
        time.sleep(0.5) 

    if not latencies:
        log_print("OpenVPN连接线程：ICMP ping 失败，未获得任何有效延迟数据。")
        return None
        
    avg_latency = sum(latencies) / len(latencies)
    log_print(f"OpenVPN连接线程：平均网络延迟为 {avg_latency:.2f} ms。")
    return avg_latency

# --- 线程循环 ---

def load_config():
    """从配置文件加载配置，如果文件不存在则创建默认文件。"""
    global LAST_CONFIG_MOD_TIME, config
    config_parser = configparser.ConfigParser()
    
    # 初始化 config 字典
    for section, defaults in DEFAULT_CONFIG.items():
        config.setdefault(section, {}).update(defaults)

    if os.path.exists(CONFIG_FILE):
        config_parser.read(CONFIG_FILE)
        log_print("已成功加载 vpngate.cfg 配置文件。")
    else:
        # 写入默认配置
        config_parser['general'] = DEFAULT_CONFIG['general']
        config_parser['vpngate'] = DEFAULT_CONFIG['vpngate']
        config_parser['local_proxies'] = DEFAULT_CONFIG['local_proxies'] 
        with open(CONFIG_FILE, 'w') as f:
            config_parser.write(f)
        log_print(f"配置文件 {CONFIG_FILE} 不存在，已创建默认文件。")
    
    # 1. 记录加载前的 debug 状态
    old_debug_mode = str(config['general'].get('debug_mode', 'no')).lower()

    # 更新全局 config 字典
    for section in config_parser.sections():
        for key, value in config_parser.items(section):
            config[section][key] = value

    config['vpngate']['country_codes'] = [code.strip() for code in config['vpngate']['country_codes'].split(',')]
    filter_patterns = [keyword.strip() for keyword in config['vpngate']['hostname_filter_keywords'].split(',') if keyword.strip()]
    config['vpngate']['hostname_filter_patterns'] = [re.compile(pattern, re.IGNORECASE) for pattern in filter_patterns]
    
    local_proxies_str = config['local_proxies'].get('proxies', '')
    config['local_proxies']['proxies'] = [p.strip() for p in local_proxies_str.split(',') if p.strip()]

    # 检查并打印调试模式状态
    
    # 3. 检查并打印调试模式状态
    new_debug_mode = str(config['general'].get('debug_mode', 'no')).lower()
    
    if new_debug_mode != old_debug_mode:
        if new_debug_mode == 'yes':
            log_print("调试模式已开启。", is_debug=False) 
        else:
            log_print("调试模式已关闭。", is_debug=False) 

    try:
        config['general']['proxy_retry_count'] = int(config['general']['proxy_retry_count'])
        config['general']['proxy_retry_delay_seconds'] = int(config['general']['proxy_retry_delay_seconds'])
    except (ValueError, KeyError) as e:
        log_print(f"警告：配置文件中代理重试参数格式错误，将使用默认值。错误：{e}")
        config['general']['proxy_retry_count'] = 3
        config['general']['proxy_retry_delay_seconds'] = 1

def main_thread_loop():
# ... (function body remains the same)
    """主线程循环，定期检测网络。"""
    global config
    while True:
        if not check_network():
            log_print("主线程：网络异常，正在调用OpenVPN连接线程...")
            vpn_thread = threading.Thread(target=connect_openvpn)
            vpn_thread.start()
            vpn_thread.join()
            
        time.sleep(int(config['general']['network_check_interval_seconds']))

def vpn_list_thread_loop():
# ... (function body remains the same)
    """获取VPN列表线程循环，定期更新列表。"""
    global config
    while True:
        time.sleep(int(config['general']['vpngate_update_interval_seconds']))
        log_print(f"VPN列表线程：定期更新VPN列表，间隔 {config['general']['vpngate_update_interval_seconds']} 秒。", is_debug=True) 
        fetch_vpngate_list()

def proxy_list_thread_loop():
# ... (function body remains the same)
    """代理列表线程循环，定期更新并验证代理。"""
    global config
    while True:
        time.sleep(int(config['general']['proxy_update_interval_seconds']))
        log_print(f"代理线程：定期验证代理，间隔 {config['general']['proxy_update_interval_seconds']} 秒。", is_debug=True) 
        validate_proxies()

def config_watcher_thread():
# ... (function body remains the same)
    """新线程：每分钟检查配置文件变动，并触发相关更新。"""
    global LAST_CONFIG_MOD_TIME, LAST_PROXY_MOD_TIME, config

    try:
        if os.path.exists(CONFIG_FILE):
            LAST_CONFIG_MOD_TIME = os.path.getmtime(CONFIG_FILE)
        if os.path.exists(PROXY_FILE):
            LAST_PROXY_MOD_TIME = os.path.getmtime(PROXY_FILE)
    except FileNotFoundError:
        pass 

    while True:
        try:
            interval = int(config['general']['config_check_interval_seconds'])
        except (KeyError, ValueError):
            interval = 300
            
        time.sleep(interval) 
        log_print("配置监控线程：正在检查配置文件变动...", is_debug=True) 
        
        try:
            current_config_mod_time = os.path.getmtime(CONFIG_FILE)
            if current_config_mod_time > LAST_CONFIG_MOD_TIME:
                log_print("配置监控线程：检测到 vpngate.cfg 文件有变动，正在重新加载配置和VPN列表。")
                load_config()
                fetch_vpngate_list()
                LAST_CONFIG_MOD_TIME = current_config_mod_time
        except FileNotFoundError:
            log_print("配置监控线程：vpngate.cfg 文件不存在，跳过检查。", is_debug=True) 

        try:
            current_proxy_mod_time = os.path.getmtime(PROXY_FILE)
            if current_proxy_mod_time > LAST_PROXY_MOD_TIME:
                log_print("配置监控线程：检测到 proxy.txt 文件有变动，正在重新验证代理。")
                validate_proxies()
                LAST_PROXY_MOD_TIME = current_proxy_mod_time
        except FileNotFoundError:
            log_print("配置监控线程：proxy.txt 文件不存在，跳过检查。", is_debug=True) 

# --- 主程序入口 ---
if __name__ == '__main__':
    # 尝试导入 socket 模块，如果失败则退出
    # if 'socket' not in sys.modules: 
    try:
        import socket
    except ImportError:
        print("错误：缺少 socket 模块。无法执行纯 Python ICMP Ping。")
        sys.exit(1)

    load_config()
    if not read_default_gateway():
        exit(1)

    validate_proxies()
    
    if not PROXY_LIST and not LOCAL_PROXY_LIST:
        log_print("程序启动：未找到有效代理，程序退出。请检查 proxy.txt 文件和 vpngate.cfg 中的本地代理配置。")
        exit(1)
    
    log_print("程序启动，正在初始化线程...")
    
    fetch_vpngate_list()
    
    # 启动所有线程
    vpn_list_thread = threading.Thread(target=vpn_list_thread_loop)
    vpn_list_thread.daemon = True
    vpn_list_thread.start()
    
    proxy_list_thread = threading.Thread(target=proxy_list_thread_loop)
    proxy_list_thread.daemon = True
    proxy_list_thread.start()
    
    config_watcher = threading.Thread(target=config_watcher_thread)
    config_watcher.daemon = True
    config_watcher.start()
    
    # 启动 VPN 监控线程
    vpn_monitor = threading.Thread(target=vpn_monitor_thread_loop)
    vpn_monitor.daemon = True
    vpn_monitor.start()
    
    main_thread = threading.Thread(target=main_thread_loop)
    main_thread.daemon = True
    main_thread.start()
    
    log_print("所有线程已启动。")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_print("\n程序终止。")
        if OPENVPN_PROCESS:
            try:
                os.killpg(os.getpgid(OPENVPN_PROCESS.pid), signal.SIGTERM)
            except:
                pass
            OPENVPN_PROCESS = None
