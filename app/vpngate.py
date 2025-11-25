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

# --- 全局状态和锁 ---
VPN_GATE_LIST = []
PROXY_LIST = []
LOCAL_PROXY_LIST = []
VPN_LIST_LOCK = threading.Lock()
PROXY_LIST_LOCK = threading.Lock()
OPENVPN_PROCESS = None
CURRENT_PROXY = None
DEFAULT_GW = None

# 关键锁：确保同一时间只有一个连接/清理流程在运行
OPENVPN_CONNECT_LOCK = threading.Lock() 

# --- 网络监控全局变量 (由持续Ping进程更新) ---
NETWORK_HEALTH_LOCK = threading.Lock()
NETWORK_HEALTH_STATUS = False 
PING_PROCESS = None 

# 文件修改时间记录
LAST_CONFIG_MOD_TIME = 0
LAST_PROXY_MOD_TIME = 0

# --- 配置文件与参数 ---
CONFIG_FILE = 'vpngate.cfg'
PROXY_FILE = 'proxy.txt'
GATEWAY_FILE = 'gateway.txt'

# 默认配置 (新增 debug 选项)
config = {
    'general': {
        'vpngate_update_interval_seconds': 3600,
        'proxy_update_interval_seconds': 300,
        'network_checker_interval_seconds': 30,
        'config_check_interval_seconds': 300,
        'proxy_test_url': 'https://www.google.com', 
        'ping_check_ip': '8.8.8.8',
        'vpngate_url': 'http://www.vpngate.net/api/iphone/',
        'proxy_retry_count': 3,
        'proxy_retry_delay_seconds': 1,
        'proxy_max_retries': 5, 
        'debug': 'false', # <-- 新增 DEBUG 模式开关
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

def log_print(message, force_print=False):
    """
    带时间戳地打印信息。
    :param message: 要打印的消息。
    :param force_print: 如果为 True，则忽略 debug 配置强制打印。
    """
    
    # 检查 debug 配置是否开启 (容错处理)
    is_debug_enabled = config['general'].get('debug', 'false').lower() in ('true', 'yes', '1')

    if force_print or is_debug_enabled:
        timestamp = datetime.now().strftime("%Y%m%d-%H:%M:%S")
        print(f"[{timestamp}] {message}")

# --- 路由和代理辅助函数 ---

def get_current_proxy():
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
    """从文件中读取默认网关IP。"""
    global DEFAULT_GW
    if os.path.exists(GATEWAY_FILE):
        with open(GATEWAY_FILE, 'r') as f:
            gw_ip = f.readline().strip()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', gw_ip):
                DEFAULT_GW = gw_ip
                log_print(f"已从 {GATEWAY_FILE} 文件中读取系统网关IP：{DEFAULT_GW}")
                return True
    
    log_print(f"错误：未找到有效的系统网关IP。请在 {GATEWAY_FILE} 文件中写入正确的IP地址。", force_print=True)
    return False

def add_route_for_proxy(proxy_ip):
    """为代理IP添加路由规则，通过默认网关，并检测是否成功。"""
    if not DEFAULT_GW:
        log_print("无法添加路由：系统网关IP未设置。", force_print=True)
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
        log_print(f"添加路由时发生未知错误：{e}", force_print=True)
        return False

def delete_route_for_proxy(proxy_ip):
    """删除为代理IP添加的路由规则。"""
    if not DEFAULT_GW:
        return False

    try:
        command = ['ip', 'route', 'del', proxy_ip]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_print(f"已删除代理IP {proxy_ip} 的路由规则。")
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        log_print(f"删除路由时发生未知错误：{e}")
        return False

def parse_proxy_line(line):
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
    """格式化代理数据为 proxy.txt 行格式。"""
    return f"{proxy_data['url']},{proxy_data['latency']:.2f},{proxy_data['retries']},{proxy_data['info']}\n"

def test_single_proxy(proxy_url, retry_count, retry_delay_seconds):
    """
    测试单个代理的可达性和延迟（使用 HTTP 探测）。
    返回: (is_success, latency_ms)
    """
    proxies = {}
    if proxy_url.startswith('socks://') or proxy_url.startswith('socks5://') or proxy_url.startswith('socks5h://'):
        proxy_url = re.sub(r'socks(5h|5)?://', 'socks5h://', proxy_url)
        proxies = {'http': proxy_url, 'https': proxy_url}
    elif proxy_url.startswith('http://') or proxy_url.startswith('socks4://'):
        proxies = {'http': proxy_url, 'https': proxy_url}
    else:
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
        except Exception:
            log_print(f"代理验证线程：代理 {proxy_url} 第 {attempt} 次尝试验证失败（连接超时/错误）。")
        
        if attempt < retry_count:
            time.sleep(retry_delay_seconds)

    if not is_successful and proxy_ip:
        delete_route_for_proxy(proxy_ip)
        
    return is_successful, latency

def validate_proxies():
    """验证 proxy.txt 和本地配置中的代理，并根据规则更新 proxy.txt 文件。"""
    global PROXY_LIST, LOCAL_PROXY_LIST
    
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
            log_print(f"错误：写入 {PROXY_FILE} 文件失败：{e}", force_print=True)
    else:
        log_print(f"代理验证线程：{PROXY_FILE} 内容无变化，跳过文件写入。")


    local_proxy_list = []
    if config['local_proxies']['enable'].lower() == 'yes':
        local_proxies_str = config['local_proxies'].get('proxies', '')
        if isinstance(local_proxies_str, str):
            local_proxy_list = [p.strip() for p in local_proxies_str.split(',') if p.strip()]
        elif isinstance(local_proxies_str, list):
            local_proxy_list = local_proxies_str
    
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

def fetch_vpngate_list():
    """从 VPN Gate 获取服务器列表并格式化。"""
    global VPN_GATE_LIST
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
        log_print(f"获取VPN列表线程：获取列表失败，错误：{e}", force_print=True)


# --- 持续 Ping 进程管理 ---

def cleanup_ping_process():
    """清理持续ping进程（如果存在）。"""
    global PING_PROCESS
    if PING_PROCESS and PING_PROCESS.poll() is None:
        log_print("持续Ping监控：清理旧的持续Ping进程...")
        pgid = None
        try:
            pgid = os.getpgid(PING_PROCESS.pid)
            os.killpg(pgid, signal.SIGTERM)
            PING_PROCESS.wait(timeout=5)
        except Exception as e:
            log_print(f"清理Ping进程失败：{e}，尝试 SIGKILL...")
            try:
                 if pgid:
                    os.killpg(pgid, signal.SIGKILL)
            except:
                pass
        finally:
            PING_PROCESS = None
            log_print("持续Ping监控：Ping进程已清理。")

def start_continuous_ping():
    """启动一个持续ping的子进程，并启动读取其输出的线程。"""
    global PING_PROCESS
    
    if PING_PROCESS and PING_PROCESS.poll() is None:
        log_print("持续Ping监控：Ping进程已在运行，跳过启动。")
        return

    cleanup_ping_process()

    host = config['general']['ping_check_ip']
    log_print(f"持续Ping监控：启动新的持续Ping进程到 {host}...")
    
    try:
        PING_PROCESS = subprocess.Popen(
            ['fping', '-l', '-p', '1000', host], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            preexec_fn=os.setsid 
        )
        log_print(f"持续Ping监控：Ping进程 PID {PING_PROCESS.pid} 已启动。")
        
        threading.Thread(target=ping_output_reader_thread, daemon=True).start()
        
    except FileNotFoundError:
        log_print("错误：'ping' 命令未找到，请确保已安装。")
        PING_PROCESS = None
    except Exception as e:
        log_print(f"启动持续Ping进程失败：{e}", force_print=True)
        PING_PROCESS = None

def ping_output_reader_thread():
    """持续读取 PING_PROCESS 的 stdout，解析延迟并更新 NETWORK_HEALTH_STATUS。"""
    global PING_PROCESS, NETWORK_HEALTH_STATUS
    
    if not PING_PROCESS:
        return
        
    log_print("Ping读取线程：开始读取 Ping 进程输出...")

    while PING_PROCESS.poll() is None:
        try:
            line = PING_PROCESS.stdout.readline() 
            if not line:
                time.sleep(0.1)
                continue

            match = re.search(r':\s*(\d+\.?\d*)\s*ms', line)
            
            with NETWORK_HEALTH_LOCK:
                if match:
                    latency = float(match.group(1))
                    NETWORK_HEALTH_STATUS = latency 
                    LAST_PING_UPDATE_TIME = time.time() 
                    log_print(f"Ping读取线程：Ping成功，延迟 {latency:.2f}ms。") # 增加Debug日志
                # 匹配不可达的输出，格式如 "8.8.8.8 : unreachable" 或 DNS 错误
                elif 'unreachable' in line or 'can\'t resolve' in line: # <-- 关键修改
                    NETWORK_HEALTH_STATUS = False 
                    LAST_PING_UPDATE_TIME = time.time()
                    log_print(f"Ping读取线程：Ping失败，目标不可达或解析失败。") # 增加Debug日志
                else:
                    pass
                
        except Exception as e:
            log_print(f"Ping读取线程：读取输出或解析时出错：{e}")
            break 

    exit_code = PING_PROCESS.wait() if PING_PROCESS else -1
    log_print(f"持续Ping监控：Ping进程意外终止，退出码 {exit_code}。")
    
    with NETWORK_HEALTH_LOCK:
        NETWORK_HEALTH_STATUS = False 

    PING_PROCESS = None

def get_network_health():
    """读取并返回 NETWORK_HEALTH_STATUS 的布尔值结果。"""
    global NETWORK_HEALTH_STATUS
    with NETWORK_HEALTH_LOCK:
        return NETWORK_HEALTH_STATUS is not False
        
# --- OpenVPN 连接逻辑 (已修正) ---

def create_ovpn_file(vpn_info):
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
        log_print(f"OpenVPN连接线程：生成配置文件失败，错误：{e}", force_print=True)
        return None

def connect_openvpn():
    """OpenVPN连接线程，尝试连接列表中的VPN。"""
    global OPENVPN_PROCESS
    
    # 关键 1：尝试获取连接锁
    if not OPENVPN_CONNECT_LOCK.acquire(blocking=False):
        log_print("OpenVPN连接线程：上一个连接或清理线程仍在运行，跳过本次连接尝试。")
        return

    try: 
        with VPN_LIST_LOCK:
            current_list = VPN_GATE_LIST[:]
        
        if not current_list:
            log_print("OpenVPN连接线程：VPN列表为空，无法连接。", force_print=True)
            return

        log_print("OpenVPN连接线程：正在尝试连接VPN...")
        
        for i, vpn_info in enumerate(current_list):
            log_print(f"OpenVPN连接线程：尝试连接第 {i+1} 条记录 ({vpn_info[0]}, {vpn_info[6]}，原始Ping: {vpn_info[3]}ms)")
            ovpn_file = create_ovpn_file(vpn_info)
            
            if not ovpn_file:
                continue
                
            try:
                # --- 进程终止和清理 START ---
                if OPENVPN_PROCESS:
                    log_print("OpenVPN连接线程：正在终止旧的OpenVPN进程...")
                    pgid = None
                    try:
                        pgid = os.getpgid(OPENVPN_PROCESS.pid)
                        os.killpg(pgid, signal.SIGTERM) 
                    except ProcessLookupError:
                        pass
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
                            except:
                                pass
                    
                    OPENVPN_PROCESS = None
                # --- 进程终止和清理 END ---
                
                # 启动新进程
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

                # 检查网络（等待 5 秒，然后读取持续 Ping 的状态）
                log_print("OpenVPN连接线程：tun0 已就绪，等待 5 秒确认连接稳定...")
                time.sleep(5) 

                if get_network_health(): 
                    
                    current_latency = None
                    with NETWORK_HEALTH_LOCK:
                        current_latency = NETWORK_HEALTH_STATUS if NETWORK_HEALTH_STATUS is not False else None
                        
                    latency_str = f"{current_latency:.2f} ms" if current_latency else "未知延迟"
                    
                    log_print(f"OpenVPN连接线程：连接成功，VPN [{vpn_info[0]}] 正常工作，网络检查通过 (延迟: {latency_str})。")
                    
                    # 准备通知信息
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
                    url_ping_info = f" 网络检查通过 (延迟: {latency_str})"
                    url_proxy_info = f" 通过代理:{proxy_str}"
                    
                    full_url = f"http://192.168.1.1:8001/?phone=test&msg={url_msg}{url_ping_info}{url_proxy_info}&from=VPNGATE"
                    
                    log_print(f"OpenVPN连接线程：发送连接成功通知到 {full_url}")
                    try :
                        requests.get(full_url, timeout=5)
                    except Exception as e :
                        log_print(f"发送SMS失败{e}", force_print=True)
                
                    return # 连接成功，退出循环
                else:
                    log_print(f"OpenVPN连接线程：VPN [{vpn_info[0]}] 连接后网络异常（5秒延迟后持续Ping未恢复），尝试下一条。")
                    
                    if OPENVPN_PROCESS:
                        pgid = os.getpgid(OPENVPN_PROCESS.pid)
                        os.killpg(pgid, signal.SIGKILL)
                        OPENVPN_PROCESS.wait()
                        OPENVPN_PROCESS = None
                    continue

            except Exception as e:
                log_print(f"OpenVPN连接线程：连接过程中出现错误：{e}", force_print=True)
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

        log_print("OpenVPN连接线程：所有VPN记录都连接失败。", force_print=True)

    except Exception as e:
        log_print(f"OpenVPN连接线程：在连接循环外部发生错误：{e}", force_print=True)
        
    finally:
        # 关键 2：确保在函数结束时释放锁
        if OPENVPN_CONNECT_LOCK.locked():
            OPENVPN_CONNECT_LOCK.release()
            log_print("OpenVPN连接线程：连接/清理循环结束，已释放连接锁。")


# --- 线程循环 ---

def network_checker_loop():
    """
    定时检查线程。
    1. 确保持续Ping进程正在运行。
    2. 检查后台状态（NETWORK_HEALTH_STATUS）来决定是否调用 connect_openvpn()。
    """
    global OPENVPN_PROCESS
    interval = int(config['general']['network_checker_interval_seconds'])
    
    start_continuous_ping()
    
    log_print("网络检查线程：首次启动，尝试连接VPN。")
    threading.Thread(target=connect_openvpn).start()

    while True:
        time.sleep(interval)
        
        if PING_PROCESS is None or PING_PROCESS.poll() is not None:
             log_print("网络检查线程：持续Ping进程已停止，尝试重启。")
             start_continuous_ping() 
             
        network_ok = get_network_health()
        
        if network_ok:
            current_latency = None
            with NETWORK_HEALTH_LOCK:
                 current_latency = NETWORK_HEALTH_STATUS
                 
            latency_msg = f"(延迟约 {current_latency:.2f} ms)" if current_latency is not False else ""
            log_print(f"网络检查线程：持续Ping显示网络正常 {latency_msg}。")
        else:
            log_print("网络检查线程：检测到网络连接失败 (持续Ping无响应或失败)。")
            
            if not OPENVPN_CONNECT_LOCK.locked() and (OPENVPN_PROCESS or os.path.exists('/sys/class/net/tun0')):
                log_print("网络检查线程：检测到网络异常，开始清理旧连接并触发重连。")
                
                reconnect_thread = threading.Thread(target=connect_openvpn)
                reconnect_thread.start()
            elif OPENVPN_CONNECT_LOCK.locked():
                 log_print("网络检查线程：网络异常，但连接线程正在运行，等待其完成。")
            else:
                log_print("网络检查线程：网络异常，但无活动 VPN 进程，启动连接。")
                reconnect_thread = threading.Thread(target=connect_openvpn)
                reconnect_thread.start()


def vpn_list_thread_loop():
    """获取VPN列表线程循环，定期更新列表。"""
    while True:
        time.sleep(int(config['general']['vpngate_update_interval_seconds']))
        log_print(f"VPN列表线程：定期更新VPN列表，间隔 {config['general']['vpngate_update_interval_seconds']} 秒。")
        fetch_vpngate_list()

def proxy_list_thread_loop():
    """代理列表线程循环，定期更新并验证代理。"""
    while True:
        time.sleep(int(config['general']['proxy_update_interval_seconds']))
        log_print(f"代理线程：定期验证代理，间隔 {config['general']['proxy_update_interval_seconds']} 秒。")
        validate_proxies()

def config_watcher_thread():
    """检查配置文件变动。"""
    global LAST_CONFIG_MOD_TIME, LAST_PROXY_MOD_TIME
    try:
        if os.path.exists(CONFIG_FILE):
            LAST_CONFIG_MOD_TIME = os.path.getmtime(CONFIG_FILE)
        if os.path.exists(PROXY_FILE):
            LAST_PROXY_MOD_TIME = os.path.getmtime(PROXY_FILE)
    except FileNotFoundError:
        pass

    interval = config.get('general', {}).get('config_check_interval_seconds', 300)
    try:
        interval = int(interval)
    except:
        interval = 300
    
    while True:
        time.sleep(interval)
        log_print("配置监控线程：正在检查配置文件变动...")
        
        try:
            current_config_mod_time = os.path.getmtime(CONFIG_FILE)
            if current_config_mod_time > LAST_CONFIG_MOD_TIME:
                log_print("配置监控线程：检测到 vpngate.cfg 文件有变动，正在重新加载配置和VPN列表。")
                load_config()
                fetch_vpngate_list()
                LAST_CONFIG_MOD_TIME = current_config_mod_time
        except FileNotFoundError:
            pass

        try:
            current_proxy_mod_time = os.path.getmtime(PROXY_FILE)
            if current_proxy_mod_time > LAST_PROXY_MOD_TIME:
                log_print("配置监控线程：检测到 proxy.txt 文件有变动，正在重新验证代理。")
                validate_proxies()
                LAST_PROXY_MOD_TIME = current_proxy_mod_time
        except FileNotFoundError:
            pass

def load_config():
    """从配置文件加载配置，如果文件不存在则创建默认文件。"""
    global LAST_CONFIG_MOD_TIME
    
    # 获取旧的 debug 状态
    old_debug_state_str = config['general'].get('debug', 'false')
    old_debug_state = old_debug_state_str.lower() in ('true', 'yes', '1')

    config_parser = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config_parser.read(CONFIG_FILE)
        # 这里使用强制打印，因为这是重要的初始化或重载信息
        log_print("已成功加载 vpngate.cfg 配置文件。")
    else:
        default_config_parser = configparser.ConfigParser()
        default_config_parser['general'] = {k: str(v) for k, v in config['general'].items()}
        default_config_parser['vpngate'] = config['vpngate']
        default_config_parser['local_proxies'] = config['local_proxies'] 
        with open(CONFIG_FILE, 'w') as f:
            default_config_parser.write(f)
        log_print(f"配置文件 {CONFIG_FILE} 不存在，已创建默认文件。")

    new_config = config.copy() 
    for section in config_parser.sections():
        new_config.setdefault(section, {}).update(config_parser.items(section))
    config.update(new_config)

    # 检查 debug 状态变化
    new_debug_state_str = config['general'].get('debug', 'false')
    new_debug_state = new_debug_state_str.lower() in ('true', 'yes', '1')
    
    if new_debug_state != old_debug_state:
        # 强制打印 DEBUG 模式变更信息
        log_print(f"DEBUG模式变更为: {new_debug_state}", force_print=True)

    # 处理 country_codes 和 filter_patterns
    config['vpngate']['country_codes'] = [code.strip() for code in config['vpngate']['country_codes'].split(',')]
    filter_patterns = [keyword.strip() for keyword in config['vpngate']['hostname_filter_keywords'].split(',') if keyword.strip()]
    config['vpngate']['hostname_filter_patterns'] = [re.compile(pattern, re.IGNORECASE) for pattern in filter_patterns]
    
    local_proxies_str = config['local_proxies'].get('proxies', '')
    if isinstance(local_proxies_str, str):
        config['local_proxies']['proxies'] = [p.strip() for p in local_proxies_str.split(',') if p.strip()]

    try:
        config['general']['proxy_retry_count'] = int(config['general']['proxy_retry_count'])
        config['general']['proxy_retry_delay_seconds'] = int(config['general']['proxy_retry_delay_seconds'])
        config['general']['network_checker_interval_seconds'] = int(config['general']['network_checker_interval_seconds'])
    except (ValueError, KeyError) as e:
        log_print(f"警告：配置文件中参数格式错误，将使用默认值。错误：{e}", force_print=True)
        config['general']['proxy_retry_count'] = 3
        config['general']['proxy_retry_delay_seconds'] = 1
        config['general']['network_checker_interval_seconds'] = 30


# --- 主程序入口 ---
if __name__ == '__main__':
    load_config()
    if not read_default_gateway():
        log_print("未读取到默认网关，程序退出。", force_print=True)
        exit(1)

    validate_proxies()
    
    if not PROXY_LIST and not LOCAL_PROXY_LIST:
        log_print("程序启动：未找到有效代理，程序退出。请检查 proxy.txt 文件和 vpngate.cfg 中的本地代理配置。", force_print=True)
        exit(1)
    
    log_print("程序启动，正在初始化线程...", force_print=True)
    
    fetch_vpngate_list()
    
    # 启动所有线程
    
    checker_thread = threading.Thread(target=network_checker_loop)
    checker_thread.daemon = True
    checker_thread.start()
    
    vpn_list_thread = threading.Thread(target=vpn_list_thread_loop)
    vpn_list_thread.daemon = True
    vpn_list_thread.start()
    
    proxy_list_thread = threading.Thread(target=proxy_list_thread_loop)
    proxy_list_thread.daemon = True
    proxy_list_thread.start()
    
    config_watcher = threading.Thread(target=config_watcher_thread)
    config_watcher.daemon = True
    config_watcher.start()
    
    log_print("所有线程已启动。", force_print=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_print("\n程序终止。", force_print=True)
        cleanup_ping_process() 
        if OPENVPN_PROCESS:
            try:
                os.killpg(os.getpgid(OPENVPN_PROCESS.pid), signal.SIGTERM)
            except:
                pass
            OPENVPN_PROCESS = None
