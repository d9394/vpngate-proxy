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

# 全局变量
VPN_GATE_LIST = []
PROXY_LIST = []
LOCAL_PROXY_LIST = []
VPN_LIST_LOCK = threading.Lock()
PROXY_LIST_LOCK = threading.Lock()
OPENVPN_PROCESS = None
CURRENT_PROXY = None
DEFAULT_GW = None

# 文件修改时间记录
LAST_CONFIG_MOD_TIME = 0
LAST_PROXY_MOD_TIME = 0

# --- 配置文件与参数 ---
CONFIG_FILE = 'vpngate.cfg'
PROXY_FILE = 'proxy.txt'
GATEWAY_FILE = 'gateway.txt'

# 默认配置
config = {
    'general': {
        'vpngate_update_interval_seconds': 3600,
        'proxy_update_interval_seconds': 300,
        'network_check_interval_seconds': 300,
        'config_check_interval_seconds': 300,
        'proxy_test_url': 'https://www.google.com',
        'ping_check_ip': '8.8.8.8',
        'vpngate_url': 'http://www.vpngate.net/api/iphone/',
        'proxy_retry_count': 3,
        'proxy_retry_delay_seconds': 1,
        'proxy_max_retries': 5, # 新增配置项：代理最大失败次数
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

def log_print(message):
    """带时间戳地打印信息。"""
    timestamp = datetime.now().strftime("%Y%m%d-%H:%M:%S")
    print(f"[{timestamp}] {message}")

# --- 网络与代理 ---

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
    
    log_print(f"错误：未找到有效的系统网关IP。请在 {GATEWAY_FILE} 文件中写入正确的IP地址。")
    return False

def add_route_for_proxy(proxy_ip):
    """为代理IP添加路由规则，通过默认网关，并检测是否成功。"""
    if not DEFAULT_GW:
        log_print("无法添加路由：系统网关IP未设置。")
        return False
    
    # 1. 尝试添加路由
    try:
        command = ['ip', 'route', 'add', proxy_ip, 'via', DEFAULT_GW]
        # 使用 check=False, 允许命令失败，以便我们能统一处理
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 2. 尝试多次检测，以防路由表更新有延迟
        max_checks = 3
        check_delay = 0.5
        
        for i in range(max_checks):
            # 检查路由表是否包含新添加的路由
            route_check_command = ['ip', 'route', 'show']
            result = subprocess.run(route_check_command, capture_output=True, text=True, check=False)
            
            # 检查输出中是否包含目标IP和网关
            # 路由条目通常格式为：<proxy_ip> via <default_gw>
            expected_route_segment = f"{proxy_ip} via {DEFAULT_GW}"

            if expected_route_segment in result.stdout:
                log_print(f"已成功为代理IP {proxy_ip} 添加路由规则并确认。")
                return True
            
            # 如果不是最后一次检查，则等待
            if i < max_checks - 1:
                time.sleep(check_delay)

        # 3. 如果多次检查后仍未找到
        log_print(f"添加路由失败：已执行 'ip route add {proxy_ip} via {DEFAULT_GW}'，但路由表中未检测到该条目。")
        return False
        
    except Exception as e:
        log_print(f"添加路由时发生未知错误：{e}")
        return False

def delete_route_for_proxy(proxy_ip):
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
    """解析 proxy.txt 中的一行内容。"""
    parts = line.strip().split(',')
    if len(parts) >= 4:
        url = parts[0].strip()
        try:
            latency = float(parts[1].strip().replace("ms",""))
            retries = int(parts[2].strip())
            info = parts[3].strip()
            # 校验 URL 格式
            if url.startswith('http://') or url.startswith('socks5h://') or url.startswith('socks5://') or url.startswith('socks4://'):
                return {'url': url, 'latency': latency, 'retries': retries, 'info': info, 'raw_line': line}
        except ValueError:
            log_print(f"代理验证线程：{PROXY_FILE}内容错误：{line}。")
    return None

def format_proxy_line(proxy_data):
    """格式化代理数据为 proxy.txt 行格式。"""
    # url,延迟(ms),测试次数,脚本ID@时间戳
    return f"{proxy_data['url']},{proxy_data['latency']:.2f},{proxy_data['retries']},{proxy_data['info']}\n"


def test_single_proxy(proxy_url, retry_count, retry_delay_seconds):
    """
    测试单个代理的可达性和延迟。
    返回: (is_success, latency_ms)
    """
    proxies = {}
    if proxy_url.startswith('socks://') or proxy_url.startswith('socks5://') or proxy_url.startswith('socks5h://'):
        # 统一使用 socks5h://
        proxy_url = re.sub(r'socks(5h|5)?://', 'socks5h://', proxy_url)
        proxies = {'http': proxy_url, 'https': proxy_url}
    elif proxy_url.startswith('http://') or proxy_url.startswith('socks4://'):
        proxies = {'http': proxy_url, 'https': proxy_url}
    else:
        log_print(f"代理验证线程：代理格式不支持，跳过测试：{proxy_url}")
        return False, None
    
    # 提取 IP 用于路由操作
    match = re.search(r'://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', proxy_url)
    proxy_ip = match.group(1) if match else None

    if proxy_ip:
        add_route_for_proxy(proxy_ip)
    
    is_successful = False
    latency = None
    
    for attempt in range(1, retry_count + 1):
        try:
            start_time = time.time()
            # 使用 config 中定义的测试 URL
            response = requests.get(config['general']['proxy_test_url'], proxies=proxies, timeout=10)
            
            if response.status_code == 200:
                latency = (time.time() - start_time) * 1000 # 转换为毫秒
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
    """
    验证 proxy.txt 和本地配置中的代理，并根据规则更新 proxy.txt 文件。
    修改：确保所有注释行和无效行在文件重写时得到保留。
    """
    global PROXY_LIST, LOCAL_PROXY_LIST
    
    validated_list_from_file = []
    
    # ----------------------------------------------------
    # I. 处理 proxy.txt 文件中的代理
    # ----------------------------------------------------
    proxy_file_records = []
    seen_urls = {}
    unprocessed_lines = [] # <-- 新增：用于存储注释行和无效行
    
    PROXY_CONTENT_CHANGED = False 
    original_file_content = ""
    
    if os.path.exists(PROXY_FILE):
        with open(PROXY_FILE, 'r') as f:
            original_lines = f.readlines()
            original_file_content = "".join(original_lines) 
            
            for line in original_lines:
                line = line.rstrip('\n') # 保留原始换行符的处理
                stripped_line = line.strip()

                if stripped_line.startswith('#'):
                    # 这是一个注释行，直接保存原始行，并在写入时带上换行符
                    unprocessed_lines.append(line + '\n') 
                    continue # 跳过解析
                
                # 非注释行尝试解析
                data = parse_proxy_line(stripped_line)
                if data:
                    # 有效的代理记录
                    data['raw_line'] = stripped_line
                    data['is_commented'] = False
                    data['original_retries'] = data['retries'] 
                    url = data['url']
                    
                    # 仅保留 URL 唯一的记录（你之前的去重逻辑）
                    seen_urls[url] = data
                else:
                    # 无法解析的行，也作为未处理行保存，以便写回
                    if stripped_line: # 避免保存空行
                         unprocessed_lines.append(line + '\n') 
                
        # 提取有效代理记录
        proxy_file_records = list(seen_urls.values())
    else :
        log_print(f"代理验证线程：{PROXY_FILE} 文件未找到。")
        
    log_print(f"代理验证线程：开始验证 {PROXY_FILE} 中的 {len(proxy_file_records)} 条有效记录，{len(unprocessed_lines)}条无效记录。")
    
    # ... (省略配置读取和 TIMESTAMP_PATTERN 定义，保持不变) ...
    requests_retry_count = int(config['general']['proxy_retry_count'])
    retry_delay_seconds = int(config['general']['proxy_retry_delay_seconds'])
    max_retries = int(config['general'].get('proxy_max_retries', 5))
    TIMESTAMP_PATTERN = r'[#%]\d{8}-\d{2}:\d{2}:\d{2}$' 
    
    updated_proxy_records = [] # 存储处理后的有效代理记录
    
    for record in proxy_file_records:
        original_retries = record.pop('original_retries') 
        
        # ... (成功/失败逻辑处理，与上次代码完全一致，略) ...
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
                    pass # 保持注释状态不变

        updated_proxy_records.append(record) # 将所有处理过的有效代理（包括需要注释的）加入列表

    # --- 文件重写控制 START ---
    
    # 1. 组装处理后的代理记录内容 (新的非注释/注释行)
    processed_content = ""
    for record in updated_proxy_records:
        line = format_proxy_line(record) 
        if record.get('is_commented'):
            processed_content += "#" + line
        else:
            processed_content += line
            
    # 2. 合并未处理的行（注释行、无效格式行）和处理后的内容
    # 保持未处理行在文件中的相对位置是复杂的，为了简化和确保有效代理总是在前面，我们只将未处理行放在文件的末尾
    file_content_to_write = processed_content + "".join(unprocessed_lines)

    # 3. 比较原始内容和新内容
    if PROXY_CONTENT_CHANGED or (file_content_to_write.strip() != original_file_content.strip() and os.path.exists(PROXY_FILE)):
        try:
            with open(PROXY_FILE, 'w') as f:
                f.write(file_content_to_write)

            log_print(f"代理验证线程：{PROXY_FILE} 已更新，共 {len(updated_proxy_records)} 条有效代理记录被处理。")
        except Exception as e:
            log_print(f"错误：写入 {PROXY_FILE} 文件失败：{e}")
    else:
        log_print(f"代理验证线程：{PROXY_FILE} 内容无变化，跳过文件写入。")
    # --- 文件重写控制 END ---


    # ----------------------------------------------------
    # II. III. 处理本地配置和更新全局列表 (保持不变)
    # ----------------------------------------------------
    
    # ... (更新 PROXY_LIST 和 LOCAL_PROXY_LIST 的逻辑保持不变) ...
    # 注意：这里的 validated_list_from_file 只需要在成功逻辑中append，所以不需要修改
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

    # 更新全局列表 PROXY_LIST 和 LOCAL_PROXY_LIST
    with PROXY_LIST_LOCK:
        validated_list_from_file.sort(key=lambda x: x['latency'])
        PROXY_LIST = [item['proxies'] for item in validated_list_from_file]
        
        validated_list_from_local.sort(key=lambda x: x['latency'])
        LOCAL_PROXY_LIST = [item['proxies'] for item in validated_list_from_local]
        log_print(f"代理验证线程：全局列表更新完成。共{len(PROXY_LIST)}个外部代理，{len(LOCAL_PROXY_LIST)}个本地代理")
        
# --- VPN Gate 列表 ---

def check_network():
    """使用ping命令检测网络连接是否正常。"""
    try:
        ping_ip = config['general']['ping_check_ip']
        log_print(f"主线程：正在使用 ping {ping_ip} 检测网络连接...")
        subprocess.run(['ping', '-c', '1', '-W', '5', ping_ip], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_print("主线程：网络连接正常。")
        return True
    except subprocess.CalledProcessError:
        log_print(f"主线程：网络连接异常，ping {ping_ip} 失败。")
        return False
    except Exception as e:
        log_print(f"主线程：网络连接异常，错误：{e}")
        return False

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
        log_print(f"获取VPN列表线程：获取列表失败，错误：{e}")

# --- OpenVPN 连接逻辑 ---

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
        log_print(f"OpenVPN连接线程：生成配置文件失败，错误：{e}")
        return None

def connect_openvpn():
    """OpenVPN连接线程，尝试连接列表中的VPN。"""
    global OPENVPN_PROCESS
    
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
            # --- 进程终止和清理 START ---
            if OPENVPN_PROCESS:
                log_print("OpenVPN连接线程：正在终止旧的OpenVPN进程...")
                pgid = None
                
                try:
                    # 尝试获取进程组ID
                    pgid = os.getpgid(OPENVPN_PROCESS.pid)
                    # 1. 尝试优雅终止 (SIGTERM)
                    os.killpg(pgid, signal.SIGTERM)
                    log_print(f"已发送 SIGTERM 到进程组 {pgid}，等待退出...")
                except ProcessLookupError:
                    log_print("旧进程已消失，无需终止。")
                except Exception as e:
                    log_print(f"终止旧进程时出现错误 (SIGTERM)：{e}")
                
                # 等待进程退出
                try:
                    # 给予进程10秒优雅退出时间
                    OPENVPN_PROCESS.wait(timeout=10) 
                    log_print("旧进程已优雅退出。")
                except subprocess.TimeoutExpired:
                    # 如果超时未退出，则强制杀死进程组 (SIGKILL)
                    log_print("旧进程超时未退出，尝试强制终止 (SIGKILL)...")
                    if pgid:
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                            OPENVPN_PROCESS.wait(timeout=5)
                        except ProcessLookupError:
                            pass # 忽略已消失的进程
                        except Exception as e:
                            log_print(f"强制终止旧进程时出现错误 (SIGKILL)：{e}")
                
                OPENVPN_PROCESS = None
            # --- 进程终止和清理 END ---
            
            # 启动新进程
            OPENVPN_PROCESS = subprocess.Popen(
                ['openvpn', '--config', ovpn_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid # 确保创建新的进程组
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
                
                # 确保清理失败的进程
                if OPENVPN_PROCESS:
                    pgid = os.getpgid(OPENVPN_PROCESS.pid)
                    os.killpg(pgid, signal.SIGKILL)
                    OPENVPN_PROCESS.wait()
                    OPENVPN_PROCESS = None
                continue
            else:
                log_print("OpenVPN连接线程：tun0 接口已就绪。")

            # 3. 检查网络和获取平均延迟
            if check_network():
                avg_latency = ping_test_average_latency(host=config['general']['ping_check_ip'], count=5)
                
                if avg_latency is not None:
                    log_print(f"OpenVPN连接线程：连接成功，VPN [{vpn_info[0]}] 正常工作，平均延迟：{avg_latency:.2f} ms。")
                    
                    # 准备通知信息
                    proxy_str = "N/A"
                    # ... (省略：读取代理配置信息，与原代码一致) ...
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
                    
                    # 组装通知URL
                    url_msg = f"已连接{vpn_info[0]}({vpn_info[6]}) 原始Ping:{vpn_info[3]}ms"
                    url_ping_info = f" 平均延迟:{avg_latency:.2f}ms"
                    url_proxy_info = f" 通过代理:{proxy_str}"
                    
                    full_url = f"http://192.168.1.1:88/?phone=test&msg={url_msg}{url_ping_info}{url_proxy_info}&from=VPNGATE"
                    
                    log_print(f"OpenVPN连接线程：发送连接成功通知到 {full_url}")
                    try :
                        requests.get(full_url, timeout=5)
                    except Exception as e :
                        log_print(f"发送SMS失败{e}")
                
                return # 连接成功并通知后，退出循环
            else:
                log_print(f"OpenVPN连接线程：VPN [{vpn_info[0]}] 连接后网络异常，尝试下一条。")
                
                # 清理失败的进程
                if OPENVPN_PROCESS:
                    pgid = os.getpgid(OPENVPN_PROCESS.pid)
                    os.killpg(pgid, signal.SIGKILL)
                    OPENVPN_PROCESS.wait()
                    OPENVPN_PROCESS = None
                continue

        except Exception as e:
            log_print(f"OpenVPN连接线程：连接过程中出现错误：{e}")
            if OPENVPN_PROCESS:
                # 确保在异常情况下也清理进程
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
    """执行ping命令并计算平均延迟（毫秒）。"""
    try:
        log_print(f"OpenVPN连接线程：正在ping {host} 获取平均延迟...")
        command = ['ping', '-c', str(count), '-w', str(count + 5), host]
        
        # 捕获输出
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=15)
        
        # 查找统计信息行 (e.g., round-trip min/avg/max = 698.240/1034.360/1548.972 ms)
        match = re.search(r'round-trip min/avg/max = [\d.]+/([\d.]+)/[\d.]+ ms', result.stdout)
    
        if match:
            avg_latency = float(match.group(1))  # 提取第二个数字（avg 延迟）
            log_print(f"OpenVPN连接线程：平均网络延迟为 {avg_latency:.2f} ms。")
            return avg_latency
        else:
            log_print("OpenVPN连接线程：ping结果中未找到平均延迟数据。")
            return None

    except subprocess.CalledProcessError as e:
        log_print(f"OpenVPN连接线程：ping命令执行失败，错误：{e.stderr.strip()}")
        return None
    except Exception as e:
        log_print(f"OpenVPN连接线程：ping测试时发生未知错误：{e}")
        return None

# --- 线程循环 ---

def load_config():
    """从配置文件加载配置，如果文件不存在则创建默认文件。"""
    global LAST_CONFIG_MOD_TIME
    config_parser = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config_parser.read(CONFIG_FILE)
        log_print("已成功加载 vpngate.cfg 配置文件。")
    else:
        config_parser['general'] = {k: str(v) for k, v in config['general'].items()}
        config_parser['vpngate'] = config['vpngate']
        config_parser['local_proxies'] = config['local_proxies'] 
        with open(CONFIG_FILE, 'w') as f:
            config_parser.write(f)
        log_print(f"配置文件 {CONFIG_FILE} 不存在，已创建默认文件。")

    for section in config_parser.sections():
        for key, value in config_parser.items(section):
            config[section][key] = value

    config['vpngate']['country_codes'] = [code.strip() for code in config['vpngate']['country_codes'].split(',')]
    filter_patterns = [keyword.strip() for keyword in config['vpngate']['hostname_filter_keywords'].split(',') if keyword.strip()]
    config['vpngate']['hostname_filter_patterns'] = [re.compile(pattern, re.IGNORECASE) for pattern in filter_patterns]
    
    local_proxies_str = config['local_proxies'].get('proxies', '')
    config['local_proxies']['proxies'] = [p.strip() for p in local_proxies_str.split(',') if p.strip()]

    try:
        config['general']['proxy_retry_count'] = int(config['general']['proxy_retry_count'])
        config['general']['proxy_retry_delay_seconds'] = int(config['general']['proxy_retry_delay_seconds'])
    except (ValueError, KeyError) as e:
        log_print(f"警告：配置文件中代理重试参数格式错误，将使用默认值。错误：{e}")
        config['general']['proxy_retry_count'] = 3
        config['general']['proxy_retry_delay_seconds'] = 1

def main_thread_loop():
    """主线程循环，定期检测网络。"""
    while True:
        if not check_network():
            log_print("主线程：网络异常，正在调用OpenVPN连接线程...")
            vpn_thread = threading.Thread(target=connect_openvpn)
            vpn_thread.start()
            vpn_thread.join()
            
        time.sleep(int(config['general']['network_check_interval_seconds']))

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
    """新线程：每分钟检查配置文件变动，并触发相关更新。"""
    global LAST_CONFIG_MOD_TIME, LAST_PROXY_MOD_TIME

    # 初始化文件修改时间
    try:
        if os.path.exists(CONFIG_FILE):
            LAST_CONFIG_MOD_TIME = os.path.getmtime(CONFIG_FILE)
        if os.path.exists(PROXY_FILE):
            LAST_PROXY_MOD_TIME = os.path.getmtime(PROXY_FILE)
    except FileNotFoundError:
        pass # 如果文件不存在，则忽略

    while True:
        time.sleep(config(['general']['config_check_interval_seconds'])) # 每config_check_interval_seconds秒检查一次
        log_print("配置监控线程：正在检查配置文件变动...")
        
        # 检查 vpngate.cfg
        try:
            current_config_mod_time = os.path.getmtime(CONFIG_FILE)
            if current_config_mod_time > LAST_CONFIG_MOD_TIME:
                log_print("配置监控线程：检测到 vpngate.cfg 文件有变动，正在重新加载配置和VPN列表。")
                load_config()
                fetch_vpngate_list()
                LAST_CONFIG_MOD_TIME = current_config_mod_time
        except FileNotFoundError:
            log_print("配置监控线程：vpngate.cfg 文件不存在，跳过检查。")

        # 检查 proxy.txt
        try:
            current_proxy_mod_time = os.path.getmtime(PROXY_FILE)
            if current_proxy_mod_time > LAST_PROXY_MOD_TIME:
                log_print("配置监控线程：检测到 proxy.txt 文件有变动，正在重新验证代理。")
                validate_proxies()
                LAST_PROXY_MOD_TIME = current_proxy_mod_time
        except FileNotFoundError:
            log_print("配置监控线程：proxy.txt 文件不存在，跳过检查。")


# --- 主程序入口 ---
if __name__ == '__main__':
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
            os.killpg(os.getpgid(OPENVPN_PROCESS.pid), signal.SIGTERM)
            OPENVPN_PROCESS = None
