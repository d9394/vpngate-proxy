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
VPN_LIST_LOCK = threading.Lock()
PROXY_LIST_LOCK = threading.Lock()
OPENVPN_PROCESS = None
CURRENT_PROXY = None
DEFAULT_GW = None

# --- 配置文件与参数 ---
CONFIG_FILE = 'vpngate.cfg'
PROXY_FILE = 'proxy.txt'

# 默认配置
config = {
    'general': {
        'vpngate_update_interval_seconds': 3600,
        'proxy_update_interval_seconds': 3600,
        'network_check_interval_seconds': 300,
        'proxy_test_url': 'https://www.google.com',
        'ping_check_ip': '8.8.8.8'
    },
    'vpngate': {
        'country_codes': 'JP,HK'
    }
}

def load_config():
    """从配置文件加载配置，如果文件不存在则创建默认文件。"""
    config_parser = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config_parser.read(CONFIG_FILE)
        log_print("已成功加载 vpngate.cfg 配置文件。")
    else:
        config_parser['general'] = config['general']
        config_parser['vpngate'] = config['vpngate']
        with open(CONFIG_FILE, 'w') as f:
            config_parser.write(f)
        log_print(f"配置文件 {CONFIG_FILE} 不存在，已创建默认文件。")

    for section in config_parser.sections():
        for key, value in config_parser.items(section):
            config[section][key] = value

    config['vpngate']['country_codes'] = [code.strip() for code in config['vpngate']['country_codes'].split(',')]

def log_print(message):
    """带时间戳地打印信息。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

# --- 网络与代理 ---

def get_current_proxy():
    """从代理列表中获取当前可用的代理字典。"""
    global CURRENT_PROXY
    with PROXY_LIST_LOCK:
        if PROXY_LIST:
            CURRENT_PROXY = PROXY_LIST[0]
            return PROXY_LIST[0]
    
    CURRENT_PROXY = None
    return None

def validate_proxies():
    """
    验证代理列表中的每个代理，生成有效的代理字典列表。
    """
    global PROXY_LIST
    validated_list = []
    with PROXY_LIST_LOCK:
        raw_proxy_list = []
        if os.path.exists(PROXY_FILE):
            with open(PROXY_FILE, 'r') as f:
                raw_proxy_list = [line.strip() for line in f.readlines() if line.strip()]
        
        if not raw_proxy_list:
            log_print("代理验证线程：代理文件为空或未找到，跳过验证。")
            PROXY_LIST = []
            return
        
        log_print(f"代理验证线程：开始验证 {len(raw_proxy_list)} 个代理。")
        for proxy_line in raw_proxy_list:
            proxies = {}
            if proxy_line.startswith('socks://'):
                proxy_url = proxy_line.replace('socks://', 'socks5h://')
                proxies = {'http': proxy_url, 'https': proxy_url}
            elif proxy_line.startswith('http://'):
                proxies = {'http': proxy_line, 'https': proxy_line}

            try:
                response = requests.get(config['general']['proxy_test_url'], proxies=proxies, timeout=10)
                if response.status_code == 200:
                    validated_list.append(proxies)
                    log_print(f"代理验证线程：代理 {proxy_line} 验证成功。")
                else:
                    log_print(f"代理验证线程：代理 {proxy_line} 验证失败，状态码：{response.status_code}。")
            except Exception as e:
                log_print(f"代理验证线程：代理 {proxy_line} 验证失败，错误：{e}。")

        PROXY_LIST = validated_list
        log_print(f"代理验证线程：验证完成，共有 {len(PROXY_LIST)} 个有效代理。")

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
    url = 'http://www.vpngate.net/api/iphone/'
    try:
        proxies = get_current_proxy()
        log_print("获取VPN列表线程：正在获取VPN Gate列表...")
        response = requests.get(url, proxies=proxies, timeout=30)
        
        if response.status_code != 200 or not response.text:
            log_print("获取VPN列表线程：获取列表失败。")
            return
            
        lines = response.text.split('\n')
        
        filtered_list = []
        country_codes = config['vpngate']['country_codes']
        for line in lines[2:-1]:
            parts = line.split(',')
            if len(parts) >= 8:
                country_code = parts[6]
                if country_code in country_codes:
                    filtered_list.append(parts)

        filtered_list.sort(key=lambda x: int(x[7]), reverse=True)
        
        with VPN_LIST_LOCK:
            VPN_GATE_LIST = filtered_list
        log_print(f"获取VPN列表线程：已成功获取并更新VPN列表，共有{len(VPN_GATE_LIST)}条记录。")

    except Exception as e:
        log_print(f"获取VPN列表线程：获取列表失败，错误：{e}")

# --- OpenVPN 连接逻辑 ---

def create_ovpn_file(vpn_info):
    """根据VPN列表记录生成.ovpn配置文件。"""
    try:
        base64_config = vpn_info[14]
        decoded_config = base64.b64decode(base64_config).decode('utf-8')
        
        ovpn_filename = 'temp_config.ovpn'
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
        log_print(f"OpenVPN连接线程：尝试连接第 {i+1} 条记录 ({vpn_info[0]})")
        ovpn_file = create_ovpn_file(vpn_info)
        
        if not ovpn_file:
            continue
            
        try:
            if OPENVPN_PROCESS:
                log_print("OpenVPN连接线程：正在终止旧的OpenVPN进程...")
                os.killpg(os.getpgid(OPENVPN_PROCESS.pid), signal.SIGTERM)
                OPENVPN_PROCESS.wait(timeout=10)
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
                OPENVPN_PROCESS.terminate()
                OPENVPN_PROCESS = None
                continue
            else:
                log_print("OpenVPN连接线程：tun0 接口已就绪。")

            if check_network():
                log_print(f"OpenVPN连接线程：连接成功，VPN [{vpn_info[0]}] 正常工作。")
                return
            else:
                log_print(f"OpenVPN连接线程：VPN [{vpn_info[0]}] 连接后网络异常，尝试下一条。")
                OPENVPN_PROCESS.terminate()
                OPENVPN_PROCESS = None

        except Exception as e:
            log_print(f"OpenVPN连接线程：连接过程中出现错误：{e}")
            if OPENVPN_PROCESS:
                OPENVPN_PROCESS.terminate()
                OPENVPN_PROCESS = None
        finally:
            if os.path.exists(ovpn_file):
                os.remove(ovpn_file)

    log_print("OpenVPN连接线程：所有VPN记录都连接失败。")

# --- 线程循环 ---

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
        load_config()
        fetch_vpngate_list()
        
def proxy_list_thread_loop():
    """代理列表线程循环，定期更新并验证代理。"""
    while True:
        time.sleep(int(config['general']['proxy_update_interval_seconds']))
        load_config()
        validate_proxies()
        
# --- 主程序入口 ---
if __name__ == '__main__':
    load_config()
    validate_proxies()
    
    if not PROXY_LIST:
        log_print("程序启动：未找到有效代理，程序退出。请检查 proxy.txt 文件。")
        exit(1)
    
    log_print("程序启动，正在初始化线程...")
    
    fetch_vpngate_list()
    
    vpn_list_thread = threading.Thread(target=vpn_list_thread_loop)
    vpn_list_thread.daemon = True
    vpn_list_thread.start()
    
    proxy_list_thread = threading.Thread(target=proxy_list_thread_loop)
    proxy_list_thread.daemon = True
    proxy_list_thread.start()
    
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
