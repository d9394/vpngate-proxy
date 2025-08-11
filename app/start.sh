#!/bin/bash

# --- 修改 DNS 配置 ---
echo "nameserver 4.2.2.2" > /etc/resolv.conf
echo "nameserver 208.67.222.222" >> /etc/resolv.conf

# 检查 iptables-save 配置文件是否存在，如果存在则加载
if [ -f "/app/iptables-save" ]; then
    echo "发现 iptables-save，正在加载规则..."
    /bin/sh -c "/app/iptables-save"
else
    echo "未发现 /app/iptables-save，跳过 iptables 加载。"
fi

# 检查 openvpn-server.conf 配置文件是否存在，如果存在则启动 OpenVPN 服务器
if [ -f "/app/openvpn-server.conf" ]; then
    echo "发现 openvpn-server.conf，正在启动 OpenVPN 服务器..."
    openvpn --config /app/openvpn-server.conf &
else
    echo "未发现 /app/openvpn-server.conf，跳过 OpenVPN 服务器启动。"
fi

# 检查 3proxy.cfg 配置文件是否存在，如果存在则启动 3proxy
if [ -f "/app/3proxy.cfg" ]; then
    echo "发现 3proxy.cfg，正在启动 3proxy..."
    3proxy /app/3proxy.cfg &
else
    echo "未发现 /app/3proxy.cfg，跳过 3proxy 启动。"
fi

# 获取默认网关
DEFAULT_GW=$(ip route show default | awk '/default/ {print $3}')
if [ -z "$DEFAULT_GW" ]; then
  echo "无法获取默认网关，跳过路由配置。"
  exit 1
else
  # 删除默认路由
  ip route del default
  echo "已删除默认路由。"$DEFAULT_GW
  echo $DEFAULT_GW > /app/gateway.txt
  # 添加可用路由
  ip route add 192.168.1.1/32 via $DEFAULT_GW

  echo "路由已添加"
  ip route show
fi

if [ -n "$DEBUG" ]; then
  tail -f /dev/null
else
  # 启动 vpngate.py
  python3 -u /app/vpngate.py 2>&1 > /app/vpngate.log
fi
