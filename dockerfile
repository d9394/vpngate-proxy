# 直接使用 Alpine Edge 作为基础镜像
FROM alpine:edge

# 设置环境变量，防止交互式安装
ENV PYTHONUNBUFFERED=1

# 更新系统并安装所有必要的软件包：
# openvpn, python3, py3-pip, bash: 运行时依赖
# 3proxy: 从 edge/testing 仓库获取
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk update && \
    apk add --no-cache iptables iptables-legacy openvpn python3 bash 3proxy traceroute tcpdump py3-requests py3-pysocks fping && \
    rm -rf /var/cache/apk/*

# 将工作目录设置为 /app
WORKDIR /app

# 暴露 OpenVPN 和 3proxy 端口
EXPOSE 1194
EXPOSE 3128
EXPOSE 8888

# 默认命令：运行 start.sh 脚本
CMD ["/bin/bash", "-c", "/app/start.sh > /app/run.log 2>&1"]
