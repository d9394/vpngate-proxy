aa=$(docker ps -a | grep vpngate-proxy | awk '{print $1}')
if [ "$aa" != "" ]; then
	docker rm $aa
fi
docker run -t -d \
    --name vpngate \
    --memory="512m" \
    --cap-add=NET_ADMIN \
    --device=/dev/net/tun:/dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    -p 1194:1194 \
    -p 3128:3128 \
    -p 8888:8888 \
    -v "$(pwd)/app/:/app/" \
    vpngate-proxy
