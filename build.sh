#!/bin/bash
aa=$(docker ps -a | grep vpngate-proxy | awk '{print $1}')
if [ "$aa" != "" ]; then
	docker rm $aa
fi
docker build -t vpngate-proxy -f ./dockerfile .
