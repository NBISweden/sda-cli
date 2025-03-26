#!/bin/bash

YQ_VERSION="v4.45.1"

if [ "$(basename "$(pwd)")" != "testing" ]; then
    cd testing || exit 1
fi

if [ "$(id -u)" != 0 ]; then
    if [ ! "$(command yq --version)" ]; then
        echo "yq not installed, get it from here: https://github.com/mikefarah/yq/releases/latest"
        exit 1
    fi
fi

if [ "$(id -u)" == 0 ] && [ ! "$(command yq --version)" ]; then
    curl --retry 100 -sL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" -o /usr/bin/yq &&
                sudo chmod +x /usr/bin/yq
fi

# Ceph needs to be started beforehand in order to get the credentials
if command -v docker-compose >/dev/null 2>&1; then
    TAG="" docker-compose up -d ceph
else
    TAG="" docker compose up -d ceph
fi

RETRY_TIMES=0
until docker ps -f name="ceph-octopus" --format "{{.Status}}" | grep -w "healthy"; do
    echo "waiting for ceph container to become ready"
    RETRY_TIMES=$((RETRY_TIMES + 1))
    if [ "$RETRY_TIMES" -eq 30 ]; then
        # Time out
        docker logs "ceph-octopus"
        exit 1
    fi
    sleep 10
done

# Get the ceph credentials
CEPH_ACCESS=$(docker exec ceph-octopus cat /nano_user_details | jq -r '.keys[0].access_key')
export CEPH_ACCESS
CEPH_SECRET=$(docker exec ceph-octopus cat /nano_user_details | jq -r '.keys[0].secret_key')
export CEPH_SECRET

yq --lua-unquoted -i '.inbox.accessKey = env(CEPH_ACCESS) | .inbox.secretKey = env(CEPH_SECRET)' ceph_proxy_config.yaml
