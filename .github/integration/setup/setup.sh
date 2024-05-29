#!/bin/bash

cd testing || exit 1

pip3 install --upgrade pip > /dev/null
pip3 install aiohttp Authlib joserfc requests > /dev/null
pip3 install s3cmd

mkdir -p keys

# create EC256 key for signing the JWT tokens
if [ ! -f "dummy.ega.nbis.se.pem" ]; then
    echo "creating jwt key"
    openssl ecparam -genkey -name prime256v1 -noout -out dummy.ega.nbis.se.pem
    openssl ec -in dummy.ega.nbis.se.pem -outform PEM -pubout >keys/dummy.ega.nbis.se.pub
    chmod 644 keys/dummy.ega.nbis.se.pub dummy.ega.nbis.se.pem
fi

cp s3cmd-template.conf s3cmd.conf
output=$(python sign_jwt.py)
echo "access_token=$output" >> s3cmd.conf

# Create crypt4gh keys for testing the download service
cat << EOF > c4gh.pub.pem
-----BEGIN CRYPT4GH PUBLIC KEY-----
avFAerx0ZWuJE6fTI8S/0wv3yMo1n3SuNTV6zvKdxQc=
-----END CRYPT4GH PUBLIC KEY-----
EOF

chmod 444 c4gh.pub.pem

cat << EOF > c4gh.sec.pem
-----BEGIN CRYPT4GH ENCRYPTED PRIVATE KEY-----
YzRnaC12MQAGc2NyeXB0ABQAAAAAwAs5mVkXda50vqeYv6tbkQARY2hhY2hhMjBf
cG9seTEzMDUAPAd46aTuoVWAe+fMGl3VocCKCCWmgFUsFIHejJoWxNwy62c1L/Vc
R9haQsAPfJMLJSvUXStJ04cyZnDHSw==
-----END CRYPT4GH ENCRYPTED PRIVATE KEY-----
EOF

chmod 444 c4gh.sec.pem

# get latest image tag for s3inbox
latest_tag=$(curl -s https://api.github.com/repos/neicnordic/sensitive-data-archive/tags | jq -r '.[0].name')

# check which compose syntax to use (useful for running locally)
if command -v docker-compose >/dev/null 2>&1
then
    TAG=$latest_tag docker-compose up -d
else
    TAG=$latest_tag docker compose up -d
fi

RETRY_TIMES=0
until docker ps -f name="s3" --format "{{.Status}}" | grep "healthy"
do echo "waiting for s3 to become ready"
    RETRY_TIMES=$((RETRY_TIMES+1));
    if [ "$RETRY_TIMES" -eq 30 ]; then
        # Time out
        docker logs "s3"
        exit 1;
    fi
    sleep 10
done

RETRY_TIMES=0
until docker ps -f name="proxy" --format "{{.Status}}" | grep "Up About"
do echo "waiting for proxy to become ready"
    RETRY_TIMES=$((RETRY_TIMES+1));
    if [ "$RETRY_TIMES" -eq 30 ]; then
        # Time out
        docker logs "proxy"
        exit 1;
    fi
    sleep 10
done

RETRY_TIMES=0
until docker logs buckets | grep "Access permission for"
do echo "waiting for buckets to be created"
    RETRY_TIMES=$((RETRY_TIMES+1));
    if [ "$RETRY_TIMES" -eq 30 ]; then
        # Time out
        docker logs "buckets"
        exit 1;
    fi
    sleep 10
done

docker ps
