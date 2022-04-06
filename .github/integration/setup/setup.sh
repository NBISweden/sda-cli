#!/bin/bash

pip3 install s3cmd

openssl genrsa -out dummy.ega.nbis.se.pem 4096
openssl rsa -in dummy.ega.nbis.se.pem -pubout -out dummy.ega.nbis.se.pub

output=$(bash testing/sign_jwt.sh RS256 dummy.ega.nbis.se.pem)
echo "access_token=$output" >> testing/s3cmd.conf

git clone https://github.com/neicnordic/sda-s3proxy.git  || exit 1
cp testing/* sda-s3proxy/dev_utils/  || exit 1
cp dummy.ega.nbis.se.pub sda-s3proxy/dev_utils/keys  || exit 1

cd sda-s3proxy/dev_utils || exit 1

docker-compose up -d
RETRY_TIMES=0
until docker ps -f name="s3" --format "{{.Status}}" | grep "Up"
do echo "waiting for s3 to become ready"
    RETRY_TIMES=$((RETRY_TIMES+1));
    if [ "$RETRY_TIMES" -eq 30 ]; then
        # Time out
        docker logs "s3"
        exit 1;
    fi
    sleep 10
done

