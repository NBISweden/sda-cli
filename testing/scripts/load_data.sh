#!/bin/sh
set -e

apk -q --no-cache add curl jq

pip -q install s3cmd

FILES="htsnexus_test_NA12878.bam htsnexus_test_NA12878.bam.bai htsnexus_test_NA12878.bam.blocks.yaml htsnexus_test_NA12878.bam.gzi"
for file in ${FILES}; do
    curl -s -L -o "$file" "https://github.com/umccr/htsget-rs/raw/main/data/bam/$file"


    yes | /shared/crypt4gh encrypt -p /shared/c4gh.pub.pem -f "$file"
    ENC_SHA=$(sha256sum "$file.c4gh" | cut -d' ' -f 1)
    ENC_MD5=$(md5sum "$file.c4gh" | cut -d' ' -f 1)
    s3cmd -q -c /shared/s3cfg put "$file.c4gh" s3://dummy_gdi.eu/"$file.c4gh"

    ## get correlation id from upload message
    CORRID=$(
        curl -s -X POST \
            -H "content-type:application/json" \
            -u test:test http://rabbitmq:15672/api/queues/sda/inbox/get \
            -d '{"count":1,"encoding":"auto","ackmode":"ack_requeue_false"}' | jq -r .[0].properties.correlation_id
    )

    ## publish message to trigger ingestion
    properties=$(
        jq -c -n \
            --argjson delivery_mode 2 \
            --arg correlation_id "$CORRID" \
            --arg content_encoding UTF-8 \
            --arg content_type application/json \
            '$ARGS.named'
    )

    encrypted_checksums=$(
        jq -c -n \
            --arg sha256 "$ENC_SHA" \
            --arg md5 "$ENC_MD5" \
            '$ARGS.named|to_entries|map(with_entries(select(.key=="key").key="type"))'
    )

    ingest_payload=$(
        jq -r -c -n \
            --arg type ingest \
            --arg user dummy@gdi.eu \
            --arg filepath dummy_gdi.eu/"$file.c4gh" \
            --argjson encrypted_checksums "$encrypted_checksums" \
            '$ARGS.named|@base64'
    )

    ingest_body=$(
        jq -c -n \
            --arg vhost test \
            --arg name sda \
            --argjson properties "$properties" \
            --arg routing_key "ingest" \
            --arg payload_encoding base64 \
            --arg payload "$ingest_payload" \
            '$ARGS.named'
    )

    curl -s -u test:test "http://rabbitmq:15672/api/exchanges/sda/sda/publish" \
        -H 'Content-Type: application/json;charset=UTF-8' \
        -d "$ingest_body"
done

### wait for ingestion to complete
echo "waiting for ingestion to complete"
RETRY_TIMES=0
until [ "$(curl -s -u test:test http://rabbitmq:15672/api/queues/sda/verified | jq -r '."messages_ready"')" -eq 4 ]; do
    echo "waiting for ingestion to complete"
    RETRY_TIMES=$((RETRY_TIMES + 1))
    if [ "$RETRY_TIMES" -eq 40 ]; then
        echo "::error::Time out while waiting for ingestion to complete"
        exit 1
    fi
    sleep 2
done

I=0
for file in ${FILES}; do
    case $file in (*.bai)
        file="$(basename "$file" .bai).bam.bai"
     ;;
    esac
    I=$((I+1))
    ## get correlation id from upload message
    MSG=$(
        curl -s -X POST \
            -H "content-type:application/json" \
            -u test:test http://rabbitmq:15672/api/queues/sda/verified/get \
            -d '{"count":1,"encoding":"auto","ackmode":"ack_requeue_false"}' | jq -r '.[0]'
    )

    ## publish message to trigger ingestion
    properties=$(
        jq -c -n \
            --argjson delivery_mode 2 \
            --arg correlation_id "$(echo "$MSG" | jq -r '.properties.correlation_id')" \
            --arg content_encoding UTF-8 \
            --arg content_type application/json \
            '$ARGS.named'
    )

    finalize_payload=$(
        jq -r -c -n \
            --arg type accession \
            --arg user dummy@gdi.eu \
            --arg filepath dummy_gdi.eu/"$file.c4gh" \
            --arg accession_id "FILE000000$I" \
            --argjson decrypted_checksums "$(echo "$MSG"| jq -r '.payload|fromjson|.decrypted_checksums|tostring')" \
            '$ARGS.named|@base64'
    )

    finalize_body=$(
        jq -c -n \
            --arg vhost test \
            --arg name sda \
            --argjson properties "$properties" \
            --arg routing_key "accession" \
            --arg payload_encoding base64 \
            --arg payload "$finalize_payload" \
            '$ARGS.named'
    )

    curl -s -u test:test "http://rabbitmq:15672/api/exchanges/sda/sda/publish" \
        -H 'Content-Type: application/json;charset=UTF-8' \
        -d "$finalize_body"
done

### wait for ingestion to complete
echo "waiting for finalize to complete"
RETRY_TIMES=0
until [ "$(curl -s -u test:test http://rabbitmq:15672/api/queues/sda/completed | jq -r '."messages_ready"')" -eq 4 ]; do
    echo "waiting for finalize to complete"
    RETRY_TIMES=$((RETRY_TIMES + 1))
    if [ "$RETRY_TIMES" -eq 30 ]; then
        echo "::error::Time out while waiting for finalize to complete"
        exit 1
    fi
    sleep 2
done

### Assign file to dataset
properties=$(
    jq -c -n \
        --argjson delivery_mode 2 \
        --arg content_encoding UTF-8 \
        --arg content_type application/json \
        '$ARGS.named'
)

mappings=$(
    jq -c -n \
        '$ARGS.positional' \
        --args "FILE0000001" \
        --args "FILE0000002" \
        --args "FILE0000003" \
        --args "FILE0000004"
)

mapping_payload=$(
    jq -r -c -n \
        --arg type mapping \
        --arg dataset_id DATASET0001 \
        --argjson accession_ids "$mappings" \
        '$ARGS.named|@base64'
)

mapping_body=$(
    jq -c -n \
        --arg vhost test \
        --arg name sda \
        --argjson properties "$properties" \
        --arg routing_key "mappings" \
        --arg payload_encoding base64 \
        --arg payload "$mapping_payload" \
        '$ARGS.named'
)

curl -s -u test:test "http://rabbitmq:15672/api/exchanges/sda/sda/publish" \
    -H 'Content-Type: application/json;charset=UTF-8' \
    -d "$mapping_body"
