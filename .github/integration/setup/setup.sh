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

# start the ceph container
# shellcheck source=/dev/null
source "$(pwd)/create_ceph_config.sh"

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
until docker ps -f name="ceph_proxy" --format "{{.Status}}" | grep "Up"; do
    echo "waiting for ceph proxy to become ready"
    RETRY_TIMES=$((RETRY_TIMES + 1))
    if [ "$RETRY_TIMES" -eq 30 ]; then
        # Time out
        docker logs "ceph_proxy"
        exit 1
    fi
    sleep 10
done

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
until docker ps -f name="proxy" --format "{{.Status}}" | grep "Up "
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

# Populate database with for testing the download service
# Insert entry in sda.files
file_ids=$(docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.files (stable_id, submission_user, \
        submission_file_path, submission_file_size, archive_file_path, \
        archive_file_size, decrypted_file_size, backup_path, header, \
        encryption_method) VALUES ('urn:neic:001-001', 'integration-test', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder/dummy_data.c4gh', \
        1048729, '4293c9a7-dc50-46db-b79a-27ddc0dad1c6', 1049081, 1048605, \
        '', '637279707434676801000000010000006c000000000000006af1407abc74656b8913a7d323c4bfd30bf7c8ca359f74ae35357acef29dc5073799e207ec5d022b2601340585ff082565e55fbff5b6cdbbbe6b12a0d0a19ef325a219f8b62344325e22c8d26a8e82e45f053f4dcee10c0ec4bb9e466d5253f139dcd4be', 'CRYPT4GH'),
        ('urn:neic:001-002', 'integration-test', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder2/dummy_data2.c4gh', \
        1048729, 'f2e8b1d3-7a5c-4e0d-9c9a-8b4e3d7a5c4e', 1049081, 1048605, \
        '', '637279707434676801000000010000006c000000000000006af1407abc74656b8913a7d323c4bfd30bf7c8ca359f74ae35357acef29dc5073799e207ec5d022b2601340585ff082565e55fbff5b6cdbbbe6b12a0d0a19ef325a219f8b62344325e22c8d26a8e82e45f053f4dcee10c0ec4bb9e466d5253f139dcd4be', 'CRYPT4GH'),
        ('urn:neic:001-003', 'integration-test', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder2/random/dummy_data3.c4gh', \
        1048729, 'd9ab71e9-3884-429a-a6b7-bd63eeafe4a9', 1049081, 1048605, \
        '', '637279707434676801000000010000006c000000000000006af1407abc74656b8913a7d323c4bfd30bf7c8ca359f74ae35357acef29dc5073799e207ec5d022b2601340585ff082565e55fbff5b6cdbbbe6b12a0d0a19ef325a219f8b62344325e22c8d26a8e82e45f053f4dcee10c0ec4bb9e466d5253f139dcd4be', 'CRYPT4GH') RETURNING id;" | xargs)

if [ -z "$file_ids" ]; then
    echo "Failed to insert file entry into database"
    exit 1
fi

# Insert dataset in sda.datasets
dataset_id=$(docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.datasets (stable_id) VALUES ('https://doi.example/ty009.sfrrss/600.45asasga') \
        ON CONFLICT (stable_id) DO UPDATE \
        SET stable_id=excluded.stable_id RETURNING id;")

if [ -z "$dataset_id" ]; then
    echo "Failed to insert dataset entry into database"
    exit 1
fi


for file_id in $file_ids; do
    # Insert entry in sda.file_event_log
    docker run --rm --name client --network testing_default \
        neicnordic/pg-client:latest \
        postgresql://postgres:rootpasswd@postgres:5432/sda \
        -t -q -c "INSERT INTO sda.file_event_log (file_id, event) \
            VALUES ('$file_id', 'ready');"

    # Insert entries in sda.checksums
    docker run --rm --name client --network testing_default \
        neicnordic/pg-client:latest \
        postgresql://postgres:rootpasswd@postgres:5432/sda \
        -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
            VALUES ('$file_id', '06bb0a514b26497b4b41b30c547ad51d059d57fb7523eb3763cfc82fdb4d8fb7', 'SHA256', 'UNENCRYPTED');"

    docker run --rm --name client --network testing_default \
        neicnordic/pg-client:latest \
        postgresql://postgres:rootpasswd@postgres:5432/sda \
        -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
            VALUES ('$file_id', '5e9c767958cc3f6e8d16512b8b8dcab855ad1e04e05798b86f50ef600e137578', 'SHA256', 'UPLOADED');"

    docker run --rm --name client --network testing_default \
        neicnordic/pg-client:latest \
        postgresql://postgres:rootpasswd@postgres:5432/sda \
        -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
            VALUES ('$file_id', '74820dbcf9d30f8ccd1ea59c17d5ec8a714aabc065ae04e46ad82fcf300a731e', 'SHA256', 'ARCHIVED');"

    # Add file to dataset
    docker run --rm --name client --network testing_default \
        neicnordic/pg-client:latest \
        postgresql://postgres:rootpasswd@postgres:5432/sda \
        -t -q -c "INSERT INTO sda.file_dataset (file_id, dataset_id) \
            VALUES ('$file_id', $dataset_id);"
done

# Add file to archive
s3cmd -c directS3 put --recursive archive_data/ s3://archive/

# Get the correct token form mockoidc
token=$(curl "http://localhost:8002/tokens" | jq -r  '.[0]')

# Create s3cmd-download.conf file for download
cp s3cmd-template.conf s3cmd-download.conf
echo "access_token=$token" >> s3cmd-download.conf

docker ps
