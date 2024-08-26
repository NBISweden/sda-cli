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

# Insert entry in sda.files for htsget testing
hts_file_ids=$(docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.files (stable_id, submission_user, \
        submission_file_path, submission_file_size, archive_file_path, \
        archive_file_size, decrypted_file_size, backup_path, header, \
        encryption_method) VALUES ('FILE0000001', 'integration-test', 'dummy_gdi.eu/htsnexus_test_NA12878.bam.c4gh', \
        NULL, 'abb0305b-861b-4983-84c2-c4ad9ab5ebe8', 2597919, 2596799, \
        'NULL', '637279707434676801000000010000006c00000000000000ea3cb13f1decddb198de260f74e59d03a372fd2ae65509dea4c63f348a21a80ef1b9be145cd3943522a62bbc1992090f0c3a5ef6b4cd05c705333ca16f86818ab99e77e4695d0f45982c70f208cce240fb5e8928713d3aae5bc88206dcf795ce4fc2259a', 'CRYPT4GH'),
        ('FILE0000002', 'integration-test', 'dummy_gdi.eu/htsnexus_test_NA12878.bam.bai.c4gh', \
        NULL, '4d6c1787-3641-4aba-8e3f-11f35b514418', 6756, 6728, \
        'NULL', '637279707434676801000000010000006c000000000000002807585fbbafa584ef89bbd4140e41dc7afe35c6491787f9ea599704770d251ba8947577ade743f1f58539a6afb41022f2c38822befd16d20bc4e5b10fa582a8c676e6f27b9c804d4db0d225b64198bd5c69a2e2c87a79c3ef22d03b7a6a10771219ce85', 'CRYPT4GH'),
        ('FILE0000003', 'integration-test', 'dummy_gdi.eu/htsnexus_test_NA12878.bam.blocks.yaml.c4gh', \
        NULL, 'bd0cc83e-86c9-41b4-b110-0089018895f4', 2061, 2033, \
        'NULL', '637279707434676801000000010000006c00000000000000fe396aefdaeec924ec33ebb1a2de25613212cb8fe902939b28e5e11199885a11c1ba17cdcdbe13fc22fcc451a3010a6008e8f494d53fb8769d23c5ebb06f7ab75821121c634541d3366ae3325bf931e1206e66ce11091b279dd18cf5da5a50f8cf156896', 'CRYPT4GH'),
        ('FILE0000004', 'integration-test', 'dummy_gdi.eu/htsnexus_test_NA12878.bam.gzi.c4gh', \
        NULL, '45a73706-7427-4839-9a89-ddb2998b091f', 2644, 2616, \
        'NULL', '637279707434676801000000010000006c00000000000000c785c033c0ffb12575603cd3ff2e745e3f6552aed9959b942cdd572623dc8007c8437921c473ce5ebf50b050b714aa39b10e784d872adfd2fb27dc96744761feb14a212348664d7d14d459a8cab8ad8380830984a611393c506778656a4fc3e8d0daa0c7', 'CRYPT4GH') RETURNING id;" | xargs)

if [ -z "$hts_file_ids" ]; then
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

# Insert entries in sda.checksums for htsget testing
hts_file_id1=$(echo $hts_file_ids | cut -d' ' -f1)
hts_file_id2=$(echo $hts_file_ids | cut -d' ' -f2)
hts_file_id3=$(echo $hts_file_ids | cut -d' ' -f3)
hts_file_id4=$(echo $hts_file_ids | cut -d' ' -f4)

docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id1', '15d28f1f14764511402e8c0eaf68316a79d8d9e7a787594307ed339a2a411b98', 'SHA256', 'ARCHIVED');"

docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id2', 'bd0dc0bd81d7ef40ba57f8dcda80264b49e227da795dcde6588e6239c93f3af2', 'SHA256', 'ARCHIVED');"

docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id3', 'b6c85131c91dc96a726e4a3dc9608c5640799b316654dadd14f7e1fd78bfd220', 'SHA256', 'ARCHIVED');"

docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id4', 'cdedc99765fd3d77bf6f12a89d4afc276d16155a08bab4ea251acaaca4cad344', 'SHA256', 'ARCHIVED');"

for id in $hts_file_ids; do
    # Insert entry in sda.file_event_log
    docker run --rm --name client --network testing_default \
        neicnordic/pg-client:latest \
        postgresql://postgres:rootpasswd@postgres:5432/sda \
        -t -q -c "INSERT INTO sda.file_event_log (file_id, event) \
            VALUES ('$id', 'ready');"

    # Add file to dataset
    docker run --rm --name client --network testing_default \
        neicnordic/pg-client:latest \
        postgresql://postgres:rootpasswd@postgres:5432/sda \
        -t -q -c "INSERT INTO sda.file_dataset (file_id, dataset_id) \
            VALUES ('$id', $dataset_id);"
done

# Add files to archive
s3cmd -c directS3 put --recursive archive_data/ s3://archive/

# Get the correct token form mockoidc
token=$(curl "http://localhost:8002/tokens" | jq -r  '.[0]')

# Create s3cmd-download.conf file for download
cp s3cmd-template.conf s3cmd-download.conf
echo "access_token=$token" >> s3cmd-download.conf

docker ps
