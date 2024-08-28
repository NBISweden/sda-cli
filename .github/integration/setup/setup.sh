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
        2597919, '1068a0b9-51c9-4bda-8fcf-14b3b884f7a4', 2597919, 2596799, \
        '', '637279707434676801000000010000006c000000000000001b8aba36a673d374614406259c60b5c658492e05a771240f0ca5a407836bfc630ff275d8ae5e213a5853127611126e2fc79b4a16e8bbb95f3d9503902ac9ce59d0d58a15e9b8b364cb7d9c17ad1d863c89cd097667a1cc17b215095779886635bdd0ea70', 'CRYPT4GH'),
        ('FILE0000002', 'integration-test', 'dummy_gdi.eu/htsnexus_test_NA12878.bam.bai.c4gh', \
        6756, '668330fb-bdd8-40b2-a88f-29e1e610fa4b', 6756, 6728, \
        '', '637279707434676801000000010000006c00000000000000856951a851a8dd081cd3f17e8212c40caea530327704aaccfb852aaabf7c947ea9b541c32358151979451259b78bbaf5e824cf76d1758ec3a34bd845a2af389639be6adf46c77910861ca1236ed1f0d46a0e91dc31ebae28f5f75776d284d75ce2c0d444', 'CRYPT4GH'),
        ('FILE0000003', 'integration-test', 'dummy_gdi.eu/htsnexus_test_NA12878.bam.blocks.yaml.c4gh', \
        2061, 'ce796074-21d8-43ef-9b5e-848ce8b6e47b', 2061, 2033, \
        '', '637279707434676801000000010000006c00000000000000d0a084f92c6ddd1193320d00e94be34d1e31d10654eae55d67fe53b165812c194a1eb18c09881adaf49a567281fceab23495ae925de7ea2027288dd1faa601e1303f87cb31968d12211825f0fa1fd6628ac33e3b629567e38ed9fe27cfefaa344b5bb523', 'CRYPT4GH'),
        ('FILE0000004', 'integration-test', 'dummy_gdi.eu/htsnexus_test_NA12878.bam.gzi.c4gh', \
        2644, '2c063d42-f57f-4e74-bb1c-f56af00825b7', 2644, 2616, \
        '', '637279707434676801000000010000006c000000000000000818521c25f759f337e0560977cd36f29edd073ac05bc6efc0def114aa81c625c485461fae5c12c8967107b0edf8fd697bb00fa103592b0f4e161541fcbabb39e1c7cfc3ee84ebaa4085ecf802ae5e010ffafcc139a3dd5ed818c13192d44548718e9437', 'CRYPT4GH') RETURNING id;" | xargs)

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
        VALUES ('$hts_file_id1', 'e0ab4f1c82bcac6fa13040f4778a6642ba21dcf7c321bdacbe02c78dbdf8e2fb', 'SHA256', 'UPLOADED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id1', 'a615ce3e5c8a59c646deb5b01cf088182a5102a02c1ce88b71d2461cfb621360', 'SHA256', 'ARCHIVED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id1', '0424dfcc1255ff5f48ae39f9bf0129d1d01cb75fa6cf8d141670101860182060', 'SHA256', 'UNENCRYPTED');"

docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id2', '0ea62b6fce887a61ecb03c2ebdadd96d398b3fd76e9e639064c19561ceb3c155', 'SHA256', 'UPLOADED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id2', '136f509276413663780928f97f2c6dbf6fff0c290420a3144fb5af36b19d8d58', 'SHA256', 'ARCHIVED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id2', '1da16bd728559f3089b87e563d3ca87e673b878cbbededbb9a33af81f386d530', 'SHA256', 'UNENCRYPTED');"

docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id3', '77bfc5dfcbd3bad740a6337df39537a9a9687cf087aa409a059c380a7476380d', 'SHA256', 'UPLOADED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id3', '5fcf7fbf9c9640e96e35fcc9feeb8d74399df02861e9368dce2d8229435df37e', 'SHA256', 'ARCHIVED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id3', 'a4f22564184871ad9a75a5dd5e3c2ffbe7c9b48f0392bbd0c151aca95964b6cf', 'SHA256', 'UNENCRYPTED');"

docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id4', 'f11a60bc3945676727af36e8f05ebede895db777addf69c8c7cabad7c5a681c7', 'SHA256', 'UPLOADED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id4', '399602f732d35374033acc5dd51b5c2b658c491eabafa826f3f4b601fbf71067', 'SHA256', 'ARCHIVED');"
docker run --rm --name client --network testing_default \
    neicnordic/pg-client:latest \
    postgresql://postgres:rootpasswd@postgres:5432/sda \
    -t -q -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$hts_file_id4', '55cc7a5adbc85096abefb83d99f784fd68adb8e2c83aa1a71c6b705bb95bf48c', 'SHA256', 'UNENCRYPTED');"

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
