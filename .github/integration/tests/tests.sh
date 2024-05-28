#!/bin/bash
set -e

# Function checking that a file was encrypted
function check_encypted_file() {

    for k in $1
    do
        output=$(head -c 8 "$k")

        if [[ "$output" = "crypt4gh"  ]]; then
            echo "Encrypted data file"
        else
            echo "Failed to encrypt file"
            exit 1
        fi
    done
}

# Function checking that a file was uploaded to the S3 backend
function check_uploaded_file() {
    output=$(s3cmd -c testing/directS3 ls s3://"$1" | grep -q "$2")
    if $output ; then
        echo "Uploaded encrypted file to s3 backend"
    else
        echo "Failed to upload file to s3 backend"
        exit 1
    fi
}

# inferred from access_key in testing/s3cmd.conf
user=test_dummy.org

# Create random file
dd if=/dev/urandom of=data_file count=1 bs=1M

# Create key pair
if ( echo "" | ./sda-cli createKey sda_key ) ; then
    echo "Created key pair for encryption"
else
    echo "Failed to create key pair for encryption"
    exit 1
fi

# Encrypt a file
./sda-cli encrypt -key sda_key.pub.pem data_file

files="data_file.c4gh"
check_encypted_file $files

# Upload a specific file and check it
./sda-cli upload -config testing/s3cmd.conf data_file.c4gh
check_uploaded_file "test/$user/data_file.c4gh" data_file.c4gh


if ./sda-cli list -config testing/s3cmd.conf | grep -q 'data_file.c4gh'
then
    echo "Listed file from s3 backend"
else
    echo "Failed to list file to s3 backend"
    exit 1
fi

# Try to upload a file twice with the --force-overwrite flag
output=$(./sda-cli upload -config testing/s3cmd.conf --force-overwrite data_file.c4gh)

# Create and encrypt multiple files in a folder

# Create folder and encrypt files in it
cp data_file data_file1
mkdir data_files_enc
./sda-cli encrypt -key sda_key.pub.pem -outdir data_files_enc data_file data_file1

check_encypted_file "data_files_enc/data_file.c4gh data_files_enc/data_file1.c4gh"

for k in data_file.c4gh data_file1.c4gh
do
    # Upload and check file
    ./sda-cli upload -config testing/s3cmd.conf --force-overwrite "data_files_enc/$k"
    check_uploaded_file "test/$user/$k" "$k"
done

# Test recursive folder upload

# Create folder with subfolder structure and add some encrypted files
mkdir data_files_enc/dir1 data_files_enc/dir1/dir2
cp data_files_enc/data_file.c4gh data_files_enc/data_file3.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file2.c4gh

# Upload a folder recursively and a single file
./sda-cli upload -config testing/s3cmd.conf -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the target path
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file "test/$user/$k" "$k"
done

# Test upload to a different path

# Upload a folder recursively and a single file in a specified upload folder
uploadDir="testfolder"
./sda-cli upload -config testing/s3cmd.conf -targetDir "$uploadDir" -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Do it again to test that we can pass -targetDir at the end
./sda-cli upload --force-overwrite -config testing/s3cmd.conf -r data_files_enc/dir1 data_files_enc/data_file3.c4gh -targetDir "$uploadDir"

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the
# target path and into the specified upload folder
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file "test/$user/$uploadDir/$k" "$k"
done

# Upload all contents of a folder recursively to a specified upload folder

uploadDir="testfolder2"
./sda-cli upload -config testing/s3cmd.conf -targetDir "$uploadDir" -r data_files_enc/dir1/.

# Check that files were uploaded with the local path prefix `data_files_enc/dir1` stripped from the
# target path and into the specified upload folder
for k in data_file.c4gh dir2/data_file.c4gh dir2/data_file2.c4gh
do
    check_uploaded_file "test/$user/$uploadDir/$k" "$k"
done

# Encrypt and upload

mkdir data_files_unenc && mkdir data_files_unenc/dir1
cp data_file data_files_unenc/. && cp data_file data_files_unenc/dir1/data_file1

uploadDir="testEncryptUpload"
./sda-cli upload -config testing/s3cmd.conf -encrypt-with-key sda_key.pub.pem -r data_files_unenc -targetDir "$uploadDir"

check_encypted_file "data_files_unenc/data_file.c4gh" "data_files_unenc/dir1/data_file1.c4gh"

for k in data_files_unenc/data_file.c4gh data_files_unenc/dir1/data_file1.c4gh
do
    check_uploaded_file "test/$user/$uploadDir/$k" "$k"
done

if ! s3cmd -c testing/directS3 ls -r s3://test/"$user"/testEncryptUpload/data_files_unenc/ | grep -v -q 'c4gh'
then
    echo "No unencrypted files were uploaded during encrypt+upload"
else
    echo "Unencrypted files were uploaded during encrypt+upload"
    exit 1
fi

# Dataset size using a local urls_list.txt
echo "http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/data_file.c4gh" > urls_list.txt

s3cmd -c testing/directS3 put data_files_enc/data_file.c4gh s3://download/A352764B-2KB4-4738-B6B5-BA55D25FB469/data_file.c4gh
check_uploaded_file download/A352764B-2KB4-4738-B6B5-BA55D25FB469/data_file.c4gh data_file.c4gh

s3cmd -c testing/directS3 put urls_list.txt s3://download/A352764B-2KB4-4738-B6B5-BA55D25FB469/urls_list.txt

# Download file with local urls_list.txt
./sda-cli download -outdir downloads urls_list.txt

if [ -f downloads/data_file.c4gh ]; then
    echo "Downloaded data file"
else
    echo "Failed to download data file"
    exit 1
fi

# Decrypt file
C4GH_PASSWORD="" ./sda-cli decrypt -key sda_key.sec.pem downloads/data_file.c4gh

if [ -f downloads/data_file ]; then
    echo "Decrypted data file"
else
    echo "Failed to decrypt data file"
    exit 1
fi

# Test multiple pub key encryption

# Create another couple of key-pairs
for c in 1 2
do
    if ( echo "" | ./sda-cli createKey sda_key$c ) ; then
        echo "Created key pair for encryption"
    else
        echo "Failed to create key pair for encryption"
        exit 1
fi
done

# Create file with concatenated pub keys
cat sda_key1.pub.pem sda_key2.pub.pem > sda_keys

# Create test files
cp data_file data_file_keys

# Encrypt with multiple key flag calls
./sda-cli encrypt -key sda_key.pub.pem -key sda_key2.pub.pem data_file_keys
check_encypted_file "data_file_keys.c4gh"

# Decrypt file with both keys
for key in sda_key sda_key2
do
    rm data_file_keys
    C4GH_PASSWORD="" ./sda-cli decrypt -key $key.sec.pem data_file_keys.c4gh
    if [ -f data_file_keys ]; then
        echo "Decrypted data file"
    else
        echo "Failed to decrypt data file with $key"
        exit 1
    fi
done
rm data_file_keys.c4gh

# Encrypt with concatenated key file
./sda-cli encrypt -key sda_keys data_file_keys
check_encypted_file "data_file_keys.c4gh"

# Decrypt file with both keys
for key in sda_key1 sda_key2
do
    rm data_file_keys
    C4GH_PASSWORD="" ./sda-cli decrypt -key $key.sec.pem data_file_keys.c4gh
    if [ -f data_file_keys ]; then
        echo "Decrypted data file"
    else
        echo "Failed to decrypt data file with $key"
        exit 1
    fi
done
rm data_file_keys.c4gh

# Encrypt with concatenated key file and a key flag call
./sda-cli encrypt -key sda_key.pub.pem -key sda_keys data_file_keys
check_encypted_file "data_file_keys.c4gh"

# Decrypt file with all keys
for key in sda_key sda_key1 sda_key2
do
    rm data_file_keys
    C4GH_PASSWORD="" ./sda-cli decrypt -key $key.sec.pem data_file_keys.c4gh
    if [ -f data_file_keys ]; then
        echo "Decrypted data file"
    else
        echo "Failed to decrypt data file with $key"
        exit 1
    fi
done

# Remove files used for encrypt and upload
rm -r data_files_enc
rm -r data_files_unenc
rm -r downloads
rm sda_key* checksum_* urls_list.txt data_file*

# Dataset size using a url urls_list.txt
output=$(./sda-cli datasetsize http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/urls_list.txt | grep -q "Total dataset size: 1.00MB")

if $output; then
    echo "Returned dataset size"
else
    echo "Failed to return dataset size"
    exit 1
fi

# Dataset size using a folder url
output=$(./sda-cli datasetsize http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/ | grep -q "Total dataset size: 1.00MB")

if $output; then
    echo "Returned dataset size"
else
    echo "Failed to return dataset size"
    exit 1
fi

# Check that Download handles http responses with error status code

# Try downloading nonexistent file
printf "%s" "Attempting to download a nonexistent file from S3..."
errorMessage="reason: request failed with \`404 Not Found\`, details: {Code:NoSuchKey"
if ./sda-cli download -outdir downloads http://localhost:9000/download/imaginary/path/ 2>&1 | grep -q "$errorMessage"; then
    echo "bad download request handled properly"
else
    echo "Failed to handle bad download request"
    exit 1
fi

# Try downloading from private bucket
printf "%s" "Attempting to download from S3 bucket with ACL=private..."
errorMessage="reason: request failed with \`403 Forbidden\`, details: {Code:AllAccessDisabled"
if ./sda-cli download -outdir downloads http://localhost:9000/minio/test/"$user"/data_file1.c4gh 2>&1 | grep -q "$errorMessage"; then
    echo "bad download request handled properly"
else
    echo "Failed to handle bad download request"
    exit 1
fi

# Download files using a folder url
./sda-cli download -outdir downloads http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/

if [ -f downloads/data_file.c4gh ]; then
    echo "Downloaded data file"
else
    echo "Failed to download data file"
    exit 1
fi

rm -r downloads

# Download files using a url to urls_list.txt
./sda-cli download -outdir downloads http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/urls_list.txt

if [ -f downloads/data_file.c4gh ]; then
    echo "Downloaded data file"
else
    echo "Failed to download data file"
    exit 1
fi

rm -r downloads

# Populate database with for testing the download service
# Insert entry in sda.files
file_id=$(docker exec -e PGPASSWORD=rootpasswd -it postgres psql -U postgres -d sda -c "INSERT INTO sda.files (stable_id, \
    submission_user, submission_file_path, submission_file_size, archive_file_path, archive_file_size, \
    decrypted_file_size, backup_path, header, encryption_method) VALUES ('urn:neic:001-002', 'integration-test', \
    'main/subfolder/dummy_data.c4gh', 1048729, '4293c9a7-dc50-46db-b79a-27ddc0dad1c6', 1049081, 1048605, '', \
    '637279707434676801000000010000006c000000000000006af1407abc74656b8913a7d323c4bfd30bf7c8ca359f74ae35357acef29dc5073799e207ec5d022b2601340585ff082565e55fbff5b6cdbbbe6b12a0d0a19ef325a219f8b62344325e22c8d26a8e82e45f053f4dcee10c0ec4bb9e466d5253f139dcd4be', \
    'CRYPT4GH') RETURNING id;" | awk 'NR==3' | tr -dc '[:alnum:]-')

# Insert entry in sda.file_event_log
docker exec -e PGPASSWORD=rootpasswd -it postgres psql -U postgres -d sda -c "INSERT INTO sda.file_event_log (file_id, event) \
    VALUES ('$file_id', 'ready');"

# Insert entries in sda.checksums
docker exec -e PGPASSWORD=rootpasswd -it postgres psql -U postgres -d sda -c "INSERT INTO sda.checksums (file_id, checksum, \
    type, source) VALUES ('$file_id', '06bb0a514b26497b4b41b30c547ad51d059d57fb7523eb3763cfc82fdb4d8fb7', 'SHA256', 'UNENCRYPTED');"

docker exec -e PGPASSWORD=rootpasswd -it postgres psql -U postgres -d sda -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$file_id', '5e9c767958cc3f6e8d16512b8b8dcab855ad1e04e05798b86f50ef600e137578', 'SHA256', 'UPLOADED');"

docker exec -e PGPASSWORD=rootpasswd -it postgres psql -U postgres -d sda -c "INSERT INTO sda.checksums (file_id, checksum, type, source) \
        VALUES ('$file_id', '74820dbcf9d30f8ccd1ea59c17d5ec8a714aabc065ae04e46ad82fcf300a731e', 'SHA256', 'ARCHIVED');"

# Insert dataset in sda.datasets
dataset_id=$(docker exec -e PGPASSWORD=rootpasswd -it postgres psql -U postgres -d sda -c "INSERT INTO sda.datasets (stable_id) \
    VALUES ('https://doi.example/ty009.sfrrss/600.45asasg') RETURNING id;" | awk 'NR==3' | tr -dc '[:alnum:]-')

# Add file to dataset
docker exec -e PGPASSWORD=rootpasswd -it postgres psql -U postgres -d sda -c "INSERT INTO sda.file_dataset (file_id, dataset_id) \
        VALUES ('$file_id', $dataset_id);"

echo "Integration test finished successfully"
