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
    output=$(s3cmd -c sda-s3proxy/dev_utils/directS3 ls s3://"$1" | grep -q "$2")
    if $output ; then
        echo "Uploaded encrypted file to s3 backend"
    else
        echo "Failed to upload file to s3 backend"
        exit 1
    fi
}

# Create random file
dd if=/dev/random of=data_file count=1 bs=$(( 1024*1024 ))

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
./sda-cli upload -config sda-s3proxy/dev_utils/s3cmd.conf data_file.c4gh
check_uploaded_file test/dummy/data_file.c4gh data_file.c4gh

# Create and encrypt multiple files in a folder
dd if=/dev/random of=data_file1 count=1 bs=$(( 1024*1024 ))

# Create folder and encrypt files in it
mkdir data_files_enc
./sda-cli encrypt -key sda_key.pub.pem -outdir data_files_enc data_file data_file1

check_encypted_file "data_files_enc/data_file.c4gh data_files_enc/data_file1.c4gh"

for k in data_file.c4gh data_file1.c4gh
do
    # Upload and check file
    ./sda-cli upload -config sda-s3proxy/dev_utils/s3cmd.conf "data_files_enc/$k"
    check_uploaded_file test/dummy/$k $k
done

# Test recursive folder upload
# Create folder with subfolder structure and add some encrypted files
mkdir data_files_enc/dir1 data_files_enc/dir1/dir2
cp data_files_enc/data_file.c4gh data_files_enc/data_file3.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file2.c4gh

# Upload a folder recursively and a single file
./sda-cli upload -config sda-s3proxy/dev_utils/s3cmd.conf -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the target path
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file test/dummy/$k $k
done

# Test upload to a different path
# Upload a folder recursively and a single file in a specified upload folder
uploadDir="testfolder"
./sda-cli upload -config sda-s3proxy/dev_utils/s3cmd.conf -targetDir "$uploadDir" -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Do it again to test that we can pass -targetDir at the end
./sda-cli upload -config sda-s3proxy/dev_utils/s3cmd.conf -r data_files_enc/dir1 data_files_enc/data_file3.c4gh -targetDir "$uploadDir"

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the
# target path and into the specified upload folder
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file test/dummy/$uploadDir"/"$k $k
done

# Upload all contents of a folder recursively to a specified upload folder
uploadDir="testfolder2"
./sda-cli upload -config sda-s3proxy/dev_utils/s3cmd.conf -targetDir "$uploadDir" -r data_files_enc/dir1/.

# Check that files were uploaded with the local path prefix `data_files_enc/dir1` stripped from the
# target path and into the specified upload folder
for k in data_file.c4gh dir2/data_file.c4gh dir2/data_file2.c4gh
do
    check_uploaded_file test/dummy/$uploadDir"/"$k $k
done

# Dataset size using a local urls_list.txt
echo "http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/data_file.c4gh" > urls_list.txt

s3cmd -c sda-s3proxy/dev_utils/directS3 put data_files_enc/data_file.c4gh s3://download/A352764B-2KB4-4738-B6B5-BA55D25FB469/data_file.c4gh
check_uploaded_file download/A352764B-2KB4-4738-B6B5-BA55D25FB469/data_file.c4gh data_file.c4gh

s3cmd -c sda-s3proxy/dev_utils/directS3 put urls_list.txt s3://download/A352764B-2KB4-4738-B6B5-BA55D25FB469/urls_list.txt

# Download file with local urls_list.txt
./sda-cli download -outdir downloads urls_list.txt

if [ -f downloads/data_file.c4gh ]; then
    echo "Downloaded data file"
else
    echo "Failed to download data file"
    exit 1
fi

# Decrypt file
./sda-cli decrypt -key sda_key.sec.pem downloads/data_file.c4gh

if [ -f downloads/data_file ]; then
    echo "Decrypted data file"
else
    echo "Failed to decrypt data file"
    exit 1
fi

# Remove files used for encrypt and upload
rm -r data_files_enc
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


# Download files using a url to urls_list.txt
./sda-cli download -outdir downloads http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/

if [ -f downloads/data_file.c4gh ]; then
    echo "Downloaded data file"
else
    echo "Failed to download data file"
    exit 1
fi

rm -r downloads

# Download files using a folder url
./sda-cli download -outdir downloads http://localhost:9000/download/A352764B-2KB4-4738-B6B5-BA55D25FB469/urls_list.txt

if [ -f downloads/data_file.c4gh ]; then
    echo "Downloaded data file"
else
    echo "Failed to download data file"
    exit 1
fi

rm -r downloads

echo "Integration test finished successfully"
