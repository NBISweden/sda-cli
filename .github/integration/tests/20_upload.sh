#!/bin/bash
set -e
# inferred from access_key in testing/s3cmd.conf
user=test_dummy.org


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
    # TODO if emtpy, this will fail silently
    output=$(s3cmd -c testing/directS3 ls s3://"$1" | grep -q "$2")
    if $output ; then
        echo "Uploaded encrypted file to s3 backend"
    else
        echo "Failed to upload file to s3 backend"
        exit 1
    fi
}


# Upload a specific file and check it
./sda-cli -config testing/s3cmd.conf upload data_file.c4gh
check_uploaded_file "test/$user/data_file.c4gh" data_file.c4gh


# Try to upload a file twice with the --force-overwrite flag
output=$(./sda-cli -config testing/s3cmd.conf upload --force-overwrite data_file.c4gh)


# Test recursive folder upload
for k in data_file.c4gh data_file1.c4gh
do
    # Upload and check file
    ./sda-cli -config testing/s3cmd.conf upload --force-overwrite "data_files_enc/$k"
    check_uploaded_file "test/$user/$k" "$k"
done



# Upload a folder recursively and a single file
./sda-cli -config testing/s3cmd.conf upload -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the target path
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file "test/$user/$k" "$k"
done

# Test upload to a different path

# Upload a folder recursively and a single file in a specified upload folder
uploadDir="testfolder"
./sda-cli -config testing/s3cmd.conf upload -targetDir "$uploadDir" -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Do it again to test that we can pass -targetDir at the end
./sda-cli -config testing/s3cmd.conf upload --force-overwrite -r data_files_enc/dir1 data_files_enc/data_file3.c4gh -targetDir "$uploadDir"

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the
# target path and into the specified upload folder
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file "test/$user/$uploadDir/$k" "$k"
done

# Upload all contents of a folder recursively to a specified upload folder

uploadDir="testfolder2"
./sda-cli -config testing/s3cmd.conf upload -targetDir "$uploadDir" -r data_files_enc/dir1/.

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
./sda-cli -config testing/s3cmd.conf upload -encrypt-with-key sda_key.pub.pem -r data_files_unenc -targetDir "$uploadDir"

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

echo "Integration tests for sda-cli upload finished successfully"