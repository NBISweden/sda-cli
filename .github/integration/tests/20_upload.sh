#!/bin/bash
set -e
test_dir=$(dirname "$0")
source "$test_dir/../scripts/checkers.sh"

# inferred from access_key in testing/s3cmd.conf
user=test_dummy.org


# Create folder with subfolder structure and add some encrypted files
mkdir -p data_files_enc/dir1 data_files_enc/dir1/dir2
cp data_files_enc/data_file.c4gh data_files_enc/data_file3.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file2.c4gh


# Upload a specific file and check it
./sda-cli --config testing/s3cmd.conf upload data_file.c4gh
check_uploaded_file "test/$user/data_file.c4gh" data_file.c4gh

# Upload the file twice check that this returns an error
msg=$(./sda-cli --config testing/s3cmd.conf upload data_file.c4gh 2>&1 | tail -1 || true)
if ! grep -q "Error:" <<< "$msg"
then
    echo "wrong error message: $msg"
    exit 1
fi

# Upload a file twice with the --force-overwrite flag
./sda-cli --config testing/s3cmd.conf upload --force-overwrite data_file.c4gh

# Upload an already uploaded file and a new one using the --continue flag (useful for resuming uploads)
./sda-cli --config testing/s3cmd.conf upload data_file.c4gh data_files_enc/data_file1.c4gh --continue

# Test upload all files from a folder, one by one
for k in data_file.c4gh data_file1.c4gh
do
    # Upload and check file
    ./sda-cli --config testing/s3cmd.conf upload --force-overwrite "data_files_enc/$k"
    check_uploaded_file "test/$user/$k" "$k"
done

# Upload a folder recursively and a single file
./sda-cli --config testing/s3cmd.conf upload -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the target path
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file "test/$user/$k" "$k"
done

# Test upload to a different path

# Upload a folder recursively and a single file in a specified upload folder
uploadDir="testfolder"
./sda-cli --config testing/s3cmd.conf upload --target-directory "$uploadDir" -r data_files_enc/dir1 data_files_enc/data_file3.c4gh

# Do it again to test that we can pass --target-directory at the end
./sda-cli --config testing/s3cmd.conf upload --force-overwrite -r data_files_enc/dir1 data_files_enc/data_file3.c4gh --target-directory "$uploadDir"

# Check that files were uploaded with the local path prefix `data_files_enc` stripped from the
# target path and into the specified upload folder
for k in dir1/data_file.c4gh dir1/dir2/data_file.c4gh dir1/dir2/data_file2.c4gh data_file3.c4gh
do
    check_uploaded_file "test/$user/$uploadDir/$k" "$k"
done

# Upload all contents of a folder recursively to a specified upload folder

uploadDir="testfolder2"
./sda-cli --config testing/s3cmd.conf upload --target-directory "$uploadDir" -r data_files_enc/dir1/.

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
./sda-cli --config testing/s3cmd.conf upload --encrypt-with-key sda_key.pub.pem -r data_files_unenc --target-directory "$uploadDir"

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
