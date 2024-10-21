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
if ( yes "" | ./sda-cli createKey sda_key ) ; then
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

# Download file by using the sda download service
./sda-cli -config testing/s3cmd-download.conf download -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir test-download main/subfolder/dummy_data.c4gh

# Check if file exists in the path
if [ ! -f "test-download/main/subfolder/dummy_data" ]; then
    echo "Downloaded file not found"
    exit 1
fi

# Check the first line of that file
first_line=$(head -n 1 test-download/main/subfolder/dummy_data)
if [[ $first_line != *"THIS FILE IS JUST DUMMY DATA"* ]]; then
    echo "First line does not contain the expected string"
    exit 1
fi

rm -r test-download

# Check listing files in a dataset
output=$(./sda-cli -config testing/s3cmd-download.conf list -dataset https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080)
expected="FileIDSizePathurn:neic:001-0011.0MB5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder/dummy_data.c4ghurn:neic:001-0021.0MB5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder2/dummy_data2.c4ghurn:neic:001-0031.0MB5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder2/random/dummy_data3.c4ghDatasetsize:3.1MB"
if [[ "${output//[$' \t\n\r']/}" == "${expected//[$' \t\n\r']/}" ]];  then
    echo "Successfully listed files in dataset"
else
    echo "Failed to list files in dataset"
    exit 1
fi

# Check listing datasets
output=$(./sda-cli list -config testing/s3cmd-download.conf --datasets -url http://localhost:8080)
expected="https://doi.example/ty009.sfrrss/600.45asasga"
if [[ $output == *"$expected"* ]]; then
    echo "Successfully listed datasets"
else
    echo "Failed to list datasets"
    exit 1
fi

# Download whole dataset by using the sda-download feature
./sda-cli download -config testing/s3cmd-download.conf -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-dataset --dataset

filepaths="download-dataset/main/subfolder/dummy_data download-dataset/main/subfolder2/dummy_data2 download-dataset/main/subfolder2/random/dummy_data3"

# Check if all the files of the dataset have been downloaded
for filepath in $filepaths; do
    if [ ! -f "$filepath" ]; then
        echo "File $filepath does not exist"
        exit 1
    fi
done

rm -r download-dataset

# Download encrypted file by using the sda download service
# Create a user key pair
if ( yes "" | ./sda-cli createKey user_key ) ; then
    echo "Created a user key pair for downloading encrypted files"
else
    echo "Failed to create a user key pair for downloading encrypted files"
    exit 1
fi
./sda-cli download -pubkey user_key.pub.pem -config testing/s3cmd-download.conf -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir test-download main/subfolder/dummy_data.c4gh

# check if file exists in the path
if [ ! -f "test-download/main/subfolder/dummy_data.c4gh" ]; then
    echo "Downloaded file not found"
    exit 1
fi

# decrypt the downloaded file
C4GH_PASSWORD="" ./sda-cli decrypt -key user_key.sec.pem test-download/main/subfolder/dummy_data.c4gh

if [ -f test-download/main/subfolder/dummy_data  ]; then
    echo "Decrypting downloaded file succeeded"
else
    echo "Failed to decrypt downloaded file"
    exit 1
fi

# check the first line of that file
first_line=$(head -n 1 test-download/main/subfolder/dummy_data)
if [[ $first_line != *"THIS FILE IS JUST DUMMY DATA"* ]]; then
    echo "First line does not contain the expected string"
    exit 1
fi

# Test multiple pub key encryption

# Create another couple of key-pairs
for c in 1 2
do
    if ( yes "" | ./sda-cli createKey sda_key$c ) ; then
        echo "Created key pair for encryption"
    else
        echo "Failed to create key pair for encryption"
        exit 1
fi
done

# Create file with concatenated pub keys
cat sda_key1.pub.pem sda_key2.pub.pem > sda_keys

# Create test files
cp test-download/main/subfolder/dummy_data data_file_keys

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
rm sda_key* data_file*
rm -r test-download

# Download recursively a folder
echo "Downloading content of folder"
./sda-cli download -config testing/s3cmd-download.conf -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-folder --recursive main/subfolder2

folderpaths="download-folder/main/subfolder2/dummy_data2 download-folder/main/subfolder2/random/dummy_data3"

# Check if the content of the folder has been downloaded
for folderpath in $folderpaths; do
    if [ ! -f "$folderpath" ]; then
        echo "Content of folder $folderpath is missing"
        exit 1
    fi
done

rm -r download-folder

# Download file by providing the file id
./sda-cli download -config testing/s3cmd-download.conf -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-fileid urn:neic:001-001

# Check if file exists in the path
if [ ! -f "download-fileid/main/subfolder/dummy_data" ]; then
    echo "Downloaded file by using the file id not found"
    exit 1
fi

# Check the first line of the file
first_line_id=$(head -n 1 download-fileid/main/subfolder/dummy_data)
if [[ $first_line_id != *"THIS FILE IS JUST DUMMY DATA"* ]]; then
    echo "This is not the file with the given file id"
    exit 1
fi

rm -r download-fileid

# Download the file paths content of a text file
echo "Downloading content of a text file"
./sda-cli download -config testing/s3cmd-download.conf -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-from-file --from-file testing/file-list.txt

# Check if the content of the text file has been downloaded
content_paths="download-from-file/main/subfolder/dummy_data download-from-file/main/subfolder2/dummy_data2"

for content_path in $content_paths; do
    if [ ! -f "$content_path" ]; then
        echo "Content of the text file $content_path is missing"
        exit 1
    fi
done

# Check the first line of the file
first_line_file=$(head -n 1 download-from-file/main/subfolder/dummy_data)
if [[ $first_line_file != *"THIS FILE IS JUST DUMMY DATA"* ]]; then
    echo "First line does not contain the expected string"
    exit 1
fi

rm -r download-from-file

echo "Integration test finished successfully"
