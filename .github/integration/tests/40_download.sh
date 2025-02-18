#!/bin/bash
set -e

# Create a user key pair
if ( yes "" | ./sda-cli createKey user_key ) ; then
    echo "Created a user key pair for downloading encrypted files"
else
    echo "Failed to create a user key pair for downloading encrypted files"
    exit 1
fi

# Download file by using the sda-cli download command
./sda-cli -config testing/s3cmd-download.conf download -pubkey user_key.pub.pem -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir test-download main/subfolder/dummy_data.c4gh

C4GH_PASSWORD="" ./sda-cli decrypt -key user_key.sec.pem test-download/main/subfolder/dummy_data.c4gh
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

# Download whole dataset by using the sda-cli download command
./sda-cli -config testing/s3cmd-download.conf download -pubkey user_key.pub.pem  -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-dataset --dataset

filepaths="download-dataset/main/subfolder/dummy_data download-dataset/main/subfolder2/dummy_data2 download-dataset/main/subfolder2/random/dummy_data3"

# Check if all the files of the dataset have been downloaded
for filepath in $filepaths; do
    if [ ! -f "$filepath.c4gh" ]; then
        echo "File $filepath does not exist"
        exit 1
    fi
done

rm -r download-dataset

# Download encrypted file by using the sda-cli download command
./sda-cli -config testing/s3cmd-download.conf download -pubkey user_key.pub.pem -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir test-download main/subfolder/dummy_data.c4gh

# Check if file exists in the path
if [ ! -f "test-download/main/subfolder/dummy_data.c4gh" ]; then
    echo "Downloaded file not found"
    exit 1
fi

# Decrypt the downloaded file
C4GH_PASSWORD="" ./sda-cli decrypt -key user_key.sec.pem test-download/main/subfolder/dummy_data.c4gh

if [ -f test-download/main/subfolder/dummy_data  ]; then
    echo "Decrypting downloaded file succeeded"
else
    echo "Failed to decrypt downloaded file"
    exit 1
fi

# Check the first line of that file
first_line=$(head -n 1 test-download/main/subfolder/dummy_data)
if [[ $first_line != *"THIS FILE IS JUST DUMMY DATA"* ]]; then
    echo "First line does not contain the expected string"
    exit 1
fi

# Download recursively a folder
echo "Downloading content of folder"
./sda-cli -config testing/s3cmd-download.conf download -pubkey user_key.pub.pem -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-folder --recursive main/subfolder2

folderpaths="download-folder/main/subfolder2/dummy_data2 download-folder/main/subfolder2/random/dummy_data3"

# Check if the content of the folder has been downloaded
for folderpath in $folderpaths; do
    if [ ! -f "$folderpath.c4gh" ]; then
        echo "Content of folder $folderpath is missing"
        exit 1
    fi
done

rm -r download-folder

# Download dataset by providing the dataset id
./sda-cli -config testing/s3cmd-download.conf download -pubkey user_key.pub.pem -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-fileid urn:neic:001-001

# Check if file exists in the path
if [ ! -f "download-fileid/main/subfolder/dummy_data.c4gh" ]; then
    echo "Downloaded file by using the file id not found"
    exit 1
fi

C4GH_PASSWORD="" ./sda-cli decrypt -key user_key.sec.pem download-fileid/main/subfolder/dummy_data.c4gh
# Check the first line of the file
first_line_id=$(head -n 1 download-fileid/main/subfolder/dummy_data)
if [[ $first_line_id != *"THIS FILE IS JUST DUMMY DATA"* ]]; then
    echo "This is not the file with the given file id"
    exit 1
fi

rm -r download-fileid

# Download the file paths content of a text file
echo "Downloading content of a text file"
./sda-cli -config testing/s3cmd-download.conf download -pubkey user_key.pub.pem -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir download-from-file --from-file testing/file-list.txt

# Check if the content of the text file has been downloaded
content_paths="download-from-file/main/subfolder/dummy_data.c4gh download-from-file/main/subfolder2/dummy_data2.c4gh"

for content_path in $content_paths; do
    if [ ! -f "$content_path" ]; then
        echo "Content of the text file $content_path is missing"
        exit 1
    fi
done

C4GH_PASSWORD="" ./sda-cli decrypt -key user_key.sec.pem download-from-file/main/subfolder/dummy_data.c4gh
# Check the first line of the file
first_line_file=$(head -n 1 download-from-file/main/subfolder/dummy_data)
if [[ $first_line_file != *"THIS FILE IS JUST DUMMY DATA"* ]]; then
    echo "First line does not contain the expected string"
    exit 1
fi

# Make sure files cannot be downloaded without giving a public key
if ./sda-cli -config testing/s3cmd-download.conf download -dataset-id https://doi.example/ty009.sfrrss/600.45asasga -url http://localhost:8080 -outdir test-download main/subfolder/dummy_data.c4gh; then
  echo "Downloaded a file without using a public key"
  exit 1
fi

rm -r download-from-file
rm -r test-download


echo "Integration tests for sda-cli download finished successfully"