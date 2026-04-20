#!/bin/bash
set -e

# Function checking that file(s) were encrypted
function check_encrypted_file {
    for k do
        echo "working with $k"
        output=$(head -c 8 "$k")

        if [[ "$output" == "crypt4gh" ]]; then
            echo "Encrypted data file: $k"
        else
            echo "Failed to encrypt file: $k"
            exit 1
        fi
    done
}


# Function checking that a file was uploaded to the S3 backend
function check_uploaded_file {
    if s3cmd -c testing/directS3 ls s3://"$1" | grep -q "$2"; then
        echo "Uploaded encrypted file to s3 backend"
        s3size=$(s3cmd -c testing/directS3 ls s3://"$1" | awk '{print $3}')
        size=$(wc -c < data_file.c4gh | awk '{print $1}')
        s3cmd -c testing/directS3 get s3://"$1" downloaded.file --force
        wc -c < downloaded.file | awk '{print $1}'
        if [ "$s3size" != "$size" ]; then
            echo "wrong size of encrypted file"
            exit 1
        fi
    else
        echo "Failed to upload file to s3 backend"
        exit 1
    fi
}
