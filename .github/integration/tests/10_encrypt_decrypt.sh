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


# Create and encrypt multiple files in a folder

# Create folder and encrypt files in it
cp data_file data_file1
mkdir data_files_enc
./sda-cli encrypt -key sda_key.pub.pem -outdir data_files_enc data_file data_file1

check_encypted_file "data_files_enc/data_file.c4gh data_files_enc/data_file1.c4gh"


# Create folder with subfolder structure and add some encrypted files
mkdir data_files_enc/dir1 data_files_enc/dir1/dir2
cp data_files_enc/data_file.c4gh data_files_enc/data_file3.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file.c4gh
cp data_files_enc/data_file.c4gh data_files_enc/dir1/dir2/data_file2.c4gh

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
echo "Could decrypt with both keys from multiple key flag"
rm data_file_keys.c4gh


# Encrypt with concatenated key file and a key flag call
./sda-cli encrypt -key sda_key.pub.pem -key sda_keys data_file_keys
check_encypted_file "data_file_keys.c4gh"

# Decrypt file with both keys
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
echo "Could decrypt with both keys from concatenated key"
rm data_file_keys.c4gh

# Encrypt with concatenated key file
./sda-cli encrypt -key sda_keys data_file_keys
check_encypted_file "data_file_keys.c4gh"

# Decrypt file with all keys
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

echo "Could decrypt with all keys from concatenated key"

echo "Integration tests for sda-cli encrypt finished successfully"