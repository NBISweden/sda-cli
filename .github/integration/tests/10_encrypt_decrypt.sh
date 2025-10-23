#!/bin/bash
set -e
test_dir=$(dirname "$0")
source "$test_dir/../scripts/checkers.sh"

# Create random file
dd if=/dev/urandom of=data_file count=10 bs=1M

# Create key pair
if ( yes "" | ./sda-cli createKey sda_key ) ; then
    echo "Created key pair for encryption"
else
    echo "Failed to create key pair for encryption"
    exit 1
fi

# Encrypt a file
./sda-cli encrypt --key sda_key.pub.pem data_file

check_encrypted_file data_file.c4gh


# Create folder and encrypt files in it
cp data_file data_file1
mkdir data_files_enc
./sda-cli encrypt --key sda_key.pub.pem --outdir data_files_enc data_file data_file1

check_encrypted_file data_files_enc/data_file.c4gh data_files_enc/data_file1.c4gh

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
./sda-cli encrypt --key sda_key.pub.pem --key sda_key2.pub.pem data_file_keys
check_encrypted_file data_file_keys.c4gh
# Decrypt file with both keys, one at the time
for key in sda_key sda_key2
do
    rm data_file_keys
    C4GH_PASSWORD="" ./sda-cli decrypt --key $key.sec.pem data_file_keys.c4gh
    if [ -f data_file_keys ]; then
        echo "Decrypted data file"
    else
        echo "Failed to decrypt data file with $key"
        exit 1
    fi
done
echo "Could decrypt with both keys from multiple key flag"
rm data_file_keys.c4gh


# Encrypt with a single key and with a concatenated key file
./sda-cli encrypt --key sda_key.pub.pem --key sda_keys data_file_keys
check_encrypted_file data_file_keys.c4gh

# Decrypt file with all three keys
for key in sda_key sda_key1 sda_key2
do
    rm data_file_keys
    C4GH_PASSWORD="" ./sda-cli decrypt --key $key.sec.pem data_file_keys.c4gh
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
./sda-cli encrypt --key sda_keys data_file_keys
check_encrypted_file data_file_keys.c4gh

# Decrypt file with all keys
for key in sda_key1 sda_key2
do
    rm data_file_keys
    C4GH_PASSWORD="" ./sda-cli decrypt --key $key.sec.pem data_file_keys.c4gh
    if [ -f data_file_keys ]; then
        echo "Decrypted data file"
    else
        echo "Failed to decrypt data file with $key"
        exit 1
    fi
done

echo "Could decrypt with all keys from concatenated key"

if ./sda-cli decrypt --key $key.sec.pem data_file_keys.c4gh --config  testing/s3cmd.conf 2> >(grep "the config flag should come before the subcommand. Eg 'sda-cli -config s3cfg decrypt" > /dev/null ) -ne 1
then
    echo "Unexpected error message"
    exit 1
fi
if ./sda-cli encrypt --key $key.sec.pem data_file_keys.c4gh --config  testing/s3cmd.conf 2> >(grep "the config flag should come before the subcommand. Eg 'sda-cli -config s3cfg encrypt" > /dev/null ) -ne 1
then
    echo "Unexpected error message"
    exit 1
fi

echo "Integration tests for sda-cli encrypt finished successfully"
