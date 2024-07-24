#!/bin/sh

# This script creates the neccessary certificates.  The certificates
# are stored in the "/shared/cert" directory, or in the directory given
# as the first argument.  This directory will be created if it does not
# already exist.  If all certificates already exist, the script does
# not recreate them.  Since the script changes ownership of the created
# certificates, root privileges are required.

set -e -u

script_dir=$(dirname "$(realpath "$0")")

# Use 1st argument as output directory, or default to /shared/cert.
out_dir=${1-/shared/cert}
mkdir -p -- "$out_dir"
cd -- "$out_dir"

# Check if certificates exist.
echo 'Checking certificates'
recreate=false
for cert in ca.crt server.crt server.key client.crt client.key
do
    if [ ! -f "$cert" ]; then
	printf '"%s" is missing\n' "$cert"
        recreate=true
        break
    fi
done

# Only recreate certificates if any certificate is missing.
if ! "$recreate"; then
    echo 'Certificates already exists'
    exit
fi

# Create CA certificate.
openssl req \
	-config "$script_dir/ssl.cnf" \
	-extensions v3_ca \
	-keyout ca.key \
	-new \
	-nodes \
	-out ca.csr \
	-sha256
openssl req \
	-config "$script_dir/ssl.cnf" \
	-days 7300 \
	-extensions v3_ca \
	-key ca.key \
	-new \
	-nodes \
	-out ca.crt \
	-sha256 \
	-x509

# Create certificate for servers.
openssl req \
	-config "$script_dir/ssl.cnf" \
	-extensions server_cert \
	-keyout server.key \
	-new \
	-newkey rsa:4096 \
	-nodes \
	-out server.csr 
openssl x509 \
	-CA ca.crt \
	-CAcreateserial \
	-CAkey ca.key \
	-days 1200 \
	-extensions server_cert \
	-extfile "$script_dir/ssl.cnf" \
	-in server.csr \
	-out server.crt \
	-req

# Create certificate for clients.
openssl req \
	-config "$script_dir/ssl.cnf" \
	-extensions client_cert \
	-keyout client.key \
	-new \
	-newkey rsa:4096 \
	-nodes \
	-out client.csr \
	-subj '/CN=admin'
openssl x509 \
	-CA ca.crt \
	-CAcreateserial \
	-CAkey ca.key \
	-days 1200 \
	-extensions client_cert \
	-extfile "$script_dir/ssl.cnf" \
	-in client.csr \
	-out client.crt \
	-req

# Fix permissions and ownership.
cp server.key mq.key
chown 0:101 mq.key
chmod 640 mq.key

cp server.key db.key
chown 0:70 db.key
chmod 640 db.key

cp server.key download.key
chown 0:65534 download.key
chmod 640 download.key

cp server.key auth.key
chown 0:65534 auth.key
chmod 640 auth.key

chown 0:65534 client.*
chmod 640 client.*

chown 0:65534 server.*
chmod 640 server.*

cp ca.crt /cacert/ca-certificates.crt
