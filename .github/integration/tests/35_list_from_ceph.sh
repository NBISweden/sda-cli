#!/bin/bash
set -e

cp testing/s3cmd.conf testing/ceph.conf
sed -i 's/8000/8800/g' testing/ceph.conf

## Upload some files
for n in {1..10}; do
    cp data_file.c4gh "data_file-$n.c4gh"
    ./sda-cli -config testing/ceph.conf upload "data_file-$n.c4gh"
    rm "data_file-$n.c4gh"
done

if [ "$(./sda-cli -config testing/ceph.conf list | wc -l)" -ne 11 ]; then
    echo "Wrong number of files returned from ceph backend"
    exit 1
fi

echo "Integration tests for sda-cli list finished successfully"
