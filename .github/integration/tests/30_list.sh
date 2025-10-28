#!/bin/bash
set -e

if ./sda-cli --config testing/s3cmd.conf list | grep -q 'data_file.c4gh'
then
    echo "Listed file from s3 backend"
else
    echo "Failed to list file to s3 backend"
    exit 1
fi


# Check listing files in a dataset
output=$(./sda-cli --config testing/s3cmd-download.conf list --dataset https://doi.example/ty009.sfrrss/600.45asasga --url http://localhost:8080)
expected="FileIDSizePathurn:neic:001-0011.0MB5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder/dummy_data.c4ghurn:neic:001-0021.0MB5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder2/dummy_data2.c4ghurn:neic:001-0031.0MB5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8_elixir-europe.org/main/subfolder2/random/dummy_data3.c4ghDatasetsize:3.1MB"
if [[ "${output//[$' \t\n\r']/}" == *"${expected//[$' \t\n\r']/}"* ]];  then
    echo "Successfully listed files in dataset"
else
    echo "Failed to list files in dataset"
    exit 1
fi

# Check listing datasets
output=$(./sda-cli --config testing/s3cmd-download.conf list --datasets --url http://localhost:8080)
expected="https://doi.example/ty009.sfrrss/600.45asasga"
if [[ $output == *"$expected"* ]]; then
    echo "Successfully listed datasets"
else
    echo "Failed to list datasets"
    exit 1
fi

echo "Integration tests for sda-cli list finished successfully"
