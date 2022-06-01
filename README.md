SDA-CLI
=======

This is the Sensitive Data Archive (SDA) Command Line Interface (sda-cli). This
tool was created to unify and simplify the tools needed to perform the most
common user actions in the SDA.

This tool can be used to encrypt and upload data when submitting to the archive,
and to download and decrypt with retrieving data from the archive.

To get help on the usage of the tool, please use the following command
```bash
./sda-cli help
```

# Installation
This section contains the information required to install, modify and run the `sda-cli` tool.

# Requirements
The `sda-cli` is written in golang. In order to be able to modify, build and run the tool, golang needs to be installed. The instructions for installing go can be found [here](https://go.dev/doc/install).

### Build tool
To build the `sda-cli` tool run the following command from the root folder of the repository
```bash
go build
```
This command will create an executable file in the root folder, named `sda-cli`.


# Usage
The main functionalities implemented in this tool are explained in the following sections.


## Encrypt

The files stored in the SDA/BP archive are encrypted using the [crypt4gh standard](https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/). The following sections explain how to encrypt and upload files to the archive.

### Download the crypt4gh public key

The files that are uploaded to the SDA/BP services, need to be encrypted with the correct public key. Depending on the service you want to use, this key can be downloaded using this command **if you are uploading to the SDA**:
```bash
wget https://raw.githubusercontent.com/NBISweden/EGA-SE-user-docs/main/crypt4gh_key.pub
```
or this command **if you are uploading to Big Picture**:
```bash
wget https://raw.githubusercontent.com/NBISweden/EGA-SE-user-docs/main/crypt4gh_bp_key.pub
```

### Encrypt file(s)

Now that the public key is downloaded, the file(s) can be encrypted using the binary file created in the first step of this guide. To encrypt a specific file, use the following command:
```bash
./sda-cli encrypt -key <public_key> <file_to_encrypt>
```
where `<public_key>` the key downloaded in the previous step. The tool also allows for encrypting multiple files at once, by listing them separated with space like:
```bash
./sda-cli encrypt -key <public_key> <file_1_to_encrypt> <file_2_to_encrypt> <file_3_to_encrypt>
```
This command comes with the `-continue` option, which will continue encrypting files, even if one of them fails. To enable this feature, the command should be executed with the `-continue=true` option.

**Developers' Notes:** The tool is creating a key pair when encrypting the files. This key pair is temporary for security reasons.


## Upload

### Download the configuration file

Once your files are encrypted, they are ready to be submitted to the SDA/BP archive. The s3 storage requires users to be authenticated, therefore a configuration files needs to be downloaded before starting the uploading of the files.

The configuration file can be downloaded by logging in with a Life Science RI account [here](https://login.sda.nbis.se/) for SDA and [here](https://login.bp.nbis.se/) for Big Picture. The configuration file should be placed in the root folder of the repository.

### Upload file(s)

Now that the configuration file is downloaded, the file(s) can be uploaded to the archive using the binary file created in the first step of this guide. To upload a specific file, use the following command:
```bash
./sda-cli upload -config <configuration_file> <encrypted_file_to_upload>
```
where `<configuration_file>` the file downloaded in the previous step and `<encrypted_file_to_upload>` a file encrypted in the earlier steps. The tool also allows for uploading multiple files at once, by listing them separated with space like:
```bash
./sda-cli upload -config <configuration_file> <encrypted_file_1_to_upload> <encrypted_file_2_to_upload>
```
Note that the files will be uploaded creating the same folder structure as the local one. For example, if the `<encrypted_file_to_upload>` is located at `<folder_1>/<folder_2>/<encrypted_file_to_upload>`, then the same folder structure will be created in the archive.

## Get dataset size

Before downloading a dataset or a specific file, the `sda-cli` tool allows for requesting the size of each file, as well as the whole dataset. In order to use this functionality, the tool expects as an argument a file containing the location of the files in the dataset. The argument can be one of the following:
1. a URL to the file containing the locations of the dataset files
2. a URL to a folder containing the `urls_list.txt` file with the locations of the dataset files
3. the path to a local file containing the locations of the dataset files.

Given this argument, the dataset size can be retrieved using the following command:
```bash
./sda-cli datasetsize <urls_file>
```
where `urls_file` as described above.

## Download

The SDA/BP archive enables for downloading files and datasets in a secure manner. That can be achieved using the `sda-cli` tool and the process consists of the following two steps

### Create keys

In order to make sure that the files are downloaded from the archive in a secure manner, the user is supposed to create the key pair that the files will be encrypted with. The key pair can be created using the following command:
```bash
./sda-cli createKey <keypair_name>
```
where `<keypair_name>` is the base name of the key files. This command will create two keys named `keypair_name.pub.pem` and `keypair_name.sec.pem`. The public key (`pub`) will be used for the encryption of the files, while the private one (`sec`) will be used in the decryption step below.

**NOTE:** Make sure to keep these keys safe. Losing the keys could lead to sensitive data leaks.

### Download file

The `sda-cli` tool allows for downloading file(s)/datasets. The whole dataset is stored in a file named `urls_list.txt`. Using this file or the URL where it is stored, it is possible to download the files. There are three different ways to pass the location of the file to the tool, similar to the [dataset size section](#get-dataset-size):
1. a URL to the file containing the locations of the dataset files
2. a URL to a folder containing the `urls_list.txt` file with the locations of the dataset files
3. the path to a local file containing the locations of the dataset files.

Given this argument, the dataset can be retrieved using the following command:
```bash
./sda-cli download <urls_file>
```
where `urls_file` as described above.
The tool also allows for selecting a folder where the files will be downloaded, using the `outdir` argument like:
```bash
./sda-cli download -outdir <outdir> <urls_file>
```

## Decrypt file

Given that the instructions in the [download section](#download) have been followed, the key pair and the data files should be stored in some location. The last step is to decrypt the files in order to access their content. That can be achieved using the following command:
```bash
./sda-cli decrypt -key <keypair_name>.sec.pem <file_to_decrypt>
```
where `<keypair_name>.sec.pem` the private key created in the [relevant section](#create-keys) and `<file_to_decrypt>` one of the files downloaded following the instructions of the [download section](#download-file).


# Create new release

The github actions include a release workflow that builds binaries for different operating systems. In order to create a new release, create a tag either using the graphical interface or through the command line. That should trigger the creation of a release with the latest code of the specified branch.

In order for the automatic release to get triggered, the releases should be of the format `vX.X.X`, e.g. `v1.0.0`.