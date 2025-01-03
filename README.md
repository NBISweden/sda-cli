# SDA-CLI

This is the Sensitive Data Archive (SDA) Command Line Interface (sda-cli). This
tool was created to unify and simplify the tools needed to perform the most
common user actions in the SDA.

This tool can be used to encrypt and upload data when submitting to the archive,
and to download and decrypt with retrieving data from the archive.

It is recommended to use precompiled executables for `sda-cli` which can be found at https://github.com/NBISweden/sda-cli/releases

To get help on the usage of the tool, please use the following command

```bash
./sda-cli help
```

# Usage

The main functionalities implemented in this tool are explained in the following sections.

If any command seems a bit puzzling, you can find guidance on how to interpret it right [here](https://ftpdocs.broadcom.com/cadocs/0/CA%20ARCserve%20%20Backup%2015-ENU/Bookshelf_Files/HTML/CMD_Ref/command_line_syntax_characters.htm) and [here](https://medium.com/@jaewei.j.w/how-to-read-man-page-synopsis-3408e7fd0e42).

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
./sda-cli encrypt [-key <public_key>] <file_to_encrypt>
```

where `<public_key>` the key downloaded in the previous step. The tool also allows for encrypting multiple files at once, by listing them separated with space like:

```bash
./sda-cli encrypt -key <public_key> <file_1_to_encrypt> <file_2_to_encrypt> <file_3_to_encrypt>
```

This command comes with the `-continue` option, which will continue encrypting files, even if one of them fails. To enable this feature, the command should be executed with the `-continue=true` option.
If no public key is provided, the tool will look for it from a previous login session.

### Encrypt file(s) with multiple keys

To encrypt files with more than one public keys, repeatedly use the `-key` flag, e.g.

```bash
./sda-cli encrypt -key <public_key1> -key <public_key2> <file_to_encrypt>
```

will encrypt a file using two keys so that it can be decrypted with either of the corresponding private keys. Encryption with more than two keys is possible, as well. Another option is to provide as argument to `-key` a file with concatenated public keys generated e.g. from a command like

```bash
cat <pub_key1> <pub_key2> > <concatenated_pub_keys>
```

Passing a combination of the above arguments is allowed, as well:

```bash
./sda-cli encrypt -key <concatenated_public_keys> -key <public_key3> <file_to_encrypt>
```

**Note**: The `encrypt` command will create four files containing hashes (both md5 and sha256) for the encrypted and unencrypted files, respectively.

**Developers' Notes:** The tool is creating a key pair when encrypting the files. This key pair is temporary for security reasons.

## Upload

### Download the configuration file

Once your files are encrypted, they are ready to be submitted to the SDA/BP archive. The s3 storage requires users to be authenticated, therefore a configuration file needs to be downloaded before starting the uploading of the files.

The configuration file can be downloaded by logging in with a Life Science RI account:

- For BigPicture use https://login.bp.nbis.se/

Follow the dialogue to get authenticated and then click on `Download inbox s3cmd credentials` to download the configuration file named s3cmd.conf. The configuration file should be placed in the root folder of the repository.

Alternatively, you can download the configuration file using the [login command](#Login).

The access token used to authenticate to the inbox can be supplied in 3 different ways; in the config file, as an ENV `ACCESSTOKEN` or on the command line `-accessToken <access-token>` as part of the upload command.

The Priority order for the access token is:

1. Using the `-accessToken` flag
2. From the ENV `ACCESSTOKEN`
3. In the config file

### Upload file(s)

Now that the configuration file is downloaded, the file(s) can be uploaded to the archive using the binary file created in the first step of this guide. To upload a specific file, use the following command:

```bash
./sda-cli -config <configuration_file> upload <encrypted_file_to_upload>
```

where `<configuration_file>` the file downloaded in the previous step and `<encrypted_file_to_upload>` a file encrypted in the earlier steps. The tool also allows for uploading multiple files at once, by listing them separated with space like:

```bash
./sda-cli -config <configuration_file> upload <encrypted_file_1_to_upload> <encrypted_file_2_to_upload>
```

Note that the files will be uploaded in the base folder of the user.

### Upload folder(s)

One can also upload entire directories recursively, i.e. including all contained files and folders while keeping the local folder structure. This can be achieved with the `-r` flag, e.g. running:

```bash
./sda-cli -config <configuration_file> upload -r <folder_to_upload>
```

will upload `<folder_to_upload>` as is, i.e. with the same inner folder and file structure as the local one, to the archive.

It is also possible to specify multiple directories and files for upload with the same command. For example,

```bash
./sda-cli -config <configuration_file> upload -r <encrypted_file_1_to_upload> <encrypted_file_2_to_upload> <folder_1_to_upload> <folder_2_to_upload>
```

However, if `-r` is omitted in the above, any folders will be skipped during upload.

### Upload to a different path

The user can specify a different path for uploading files/folders with the `-targetDir` flag followed by the name of the folder. For example, the command:

```bash
./sda-cli -config <configuration_file> upload -r <encrypted_file_1_to_upload> <folder_1_to_upload> -targetDir <upload_folder>
```

will create `<upload_folder>` under the user's base folder with contents `<upload_folder>/<encrypted_file_1_to_upload>` and `<upload_folder>/<folder_1_to_upload>`. Note that the given `<upload_folder>` may well be a folder path, e.g. `<folder1/folder2>`, and in this case `<encrypted_file_1_to_upload>` will be uploaded to `folder1/folder2/<encrypted_file_1_to_upload>`.

As a side note it is possible to include all the contents of a directory with `/.`, for example,

```bash
./sda-cli -config <configuration_file> upload -r <folder_to_upload>/. -targetDir <new_folder_name>
```

will upload all contents of `<folder_to_upload>` to `<new_folder_name>` recursively, effectively renaming `<folder_to_upload>` upon upload to the archive.

### Encrypt on upload

It is possible to combine the encryption and upload steps with the use of the flag `--encrypt-with-key` followed by the path of the crypt4gh public key to be used for encryption. In this case, the input list of file arguments can only contain _unencrypted_ source files. For example the following,

```bash
./sda-cli -config <configuration_file> upload --encrypt-with-key <public_key> <unencrypted_file_to_upload>
```

will encrypt `<unencrypted_file_to_upload>` using `<public_key>` as public key and upload the created `<file_to_upload.c4gh>` in the base folder of the user.

Encrypt on upload can be combined with any of the flags above. For example,

```bash
./sda-cli -config <configuration_file> upload --encrypt-with-key <public_key> -r <folder_to_upload_with_unencrypted_data> -targetDir <new_folder_name>
```

will first encrypt all files in `<folder_to_upload_with_unencrypted_data>` and then upload the folder recursively (selecting only the created `c4gh` files) under `<new_folder_name>`.

**Notes**: The tool calls the [encrypt](#Encrypt) module internally, therefore similar behavior to that command is expected, including the creation of hash files. In addition,

- For encryption with [multiple public keys](<#Encrypt-file(s)-with-multiple-keys>), concatenate all public keys into one file and pass it as the argument to `encrypt-with-key`.
- If the input includes encrypted files, the tool will exit without performing further tasks.
- The encrypted files will be created next to their unencrypted counterparts.
- The tool will not overwrite existing encrypted files. It will exit early if encrypted counterparts of the source files already exist with the same source path.
- If the flag `--force-overwrite` is used, the tool will overwrite any already existing file.
- The cli will exit if the input has any un-encrypred files. To override that, use the flag `--force-unencrypted`.

## List

All the following cases require a [configuration file to be downloaded](https://github.com/NBISweden/sda-cli/blob/documentation/datset-list/README.md#download-the-configuration-file) before starting the operation, and the `list` parameter should be used.

### List uploaded files

This feature returns all the files in the user's inbox recursively and can be executed using:

```bash
./sda-cli [-config <configuration_file>] list
```

It also allows for requesting files/filepaths with a specified prefix using:

```bash
./sda-cli [-config <configuration_file>] list <prefix>
```

This command will return any file/path starting with the defined `<prefix>`.
If no config is given by the user, the tool will look for a previous login from the user.

### List datasets and their files

To list datasets or the files within a dataset that the user has access to, the `--datasets` flag should be used and the login URL must be provided:

```bash
./sda-cli -config <configuration_file> list --datasets --url <login_url> (--bytes)
```

where `<login_url>` is the URL where the user goes for authentication. This command returns a list of accessible datasets, including the number
of files in each dataset and the total size of it. The `--bytes` flag is optional and it will display the size of the dataset in bytes.

To list the files within a particular dataset, the user must provide the dataset ID (which can be obtained by executing the previous command):

```bash
./sda-cli -config <configuration_file> list -dataset <datasetID> -url <login_url> (--bytes)
```

This command returns a list of files within the dataset, including their file IDs, file sizes and file paths. The `--bytes` flag is optional and it will display the size of the files in bytes.

## Download

Files and datasets can be downloaded using the `download` parameter.
This utilizes the Download API which enables secure downloads from the SDA/BP archive.

The download API allows for downloading files from the archive and it requires the user to have access to the dataset, therefore a [configuration file](#download-the-configuration-file) needs to be downloaded before starting the downloading of the files.
For downloading files the user also needs to know the download service URL and the dataset ID. The user has several options for downloading:

- specific files by using their paths
- specific files by using their file ids
- multiple files recursively
- multiple files by providing a text file with the paths of the files to download
- all the files of the dataset
- specific encrypted files

#### Download specific files of the dataset (using filepaths or file ids)

For downloading one specific file the user needs to provide the path or the id (the id should **NOT** have "/") of this file by running the command below:

```bash
./sda-cli -config <configuration_file> download -dataset-id <datasetID> -url <download-service-URL> [<filepath> or <fileid>]
```

where `<configuration_file>` the file downloaded in the [previous step](#download-the-configuration-file), `<dataset_id>` the ID of the dataset and `<filepath>` the path of the file (or `<fileid>` the id of the file) in the dataset.
The tool also allows for downloading multiple files at once, by listing their filepaths (or file ids) separated with space and it also allows for selecting a folder where the files will be downloaded, using the `outdir` argument:

```bash
./sda-cli -config download <configuration_file> -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> <path/to/file1> <other/path/to/file2> ... (or <fileID_1> <fileID_2> ...)
```

#### Download files recursively

For downloading the content of a folder (including subfolders) the user need to add the `--recursive` flag followed by the path(s) of the folder(s):

```bash
./sda-cli -config download <configuration_file> -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> --recursive path/to/folder1 path/to/folder2 ...
```

#### Download from file

For downloading multiple files the user can provide a text file with the paths of the files to download. The file should contain one path per line.
In this case user needs to use the `--from-file` flag and at the end user needs to provide the path of the text file with the paths of the files to download:

```bash
./sda-cli -config download <configuration_file> -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> --from-file <path/to/text_file>
```

#### Download all the files of the dataset

For downloading the whole dataset the user needs add the `--dataset` flag and NOT providing any filepaths:

```bash
./sda-cli -config download <configuration_file> -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> --dataset
```

where the dataset will be downloaded in the `<outdir>` directory be keeping the original folder structure of the dataset.

#### Download encrypted files using the download API

When a [public key](#create-keys) is provided, you can download files that are encrypted on the server-side with that public key. The command is similar to downloading the unencrypted files except that a public key is provided through the `-pubkey` flag. For example:

```bash
./sda-cli -config <configuration_file> download -pubkey <public-key-file> -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> <filepath_1_to_download> <filepath_2_to_download> ...
```

After a successful download, the encrypted files can be [decrypted](#decrypt-file) using the private key corresponding to the provided public key.

## Decrypt file

Given that the instructions in the [download section](#download) have been followed, the key pair and the data files should be stored in some location. The last step is to decrypt the files in order to access their content. That can be achieved using the following command:

```bash
./sda-cli decrypt -key <keypair_name>.sec.pem <file_to_decrypt>
```

where `<keypair_name>.sec.pem` is the private key created in the [relevant section](#create-keys) and `<file_to_decrypt>` is one of the files downloaded following the instructions of the [download section](#download-file). The `--force-overwrite` flag can be used to over-write the decrypted file if it exists and the `--clean` flag to delete the encrypted file after successful decryption.

## Login

You can login to download the configuration file needed for some of the the tool's operation using the login command:

```bash
./sda-cli login <login_target>
```

where `login_target` is the URL to the `sda-auth` service from the [sensitive-data-archive](https://github.com/neicnordic/sensitive-data-archive/) project.

This will open a link for the user where they can go and log in.
After the login is complete, a configuration file will be created in the tool's directory with the name of `.sda-cli-session`

## Version

You can get the current version of the sda-cli by running:

```bash
./sda-cli version
```

## Htsget

You can download a (partial) file using the htsget server. You can define the name of the file you want to save the result to by using the `output` variable. If `output` is not defined, the file will keep it's original name. If the file already exists, it will not be over-written unless you use the `--force-overwrite` flag. `filename`, `host`, and `key` are required. `reference` refers to the part of the file you wish to download.

```bash
htsget -dataset <datasetID> -filename <filename> -reference <reference-number> -host <htsget-hostname> -pubkey <public-key-file> -output <file>
```

for example:

```
./sda-cli -config testing/s3cmd.conf htsget -dataset DATASET0001 -filename htsnexus_test_NA12878 -reference 11 -host http://localhost:8088 -pubkey testing/c4gh.pub.pem -output ~/tmp/result.c4gh --force-overwrite
```

# Developers' section

This section contains the information required to install, modify and run the `sda-cli` tool.

## Requirements

The `sda-cli` is written in golang. In order to be able to modify, build and run the tool, golang (>= 1.22) needs to be installed. The instructions for installing `go` can be found [here](https://go.dev/doc/install).

## Build tool

To build the `sda-cli` tool run the following command from the root folder of the repository

```bash
go build
```

This command will create an executable file in the root folder, named `sda-cli`.

# Create new release

The github actions include a release workflow that builds binaries for different operating systems. In order to create a new release, create a tag either using the graphical interface or through the command line. That should trigger the creation of a release with the latest code of the specified branch.

In order for the automatic release to get triggered, the releases should be of the format `vX.X.X`, e.g. `v1.0.0`.

## Update releaser

Before pushing a change to the releaser, make sure to run the check for the configuration file, running:

```sh
goreleaser check -f .goreleaser.yaml
```
