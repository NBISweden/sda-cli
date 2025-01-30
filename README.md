# SDA-CLI

This is the Sensitive Data Archive (SDA) Command Line Interface (sda-cli). This
tool was created to unify and simplify the utilities required to perform the most
common user actions in the SDA.

The tool can be used to encrypt and upload data when submitting it to the archive,
as well as to download and decrypt data when retrieving it from the archive.

It is recommended to use precompiled executables for `sda-cli`, which can be
found at https://github.com/NBISweden/sda-cli/releases.

To get help using the tool, run the following command

```bash
./sda-cli help
```

# Usage

The main functionalities of this tool are explained in the following sections.

Users unfamiliar with using a command line tools in a terminal window, may find the contents of [this article](https://ftpdocs.broadcom.com/cadocs/0/CA%20ARCserve%20%20Backup%2015-ENU/Bookshelf_Files/HTML/CMD_Ref/command_line_syntax_characters.htm)
and
[this](https://medium.com/@jaewei.j.w/how-to-read-man-page-synopsis-3408e7fd0e42) helpful.

## Encrypt

Files stored in the SDA/BP archive are encrypted using the [Crypt4GH
standard](https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/).
The sections below explain how to encrypt and upload files to the archive.

### Download the Crypt4GH public key file

Files uploaded to the SDA/BP services must be encrypted with the appropriate
public key. Depending on the service you are using, you can download
the key file with the following commands:

**For uploading to the SDA**:

```bash
wget https://raw.githubusercontent.com/NBISweden/EGA-SE-user-docs/main/crypt4gh_key.pub
```

**For uploading to Big Picture**:

```bash
wget https://raw.githubusercontent.com/NBISweden/EGA-SE-user-docs/main/crypt4gh_bp_key.pub
```

### Encrypt files

After downloading the public key file, you can encrypt your files using the
`sda-cli` executable obtained in the first step of this guide. To encrypt a
specific file, use the following command:

```bash
./sda-cli encrypt -key <public_key_file> <file_to_encrypt>
```

where `<public_key_file>` is the key file downloaded in the previous step. You
can also encrypt multiple files at once by listing them, separated by spaces,
as shown below:

```bash
./sda-cli encrypt -key <public_key_file> <file_1_to_encrypt> <file_2_to_encrypt>
```

The tool also provides a `-continue` option, which allows encryption to
continue even if one of the files fails. To enable this feature, run the
command like this:

```bash
./sda-cli encrypt -key <public_key_file> -continue=true <file_1_to_encrypt> <file_2_to_encrypt>
```

### Encrypt files with multiple keys

You can encrypt files using multiple public keys by specifying the `-key` flag
multiple times. For example:

```bash
./sda-cli encrypt -key <public_key_file1> -key <public_key_file2> <file_to_encrypt>
```

This command encrypts the file with two keys, allowing it to be decrypted using
either of the corresponding private keys. Encryption with more than two keys is
also supported.

Alternatively, you can use a single file containing concatenated public keys. To
create such a file, use a command like:

```bash
cat <public_key_file1> <public_key_file2> > <concatenated_public_key_file>
```

You can then provide this concatenated key file to the `-key` argument:

```bash
./sda-cli encrypt -key <concatenated_public_key_file> <file_to_encrypt>
```

Combining both approaches is also allowed. For instance:

```bash
./sda-cli encrypt -key <concatenated_public_key_file> -key <public_key_file3> <file_to_encrypt>
```

**Note**: The `encrypt` command generates four hash files (MD5 and SHA256) for
both the encrypted and unencrypted versions of the file.

**Developer Notes**: The tool creates a temporary key pair during the encryption
process for enhanced security.

## Upload

### Download the configuration file

After encrypting your files, they are ready to be uploaded to the SDA/BP
archive. Since the S3 storage requires user authentication, you must download a
configuration file before starting the upload process.

To obtain the configuration file, log in using your Life Science RI account:

- For BigPicture, visit https://login.bp.nbis.se/

Follow the dialogue to get authenticated and then click on `Download inbox s3cmd
credentials` to download the configuration file named `s3cmd.conf`. Place this
file in the same folder as the `sda-cli` executable you downloaded earlier.

The access token required for authentication can be provided in one of three
ways, listed in order of priority:

1. Using the `-accessToken` flag in the command.
2. From the `ACCESSTOKEN` environment variable.
3. In the configuration file.

### Upload files

Once the configuration file has been downloaded, files can be uploaded to the
archive using the `sda-cli` executable. To upload a specific file, use the
following command:

```bash
./sda-cli -config <configuration_file> upload <encrypted_file_to_upload>
```

where `<configuration_file>` refers to the configuration file downloaded in the
previous step, and `<encrypted_file_to_upload>` refers to a file encrypted in
the earlier steps.

The tool also supports uploading multiple files simultaneously by listing them,
separated by spaces, as shown below:

```bash
./sda-cli -config <configuration_file> upload <encrypted_file_1_to_upload> <encrypted_file_2_to_upload>
```

**Note**:

- By default, files are uploaded to the user's base directory on the archive.
- If the input contains unencrypted files, the process will exit early. To
override this behavior, use the `-force-unencrypted` flag.

### Upload folders

You can upload entire directories recursively, including all contained files and
subfolders while preserving the local folder structure. This can be done using
the `-r` flag. For example:

```bash
./sda-cli -config <configuration_file> upload -r <folder_to_upload>
```

This command uploads `<folder_to_upload>` to the archive, maintaining its internal
folder and file structure.

You can also upload multiple directories and files in a single command. For example:

```bash
./sda-cli -config <configuration_file> upload -r <encrypted_file_1_to_upload> <encrypted_file_2_to_upload> <folder_1_to_upload> <folder_2_to_upload>
```

**Note**: If the `-r` flag is omitted, any specified folders will be skipped
during the upload.

### Upload to a different path

You can specify a custom path for uploading files or folders using the
`-targetDir` flag, followed by the desired folder name. For example:

```bash
./sda-cli -config <configuration_file> upload -r <encrypted_file_1_to_upload> <folder_1_to_upload> -targetDir <upload_folder>
```

This command creates `<upload_folder>` under the user's base folder and uploads
the contents as follows:

- `<upload_folder>/<encrypted_file_1_to_upload>`
- `<upload_folder>/<folder_1_to_upload>`

The `<upload_folder>` argument can also include a folder path, such as
`folder1/folder2`. In this case, `<encrypted_file_1_to_upload>` will be uploaded
to `folder1/folder2/<encrypted_file_1_to_upload>`.

**Note**: To include all the contents of a directory without the directory
itself, you can append `/.` to `<folder_to_upload>`. For instance:

```bash
./sda-cli -config <configuration_file> upload -r <folder_to_upload>/. -targetDir <new_folder_name>
```

This command uploads all the contents of `<folder_to_upload>` to
`<new_folder_name>` recursively, effectively renaming `<folder_to_upload>` to
`<new_folder_name>` in the archive.

### Encrypt on upload

You can combine the encryption and upload steps using the `-encrypt-with-key`
flag, followed by the path to the Crypt4GH public key for encryption. In this
case, the input list of files can only contain unencrypted files. For
example:

```bash
./sda-cli -config <configuration_file> upload -encrypt-with-key <public_key_file> <unencrypted_file_to_upload>
```

This command encrypts `<unencrypted_file_to_upload>` using `<public_key_file>`
and uploads the resulting `<file_to_upload.c4gh>` to the user's base folder.

The encrypt on upload feature can be combined with other flags. For example:

```bash
./sda-cli -config <configuration_file> upload -encrypt-with-key <public_key_file> -r <folder_to_upload_with_unencrypted_data> -targetDir <new_folder_name>
```

This command encrypts all files in `<folder_with_unencrypted_data>` and uploads
the folder recursively (including only the resulting `.c4gh` files) under
`<new_folder_name>`.

**Notes**:

- The command internally calls the [encrypt](#Encrypt) module when performing
encrypt-on-upload, mirroring its behavior, including the creation of hash files.
- For encryption with [multiple public keys](#Encrypt-files-with-multiple-keys),
concatenate all public keys into a single file and provide it using the
`-encrypt-with-key` flag.
- If the input includes already encrypted files, the process will exit without
further processing.
- Encrypted files are created in the same directory as their unencrypted counterparts.
- If encrypted counterparts of the input files already exist, the process will
exit without further processing.
- If a file has already been uploaded, the process will exit without further
processing. To overwrite existing files, use the `-force-overwrite` flag.

## List

Before using the `list` functionality, ensure you have [downloaded the configuration file](#download-the-configuration-file).

### List uploaded files

You can retrieve all the files along with their sizes in the user's inbox,
including those in subdirectories, recursively using the following command:

```bash
./sda-cli [-config <configuration_file>] list
```

You can also list files or file paths with a specific prefix by using:

```bash
./sda-cli [-config <configuration_file>] list <prefix>
```

This command will return all files or paths that start with the specified `<prefix>`.

### List datasets

To list datasets or the files within a dataset that the user has access to, use
the `-datasets` flag and provide the download service URL:

```bash
./sda-cli -config <configuration_file> list -datasets (-bytes) -url <download-service-url>
```

where `<download-service-url>` is the URL for the SDA download service. The
command will return a list of accessible datasets, including the number of files
and the total size of each dataset. The `-bytes` flag is optional and displays
the dataset size in bytes when enabled.

### List files within a dataset

To list the files within a specific dataset, use the dataset ID (retrieved from
the previous command):

```bash
./sda-cli -config <configuration_file> list -dataset <datasetID> (-bytes) -url <download-service-url>
```

This command returns a list of files within the sepcified dataset, including
file IDs, sizes, and paths. The `-bytes` flag is optional and displays file
sizes in bytes.

## Download

Before using the `download` functionality, ensure you have [downloaded the configuration file](#download-the-configuration-file).

Depending on the setup of the SDA/BP services, files can be downloaded
unencrypted or encrypted.

If the download service is configured for encrypted downloads, you can download files
encrypted on the server-side by providing a
[public key file](#create-crypt4gh-key-pair) using the `-pubkey` flag. For
detailed instructions, refer to [download encrypted files](#download-encrypted-files).

The following options are available for downloading files:

- Download specific files by their paths.
- Download specific files by their file IDs.
- Download multiple files recursively.
- Download multiple files by providing a text file listing file paths.
- Download all files in a dataset.

The file paths and fileIDs can be obtained by [listing files of a dataset](#list-files-within-a-dataset).

### Download specific files of a dataset

#### Using file paths

To download a specific file from a dataset by their file path, use the following
command:

```bash
./sda-cli -config <configuration_file> download -dataset-id <datasetID> -url <download-service-URL> <filepath>
```

where `<configuration_file>` refers to the configuration file downloaded in the
[previous step](#download-the-configuration-file), `<datasetID>` is the ID of
the dataset, and `<filepath>` is the path of the file in the dataset that you
want to download.

To download multiple files using their file paths, list them separated by
spaces.

```bash
./sda-cli -config <configuration_file> download -dataset-id <datasetID> -url <download-service-url> <filepath_1> <filepath_2>
```

By default, files are downloaded to the current directory. To specify a custom
output folder, use the `-outdir` flag. Additionally, if `<filepath>` includes a
nested folder structure, the original directory hierarchy will be preserved
during the download process.

#### Using file IDs

Downloading specific files by their file IDs follows the same syntax as
downloading files by file paths. The only difference is that you replace the
file paths with their corresponding file IDs. Ensure that the file IDs do not
contain slashes (`/`).

### Download files recursively

To download the contents of a folder, including all subfolders, use the
`-recursive` flag followed by the folder path. For example:

```bash
./sda-cli -config <configuration_file> download -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> -recursive <path_to_folder> 
```

This command preserves the folder structure of the specified directories during
the download process.

To recursively download multiple folders, list them separated by spaces.

### Download files from a list file

To download multiple files, you can also provide a text file containing the file
paths. Each path should be on a separate line. Use the `-from-file` flag followed
by the path to the text file, as shown below:

```bash
./sda-cli -config <configuration_file> download -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> -from-file <path_to_list_file>
```

This approach simplifies downloading large numbers of files.

### Download all the files of a dataset

To download all files in a dataset, use the `-dataset` flag without providing
any argument.

```bash
./sda-cli -config <configuration_file> download -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> -dataset
```

The dataset will be downloaded to the `<outdir>`, preserving its original folder
structure.

### Download encrypted files

When a [public key](#create-crypt4gh-key-pair) is provided, you can download
files encrypted on the server-side with that key. The syntax is similar to
downloading unencrypted files, but includes the `-pubkey` flag to specify the
public key. For example:

```bash
./sda-cli -config <configuration_file> download -pubkey <public-key-file> -dataset-id <datasetID> -url <download-service-url> -outdir <outdir> <filepath_1> <filepath_2>
```

After a successful download, the encrypted files will be saved to `<outdir>`,
maintaining their original folder structure. These files can then be
[decrypted](#decrypt-files) using the private key corresponding to the provided
public key.

## Create Crypt4GH key pair

To create a Crypt4GH key pair, run the following command:

```bash
./sda-cli createKey <name>
```

where `<name>` is the base name for the key files to be generated.
This command will two files:

- `<name>.pub.pem` (public key)
- `<name>.sec.pem` (private key)

**Notes**:

- The keys generated with this command are intended solely for decrypting files
that are downloaded from the archive, using the corresponding custom public key.
- These keys **should not** be used for encrypting submission files to the archive.

## Decrypt files

To decrypt an encrypted file downloaded from the download service of SDA, use
the following command:

```bash
./sda-cli decrypt -key <private-key-file> <file_to_decrypt>
```

where `<private-key-file>` is the private key of the [Crypt4GH key
pair](#create-crypt4gh-key-pair) created along with the public key that has been
used to [download the file](#download-encrypted-files).

By default, the command skips decrypting a file if its unencrypted counterpart
already exists. To override this behavior, use the `-force-overwrite` flag.
Optionally, the `-clean` flag can be used to delete the encrypted file after
successful decryption. Otherwise, both the encrypted and decrypted files will
remain after decryption.

To decrypt multiple files at once, list them separated by spaces, like this:

```bash
./sda-cli decrypt -key <private-key-file> <file_1_to_decrypt> <file_2_to_decrypt>
```

## Download files using htsget

You can download a (partial) file using the htsget server. 

```bash
./sda-cli -config <configuration_file> htsget -dataset <datasetID> -filename <filepath> -reference <reference-number> -host <htsget-hostname> -pubkey <public-key-file> 
```

where `<configuration_file>` refers to the configuration file downloaded in the
[previous step](#download-the-configuration-file), `<datasetID>` is the ID of
the dataset, `<filepath>` is the path of the file in the dataset that you
want to download, `<reference-number>` specifies the specific part of the file
to download, `<htsget-hostname>` is the URL of the htsget server, and
`<public-key-file>` is the [public key](#create-crypt4gh-key-pair) used to
server-side encrypt the downloaded file.

By default, the downloaded file retains its original name. You can use the
`-output` flag to specify a custom name for the file.
Additionally, existing files will **not** be overwritten unless the `-force-overwrite`
flag is set.

---

# Developers' section

This section contains the information required to install, modify, and run the
`sda-cli` tool.

## Requirements

The `sda-cli` is written in Go. To modify, build, and run the tool, Go (>= 1.22)
needs to be installed. Instructions for installing `Go` can be found
[here](https://go.dev/doc/install).

## Build tool

To build the `sda-cli` tool run the following command from the root folder of
the repository

```bash
go build
```

This command will create an executable file in the root folder, named `sda-cli`.

## Create a new release

The Github Actions include a release workflow that builds binaries for different
operating systems. To create a new release, create a tag either using
the graphical interface or through the command line. This should trigger the
creation of a release with the latest code from the specified branch.

For the automatic release to be triggered, the releases should follow the format
`vX.X.X`, e.g., `v1.0.0`.

### Update releaser

Before pushing a change to the releaser, make sure to check the configuration
file by running:

```sh
goreleaser check -f .goreleaser.yaml
```

## Features under development

### Login

You can log in to download the configuration file required for some of the
tool's operations using the login command:

```bash
./sda-cli login <login_target>
```

where `login_target` is the URL of the `sda-auth` service from the
[sensitive-data-archive](https://github.com/neicnordic/sensitive-data-archive/)
project.

This will open a link where the user can log in.
After login is complete, a configuration file named `.sda-cli-session` will be
created in the tool's directory.
