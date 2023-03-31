# Instructions to test uploading/downloading for BigPicture

## Get the repo
The command line tool `sda-cli`` can be obtained by
```    
git clone https://github.com/NBISweden/sda-cli
```

## Build the executable
The `sda-cli` executable can be built by the following command
> Make sure you have installed go >= 1.20, see 
https://go.dev/doc/install for instructions.

```
go build 
```

### Obtain the pub key for BicPicture

```
wget https://raw.githubusercontent.com/NBISweden/EGA-SE-user-docs/main/crypt4gh_bp_key.pub
```

### Obtain the configuration file for BicPicture

The configuration file can be obtained from https://login.bp.nbis.se/ with your university account. After login and seeing a page with a bunch of tokens, click `Download inbox s3cmd credentials` at the bottom of the page. The file is named `s3cmd.conf` if unchanged. Copy this config file to the `sda-cli` folder.

### Verify the setup

Verify if the `sda-cli` executable and the configuration file works with the command 

```
./sda-cli list -config s3cmd.conf
```
You should not to see any error message if it works. 

### Prepare data for uploading
> Make sure no sensitive data are used in testing 

You may create a large dummy file by 
``` 
mkfile -n 10g temp_10GB_file # for Mac user

fallocate -l 10G temp_10GB_file # for Linux user

fsutil file createnew temp_10GB_file 10000000000 # for Windows user
```

#### Encrypt you file before uploading
> suppose the file is named `temp_10GB_file`
```
./sda-cli encrypt -key crypt4gh_bp_key.pub temp_10GB_file
``` 

A file named `temp_10GB_file.c4gh` will be generated after successful run.

### Test file uploading
#### Upload one file

```
./sda-cli upload -config s3cmd.conf temp_10GB_file.c4gh 
```

Once uploading is succeeded, you can check it by listing the file on the server by 

```
./sda-cli list -config s3cmd.conf
```

### Upload multiple files with recursive uploading

Prepare multiple data files in a folder, e.g. `testing_dataset`, then you can upload all files in that folder by 
> Note that all files in subfolders will also be uploaded

```
./sda-cli upload -r  -config s3cmd.conf testing_dataset
```
