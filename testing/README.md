# Testing material

All the files included in this folder are support material for the integration tests.

## How to test the device authorization flow implemented by the login command

From the current (`testing/`) directory and run:

```sh
export TAG=v0.2.103 && docker compose --profile login up auth oidc --build --force-recreate
```

and from another terminal:

```sh
go build .
./sda-cli login http://localhost:8080
```

After the login succeeds there should be a `.sda-cli-session` file created in the current directory. To cleanup the environment run:

```sh
docker compose --profile login down --remove-orphans -v
```