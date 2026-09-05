# go-carta

[![Go Reference](https://pkg.go.dev/badge/github.com/CARTAvis/go-carta.svg)](https://pkg.go.dev/github.com/CARTAvis/go-carta)

## Required tools and packages

### Golang

### Protocol buffer compiler and grpc plugin

The protocol buffer compiler and grpc plugin can be installed in a number of ways:

golang:
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
# verify:
which protoc-gen-go-grpc
which protoc-gen-go
```

homebrew (macOS):
```bash
brew install protoc-gen-go protoc-gen-go-grpc
```

apt-get (ubuntu):
```bash
sudo apt install protoc-gen-go protoc-gen-go-grpc
```

Tested with: 
- `protoc-gen-go v1.36.6` and `protoc-gen-go-grpc v1.5.1` (macOS)
- `protoc-gen-go v1.32.0` and `protoc-gen-go-grpc v1.0` (ubuntu 24.04.2 LTS)

### cfitsio

The worker service uses cgo to compile some simple functions that utilise cfitsio. Install `libcfitsio-dev` (ubuntu) or `cfitsio` (macOS homebrew).

## Build
Ensure the `carta-protobuf` submodule is initialised:
```shell
git submodule update --init
```
gRPC files need to be built first, followed by the services. Use the provided Makefile:

```shell
# From the project root
make proto     # Build gRPC protobuf files
make services  # Build all services
```

For other development tasks, see available commands:
```bash
make help
```

## Run

Compiled services are found in the `build` folder.

```bash
# From the project root
./build/carta-spawn --worker_exec build/worker --port 8080
./build/carta-ctl --spawner_address http://localhost:8080 --port 8081
```

## Configure

Common configuration options can be provided as optional parameters to service commands. Invoke the service with `--help` to see a list of available commands. The recommended way to configure persistent options is through a configuration file in [TOML format](https://toml.io). An annotated [example configuration file](config.toml.example) is provided. By default, services look for configuration in `/etc/carta/config.toml`.

You can specify a different file location with a command line parameter, for example:

```bash
./build/carta-spawn --config=./config.toml
```

Configuration options with string, integer or boolean values can also be overridden on the commandline with the `--override` parameter.

### Configuring the controller

#### Authentication

The `auth_mode` parameter is used to enable different authentication methods. For example, this command launches the controller with only PAM authentication enabled. A custom service name can be set in the configuration file.

```bash
./build/carta-ctl --auth_mode=pam
```

The controller can also be integrated with an OIDC service such as Keycloak. In this case, `auth_mode` must be set to `oidc`, and additional configuration is required to set properties such as the service URL and the secret. These options are not available as command line parameters, and must be set in the main configuration file. Here is an example of typical values:

```toml
[controller]
auth_mode = "oidc"

[controller.oidc]
issuer_url = "http://localhost:8080/realms/carta"
client_id = "carta-ctl"
client_secret = "YOUR_OIDC_SECRET"
redirect_url = "http://localhost:8081/oidc/callback"
```

#### Frontend directory

To configure the controller to serve the frontend, you must provide a path to the root directory of a static frontend build:

```bash
./build/carta-ctl --frontend_dir=/usr/share/carta/frontend
```

### Configuring the spawner

#### Worker executable

A common initial use case for `go-carta` is as a replacement for the old CARTA controller: in this scenario, the spawner must be configured to use the CARTA backend executable to launch worker processes. This option may be set on the command line or in the configuration file (as in the example file).

```bash
./build/carta-spawn --worker_exec=carta_backend
```

The spawner will attempt to launch the worker executable using `sudo` and must be given the ability to launch instances of the executable password-lessly for permitted users. Workers are started without a controlling terminal, so the sudoers configuration must not set `requiretty`. For single-user or development machines the `run_as_current_user` option launches workers directly instead.  This is likely to require [modifying the sudoers configuration](https://www.sudo.ws/man/1.9.0/sudoers.man.html).  For example the sudoers rule below will allow the user `carta` to launch instances of the backend for any user in the `carta-users` group.

```
# carta user can run the carta_backend command as any user in the carta-users group without entering password
carta ALL=(%carta-users) NOPASSWD:SETENV: /usr/bin/carta_backend
```