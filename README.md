# Docker FastPath

Docker FastPath is a command line utility that interacts with your Git repo and your Docker image registry to allow you to avoid building an image for the same codebase more than once. It analyzes your git history and check if an image suitable for your current codebase is already available in your Docker image registry. For an introduction to Docker FastPath, please read my [blog post](???).

## Examples
Two deployment examples are provided:
* [docker-fastpath-jenkins](https://github.com/mfornasa/docker-fastpath-jenkins), based on Jenkins Pipelines
* [docker-fastpath-travis](https://github.com/mfornasa/docker-fastpath-travis), based on Travis CI.

It should be easy to use those examples to adapt FastPath to your existing software project based on Docker.

## Usage
```
       fastpath [<options>] <revspec> <image-name>

DESCRIPTION
       <revspec> can be a reference ("HEAD") or a SHA commit id.
       <image-name> is the name of the Docker image (without the tag).


       If you use `docker login` before running this command, Docker registry
       credentials are taken from Docker client local configuration.

       Credentials can also be specified using DOCKER_USERNAME and
       DOCKER_PASSWORD environment variables.

OPTIONS
       -v, --verbose             Be verbose
       -q, --quiet               Be quiet
```

## Installing
### Prerequisites
* Docker >= 1.7

### Linux
Fastpath is available in binary form for 64-bit Linux systems.

1. Download the [latest release](https://docker-fastpath.s3-eu-west-1.amazonaws.com/releases/linux/docker-fastpath-linux-amd64-latest.tgz)
2. Run `tar xzvf docker-fastpath-linux-amd64-latest.tgz` to extract the executable file
3. Run `./fastpath`

### macOS
1. Download the [latest release](https://docker-fastpath.s3-eu-west-1.amazonaws.com/releases/osx/docker-fastpath-osx-latest.zip)
2. Run `unzip docker-fastpath-osx-latest.zip` to extract the executable file
3. Run `./fastpath`


## Building
FastPath is available as a binary for macOS and for Linux. If you prefer to build from source, see the following build instructions.

### Linux
The Linux version is statically linked to `libgit2` v.0.25.1 and to `libcurl` 7.53.1 to provide recent versions not usually available out-of-the-box on common distributions.

The following procedure has been tested on Ubuntu Precise, but the package should be buildable on most recent distributions.

```
apt-get update
apt-get install build-essential cmake
mkdir build && cd build
cmake ..
make
```

The executable is availble as `build/fastpath`.


## MacOS

The MacOS version is statically linked to `libgit2` v.0.25.1 (approach reccomended by `libgit2` maintainers) and to `libcurl` 7.53.1 (to provide a recent version not usually available on XCode.

```
brew install libssh2
brew install cmake
brew install openssl
mkdir build && cd build
cmake ..
make
```

The executable is availble as `build/fastpath`.

