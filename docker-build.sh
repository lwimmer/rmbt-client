#!/bin/sh

docker build --build-arg "GIT_VERSION=$(git describe --abbrev=9 --dirty --always --tags --long 2> /dev/null)" -t rmbt .
