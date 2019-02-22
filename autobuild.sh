#!/bin/sh
set -e
[ -e configure ] || autoreconf -i
[ -e Makefile ]  || ./configure
make ${GIT_VERSION:+GIT_VERSION="$GIT_VERSION"}
