rmbt-client - RMBT speed measurement client in C
===========

For more information and the server code see also https://github.com/alladin-IT/open-rmbt

This code is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

Building
--------

rmbt-client has the following requirements:

* `autoconf`, `automake`, `make`
* `gcc`, `clang` or another C compiler
* `libuuid`
* `libssl`, `libcrypto`
* `libjson-c`
* (`xz-utils` / `liblzma`)
* (`git`)

To install the required build dependencies on `apt` based distos (Debian, Ubuntu, ...) run:

```
sudo apt install libc-dev git autoconf automake make gcc pkg-config libjson-c-dev libssl-dev uuid-dev liblzma-dev
```

For `yum` based distros (CentOS, Fedora, ...) this should work:

```
yum install git autoconf automake make gcc json-c-devel openssl-devel libuuid-devel xz-devel
```

To build simply run:

```
git clone https://github.com/lwimmer/rmbt-client
cd rmbt-client
./autobuild.sh
```

To install run:
```
make install
```

Running
-------

To run rmbt-client you need to supply rmbt-client with the configuration.

For the most important parameters this can be done via the command line (see `rmbt -?`):

```
-c     json config file; use "-" to read from stdin
-b     local ip to bind
-h     host to connect to
-p     port to connect to
-e     connect using SSL/TLS
-t     token to use (either -t or -s is needed)
-s     secret for token generation
-f     number of flows
-d     measurement duration for downlink
-u     measurement duration for uplink
-n     number of rtt_tcp_payloads
```

Alternatively a JSON configuration file can be supplied via stdin (`rmbt -c -`) or as a file (`rmbt -c config.json`).

A minimum configuration file could look something like this:
```
{
  "cnf_server_host": "127.0.0.1",
  "cnf_server_port": 8081,
}
```

For more information see the file [`config.example.json`](config.example.json).
