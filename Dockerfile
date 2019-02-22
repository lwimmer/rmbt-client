#####
FROM alpine AS build-env
RUN apk add --no-cache util-linux-dev gcc autoconf automake make openssl-dev json-c-dev musl-dev

ADD . /work
WORKDIR /work

ARG GIT_VERSION
RUN GIT_VERSION=${GIT_VERSION:-unknown} ./autobuild.sh

#####
FROM alpine
ARG GIT_VERSION
LABEL version=${GIT_VERSION:-unknown}
RUN apk add --no-cache libuuid json-c
COPY --from=build-env /work/src/rmbt /bin/rmbt
ENTRYPOINT ["/bin/rmbt"]
