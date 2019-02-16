FROM alpine AS build-env
RUN apk add --no-cache util-linux-dev gcc autoconf automake make openssl-dev json-c-dev musl-dev git

ADD . /work
WORKDIR /work

RUN ./autobuild.sh

FROM alpine
RUN apk add --no-cache libuuid json-c
COPY --from=build-env /work/src/rmbt /bin/rmbt
ENTRYPOINT ["/bin/rmbt"]
