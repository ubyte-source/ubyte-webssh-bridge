FROM golang:alpine AS build-stage 

COPY ws /app

WORKDIR /app

RUN go mod download
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -o ubyte-webssh-bridge .

FROM amd64/alpine:3.19

ENV STARTUP_COMMAND_RUN_NGINX="nginx"
ENV STARTUP_COMMAND_RUN_UBYTE="/usr/local/bin/ubyte-webssh-bridge | ubyte-webssh-bridge"
ARG TIMEZONE="UTC"

RUN apk update && \
    apk add --no-cache nginx nginx-mod-stream curl && \
    apk add --no-cache bash openssl && \
    apk add --no-cache tzdata && \
    mkdir -p /var/www /data && \
    rm -rf /var/cache/apk/*

COPY wrapper /usr/sbin/wrapper
COPY healthcheck /usr/sbin/healthcheck
COPY frontend /var/www
COPY nginx /etc/nginx

COPY --from=build-stage /app/ubyte-webssh-bridge /usr/local/bin/ubyte-webssh-bridge

RUN adduser -D -g www www && \
    chown -R www:www /var/lib/nginx /var/log/nginx /var/www /data /etc/nginx && \
    chmod +x /usr/sbin/wrapper /usr/sbin/healthcheck /usr/local/bin/ubyte-webssh-bridge && \
    rm -Rf /etc/nginx/sites-enabled /etc/nginx/sites-available && \
    cp -r /usr/share/zoneinfo/${TIMEZONE} /etc/localtime && \
    echo "${TIMEZONE}" > /etc/timezone

EXPOSE 8443/tcp

USER www

HEALTHCHECK --interval=12s --timeout=4s CMD /usr/sbin/healthcheck

ENTRYPOINT /usr/sbin/wrapper
