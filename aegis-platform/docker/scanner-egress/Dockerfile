FROM alpine:3.22

RUN apk add --no-cache nftables iproute2 libc-utils ca-certificates

COPY entrypoint.sh /usr/local/bin/aegis-scanner-egress
RUN chmod 0755 /usr/local/bin/aegis-scanner-egress

ENTRYPOINT ["/usr/local/bin/aegis-scanner-egress"]
