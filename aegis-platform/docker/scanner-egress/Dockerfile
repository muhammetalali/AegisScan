FROM mirror.gcr.io/library/alpine:3.22

RUN apk add --no-cache nftables iproute2 libc-utils ca-certificates python3

COPY entrypoint.sh /usr/local/bin/aegis-scanner-egress
COPY control.py /usr/local/lib/aegis-egress-control.py
RUN chmod 0755 /usr/local/bin/aegis-scanner-egress /usr/local/lib/aegis-egress-control.py

ENTRYPOINT ["/usr/local/bin/aegis-scanner-egress"]
