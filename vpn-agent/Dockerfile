FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN apk add --no-cache nodejs openvpn iproute2
RUN addgroup -S vpnagent && adduser -S -G vpnagent vpnagent
WORKDIR /opt/vpn-agent
COPY --chown=vpnagent:vpnagent server.mjs ./server.mjs
EXPOSE 9090
CMD ["node", "server.mjs"]
