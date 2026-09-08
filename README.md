# HedgeWeb

HedgeWeb is a small, self-hosted infrastructure workspace designed for deployment behind Traefik and Authentik. It provides a desktop-style web interface, an SSH connection manager, browser preview, application scaling, and an optional OpenVPN access tunnel with TOTP challenge-response.

## Current status

HedgeWeb is an early preview. It is suitable for evaluation and a personal, single-user deployment. It has not received an independent security assessment and must not yet be treated as a production-grade privileged-access platform.

The OpenVPN implementation currently creates one tunnel for the entire HedgeWeb deployment. All server-side SSH connections share that network namespace while the tunnel is active. Do not use this release for multiple mutually untrusted users. Per-user browser, SSH, RDP, and VPN workers are planned.

## Security model

- Authentik identity headers are accepted only from exact addresses in `TRUSTED_PROXY_IPS`.
- Local passwords are hashed with scrypt and unique random salts.
- Local login is throttled after repeated failures.
- Session cookies are opaque, HTTP-only, SameSite Lax, and held in server memory.
- SSH passwords exist only for the lifetime of their connection and are not written to persistent storage.
- SSH host keys require explicit verification and are pinned per profile.
- Only administrators may modify SSH or VPN configuration.
- The application container is unprivileged, read-only, and has all Linux capabilities dropped.
- The VPN agent has a read-only filesystem and drops every capability except `NET_ADMIN`.
- Imported OpenVPN profiles are encrypted with AES-256-GCM.
- OpenVPN profiles containing executable hooks, plugins, credential blocks, or management interfaces are rejected.
- VPN credentials and TOTP responses are written only to a restricted tmpfs and removed when the tunnel exits.
- Redirected default routes are ignored; the VPN endpoint should push only explicitly approved routes.

The VPN agent necessarily has elevated network privileges. Keep the Docker daemon, host, images, dependencies, Traefik, Authentik, and OpenVPN endpoint patched and independently secured.

## Local Docker deployment

Copy `.env.example` to `.env.docker`, set a bootstrap administrator password of at least 16 characters, and run:

```sh
docker compose -f compose.local.yaml up -d --build
```

The local stack binds HedgeWeb to `127.0.0.1:8080`. The OpenVPN agent has no published management port.

After the administrator has been created, remove `BOOTSTRAP_ADMIN_PASSWORD` from `.env.docker` and recreate the application container.

## Production prerequisites

1. Create the external Docker network used by Traefik:

   ```sh
   docker network create proxy
   ```

2. Generate a 32-byte VPN configuration key and save its base64 representation to `secrets/vpn_config_key`:

   ```sh
   mkdir -p secrets
   openssl rand -base64 32 > secrets/vpn_config_key
   chmod 600 secrets/vpn_config_key
   ```

3. Set `PUBLIC_ORIGIN`, `TRUSTED_PROXY_IPS`, authentication mode, and bootstrap values in a local `.env` file. Never commit `.env`, `.env.docker`, `secrets/`, VPN profiles, certificates, or the data volume.

4. Start the production stack:

   ```sh
   docker compose up -d --build
   ```

Traefik should route to `hedgeweb:8080` on the external `proxy` network. The `hedgeweb` alias belongs to the VPN network namespace shared by the application container.

## Authentik and Traefik

Use Authentik forward authentication and forward these response headers:

- `X-Authentik-Username`
- `X-Authentik-Email`
- `X-Authentik-Groups`

Set `TRUSTED_PROXY_IPS` to the exact direct peer address that HedgeWeb sees for Traefik. Do not use a subnet or wildcard. Traefik must discard identically named headers supplied by clients before setting authenticated values.

Set `PUBLIC_ORIGIN` to the exact external HTTPS origin without a trailing slash. Do not expose HedgeWeb directly when `AUTH_MODE=authentik` is used.

## VPN profiles

The VPN settings page accepts inline OpenVPN client profiles. Embed CA, client certificate, private key, and TLS key material inside the profile rather than referencing host files. `auth-user-pass` is supplied securely by the VPN agent and may be omitted.

The client supports password-only authentication and the OpenVPN `SCRV1` static challenge format used for password plus TOTP. A YubiKey can hold the TOTP secret through Yubico Authenticator. Direct USB or PKCS#11 forwarding into the container is intentionally unsupported.

## Development

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm start
```

For HTTP development only, set `COOKIE_SECURE=false` and use an HTTP `PUBLIC_ORIGIN`.

## Responsible deployment

Before placing HedgeWeb on an untrusted network, perform an independent review, add per-user worker isolation, configure firewall allowlists outside Docker, enable centralized audit logging, pin container image digests, and establish a tested update and backup process.
