# NavoMTP — One-Click Telemt MTProto Proxy Installer with Docker, Nginx SNI and FakeTLS

[简体中文](README.zh-CN.md) | [English](README.md) | [Русский](README.ru.md)

> Deploy and manage a [Telemt](https://github.com/telemt/telemt)-based Telegram MTProto Proxy on a Debian or Ubuntu VPS. NavoMTP installs Docker when needed, routes FakeTLS traffic by camouflage-domain SNI with Nginx `ssl_preread`, and supports multiple public proxy ports.

NavoMTP is designed for users looking for a practical **Telegram MTProxy / MTProto Proxy installer** with Docker Compose, Nginx SNI routing, FakeTLS, `ad_tag` support, and a terminal management interface. You do not need to write `config.toml`, Compose, or Nginx stream configuration by hand.

If NavoMTP helps you, please give the repository a **Star** so more people can discover the project.

Discover more Navo projects, products, and updates on the [official Navo website](https://www.navo.im/).

## Why NavoMTP?

| Feature | What it does |
| --- | --- |
| One-click Telemt setup | Detects Docker and installs Docker Engine plus the Compose plugin from Docker's official apt repository when missing |
| Interactive terminal UI | Configures the public address, multiple ports, username, secret, optional `ad_tag`, and FakeTLS camouflage domain |
| Nginx SNI routing | Uses `stream` and `ssl_preread` to forward only the configured camouflage-domain traffic to Telemt |
| Multiple MTProxy ports | Exposes one Telemt instance through multiple public TCP ports and creates a connection link for each port |
| Reduced exposure | Publishes only Nginx ports; Telemt `9443`, Metrics, and the Control API remain private |
| Original client IP | Uses PROXY protocol between Nginx and Telemt and trusts only the dedicated Docker-network peer |
| Validation and rollback | Validates candidate configurations and restores the previous deployment after a failed start or image update |
| Operations menu | Reconfigure, inspect status, follow logs, update images, display links, or uninstall from one menu |

## How It Works

```text
Telegram client
      │ FakeTLS with the configured SNI
      ▼
Public ports: 443, 12432, 22124 ...
      │
      ▼
Nginx stream + ssl_preread
      │
      ├─ Matching camouflage-domain SNI ──► Telemt:9443 ──► Telegram
      └─ Wrong SNI / no SNI / non-TLS ──► rejected
```

Nginx never forwards traffic to an arbitrary hostname supplied by a client, so the server does not become an open TCP proxy. Because this deployment relies on TLS SNI, it enables Telemt FakeTLS mode only; Classic and Secure modes are disabled.

## Requirements

- Debian or Ubuntu with systemd;
- `amd64` or `arm64` architecture;
- root or sudo access;
- outbound access to Docker's repository, GitHub, GHCR, and the selected camouflage website;
- cloud firewall/security-group access for the selected public TCP ports.

## Quick Telemt MTProxy Installation

After downloading the project, run:

```bash
chmod +x navomtp.sh
sudo bash navomtp.sh
```

To open the installation flow directly:

```bash
sudo bash navomtp.sh install
```

The terminal wizard asks for:

1. A public IPv4 address or public hostname;
2. One or more TCP ports, such as `443,12432,22124`;
3. A Telemt username;
4. A 32-character hexadecimal secret, or an empty value to generate one securely;
5. An optional `ad_tag`;
6. A FakeTLS camouflage domain, such as `www.microsoft.com`.

After deployment, NavoMTP prints `tg://proxy` and `https://t.me/proxy` links for every public port. These links contain the proxy secret and should not be posted publicly.

## Management Commands

Run without arguments to open the management menu:

```bash
sudo bash navomtp.sh
```

Or run a command directly:

```bash
sudo bash navomtp.sh configure   # Change ports, secret, ad_tag, or camouflage domain
sudo bash navomtp.sh status      # Show Telemt and Nginx container status
sudo bash navomtp.sh logs        # Follow service logs
sudo bash navomtp.sh update      # Update images with automatic rollback on failure
sudo bash navomtp.sh links       # Display Telegram proxy links again
sudo bash navomtp.sh uninstall   # Remove NavoMTP without uninstalling Docker
```

## Generated Telemt and Nginx Configuration

Managed files are stored in `/opt/navomtp` by default:

```text
/opt/navomtp/
├── compose.yaml
├── config/telemt.toml
├── nginx/nginx.conf
├── state.env
├── links.txt
├── image-digests.txt
└── backups/
```

- `state.env` and `links.txt` are readable by root only;
- `telemt.toml` is readable only by root and the dedicated Telemt container GID;
- a timestamped backup is created before a configuration change;
- uninstalling NavoMTP does not remove Docker Engine or shared container images.

## Network and Security Notes

- Telemt listens on `9443` inside the Docker network only;
- Metrics on `9090` and the Control API on `9091` are not published;
- wrong SNI, missing SNI, and non-TLS connections are rejected quickly;
- the camouflage domain does not need to resolve to your proxy server, but it must resolve and serve HTTPS normally;
- all public ports share one Telemt user, secret, and camouflage domain;
- if UFW is active, NavoMTP asks before opening the selected ports;
- cloud security groups must be configured manually;
- make sure operating a proxy complies with the laws and service terms applicable to the server and its users.

## Frequently Asked Questions

### Can NavoMTP install Docker automatically?

Yes. It checks Docker Engine and Docker Compose first. If they are missing, it installs them from Docker's official apt repository. It does not silently remove an existing `docker.io`, Podman, or third-party container installation.

### Can one Telegram MTProxy use multiple ports?

Yes. Enter comma-separated ports such as `443,12432,22124`. Every port routes to the same Telemt instance and secret, and NavoMTP produces a separate Telegram connection link for each port.

### Must the camouflage domain point to the VPS?

No. It is the SNI front used by FakeTLS traffic. Choose a stable domain that resolves correctly and provides a working HTTPS endpoint.

### Why is FakeTLS the only enabled Telemt mode?

This setup routes connections by reading SNI from the TLS ClientHello. Telemt Classic and Secure modes do not provide the TLS SNI required by this strict Nginx entry point, so they are disabled.

### The containers are healthy, but Telegram cannot connect. What should I check?

Check the cloud security group, UFW, port conflicts, `sudo bash navomtp.sh status`, and `sudo bash navomtp.sh logs`. Also verify the public address, port, and secret in the client link. A healthy container alone does not prove end-to-end Telegram connectivity.

### How do I configure an MTProxy promotion channel and ad tag?

Obtain a 32-character hexadecimal `ad_tag` from Telegram's official `@MTProxybot`, then run `configure`. Keep using the FakeTLS links generated by NavoMTP rather than an outdated link or port returned during registration.

## Testing

Run local checks without Docker:

```bash
bash -n navomtp.sh
bash tests/test_navomtp.sh
shellcheck navomtp.sh tests/test_navomtp.sh
```

A production deployment should also be tested with a real Telegram client through every public port.

## Related Projects and Official Documentation

- [Telemt — MTProxy in Rust and Tokio](https://github.com/telemt/telemt)
- [Telemt Docker Compose quick start](https://github.com/telemt/telemt/blob/main/docs/Quick_start/QUICK_START_GUIDE.en.md#telemt-via-docker-compose)
- [Nginx stream ssl_preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)
- [Docker Engine for Debian](https://docs.docker.com/engine/install/debian/)
- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

## Disclaimer

NavoMTP is an independent community deployment tool and is not officially affiliated with Telegram or the Telemt maintainers. Telegram is a trademark of its respective owner.
