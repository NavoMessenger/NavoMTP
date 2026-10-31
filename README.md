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
| Interactive terminal UI | Configures the public address, multiple ports, secret, optional `ad_tag`, and FakeTLS camouflage domain |
| Multiple promotion tags | Each connection group has its own secret, `ad_tag`, and links; all groups share the overall upload/download limits; no username input |
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

### Official image or local source build

The installation/configuration wizard now asks for the Telemt image mode:

- `official` (default): pull the saved registry image, normally `ghcr.io/telemt/telemt:latest`.
- `source`: build from an absolute directory on **the proxy server**, using `Dockerfile.live-tag`. The directory must contain `Cargo.toml`, `Cargo.lock`, `src/main.rs`, and that Dockerfile. Upload the complete modified checkout first; a path on your laptop is not accessible to the server.

For example, upload the patched source to `/root/NavoMTP/telemt`, run `sudo bash navomtp.sh configure`, select `source`, and enter that path. No registry push or manual state-file editing is needed. Do not use the upstream Dockerfile, which downloads a prebuilt release rather than compiling your changes.

Source builds receive new local image tags; previous images are retained for rollback. The selected mode and source path persist in `state.env`. `update` pulls in official mode and rebuilds the saved local directory in source mode; it does **not** run `git pull`. Nginx remains a registry image. Reconfiguration (including rotation configuration) also builds the selected source. Automatic tag-rotation ticks do not build images.

Compose uses the already validated Telemt image without implicit pulls. Switching modes uses the same candidate validation and rollback flow; failures restore prior configuration and running-image references. Existing deployments without a saved mode default to `official`. `status` shows the selected mode and source path. Local building needs enough disk/RAM and network access to build dependencies and base images; this is not an offline build.

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
3. A FakeTLS camouflage domain, such as `www.microsoft.com`;
4. The number of connection groups (`1–100`, default `1`);
5. For each group: a unique 32-character hexadecimal secret (leave empty to generate) and an optional `ad_tag`;
6. Overall upload/download limits in integer Mbps (`0–100000`; `0` means unlimited).

Upload means client → Telegram; download means Telegram → client. All groups, secrets, clients, and public ports share one total limit per direction. For example, upload `10` and download `25` cap the combined proxy traffic at 10 Mbps upload and 25 Mbps download (1 Mbps = 1,000,000 bits/s, not 1 MB/s). These are sustained average limits with bounded bursts.

The current IPv4 ingress uses one native Telemt `[access.cidr_rate_limits]` bucket for `0.0.0.0/0`, rather than separate user limits. IPv6 ingress is not configured; adding it requires revisiting the shared bucket rather than assigning a second independent budget. Only authenticated proxy traffic is counted, not unrelated services on the host.

Both limits default to unlimited, including existing deployments without saved limits. Run `sudo bash navomtp.sh configure` to change them or enter `0` to remove either limit; `status` displays both. Image updates preserve the settings. If the current Telemt image does not recognize the limit fields, validation stops before replacing the deployment; use the existing `update` command to upgrade and retry.

The menu displays links directly in the terminal without a dialog box, keeping each URL on one logical line for copying; press Enter to return.

After deployment, NavoMTP prints `tg://proxy` and `https://t.me/proxy` links for every public port. These links contain the proxy secret and should not be posted publicly.

### Multiple ad tags and connection groups

Run `sudo bash navomtp.sh configure`, increase the group count, then set each group's secret and `ad_tag`. Each group gets separate links for every public port, while all groups use the same Telemt instance, camouflage domain, and overall directional limits. Configure the two limits once after entering all groups. Internal identifiers are generated automatically.

Tags are stored in Telemt's native `[access.user_ad_tags]`, not a comma-separated global `ad_tag`. A blank tag means no promotion for that group, without inheriting another group's tag. Register each group's secret with `@MTProxybot` to obtain its tag. Use the matching group links when sharing a promotion channel.

Existing single-group installations become group 1 with their secret, tag, and limits preserved. Reconfiguration keeps each existing group's defaults; new groups generate independent secrets. Reducing the group count removes the trailing groups after confirmation and invalidates their links. Image updates retain all groups; failed deployments restore the previous configuration. `status` lists each group, and `links` shows all group/port combinations.

To migrate an older per-group deployment, run `configure`: the former group 1 limits are offered as the overall defaults for confirmation. Other per-group limits are removed from the new configuration. Updating the script or images alone does not rewrite a live per-group configuration; `status` indicates that reconfiguration is required.

## Management Commands

### Scheduled tag rotation with an unchanged link

Run `sudo bash navomtp.sh rotation` or select **Configure scheduled tag rotation** in the menu. Select an existing connection group, then choose:

- `sequence`: cycle through the tag list in order.
- `random`: randomly select another tag at each interval, avoiding consecutive repeats.

A single tag in either mode keeps that tag fixed, skips the interval prompt, and needs no rotation timer. Existing `fixed` configurations remain compatible. Use `configure` to clear a tag.

For either rotation mode, enter 1–100 unique, nonzero 32-character hexadecimal tags separated by commas, and an interval of 1–10080 minutes (default 30). Use valid tags obtained through `@MTProxybot`. If the current tag is in the pool, it stays active until the first interval expires; otherwise the first tag becomes active when configuration is deployed. Each group has its own pool and schedule. The proxy secret, public address, ports, and camouflage domain remain unchanged, so existing links continue to work. Overall upload/download limits remain shared.

Initial configuration rebuilds containers to use a read-only directory mount and may briefly interrupt connections. Subsequent scheduled changes use Telemt hot reload and do not deliberately disconnect clients. They apply to new proxy sessions; existing sessions and Telegram's sponsored-channel display are not guaranteed to switch immediately. This is scheduled rotation, not random selection for every new connection.

A root-owned `navomtp-rotation.timer` checks due groups every minute and starts again after reboot. Overdue groups switch once at the next check, without replaying missed intervals. New settings and rotation progress persist in protected `state.env`; an installed copy of the script runs the timer. Disabling rotation for all groups removes the timer, and uninstall removes it too. Configuration and image updates retain the schedules. Changing a group's tag through `configure` disables that group's rotation; leaving its current tag unchanged preserves it.

Every candidate is validated before publication. The worker waits for Telemt's tag-reload log before committing state; failures restore the previous files, and an interrupted transaction is recovered on the next mutation or timer tick. Updates, deployment, uninstall, and timer ticks share a lock. Logs and actual promotion display should still be checked on the target server.

```bash
sudo bash navomtp.sh rotation      # Configure or stop rotation for one group
sudo bash navomtp.sh status        # Current tag, mode, interval, next due Unix timestamp
sudo systemctl status navomtp-rotation.timer
sudo journalctl -u navomtp-rotation.service -n 50 --no-pager
sudo bash navomtp.sh rotate        # Check due groups now; does not force an early switch
```

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
- all groups share the camouflage domain; within each group, public ports share its secret;
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
bash tests/test_rotation.sh
bash tests/test_image_modes.sh
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
