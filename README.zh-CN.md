# NavoMTP：Telemt MTProto Proxy 一键安装脚本（Docker + Nginx SNI + FakeTLS）

[简体中文](README.zh-CN.md) | [English](README.md) | [Русский](README.ru.md)

> 在 Debian 或 Ubuntu VPS 上，一键部署和管理基于 [Telemt](https://github.com/telemt/telemt) 的 Telegram MTProto Proxy。NavoMTP 自动安装 Docker，通过 Nginx `ssl_preread` 按 FakeTLS 伪装域名进行 SNI 分流，并支持多个公网端口。

NavoMTP 适合希望快速搭建 **Telegram MTProxy / MTProto Proxy**，同时需要 Docker Compose、Nginx SNI 路由、FakeTLS、`ad_tag` 和日常运维菜单的用户。无需手写 `config.toml`、Compose 或 Nginx stream 配置。

如果这个项目对你有帮助，欢迎点亮 **Star**，让更多需要 Telemt 一键部署方案的人找到它。

想了解更多 Navo 项目、产品与最新动态，请访问 [Navo 官方网站](https://www.navo.im/)。

## 为什么选择 NavoMTP

| 能力 | 说明 |
| --- | --- |
| 一键安装 Telemt | 自动检测 Docker；未安装时通过 Docker 官方 apt 仓库安装 Engine 和 Compose 插件 |
| 终端可视化配置 | 使用中文 TUI 设置公网地址、多个端口、密钥、`ad_tag` 和 FakeTLS 伪装域名 |
| 多推广标签 | 每组独立密钥、`ad_tag` 和连接链接，所有组共享整体上下行限速，无需设置用户名 |
| Nginx SNI 分流 | 使用 `stream` + `ssl_preread`，仅将匹配伪装域名的 TLS 流量转发到 Telemt |
| 多端口 MTProxy | 一个 Telemt 实例可同时通过多个公网 TCP 端口提供服务，并分别生成连接链接 |
| 更小的暴露面 | 只有 Nginx 端口对外开放；Telemt `9443`、Metrics 和 Control API 不发布到宿主机 |
| 保留客户端 IP | Nginx 与 Telemt 之间启用 PROXY protocol，并限制可信来源为专用 Docker 网络 |
| 安全更新与回滚 | 配置生效前执行校验；启动或镜像更新失败时恢复上一版本 |
| 日常管理菜单 | 支持重新配置、状态、日志、镜像更新、连接链接和卸载 |

## 工作原理

```text
Telegram 客户端
       │ FakeTLS / 指定 SNI
       ▼
公网端口：443, 12432, 22124 ...
       │
       ▼
Nginx stream + ssl_preread
       │
       ├─ SNI 等于伪装域名 ──► Telemt:9443 ──► Telegram
       └─ 错误 SNI / 无 SNI / 非 TLS ──► 拒绝
```

Nginx 不会按照客户端提供的任意域名转发，因此不会把服务器变成开放 TCP 代理。该部署严格依赖 TLS SNI，所以默认只启用 Telemt FakeTLS 模式，不启用 Classic 或 Secure 模式。

## 系统要求

- Debian 或 Ubuntu，使用 systemd；
- `amd64` 或 `arm64` 架构；
- root 或 sudo 权限；
- 能够访问 Docker 官方仓库、GitHub、GHCR 和所选伪装网站；
- 云服务器安全组允许所选公网 TCP 端口。

## 快速安装 Telemt MTProxy

下载项目后运行：

```bash
chmod +x navomtp.sh
sudo bash navomtp.sh
```

也可以直接进入安装流程：

```bash
sudo bash navomtp.sh install
```

首次运行时，终端菜单会引导你设置：

1. 公网 IPv4 或入口域名；
2. 一个或多个公网 TCP 端口，例如 `443,12432,22124`；
3. FakeTLS 伪装域名，例如 `www.microsoft.com`；
4. 连接组数量（`1–100`，默认 `1`）；
5. 逐组设置独立的 32 位十六进制密钥（留空安全生成）和可选的 `ad_tag`；
6. 统一设置整体上下行限速（整数 Mbps，`0–100000`；`0` 不限速）。

上行指客户端 → Telegram，下行指 Telegram → 客户端。所有组、密钥、客户端和公开端口共享每个方向的总限速。例如上行 `10`、下行 `25`，整个代理合计限制为上行 10 Mbps、下行 25 Mbps（1 Mbps = 1,000,000 bit/s，不是 1 MB/s）。限速针对持续传输的平均速度，允许有限的瞬时突发。

当前 IPv4 入口使用 Telemt 原生 `[access.cidr_rate_limits]` 中的单个 `0.0.0.0/0` 聚合桶，不再逐用户限速。未配置 IPv6 入口；未来增加时需要重新设计共享桶，不能直接增加一份独立额度。统计范围为已认证的代理传输，不限制宿主机其他服务。

两个方向默认均不限速，旧部署没有保存限速设置时也按不限速处理。运行 `sudo bash navomtp.sh configure` 修改，输入 `0` 可取消对应方向的限制；`status` 会展示上下行限速。更新镜像会保留设置。若当前 Telemt 镜像不识别限速字段，验证会在替换部署前停止；请通过现有 `update` 命令升级镜像后重试。

部署完成后，脚本会输出每个公网端口对应的 `tg://proxy` 和 `https://t.me/proxy` 链接。连接链接包含密钥，请勿公开发布。

### 多个 ad_tag 与连接组

运行 `sudo bash navomtp.sh configure`，增加连接组数量，然后逐组配置密钥和 `ad_tag`。每组在每个公网端口上都有独立链接，所有组共用 Telemt 实例、伪装域名及整体上下行上限。填写完所有组后，只需统一设置一次上下行限速。内部编号自动生成，无需设置用户名。

标签写入 Telemt 原生的 `[access.user_ad_tags]`，不是在全局 `ad_tag` 中填入逗号列表。某组 tag 留空表示该组不推广，不会继承另一组的 tag。请用各组密钥向 `@MTProxybot` 注册并取得对应 tag，分享时使用对应组的连接链接。

旧单组部署自动作为第 1 组，保留原密钥、tag 和限速；重新配置会回显已有值，新增组生成独立密钥。减少组数会二次确认并移除末尾组，其旧链接将失效。镜像更新保留全部组，部署失败恢复上一版配置。`status` 逐组展示，`links` 输出所有组和端口的链接。

从旧版按组限速迁移时，运行 `configure`，默认沿用原第 1 组上下行值作为整体限速，确认后生效，其他组原来的限速项会移除。仅更新脚本或镜像不会改写运行中的旧配置；`status` 会提示需重新配置。

## 管理命令

### 同一链接定时轮换 tag

运行 `sudo bash navomtp.sh rotation`，或在菜单中选择“配置 tag 定时轮换”，选择已有连接组后设置模式：

- `fixed`：停止该组轮换，保留当前 tag；需要更换或清空时使用 `configure`。
- `sequence`：按 tag 列表依次循环。
- `random`：每个周期随机选另一个 tag，避免连续重复。

轮换模式需要填写 2–100 个不同的、非全零的 32 位十六进制 tag，用英文逗号分隔；间隔为 1–10080 分钟，默认 30 分钟。请使用通过 `@MTProxybot` 取得的有效 tag。若当前 tag 在列表内，保持到首个周期到期；否则配置部署时先启用列表第一个 tag。每组独立设置列表与周期，密钥、公网地址、端口和伪装域名保持不变，原有链接继续使用，整体上下行限速也不变。

首次设置会重建容器以升级为只读目录挂载，可能短暂断线。之后后台通过 Telemt 热重载切换，不主动断开客户端。切换影响新建代理会话，已有连接及 Telegram 推广频道显示不保证立即变化；这不是“每个新连接随机分配”。

`navomtp-rotation.timer` 由 root 管理，每分钟检查到期组，服务器重启后自动恢复；错过多个周期时只在下次检查补切换一次，不补放全部历史周期。设置和进度保存在受保护的 `state.env`，后台使用部署目录中的脚本副本。所有组关闭轮换或卸载时会移除定时器。配置及镜像更新保留轮换设置；在 `configure` 中更改某组 tag 会关闭该组轮换，保持当前 tag 不变则保留轮换。

每次切换先验证候选配置，等待 Telemt 的 tag 热重载日志后再提交状态；失败恢复原文件，中断事务在下次修改操作或定时任务中恢复。安装、配置、更新、卸载和轮换共用操作锁。实际推广显示仍需在目标服务器和 Telegram 客户端检查。

```bash
sudo bash navomtp.sh rotation      # 配置或停止某组轮换
sudo bash navomtp.sh status        # 当前 tag、模式、间隔、下次执行 Unix 时间戳
sudo systemctl status navomtp-rotation.timer
sudo journalctl -u navomtp-rotation.service -n 50 --no-pager
sudo bash navomtp.sh rotate        # 立即检查到期组，不提前强制切换
```

不带参数运行会打开管理菜单：

```bash
sudo bash navomtp.sh
```

也可以直接执行命令：

```bash
sudo bash navomtp.sh configure   # 修改端口、密钥、ad_tag 或伪装域名
sudo bash navomtp.sh status      # 查看 Telemt 与 Nginx 容器状态
sudo bash navomtp.sh logs        # 查看实时日志
sudo bash navomtp.sh update      # 更新容器镜像，失败时自动回滚
sudo bash navomtp.sh links       # 再次显示 Telegram 代理链接
sudo bash navomtp.sh uninstall   # 删除本项目，不卸载 Docker
```

## 生成的 Telemt 和 Nginx 配置

受管文件默认位于 `/opt/navomtp`：

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

- `state.env` 和 `links.txt` 仅允许 root 读取；
- `telemt.toml` 仅允许 root 和 Telemt 容器的专用 GID 读取；
- 配置修改前会创建时间戳备份；
- 卸载不会删除 Docker Engine 或共享容器镜像。

## 网络与安全说明

- Telemt 只在 Docker 网络内部监听 `9443`；
- Metrics `9090` 和 Control API `9091` 均不发布；
- 未匹配的 SNI、没有 SNI 的连接以及非 TLS 流量会被快速拒绝；
- 伪装域名不需要解析到代理服务器，但必须能够正常解析并提供 HTTPS；
- 所有组共用伪装域名；每组内的多个公网端口共用该组密钥；
- 检测到已启用的 UFW 时，脚本会询问是否放行所选端口；
- 云厂商安全组无法由脚本统一修改，需要在控制台中手动放行；
- 使用代理服务前，请确认符合服务器所在地及使用者所在地的法律和服务条款。

## 常见问题

### 没有 Docker，可以直接安装吗？

可以。NavoMTP 会检测 Docker Engine 和 Docker Compose。缺失时，它会使用 Docker 官方 apt 仓库进行安装；不会静默删除现有的 `docker.io`、Podman 或其他容器环境。

### 可以为 Telegram MTProxy 配置多个端口吗？

可以。在端口输入框中使用英文逗号分隔，例如 `443,12432,22124`。所有端口使用同一个 Telemt 实例和密钥，脚本会为每个端口生成独立连接链接。

### 伪装域名需要指向 VPS IP 吗？

不需要。它是 FakeTLS 流量使用的 SNI 前置域名，应选择一个能够稳定解析并正常提供 HTTPS 的域名。

### 为什么只启用 FakeTLS？

本项目依靠 Nginx 读取 TLS ClientHello 中的 SNI 进行严格分流。Classic 和 Secure 模式没有可供该入口分流的 TLS SNI，因此默认关闭。

### 容器正常，但 Telegram 无法连接怎么办？

依次检查：云厂商安全组、UFW、端口占用、`sudo bash navomtp.sh status`、`sudo bash navomtp.sh logs`，以及客户端链接中的服务器地址、端口和密钥。容器健康不等同于真实 Telegram 客户端已经连通。

### 如何配置 MTProxy 推广频道和 ad_tag？

先通过 Telegram 官方 `@MTProxybot` 获取 32 位十六进制 `ad_tag`，然后重新运行 `configure`。不要使用机器人返回的错误端口或旧链接替换脚本生成的 FakeTLS 链接。

## 测试

无需 Docker 的本地检查：

```bash
bash -n navomtp.sh
bash tests/test_navomtp.sh
bash tests/test_rotation.sh
shellcheck navomtp.sh tests/test_navomtp.sh
```

真实部署还应在每个公网端口上使用 Telegram 客户端完成连接测试。

## 相关项目与官方文档

- [Telemt：Rust + Tokio 实现的 MTProxy](https://github.com/telemt/telemt)
- [Telemt Docker Compose 快速入门](https://github.com/telemt/telemt/blob/main/docs/Quick_start/QUICK_START_GUIDE.en.md#telemt-via-docker-compose)
- [Nginx stream ssl_preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)
- [Docker Engine for Debian](https://docs.docker.com/engine/install/debian/)
- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

## 免责声明

NavoMTP 是独立的社区部署工具，与 Telegram 或 Telemt 项目维护者不存在官方隶属关系。Telegram 是其相应权利人的商标。
