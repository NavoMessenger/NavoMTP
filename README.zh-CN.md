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
| 终端可视化配置 | 使用中文 TUI 设置公网地址、多个端口、用户名、密钥、`ad_tag` 和 FakeTLS 伪装域名 |
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
3. Telemt 用户名；
4. 32 位十六进制密钥，留空则自动安全生成；
5. 可选的 `ad_tag`；
6. FakeTLS 伪装域名，例如 `www.microsoft.com`。

部署完成后，脚本会输出每个公网端口对应的 `tg://proxy` 和 `https://t.me/proxy` 链接。连接链接包含密钥，请勿公开发布。

## 管理命令

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
- 多个公网端口共用同一个 Telemt 用户、密钥和伪装域名；
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
