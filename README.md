# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，查看每个来源 IP 的城市、近24小时流量、近7天流量和最近活动时间。保留中文彩色表格，后台每120秒采样，自动开机启动。

## 新 VPS 一行安装

先以 **root** 登录 VPS，然后复制整行：

```sh
wget -qO- https://raw.githubusercontent.com/imthnio/liuliang/main/install.sh | sh
```

如果只有 curl：

```sh
curl -fsSL https://raw.githubusercontent.com/imthnio/liuliang/main/install.sh | sh
```

安装时只需回答两个问题：

1. **统计端口**：自动提示常见代理进程的监听端口，核对后回车；也可以输入 `443,8443`。NAT VPS 填代理在 VPS 内部实际监听的端口，不一定等于外部映射端口。
2. **城市查询**：输入 `y` 开启。它会向 **ipwho.is** 发送连接客户端的 IP 查询国家和城市；回车默认关闭，流量统计仍正常。

安装完成后，使用节点产生流量，约两分钟后运行：

```sh
liuliang
```

城市属于 IP 归属地估计，并非客户端实际位置。地区数据库缺失或接口不可用时显示“未解析”。

### 指定端口，无需回答问题

以下示例统计443端口，并明确允许向 ipwho.is 查询客户端 IP：

```sh
curl -fsSL https://raw.githubusercontent.com/imthnio/liuliang/main/install.sh | sh -s -- --ports 443 --geo yes
```

不需要城市信息时使用 `--geo no`。支持多个端口：`--ports 443,8443`。

## 适用范围

- 安装器支持 **Alpine + OpenRC**、**Debian/Ubuntu + systemd**，使用发行版仓库中的 Python 3、nftables 和 CA 证书。
- 需要 root 权限和内核 nftables 动态计数集合支持。部分受限 LXC/OpenVZ 不允许操作 nftables，安装预检查会报错，无法仅靠这个脚本解除宿主机限制。
- 同时统计选定端口的 **TCP/UDP、IPv4/IPv6、收发流量之和**；多个端口按客户端 IP 汇总。
- 统计本机进程的 input/output 流量。**不支持 Docker 桥接端口映射或仅经过 FORWARD 链的路由转发**；不要把这些场景的零流量当作实际没有流量。
- 只跟踪公网来源 IP。端口扫描、未认证连接也可能计入，不代表已成功登录代理。
- 流量按内核 IP 数据包字节计数，包含协议开销，不一定等于商家账单。不是整台 VPS 所有端口的总流量。
- 从安装后开始记录，不能恢复安装前的数据。24小时/7天是滚动窗口，时间以采样时刻归属，120秒采样会带来窗口边界误差。
- 正常重启后保留磁盘历史，但关机前尚未采样的流量、两次采样之间消失的计数元素无法恢复。检测到重启、计数归零或统计表丢失时会重新建立计数基线。
- 8天后清理过期记录，静止 IP 不反复写入无变化样本；大量活跃 IP 仍会增加内存和磁盘用量。每个方向/地址族集合最多16384个 IP。

## 对已有环境的处理

脚本添加独立的 `inet liuliang_v1` 计数表，不清空整套防火墙，不添加放行规则、不改代理配置。表里的 accept 策略不会跳过其他过滤链的拒绝规则。

发现已有 `liuliang` 文件会停止覆盖，包括旧版安装。这是**新机安装器**，当前版本不提供自动迁移旧数据库；已安装机器直接运行 `liuliang` 即可。

## 常用维护

Alpine：

```sh
rc-service liuliang status
rc-service liuliang restart
tail /var/log/liuliang/collector.log
```

Debian/Ubuntu：

```sh
systemctl status liuliang
systemctl restart liuliang
journalctl -u liuliang -n 30 --no-pager
```

主要文件：

| 内容 | 路径 |
|---|---|
| 配置 | `/etc/liuliang/config.json` |
| 统计规则 | `/etc/liuliang/counters.nft` |
| 历史数据库 | `/var/lib/liuliang/history-v1.db` |
| 程序 | `/usr/local/lib/liuliang/liuliang.py` |

## 版本与验证

当前版本：`1.0.0`。仓库代码不包含任何 VPS 登录信息或客户端历史记录。

`install.sh` 内嵌完整的 `liuliang.py`，安装时不再下载另一份程序。`main` 安装命令会取得仓库最新代码；需要固定版本时，可将 URL 中的 `main` 换为审查过的完整 commit SHA。

验证包括端口校验、IPv4/IPv6 JSON 解析、双向流量累计、首次采样、单方向计数重置、重启、集合元素消失、窗口边界、过期清理、中文表格和安装器内嵌代码一致性。运行：

```sh
python3 test_liuliang.py
```

基础计数方案已在 Alpine 3.21 VPS 实测。通用版的 Debian/Ubuntu 安装分支尚未在真实 Debian/Ubuntu VPS 上验收，不能视作所有 VPS 环境都已验证。

## 官方参考

- [nftables 手册](https://www.netfilter.org/projects/nftables/manpage.html)
- [nftables 计数器](https://wiki.nftables.org/wiki-nftables/index.php/Counters)
- [Alpine 服务脚本](https://wiki.alpinelinux.org/wiki/Writing_Init_Scripts)
- [OpenRC supervise-daemon](https://github.com/OpenRC/openrc/blob/master/supervise-daemon-guide.md)
- [systemd service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [ipwho.is 接口说明](https://ipwhois.io/documentation)
