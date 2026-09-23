# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，查看每个来源 IP 的运营商、城市、近24小时 / 近7天流量和最近活动时间。后台每 120 秒采样，开机自启。

## 安装（root，一行）

```sh
wget -qO- https://raw.githubusercontent.com/imthnio/vps-lianjie-ip/main/install.sh | sh
```

只有 curl：

```sh
curl -fsSL https://raw.githubusercontent.com/imthnio/vps-lianjie-ip/main/install.sh | sh
```

全自动安装，全程无需任何操作：自动检测代理监听端口（NAT VPS 取内部监听端口）；城市查询默认开启（会向 ipwho.is 发送客户端 IP）。

装好后产生一点流量，约两分钟后运行 `liuliang` 查看。

归属地（运营商 / 城市）是 IP 估计值，仅供参考。
