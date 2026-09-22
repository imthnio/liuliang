# liuliang · VPS 流量表格

在 VPS 输入 `liuliang`，查看每个来源 IP 的运营商、城市、近24小时 / 近7天流量和最近活动时间。后台每 120 秒采样，开机自启。

## 安装（root，一行）

```sh
wget -qO- https://raw.githubusercontent.com/imthnio/liuliang/main/install.sh | sh
```

只有 curl：

```sh
curl -fsSL https://raw.githubusercontent.com/imthnio/liuliang/main/install.sh | sh
```

安装时问两个问题：**统计端口**（自动检测代理监听端口，回车确认；NAT VPS 填内部监听端口）、**城市查询**（默认开启，`n` 关闭；会向 ipwho.is 发送客户端 IP）。没有交互终端时自动用检测到的端口、默认开启。

装好后产生一点流量，约两分钟后运行 `liuliang` 查看。

手动指定端口和城市查询：

```sh
curl -fsSL https://raw.githubusercontent.com/imthnio/liuliang/main/install.sh | sh -s -- --ports 443,8443 --geo no
```

归属地（运营商 / 城市）是 IP 估计值，仅供参考。
