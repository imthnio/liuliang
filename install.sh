#!/bin/sh
set -eu
if [ "$(id -u)" != 0 ]; then echo "请先使用 root 登录 VPS" >&2; exit 1; fi
if [ -e /etc/liuliang/config.json ] || [ -e /usr/local/bin/liuliang ]; then
  echo "已安装 liuliang，停止覆盖。直接输入 liuliang 查看统计。"; exit 0
fi
# Install only standard packages from this machine's configured distribution repositories.
# apt/dpkg 锁被系统自动更新占住时等待重试（Ubuntu 刚开机常见）；非锁错误直接失败。
apt_retry() {
  _ar_rounds=$1; shift
  _ar_i=0
  while [ $_ar_i -lt "$_ar_rounds" ]; do
    if "$@" 2>/tmp/liuliang-apt.log; then return 0; fi
    grep -qiE 'Could not get lock|Unable to acquire|lock.*frontend|frontend.*lock' /tmp/liuliang-apt.log || return 1
    _ar_i=$((_ar_i + 1))
    echo "apt 正被系统更新占用，等待 20 秒后重试（$_ar_i/$_ar_rounds）…"
    sleep 20
  done
  return 1
}
apt_update() { apt-get update; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 python3 nftables ca-certificates iproute2; }
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache python3 nftables ca-certificates iproute2
elif command -v apt-get >/dev/null 2>&1; then
  if ! apt_retry 10 apt_update; then
    # Ubuntu EOL: this release no longer has a Release file on the official
    # mirrors. Retry once against old-releases.ubuntu.com.
    if grep -qiE 'no longer has a Release file' /tmp/liuliang-apt.log; then
      echo '检测到系统版本已停止维护，切换到 old-releases 源后重试…'
      sed -i -e 's#https\?://archive\.ubuntu\.com/ubuntu#http://old-releases.ubuntu.com/ubuntu#g' -e 's#https\?://security\.ubuntu\.com/ubuntu#http://old-releases.ubuntu.com/ubuntu#g' /etc/apt/sources.list
      for f in /etc/apt/sources.list.d/*.list; do
        [ -e "$f" ] || continue
        sed -i -e 's#https\?://archive\.ubuntu\.com/ubuntu#http://old-releases.ubuntu.com/ubuntu#g' -e 's#https\?://security\.ubuntu\.com/ubuntu#http://old-releases.ubuntu.com/ubuntu#g' "$f"
      done
      apt_retry 10 apt_update || { cat /tmp/liuliang-apt.log >&2; exit 1; }
    else
      cat /tmp/liuliang-apt.log >&2
      exit 1
    fi
  fi
  apt_retry 3 apt_install || { echo '依赖安装失败，apt 最后输出：' >&2; tail -5 /tmp/liuliang-apt.log >&2; exit 1; }
else
  echo "目前支持 Alpine、Debian、Ubuntu。" >&2; exit 1
fi
jobdir=$(mktemp -d)
trap 'rm -rf "$jobdir"' EXIT HUP INT TERM
cat > "$jobdir/liuliang.py" <<'LIULIANG_PYTHON'
#!/usr/bin/env python3
"""Per-IP port traffic accounting. Python standard library only."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import unicodedata
import urllib.parse
import urllib.request

VERSION = '1.0.8'
CONFIG = Path('/etc/liuliang/config.json')
DATA = Path('/var/lib/liuliang')
TABLE = 'liuliang_v1'
PROGRAM = Path('/usr/local/lib/liuliang/liuliang.py')
INTERVAL = 120
# nft set 元素超时秒数，必须与 rules() 里 `timeout 8d` 保持一致。
# 每次有包命中，内核会把该元素的 expires 重置为该值，因此可以用它
# 反推出"最后一个包"的时间（约 1 秒精度），而不用采样时刻代替。
SET_TIMEOUT = 8 * 86400
# 展示过滤阈值：近7天总流量低于该值的 IP 不在表格中显示（也不计入合计）。
# 用户要求：低于 800KB 的流量不用统计。
MIN_TRAFFIC_BYTES = 800 * 1024


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def ports(value):
    pieces = re.split(r'[,\s]+', value.strip())
    if not pieces or any(not re.fullmatch(r'[0-9]{1,5}', p) for p in pieces):
        raise ValueError('端口格式应为 443 或 443,8443')
    result = sorted(set(map(int, pieces)))
    if any(p < 1 or p > 65535 for p in result) or len(result) > 64:
        raise ValueError('端口须在 1–65535，最多64个')
    return result


def rules(selected):
    selected = ports(','.join(map(str, selected)))
    portset = '{ ' + ', '.join(map(str, selected)) + ' }'
    lines = ['table inet ' + TABLE + ' {']
    for direction in ('up', 'down'):
        for version in (4, 6):
            lines.append(f' set {direction}{version} {{ type ipv{version}_addr; flags dynamic,timeout; timeout 8d; size 16384; }}')
    for chain, direction, field, address in [('input','up','dport','saddr'), ('output','down','sport','daddr')]:
        lines.append(f' chain {chain} {{ type filter hook {chain} priority 11; policy accept;')
        for version, family in [(4, 'ip'), (6, 'ip6')]:
            for protocol in ('tcp', 'udp'):
                lines.append(f'  meta nfproto ipv{version} {protocol} {field} {portset} update @{direction}{version} {{ {family} {address} counter }}')
        lines.append(' }')
    return '\n'.join(lines + ['}', ''])


def ensure_table():
    probe = subprocess.run(['nft','list','table','inet',TABLE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode == 0:
        return False
    run(['nft','-f','/etc/liuliang/counters.nft'], capture_output=True)
    return True


def parse_duration(value):
    """把 expires 超时转成秒。

    不同 nft 版本的 -j 输出里，expires 可能是数字（秒），也可能是
    '7d23h59m' 这样的字符串；两种都转成秒。拿不到有效值时返回 None，
    调用方回退到采样时刻（精度降级，但不崩）。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or '').strip()
    if re.fullmatch(r'[0-9]+', text):
        return int(text)
    total = 0
    for amount, unit in re.findall(r'([0-9]+)\s*([dhms])', text):
        total += int(amount) * {'d': 86400, 'h': 3600, 'm': 60, 's': 1}[unit]
    return total or None


def parse_counters(document):
    """返回 {(set 名, ip): (累计字节数, expires)}。

    expires 是该元素距离超时还剩的秒数（nft -j 输出）；元素每次被包命中
    都会被重置为 SET_TIMEOUT。若 nft 没给 expires（如旧版本），则为 None。
    """
    result = {}
    def walk(obj, setname):
        if isinstance(obj, dict):
            counter = obj.get('counter')
            value = obj.get('val', obj.get('elem'))
            if isinstance(counter, dict) and 'bytes' in counter:
                try:
                    ip = ipaddress.ip_address(str(value))
                    if ip.is_global:
                        result[(setname, str(ip))] = (
                            int(counter['bytes']),
                            parse_duration(obj.get('expires')),
                        )
                except ValueError:
                    pass
            for child in obj.values():
                walk(child, setname)
        elif isinstance(obj, list):
            for child in obj:
                walk(child, setname)
    for entry in document.get('nftables', []):
        obj = entry.get('set', {})
        if obj.get('name') in ('up4','down4','up6','down6'):
            walk(obj.get('elem', []), obj['name'])
    return result


def open_db(path=None):
    c = sqlite3.connect(str(path or DATA / 'history-v1.db'), timeout=30)
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript('''
        CREATE TABLE IF NOT EXISTS clients(ip TEXT PRIMARY KEY, country TEXT DEFAULT '', city TEXT DEFAULT '', isp TEXT DEFAULT '', last_seen REAL NOT NULL, geo_due REAL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS traffic(ts REAL NOT NULL, ip TEXT NOT NULL, bytes INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS traffic_ip_ts ON traffic(ip,ts);
        CREATE INDEX IF NOT EXISTS traffic_ts ON traffic(ts);
        CREATE TABLE IF NOT EXISTS counters(name TEXT, ip TEXT, bytes INTEGER NOT NULL, PRIMARY KEY(name,ip));
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT);
    ''')
    cols = [row[1] for row in c.execute('PRAGMA table_info(clients)')]
    if 'isp' not in cols:
        c.execute("ALTER TABLE clients ADD COLUMN isp TEXT DEFAULT ''")
        # Re-resolve existing rows once so they gain an ISP label.
        c.execute("UPDATE clients SET geo_due=0 WHERE country<>''")
        c.commit()
    return c


def save_sample(c, current, now, reset=False):
    if reset:
        c.execute('DELETE FROM counters')
    previous = {(name, ip): n for name, ip, n in c.execute('SELECT name,ip,bytes FROM counters')}
    activity = {}
    last_seen = {}
    for (name, ip), (n, expires) in current.items():
        old = previous.get((name, ip), 0)
        delta = n - old if n >= old else n
        if delta > 0:
            activity[ip] = activity.get(ip, 0) + delta
            if expires is not None:
                # 该 set 元素在本轮采样内被包命中过：用 expires 反推最后
                # 一个包的时间（约 1 秒精度），比直接用采样时刻准得多。
                t = min(max(now - (SET_TIMEOUT - expires), 0), now)
                if t > last_seen.get(ip, 0):
                    last_seen[ip] = t
        c.execute('INSERT OR REPLACE INTO counters VALUES(?,?,?)', (name, ip, n))
    for name, ip in previous.keys() - current.keys():
        c.execute('DELETE FROM counters WHERE name=? AND ip=?', (name, ip))
    for ip, n in activity.items():
        c.execute('INSERT INTO traffic VALUES(?,?,?)', (now, ip, n))
        # 取四个方向里最晚的那个包的时间；没有 expires 时回退到采样时刻；
        # max() 保证 last_seen 只增不减，避免时钟抖动造成时间倒退。
        c.execute('INSERT INTO clients(ip,last_seen) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET last_seen=max(clients.last_seen, excluded.last_seen)', (ip, last_seen.get(ip, now)))
    c.execute('DELETE FROM traffic WHERE ts<?', (now - 8*86400,))
    c.execute('DELETE FROM clients WHERE last_seen<?', (now - 8*86400,))
    c.commit()


def geo_lookup(ip):
    url = 'https://ipwho.is/' + urllib.parse.quote(ip, safe=':') + '?fields=success,country_code,city,connection.isp&lang=zh-CN'
    req = urllib.request.Request(url, headers={'User-Agent':'liuliang/' + VERSION})
    with urllib.request.urlopen(req, timeout=3) as response:
        data = json.load(response)
    if not data.get('success'):
        raise ValueError('归属地查询暂不可用')
    # Never render terminal control sequences supplied by an external service.
    clean = lambda s: ''.join(ch for ch in str(s or '') if ch.isprintable())[:60]
    connection = data.get('connection') or {}
    return clean(data.get('country_code')), clean(data.get('city')), clean(connection.get('isp'))


def isp_display(raw):
    """Short carrier label: Chinese carriers in Chinese, others as returned."""
    s = ''.join(ch for ch in str(raw or '') if ch.isprintable()).strip()
    low = s.lower()
    if 'china mobile' in low:
        return '中国移动'
    if 'china telecom' in low:
        return '中国电信'
    if 'china unicom' in low or 'china united network' in low:
        return '中国联通'
    if not s:
        return '未解析'
    return s[:18]


def collect(config):
    with open('/run/liuliang.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        recreated = ensure_table()
        doc = json.loads(run(['nft','-j','list','table','inet',TABLE], capture_output=True).stdout)
        current = parse_counters(doc)
        now = time.time()
        with open_db() as c:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            last_boot = c.execute("SELECT value FROM metadata WHERE key='boot'").fetchone()
            save_sample(c, current, now, recreated or not last_boot or last_boot[0] != boot)
            c.execute("INSERT OR REPLACE INTO metadata VALUES('boot',?)", (boot,))
            c.commit()
    # Geo lookups run outside the lock: each one is a network round trip
    # (up to 10 per cycle), and holding the lock that long would stall any
    # concurrent `liuliang --once`. The DB itself is safe via WAL + busy timeout.
    if config['geo']:
        geo_resolve()


def geo_resolve():
    now = time.time()
    with open_db() as c:
        for ip, in c.execute('SELECT ip FROM clients WHERE geo_due<=? ORDER BY last_seen DESC LIMIT 10', (now,)).fetchall():
            try:
                country, city, isp = geo_lookup(ip)
                c.execute('UPDATE clients SET country=?,city=?,isp=?,geo_due=? WHERE ip=?', (country,city,isp,now+30*86400,ip))
            except Exception:
                c.execute('UPDATE clients SET geo_due=? WHERE ip=?', (now+86400,ip))
            c.commit()


PROXY_PROCESS = re.compile(r'(xray|v2ray|sing-box|hysteria|tuic|shadowsocks|ss-server|trojan|anytls)', re.I)

def listening_ports(proxy_only=True):
    """Return sorted listening TCP ports on this machine.

    proxy_only=True: only ports whose process name looks like a proxy/tunnel
    server (xray, sing-box, hysteria, tuic, trojan, ...).
    proxy_only=False: every listening TCP port (fallback when no proxy
    process is recognized).
    """
    cmd = ['ss','-H','-lntup'] if shutil.which('ss') else ['netstat','-lntup']
    try:
        text = run(cmd, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    found = set()
    for line in text.splitlines():
        if proxy_only and not PROXY_PROCESS.search(line):
            continue
        words = line.split()
        # ss: netid state recv-q send-q local peer; netstat: proto recv-q send-q local peer
        index = 4 if cmd[0] == 'ss' else 3
        if len(words) > index:
            match = re.search(r':([0-9]+)$', words[index])
            if match:
                found.add(int(match.group(1)))
    return sorted(found)


def install(args):
    if os.geteuid() != 0:
        raise RuntimeError('请使用 root 用户运行安装')
    managed = [CONFIG, PROGRAM, Path('/usr/local/bin/liuliang'), Path('/etc/init.d/liuliang'), Path('/etc/systemd/system/liuliang.service')]
    if any(p.exists() for p in managed):
        raise RuntimeError('已发现 liuliang 文件。为保留已有历史，本安装器不覆盖；已安装的机器直接输入 liuliang。')
    if Path('/run/systemd/system').is_dir():
        init = 'systemd'
    elif Path('/sbin/openrc-run').exists():
        init = 'openrc'
    else:
        raise RuntimeError('需要正在使用 systemd 或 OpenRC 的 Linux VPS')
    if args.ports:
        selected = ports(args.ports)
        print('使用手动指定的端口：' + ','.join(map(str, selected)))
    else:
        # 全自动：先按代理进程名识别，识别不到就退到本机全部监听端口（不含 SSH 22）。
        # 全程不提问，小白直接回车粘贴一行命令即可。
        candidates = listening_ports(proxy_only=True)
        if candidates:
            selected = candidates
            print('自动检测到代理端口：' + ','.join(map(str, selected)) + '（NAT VPS 取内部监听端口）')
        else:
            everything = [p for p in listening_ports(proxy_only=False) if p != 22]
            if not everything:
                raise RuntimeError('未检测到任何监听端口：请先把节点装好，再重跑一键安装')
            selected = everything
            print('未识别出代理进程，已自动选用本机全部监听端口：' + ','.join(map(str, selected)) + '（不含 SSH 22）')
    geo = args.geo != 'no'
    print('城市查询：默认开启（向 ipwho.is 发送客户端 IP；归属地是估计值，仅供参考）')
    existing = subprocess.run(['nft','list','table','inet',TABLE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if existing.returncode == 0:
        raise RuntimeError('同名 nftables 表已存在，停止安装以免冲突')
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.nft') as f:
        f.write(rules(selected)); f.flush()
        run(['nft','-c','-f',f.name], capture_output=True)
    # All compatibility checks precede persistent file creation.
    config = {'version':VERSION, 'ports':selected, 'geo':geo}
    for folder in [CONFIG.parent, PROGRAM.parent, DATA]:
        folder.mkdir(parents=True, exist_ok=True)
    DATA.chmod(0o700)
    CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2)+'\n')
    CONFIG.chmod(0o600)
    (CONFIG.parent/'counters.nft').write_text(rules(selected))
    PROGRAM.write_bytes(Path(__file__).read_bytes()); PROGRAM.chmod(0o755)
    wrapper = Path('/usr/local/bin/liuliang')
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/liuliang/liuliang.py "$@"\n'); wrapper.chmod(0o755)
    if init == 'systemd':
        Path('/etc/systemd/system/liuliang.service').write_text('''[Unit]
Description=Per-IP port traffic statistics
After=network.target nftables.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /usr/local/lib/liuliang/liuliang.py --daemon
Restart=on-failure
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
''')
        run(['systemctl','daemon-reload'])
        run(['systemctl','enable','--now','liuliang'])
        run(['systemctl','is-active','--quiet','liuliang'])
    else:
        logdir = Path('/var/log/liuliang'); logdir.mkdir(exist_ok=True); logdir.chmod(0o700)
        service = Path('/etc/init.d/liuliang')
        service.write_text('''#!/sbin/openrc-run
name="liuliang"
description="Per-IP port traffic statistics"
supervisor="supervise-daemon"
command="/usr/bin/python3"
command_args="-u /usr/local/lib/liuliang/liuliang.py --daemon"
respawn_delay=5
respawn_max=5
respawn_period=60
output_log="/var/log/liuliang/collector.log"
error_log="/var/log/liuliang/collector.log"
depend() { need net; after firewall nftables; }
start_pre() { /usr/bin/python3 /usr/local/lib/liuliang/liuliang.py --once; }
'''); service.chmod(0o755)
        run(['rc-service','liuliang','start'])
        run(['rc-update','add','liuliang','default'])
        run(['rc-service','liuliang','status'])
    collect(config)
    print('\n安装完成。以后输入：liuliang\n端口：'+','.join(map(str,selected))+'；城市查询：'+('已启用' if geo else '关闭'))


def main():
    parser = argparse.ArgumentParser(description='按 IP 查看近24小时和近7天端口流量')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--ports', help='高级：手动指定统计端口，如 443,8443（默认自动检测）')
    parser.add_argument('--geo', choices=['yes','no'], help='高级：--geo no 关闭城市查询（默认开启）')
    parser.add_argument('--daemon', action='store_true')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    if args.install:
        install(args); return
    config = json.loads(CONFIG.read_text())
    if args.once:
        collect(config)
    elif args.daemon:
        while True:
            try:
                collect(config)
            except Exception as exc:
                print('liuliang:', str(exc), file=sys.stderr, flush=True)
            time.sleep(INTERVAL)
    else:
        report(config)


from datetime import datetime,timedelta,timezone
Z=timezone(timedelta(hours=8)); E='\33[0m'; B='\33[1m'; C='\33[36m'; G='\33[32m'; Y='\33[33m'; D='\33[2m'; X='\33[90m'
def col(x,*a): return ''.join(a)+str(x)+E if sys.stdout.isatty() and a else str(x)
def sz(n):
 u=['B','KB','MB','GB','TB'];v=float(max(0,n or 0))
 for q in u:
  if v<1024 or q==u[-1]: break
  v/=1024
 return f'{v:.0f} {q}' if q=='B' or v>=10 else f'{v:.1f} {q}'
def ww(s): return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WFA' else 1 for c in str(s))
def cell(s,n): return str(s)+' '*(n-ww(s))
def diff(c,ip,a,b):
 return c.execute('select coalesce(sum(bytes),0) from traffic where ip=? and ts>? and ts<=?',(ip,a,b)).fetchone()[0]
def report(config):
 DB=str(DATA / "history-v1.db")
 now=time.time();print(col('端口 '+','.join(map(str,config['ports']))+' · 近7天连接',B,C))
 if not os.path.exists(DB):print('(暂无流量数据库记录)');return
 c=sqlite3.connect(DB); rows=[]
 cols=[r[1] for r in c.execute('PRAGMA table_info(clients)')]
 sel='ip,country,city,isp,last_seen' if 'isp' in cols else 'ip,country,city,last_seen'
 for rec in c.execute(f'select {sel} from clients where last_seen>=? order by last_seen desc',(now-604800,)):
  ip,co,ci=rec[0],rec[1],rec[2]; isp,ls=(rec[3],rec[4]) if len(rec)==5 else ('',rec[3])
  d=diff(c,ip,now-86400,now);w=diff(c,ip,now-604800,now)
  if w<MIN_TRAFFIC_BYTES: continue
  age=max(0,now-float(ls));place=' '.join(x for x in(co,ci) if x) or '未解析';rows.append((ip,isp_display(isp),place,d,w,ls,age))
 if not rows:
  print('(近7天无达到 800KB 的流量记录)');c.close();return
 h=['IP','运营商','城市','近24小时','近7天','最近连接'];N=[15,10,8,10,10,19]
 for ip,net,pl,d,w,ls,age in rows:N=[max(N[i],ww(x)) for i,x in enumerate([ip,net,pl,sz(d),sz(w),datetime.fromtimestamp(ls,Z).strftime('%Y-%m-%d %H:%M:%S')])]
 def line(a,m,b):return a+m.join('─'*(n+2) for n in N)+b
 print(line('┌','┬','┐'));print(col('│ '+' │ '.join(cell(x,N[i]) for i,x in enumerate(h))+' │',B,C));print(line('├','┼','┤'))
 for ip,net,pl,d,w,ls,age in rows:
  v=[ip,net,pl,sz(d),sz(w),datetime.fromtimestamp(ls,Z).strftime('%Y-%m-%d %H:%M:%S')];out=[]
  for i,x in enumerate(v):
   st=[D,X] if d<=0 and w<=0 else ([B,G] if i==0 and d>0 else [])
   if i==3 and d>=100*1024**2 or i==4 and w>=1024**3:st=[B,Y]
   if i==5:st=[B,G] if age<=3600 else ([D,X] if age>259200 else [])
   out.append(col(cell(x,N[i]),*st))
  print('│ '+' │ '.join(out)+' │')
 print(line('└','┴','┘'));a=sum(1 for r in rows if r[3]>0 or r[4]>0);print('合计：IP 数 %d · 有流量 IP 数 %d · 近24小时总流量 %s · 近7天总流量 %s'%(len(rows),a,sz(sum(r[3] for r in rows)),sz(sum(r[4] for r in rows))))
 c.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print('错误：'+str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        sys.exit(1)
LIULIANG_PYTHON
python3 "$jobdir/liuliang.py" --install "$@"
