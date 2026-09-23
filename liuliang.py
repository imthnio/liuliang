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

VERSION = '1.0.4'
CONFIG = Path('/etc/liuliang/config.json')
DATA = Path('/var/lib/liuliang')
TABLE = 'liuliang_v1'
PROGRAM = Path('/usr/local/lib/liuliang/liuliang.py')
INTERVAL = 120
# nft set 元素超时秒数，必须与 rules() 里 `timeout 8d` 保持一致。
# 每次有包命中，内核会把该元素的 expires 重置为该值，因此可以用它
# 反推出"最后一个包"的时间（约 1 秒精度），而不用采样时刻代替。
SET_TIMEOUT = 8 * 86400


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
                        expires = obj.get('expires')
                        result[(setname, str(ip))] = (
                            int(counter['bytes']),
                            int(expires) if isinstance(expires, (int, float)) else None,
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


def prompt(message):
    """Read one line from the controlling terminal.

    Returns None when there is no controlling terminal (e.g. installed via
    `wget ... | sh` from a session without a TTY), so callers can fall back
    to auto-detected defaults instead of aborting.
    """
    try:
        with open('/dev/tty', 'r+') as tty:
            tty.write(message); tty.flush()
            value = tty.readline()
            if not value:
                raise RuntimeError('无法读取输入，请使用 --ports 和 --geo 参数')
            return value.strip()
    except OSError:
        return None


def listening_candidates():
    cmd = ['ss','-H','-lntup'] if shutil.which('ss') else ['netstat','-lntup']
    try:
        text = run(cmd, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    found = set()
    for line in text.splitlines():
        if not re.search(r'(xray|sing-box|hysteria|tuic|ss-server)', line, re.I):
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
    else:
        candidates = listening_candidates()
        default = ','.join(map(str, candidates))
        print('检测到的代理端口：' + (default or '未识别，请填实际监听端口'))
        print('统计本机进程监听的端口；NAT VPS 填内部监听端口。多个端口以逗号分隔。')
        answer = prompt('统计端口' + (f' [{default}]' if default else '') + '：')
        if answer is None:
            # No controlling terminal (e.g. `wget ... | sh` without a TTY):
            # use auto-detected ports instead of aborting.
            if not default:
                raise RuntimeError('未检测到代理监听端口，非交互安装请用 --ports 指定，例如：wget -qO- <install.sh> | sh -s -- --ports 443,8443')
            selected = ports(default)
            print('非交互安装：使用检测到的端口 ' + default)
        else:
            selected = ports(answer or default)
    if args.geo:
        geo = args.geo == 'yes'
    else:
        answer = prompt('城市查询会向 ipwho.is 发送客户端 IP，是否开启？[Y/n]：')
        if answer is None:
            geo = True
            print('非交互安装：城市查询默认开启（加 --geo no 可关闭）')
        else:
            geo = answer.lower() not in ('n', 'no')
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
    parser.add_argument('--ports', help='安装时指定端口，如 443,8443')
    parser.add_argument('--geo', choices=['yes','no'], help='安装时选择是否向 ipwho.is 查询客户端 IP')
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
  d=diff(c,ip,now-86400,now);w=diff(c,ip,now-604800,now);age=max(0,now-float(ls));place=' '.join(x for x in(co,ci) if x) or '未解析';rows.append((ip,isp_display(isp),place,d,w,ls,age))
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
