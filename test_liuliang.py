import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('liuliang', Path(__file__).with_name('liuliang.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
IP = '8.8.8.8'

class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.c = m.open_db(':memory:')
    def tearDown(self):
        self.c.close()
    def amount(self):
        return self.c.execute('select coalesce(sum(bytes),0) from traffic').fetchone()[0]
    def test_port_validation(self):
        self.assertEqual(m.ports('443,8443,443'), [443,8443])
        for value in ('0','65536','-1','443; reboot','abc','443,',''):
            with self.assertRaises(ValueError):m.ports(value)
    def test_initial_and_increment(self):
        m.save_sample(self.c,{('up4',IP):(100, None),('down4',IP):(200, None)},1000)
        m.save_sample(self.c,{('up4',IP):(120, None),('down4',IP):(230, None)},1120)
        self.assertEqual(self.amount(),350)
    def test_one_direction_reset(self):
        m.save_sample(self.c,{('up4',IP):(100, None),('down4',IP):(1000, None)},1000)
        m.save_sample(self.c,{('up4',IP):(20, None),('down4',IP):(2000, None)},1120)
        self.assertEqual(self.amount(),2120)
    def test_reboot_with_larger_new_counter(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{('up4',IP):(150, None)},1120,reset=True)
        self.assertEqual(self.amount(),250)
    def test_missing_and_returning_counter(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{},1120)
        m.save_sample(self.c,{('up4',IP):(20, None)},1240)
        self.assertEqual(self.amount(),120)
    def test_idle_does_not_change_activity(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{('up4',IP):(100, None)},1120)
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0],1000)
        self.assertEqual(self.c.execute('select count(*) from traffic').fetchone()[0],1)
    def test_retention(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{},1000+9*86400)
        self.assertEqual(self.amount(),0)
        self.assertEqual(self.c.execute('select count(*) from clients').fetchone()[0],0)
    def test_window_boundaries(self):
        m.save_sample(self.c,{('up4',IP):(100, None)},1000)
        m.save_sample(self.c,{('up4',IP):(300, None)},1120)
        self.assertEqual(m.diff(self.c,IP,1000,1120),200)
    def test_json_ipv4_ipv6_expires_and_private_filter(self):
        items=[]
        for name,ip,count,expires in [('up4',IP,100,691190),('down4',IP,200,691195),('up6','2606:4700:4700::1111',300,None),('down4','127.0.0.1',400,691200)]:
            elem={'val':ip,'counter':{'bytes':count,'packets':1}}
            if expires is not None:elem['expires']=expires
            items.append({'set':{'name':name,'elem':[{'elem':elem}]}})
        actual=m.parse_counters({'nftables':items})
        self.assertEqual(actual,{('up4',IP):(100,691190),('down4',IP):(200,691195),('up6','2606:4700:4700::1111'):(300,None)})
    def test_last_seen_uses_expires_not_sample_time(self):
        # 采样时刻 now=10000，但 expires 显示最后一个包是 37 秒前：
        # last_seen 应 ≈ 9963，而不是 10000（原来直接记采样时刻，最多差 120 秒）
        m.save_sample(self.c,{('up4',IP):(100,m.SET_TIMEOUT-37)},10000)
        seen=self.c.execute('select last_seen from clients').fetchone()[0]
        self.assertAlmostEqual(seen,9963,delta=1)
    def test_last_seen_takes_latest_of_four_directions(self):
        m.save_sample(self.c,{('up4',IP):(100,m.SET_TIMEOUT-50),('down4',IP):(200,m.SET_TIMEOUT-10)},10000)
        seen=self.c.execute('select last_seen from clients').fetchone()[0]
        self.assertAlmostEqual(seen,9990,delta=1)
    def test_last_seen_falls_back_to_sample_time_without_expires(self):
        m.save_sample(self.c,{('up4',IP):(100,None)},10000)
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0],10000)
    def test_last_seen_never_goes_backward(self):
        m.save_sample(self.c,{('up4',IP):(100,None)},10000)
        # 后一轮采样 now 更大，但 expires 算出的时间反而更早：last_seen 不应倒退
        m.save_sample(self.c,{('up4',IP):(200,m.SET_TIMEOUT-5000)},10120)
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0],10000)
    def test_set_timeout_matches_rules(self):
        self.assertEqual(m.SET_TIMEOUT,8*86400)
        self.assertIn('timeout 8d',m.rules([443]))
    def test_rules_only_count_selected_ports(self):
        s=m.rules([443,8443])
        self.assertIn('tcp dport { 443, 8443 }',s)
        self.assertIn('udp sport { 443, 8443 }',s)
        self.assertNotIn('flush',s);self.assertNotIn('drop',s);self.assertNotIn('forward',s)
    def test_detect_ss_ports(self):
        output='tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=8,fd=3))\n'
        with patch.object(m.shutil,'which',return_value='/bin/ss'),patch.object(m,'run') as run:
            run.return_value.stdout=output
            self.assertEqual(m.listening_candidates(),[443])
    def test_detect_netstat_ports(self):
        with patch.object(m.shutil,'which',return_value=None),patch.object(m,'run') as run:
            run.return_value.stdout='tcp 0 0 :::51911 :::* LISTEN 1194/xray\n'
            self.assertEqual(m.listening_candidates(),[51911])
    def test_report_unicode(self):
        with tempfile.TemporaryDirectory() as temp:
            db=m.open_db(Path(temp)/'history-v1.db')
            m.save_sample(db,{('up6','2606:4700:4700::1111'):(1024, None)},m.time.time())
            db.execute("update clients set city='测试城市',country='US'");db.commit();db.close()
            out=io.StringIO()
            with patch.object(m,'DATA',Path(temp)),contextlib.redirect_stdout(out):m.report({'ports':[443],'geo':True})
            self.assertIn('测试城市',out.getvalue());self.assertIn('1.0 KB',out.getvalue())
    def test_payload_is_self_contained(self):
        s=Path(__file__).with_name('install.sh').read_text()
        payload=s.split("<<'LIULIANG_PYTHON'\n",1)[1].split('\nLIULIANG_PYTHON\n',1)[0]+'\n'
        self.assertEqual(payload,Path(__file__).with_name('liuliang.py').read_text())

if __name__=='__main__':unittest.main(verbosity=2)
