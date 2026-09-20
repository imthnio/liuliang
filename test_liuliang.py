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
        m.save_sample(self.c,{('up4',IP):100,('down4',IP):200},1000)
        m.save_sample(self.c,{('up4',IP):120,('down4',IP):230},1120)
        self.assertEqual(self.amount(),350)
    def test_one_direction_reset(self):
        m.save_sample(self.c,{('up4',IP):100,('down4',IP):1000},1000)
        m.save_sample(self.c,{('up4',IP):20,('down4',IP):2000},1120)
        self.assertEqual(self.amount(),2120)
    def test_reboot_with_larger_new_counter(self):
        m.save_sample(self.c,{('up4',IP):100},1000)
        m.save_sample(self.c,{('up4',IP):150},1120,reset=True)
        self.assertEqual(self.amount(),250)
    def test_missing_and_returning_counter(self):
        m.save_sample(self.c,{('up4',IP):100},1000)
        m.save_sample(self.c,{},1120)
        m.save_sample(self.c,{('up4',IP):20},1240)
        self.assertEqual(self.amount(),120)
    def test_idle_does_not_change_activity(self):
        m.save_sample(self.c,{('up4',IP):100},1000)
        m.save_sample(self.c,{('up4',IP):100},1120)
        self.assertEqual(self.c.execute('select last_seen from clients').fetchone()[0],1000)
        self.assertEqual(self.c.execute('select count(*) from traffic').fetchone()[0],1)
    def test_retention(self):
        m.save_sample(self.c,{('up4',IP):100},1000)
        m.save_sample(self.c,{},1000+9*86400)
        self.assertEqual(self.amount(),0)
        self.assertEqual(self.c.execute('select count(*) from clients').fetchone()[0],0)
    def test_window_boundaries(self):
        m.save_sample(self.c,{('up4',IP):100},1000)
        m.save_sample(self.c,{('up4',IP):300},1120)
        self.assertEqual(m.diff(self.c,IP,1000,1120),200)
    def test_json_ipv4_ipv6_and_private_filter(self):
        items=[]
        for name,ip,count in [('up4',IP,100),('down4',IP,200),('up6','2606:4700:4700::1111',300),('down4','127.0.0.1',400)]:
            items.append({'set':{'name':name,'elem':[{'elem':{'val':ip,'counter':{'bytes':count,'packets':1}}}]}})
        actual=m.parse_counters({'nftables':items})
        self.assertEqual(actual,{('up4',IP):100,('down4',IP):200,('up6','2606:4700:4700::1111'):300})
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
            m.save_sample(db,{('up6','2606:4700:4700::1111'):1024},m.time.time())
            db.execute("update clients set city='测试城市',country='US'");db.commit();db.close()
            out=io.StringIO()
            with patch.object(m,'DATA',Path(temp)),contextlib.redirect_stdout(out):m.report({'ports':[443],'geo':True})
            self.assertIn('测试城市',out.getvalue());self.assertIn('1.0 KB',out.getvalue())
    def test_payload_is_self_contained(self):
        s=Path(__file__).with_name('install.sh').read_text()
        payload=s.split("<<'LIULIANG_PYTHON'\n",1)[1].split('\nLIULIANG_PYTHON\n',1)[0]+'\n'
        self.assertEqual(payload,Path(__file__).with_name('liuliang.py').read_text())

if __name__=='__main__':unittest.main(verbosity=2)
