<!-- @(#) $Id: decoder.xml,v 1.166 2010/06/15 12:52:01 dcid Exp $
  -  OSSEC log decoder.
  -  Author: Daniel B. Cid
  -  License: http://www.ossec.net/en/licensing.html
  -->
        

<!--
   - Allowed fields:
   - location - where the log came from (only on FTS)
   - srcuser  - extracts the source username
   - dstuser  - extracts the destination (target) username
   - user     - an alias to dstuser (only one of the two can be used)
   - srcip    - source ip
   - dstip    - dst ip
   - srcport  - source port
   - dstport  - destination port
   - protocol - protocol
   - id       - event id 
   - url      - url of the event
   - action   - event action (deny, drop, accept, etc)
   - status   - event status (success, failure, etc)
   - extra_data     - Any extra data
  -->


<decoder name="auditd">
  <prematch>^type=</prematch>
</decoder>

<!-- SELinux -->
<decoder name="auditd-selinux">
  <parent>auditd</parent>
  <prematch offset="after_parent">^AVC </prematch>
  <regex offset="after_parent">^(AVC) msg=audit\([^\)]+\) : avc:  (\S+)  { \.+ } for  pid=\S+ comm=(\S+) path=\S+ dev=\S+ ino=\S+ scontext=\S+ tcontext=\S+ tclass=\S+$</regex>
  <order>action,id,status,extra_data</order>
</decoder>

<!-- syscall -->
<decoder name="auditd-syscall">
  <parent>auditd</parent>
  <prematch offset="after_parent">^SYSCALL </prematch>
  <regex offset="after_parent">^(SYSCALL) msg=audit\([^\)]+\) : arch=\w+ syscall=\S+ success=(\S+) exit=\S+ a0=\S+ a1=\S+ a2=\S+ a3=\S+ items=\S+ ppid=\S+ pid=\S+ auid=\S+ uid=\S+ gid=\S+ euid=\S+ suid=\S+ fsuid=\S+ egid=\S+ sgid=\S+ fsgid=\S+ tty=\S+ ses=\S+ comm=\S+ exe=(\.+)</regex>
  <order>action,id,status,extra_data</order>
</decoder>

<!-- config -->
<decoder name="auditd-config">
  <parent>auditd</parent>
  <prematch offset="after_parent">^CONFIG_CHANGE </prematch>
  <regex offset="after_parent">^(CONFIG_CHANGE) msg=audit\([^\)]+\) : auid=\S+ ses=\S+ op=\.+ path=(\.+) key=\S+ list=\S+ res=\S+$</regex>
  <order>action,id,extra_data</order>
</decoder>

<!-- path (will only decode if name is not null)-->
<decoder name="auditd-path">
  <parent>auditd</parent>
  <prematch offset="after_parent">^PATH </prematch>
  <regex offset="after_parent">^(PATH) msg=audit\([^\)]+\) : item=\S+ name=(\.+) inode=\S+ dev=\S+ mode=\S+ ouid=\S+ ogid=\S+ rdev=\S+</regex>
  <order>action,id,extra_data</order>
</decoder>

<!-- user-related -->
<decoder name="auditd-user">
  <parent>auditd</parent>
  <regex offset="after_parent">^(USER_\S+) msg=audit\([^\)]+\) : user pid=\S+ uid=\S+ auid=\S+|</regex>
  <regex>^(CRED_\S+) msg=audit\([^\)]+\) : user pid=\S+ uid=\S+ auid=\S+</regex>
  <order>action,id</order>
</decoder>

<decoder name="auditd-user">
  <parent>auditd</parent>
  <regex offset="after_regex"> acct=(\.+) : exe=(\.+) \(hostname=\S+, addr=(\S+), terminal=\S+$</regex>
  <order>user,extra_data,srcip</order>
</decoder>

<decoder name="auditd-user">
  <parent>auditd</parent>
  <regex offset="after_regex"> ses=\S+ subj=\S+ msg='\.+ acct=(\.+) exe=(\.+) hostname=\S+ addr=(\S+) terminal=\S+ res=(\S+)$</regex>
  <order>user,extra_data,srcip,status</order>
</decoder>

<decoder name="auditd-user">
  <parent>auditd</parent>
  <regex offset="after_regex"> subj=\S+ msg='\.+ acct=(\.+) \p*\s*exe=(\.+) \(hostname=\S+, addr=(\S+), terminal=\S+ res=(\S+)\)'$</regex>
  <order>user,extra_data,srcip,status</order>
</decoder>

<decoder name="auditd-user">
  <parent>auditd</parent>
  <regex offset="after_regex"> subj=\S+ msg='\.+ exe=(\.+) \(hostname=\S+, addr=(\S+), terminal=\S+ res=(\S+)\)'$</regex>
  <order>extra_data,srcip,status</order>
</decoder>

<!-- EOF -->
