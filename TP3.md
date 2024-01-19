# TP3 : Linux Hardening

🌞 **Suivre un guide CIS**

- téléchargez le guide CIS de Rocky 9 [ici](https://downloads.cisecurity.org/#/)
- vous devez faire :
  - toute la section 5.2 Configure SSH Server
  - au moins 10 points dans la section 6.1 System File Permissions
  - au moins 10 points ailleur sur un truc que vous trouvez utile

### Section 2.1.1

```
[fmaxance@Rocky ~]$ rpm -q chrony
chrony-4.3-1.el9.x86_64
```

### Section 2.1.2

```
[fmaxance@Rocky ~]$ grep -E "^(server|pool)" /etc/chrony.conf
pool 2.rocky.pool.ntp.org iburst
```

```
[fmaxance@Rocky ~]$ grep ^OPTIONS /etc/sysconfig/chronyd
OPTIONS="-u chrony"
```

### Section 3.1

```
[fmaxance@Rocky ~]$ grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && echo -e "\n - IPv6 is enabled\n" || echo -e "\n - IPv6 is not enabled\n"

 - IPv6 is enabled
```

### Section 3.1.2

```
[fmaxance@Rocky ~]$ bash audit.sh 

- Audit Result:
 ** PASS **

 - System has no wireless NICs installed
```

### Section 3.1.3

```
[fmaxance@Rocky ~]$ bash audit.sh 

- Audit Result:
 ** PASS **

 - Module "tipc" doesn't exist on the
system
```

### Section 3.2.1

```
[fmaxance@Rocky ~]$ bash audit.sh 

- Audit Result:
 ** PASS **

 - "net.ipv4.ip_forward" is set to
"0" in the running configuration
 - "net.ipv4.ip_forward" is set to "0"
in "/etc/sysctl.d/60-netipv4_sysctl.conf"
 - "net.ipv4.ip_forward" is not set incorectly in
a kernel parameter configuration file
 - "net.ipv6.conf.all.forwarding" is set to
"0" in the running configuration
 - "net.ipv6.conf.all.forwarding" is set to "0"
in "/etc/sysctl.d/60-netipv6_sysctl.conf"
 - "net.ipv6.conf.all.forwarding" is not set incorectly in
a kernel parameter configuration file
```

### Section 3.2.2

```
[root@Rocky fmaxance]# printf "          
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.route.flush = 1
```

### Section 3.3.1

```
[root@Rocky fmaxance]# printf "          
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.route.flush = 1
```

```
[root@Rocky fmaxance]# printf "          
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
" >> /etc/sysctl.d/60-netipv6_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv6.route.flush=1
}
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.route.flush = 1
```
### Section 3.3.2

```
[root@Rocky fmaxance]# printf "          
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.route.flush = 1
```

```
[root@Rocky fmaxance]# printf "          
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
" >> /etc/sysctl.d/60-netipv6_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1
}
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.route.flush = 1
```

### Section 3.3.3

```
[root@Rocky fmaxance]#  printf "         
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.route.flush = 1
```

### Section 3.3.4

```
[root@Rocky fmaxance]# printf "          
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.route.flush = 1
```

### Section 3.3.5

```
[root@Rocky fmaxance]# printf "          
net.ipv4.icmp_echo_ignore_broadcasts = 1
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.route.flush = 1
```

### Section 3.3.6

```
[root@Rocky fmaxance]#  printf "         
net.ipv4.icmp_ignore_bogus_error_responses = 1
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.route.flush = 1
```

### Section 3.3.7

```
[root@Rocky fmaxance]#  printf "         
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.route.flush = 1
```

### Section 3.3.8

```
[root@Rocky fmaxance]# printf "          
net.ipv4.tcp_syncookies = 1
" >> /etc/sysctl.d/60-netipv4_sysctl.conf
```

```
[root@Rocky fmaxance]#  {
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
}
net.ipv4.tcp_syncookies = 1
net.ipv4.route.flush = 1
```

### Section 3.3.9

```
[root@Rocky fmaxance]#  printf "         
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
" >> /etc/sysctl.d/60-netipv6_sysctl.conf
```

```
[root@Rocky fmaxance]# {
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
}
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.route.flush = 1
```

### Section 5.2.1

```
[fmaxance@Rocky ~]$ stat -Lc "%n %a %u/%U %g/%G" /etc/ssh/sshd_config
/etc/ssh/sshd_config 600 0/root 0/root
```

### Section 5.2.2

```
[fmaxance@Rocky ~]$ bash audit.sh 

- Audit Result:
 ** PASS **
```

### Section 5.2.3

```
[root@Rocky fmaxance]# bash audit.sh 
 - Checking private key file: "/etc/ssh/ssh_host_ecdsa_key.pub"
 - File: "/etc/ssh/ssh_host_ecdsa_key.pub" is owned by: "" changing
owner to "root"
 - File: "/etc/ssh/ssh_host_ecdsa_key.pub" is owned by group ""
changing to group "root"
 - Checking private key file: "/etc/ssh/ssh_host_ed25519_key.pub"
 - File: "/etc/ssh/ssh_host_ed25519_key.pub" is owned by: "" changing
owner to "root"
 - File: "/etc/ssh/ssh_host_ed25519_key.pub" is owned by group ""
changing to group "root"
 - Checking private key file: "/etc/ssh/ssh_host_rsa_key.pub"
 - File: "/etc/ssh/ssh_host_rsa_key.pub" is owned by: "" changing
owner to "root"
 - File: "/etc/ssh/ssh_host_rsa_key.pub" is owned by group ""
changing to group "root"
```

### Section 5.2.4

```
[root@Rocky fmaxance]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'main: sshd: ssh-rsa algorithm is disabled
[root@Rocky fmaxance]# 
[root@Rocky fmaxance]# grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
```

### Section 5.2.5

```
[root@Rocky fmaxance]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep loglevel
main: sshd: ssh-rsa algorithm is disabled
loglevel INFO

[root@Rocky fmaxance]# sudo grep -Pi -- '^\h*loglevel' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi '(VERBOSE|INFO)'
[root@Rocky fmaxance]# 
```

### Section 5.2.6

```
[root@Rocky fmaxance]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i usepam
main: sshd: ssh-rsa algorithm is disabled
usepam yes

[root@Rocky fmaxance]# grep -Pi '^\h*UsePAM\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'yes'
```

### Section 5.2.7

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin
main: sshd: ssh-rsa algorithm is disabled
permitrootlogin no
```

### Section 5.2.8

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep hostbasedauthentication
main: sshd: ssh-rsa algorithm is disabled
hostbasedauthentication no

[root@Rocky sshd_config.d]# grep -Pi '^\h*HostbasedAuthentication\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'no'
[root@Rocky sshd_config.d]# 
```

### Section 5.2.9

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitemptypasswords
main: sshd: ssh-rsa algorithm is disabled
permitemptypasswords no

[root@Rocky sshd_config.d]# grep -Pi '^\h*PermitEmptyPasswords\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'no'
[root@Rocky sshd_config.d]# 
```

### Section 5.2.10

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permituserenvironment
main: sshd: ssh-rsa algorithm is disabled
permituserenvironment no

[root@Rocky sshd_config.d]# grep -Pi '^\h*PermitUserEnvironment\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'no'
[root@Rocky sshd_config.d]# 
```

### Section 5.2.11

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep ignorerhosts
main: sshd: ssh-rsa algorithm is disabled
ignorerhosts yes

[root@Rocky sshd_config.d]# grep -Pi '^\h*ignorerhosts\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'yes'
[root@Rocky sshd_config.d]# 
```

### Section 5.2.12

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i x11forwarding
main: sshd: ssh-rsa algorithm is disabled
x11forwarding no

[root@Rocky sshd_config.d]# grep -Pi '^\h*X11Forwarding\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'no'
[root@Rocky sshd_config.d]# 
```

### Section 5.2.13

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding
main: sshd: ssh-rsa algorithm is disabled
allowtcpforwarding no

[root@Rocky sshd_config.d]# grep -Pi '^\h*AllowTcpForwarding\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'no'
[root@Rocky sshd_config.d]# 
```

### Section 5.2.14

```
[root@Rocky sshd_config.d]# grep -i '^\s*CRYPTO_POLICY=' /etc/sysconfig/sshd
/etc/ssh/sshd_config.d/*.conf
[root@Rocky sshd_config.d]# 
```

### Section 5.2.15

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep banner

banner /etc/issue.net
```

### Section 5.2.16

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep maxauthtries

maxauthtries 4
```

### Section 5.2.17

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxstartups
main: sshd: ssh-rsa algorithm is disabled
maxstartups 10:30:60

[root@Rocky sshd_config.d]# grep -Ei '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
[root@Rocky sshd_config.d]# 
```

### Section 5.2.18

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxsessions
main: sshd: ssh-rsa algorithm is disabled
maxsessions 10

[root@Rocky sshd_config.d]# grep -Ei '^\s*MaxSessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
[root@Rocky sshd_config.d]# 
```

### Section 5.2.19

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep logingracetime

logingracetime 60
```

### Section 5.2.20

```
[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientaliveinterval
clientaliveinterval 15

[root@Rocky sshd_config.d]# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientalivecountmax
clientalivecountmax 3
```

### Section 6.1.1

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/passwd
/etc/passwd 644 0/root 0/root
```

### Section 6.1.2

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/passwd-
/etc/passwd- 644 0/root 0/root
```

### Section 6.1.3

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/group
/etc/group 644 0/root 0/root
```

### Section 6.1.4

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/group-
/etc/group- 644 0/root 0/root
```

### Section 6.1.5

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/shadow
/etc/shadow 0 0/root 0/root
```

### Section 6.1.6

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/shadow-
/etc/shadow- 0 0/root 0/root
```

### Section 6.1.7

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/gshadow
/etc/gshadow 0 0/root 0/root
```

### Section 6.1.8

```
[root@Rocky sshd_config.d]# stat -Lc "%n %a %u/%U %g/%G" /etc/gshadow-
/etc/gshadow- 0 0/root 0/root
```

### Section 6.1.9

```
[root@Rocky sshd_config.d]# df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
[root@Rocky sshd_config.d]# super merci y'a aucun fichier :3
> ah
> ^C
[root@Rocky sshd_config.d]# 
```

### Section 6.1.10

```
[root@Rocky sshd_config.d]# df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
[root@Rocky sshd_config.d]# 
```

### Section 6.2.1

```
[root@Rocky sshd_config.d]# awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd
[root@Rocky sshd_config.d]# 
```

### Section 6.2.2

```
[root@Rocky sshd_config.d]# awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
[root@Rocky sshd_config.d]# 
```

### Section 6.2.3

```
[root@Rocky fmaxance]# cat audit.sh 
#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:[^:]*:$i:" /etc/group
if [ $? -ne 0 ]; then
echo "Group $i is referenced by /etc/passwd but does not exist in
/etc/group"
fi
done
[root@Rocky fmaxance]# bash audit.sh 
[root@Rocky fmaxance]# 
```

### Section 6.2.4

```
[root@Rocky fmaxance]# cat audit.sh 
#!/bin/bash
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
[ -z "$x" ] && break
set - $x
if [ $1 -gt 1 ]; then
users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
echo "Duplicate UID ($2): $users"
fi
done
[root@Rocky fmaxance]# bash audit.sh 
[root@Rocky fmaxance]# 
```

### Section 6.2.5

```
[root@Rocky fmaxance]# cat audit.sh 
#!/bin/bash
cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
echo "Duplicate GID ($x) in /etc/group"
done
[root@Rocky fmaxance]# bash audit.sh 
[root@Rocky fmaxance]# 
```

### Section 6.2.6

```
[root@Rocky fmaxance]# cat audit.sh 
#!/bin/bash
cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do
echo "Duplicate login name $x in /etc/passwd"
done
[root@Rocky fmaxance]# bash audit.sh 
[root@Rocky fmaxance]# 
```

### Section 6.2.7

```
[root@Rocky fmaxance]# cat audit.sh 
#!/bin/bash
cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do
echo "Duplicate group name $x in /etc/group"
done
[root@Rocky fmaxance]# bash audit.sh 
[root@Rocky fmaxance]# 
```

### Section 6.2.8

```
[root@Rocky fmaxance]# cat audit.sh 
#!/bin/bash
RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory
(::)"
echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
for x in $(echo "$RPCV" | tr ":" " "); do
if [ -d "$x" ]; then
ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working
directory (.)"}
$3 != "root" {print $9, "is not owned by root"}
substr($1,6,1) != "-" {print $9, "is group writable"}
substr($1,9,1) != "-" {print $9, "is world writable"}'
else
echo "$x is not a directory"
fi
done
[root@Rocky fmaxance]# bash audit.sh
[root@Rocky fmaxance]#
```

### Section 6.2.9

```
[root@Rocky fmaxance]# awk -F: '($3 == 0) { print $1 }' /etc/passwd
root
```

### Section 6.2.10

```
[root@Rocky fmaxance]# cat audit.sh 
#!/usr/bin/env bash
{
output=""
valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -
d '|' - ))$"
awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
/etc/passwd | (while read -r user home; do
[ ! -d "$home" ] && output="$output\n - User \"$user\" home directory
\"$home\" doesn't exist"
done
if [ -z "$output" ]; then
echo -e "\n-PASSED: - All local interactive users have a home
directory\n"
else
echo -e "\n- FAILED:\n$output\n"
fi
)
}
[root@Rocky fmaxance]# bash audit.sh
[root@Rocky fmaxance]#
```

## 2. Conf SSH

🌞 **Chiffrement fort côté serveur**

Ressource : https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu-20-04

```
[fmaxance@Rocky ~]$ sudo cat /etc/ssh/sshd_config
#       $OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# To modify the system-wide sshd configuration, create a  *.conf  file under
#  /etc/ssh/sshd_config.d/  which will be automatically included below
Include /etc/ssh/sshd_config.d/*.conf

# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#
#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

LoginGraceTime 20
PermitRootLogin no
#StrictModes yes
MaxAuthTries 3
#MaxSessions 10
ChallengeResponseAuthentication no

#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile      .ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
PermitEmptyPasswords no

# Change to no to disable s/key passwords
#KbdInteractiveAuthentication yes

# Kerberos options
KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
#GSSAPIEnablek5users no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
# WARNING: 'UsePAM no' is not supported in RHEL and may cause several
# problems.
#UsePAM no

AllowAgentForwarding no
AllowTcpForwarding no
#GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem       sftp    /usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
```

🌞 **Clés de chiffrement fortes pour le client**

Ressource Partie 4 :
https://www.digitalocean.com/community/tutorials/how-to-harden-openssh-on-ubuntu-20-04

🌞 **Connectez-vous en SSH à votre VM avec cette paire de clés**

```
fmaxance@ZeyKiiPC:~$ ssh -vvvv fmaxance@192.168.57.3
OpenSSH_9.2p1 Debian-2+deb12u2, OpenSSL 3.0.11 19 Sep 2023
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug2: resolve_canonicalize: hostname 192.168.57.3 is address
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts' -> '/home/fmaxance/.ssh/known_hosts'
debug3: expanded UserKnownHostsFile '~/.ssh/known_hosts2' -> '/home/fmaxance/.ssh/known_hosts2'
debug3: ssh_connect_direct: entering
debug1: Connecting to 192.168.57.3 [192.168.57.3] port 22.
debug3: set_sock_tos: set socket 3 IP_TOS 0x10
debug1: Connection established.
debug1: identity file /home/fmaxance/.ssh/id_rsa type 0
debug1: identity file /home/fmaxance/.ssh/id_rsa-cert type -1
debug1: identity file /home/fmaxance/.ssh/id_ecdsa type -1
debug1: identity file /home/fmaxance/.ssh/id_ecdsa-cert type -1
debug1: identity file /home/fmaxance/.ssh/id_ecdsa_sk type -1
debug1: identity file /home/fmaxance/.ssh/id_ecdsa_sk-cert type -1
debug1: identity file /home/fmaxance/.ssh/id_ed25519 type -1
debug1: identity file /home/fmaxance/.ssh/id_ed25519-cert type -1
debug1: identity file /home/fmaxance/.ssh/id_ed25519_sk type -1
debug1: identity file /home/fmaxance/.ssh/id_ed25519_sk-cert type -1
debug1: identity file /home/fmaxance/.ssh/id_xmss type -1
debug1: identity file /home/fmaxance/.ssh/id_xmss-cert type -1
debug1: identity file /home/fmaxance/.ssh/id_dsa type -1
debug1: identity file /home/fmaxance/.ssh/id_dsa-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
debug1: Remote protocol version 2.0, remote software version OpenSSH_8.7
debug1: compat_banner: match: OpenSSH_8.7 pat OpenSSH* compat 0x04000000
debug2: fd 3 setting O_NONBLOCK
debug1: Authenticating to 192.168.57.3:22 as 'fmaxance'
debug3: record_hostkey: found key type ED25519 in file /home/fmaxance/.ssh/known_hosts:12
debug3: load_hostkeys_file: loaded 1 keys from 192.168.57.3
debug1: load_hostkeys: fopen /home/fmaxance/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug3: order_hostkeyalgs: have matching best-preference key type ssh-ed25519-cert-v01@openssh.com, using HostkeyAlgorithms verbatim
debug3: send packet: type 20
debug1: SSH2_MSG_KEXINIT sent
debug3: receive packet: type 20
debug1: SSH2_MSG_KEXINIT received
debug2: local client KEXINIT proposal
debug2: KEX algorithms: sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com
debug2: host key algorithms: ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256
debug2: ciphers ctos: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
debug2: MACs ctos: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
debug2: MACs stoc: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
debug2: compression ctos: none,zlib@openssh.com,zlib
debug2: compression stoc: none,zlib@openssh.com,zlib
debug2: languages ctos: 
debug2: languages stoc: 
debug2: first_kex_follows 0 
debug2: reserved 0 
debug2: peer server KEXINIT proposal
debug2: KEX algorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
debug2: host key algorithms: rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519
debug2: ciphers ctos: aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
debug2: ciphers stoc: aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
debug2: MACs ctos: hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512
debug2: MACs stoc: hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512
debug2: compression ctos: none,zlib@openssh.com
debug2: compression stoc: none,zlib@openssh.com
debug2: languages ctos: 
debug2: languages stoc: 
debug2: first_kex_follows 0 
debug2: reserved 0 
debug1: kex: algorithm: curve25519-sha256
debug1: kex: host key algorithm: ssh-ed25519
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug3: send packet: type 30
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug3: receive packet: type 31
debug1: SSH2_MSG_KEX_ECDH_REPLY received
debug1: Server host key: ssh-ed25519 SHA256:Pu68IMCzfs/658FYeor7Sv3Yv67Z7AQ1DIrl/bYLC/0
debug3: record_hostkey: found key type ED25519 in file /home/fmaxance/.ssh/known_hosts:12
debug3: load_hostkeys_file: loaded 1 keys from 192.168.57.3
debug1: load_hostkeys: fopen /home/fmaxance/.ssh/known_hosts2: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts: No such file or directory
debug1: load_hostkeys: fopen /etc/ssh/ssh_known_hosts2: No such file or directory
debug1: Host '192.168.57.3' is known and matches the ED25519 host key.
debug1: Found key in /home/fmaxance/.ssh/known_hosts:12
debug3: send packet: type 21
debug2: ssh_set_newkeys: mode 1
debug1: rekey out after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug3: receive packet: type 21
debug1: SSH2_MSG_NEWKEYS received
debug2: ssh_set_newkeys: mode 0
debug1: rekey in after 134217728 blocks
debug3: ssh_get_authentication_socket_path: path '/run/user/1000/openssh_agent'
debug1: get_agent_identities: bound agent to hostkey
debug1: get_agent_identities: ssh_fetch_identitylist: agent contains no identities
debug1: Will attempt key: /home/fmaxance/.ssh/id_rsa RSA SHA256:kC4bPcRWPV8lcxpMqLB5kiNy4AChBEF4T9wh5Qhk9Yc
debug1: Will attempt key: /home/fmaxance/.ssh/id_ecdsa 
debug1: Will attempt key: /home/fmaxance/.ssh/id_ecdsa_sk 
debug1: Will attempt key: /home/fmaxance/.ssh/id_ed25519 
debug1: Will attempt key: /home/fmaxance/.ssh/id_ed25519_sk 
debug1: Will attempt key: /home/fmaxance/.ssh/id_xmss 
debug1: Will attempt key: /home/fmaxance/.ssh/id_dsa 
debug2: pubkey_prepare: done
debug3: send packet: type 5
debug3: receive packet: type 7
debug1: SSH2_MSG_EXT_INFO received
debug1: kex_input_ext_info: server-sig-algs=<ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com>
debug3: receive packet: type 6
debug2: service_accept: ssh-userauth
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug3: send packet: type 50
debug3: receive packet: type 53
debug3: input_userauth_banner: entering
\S
Kernel \r on an \m
debug3: receive packet: type 51
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic
debug3: start over, passed a different list publickey,gssapi-keyex,gssapi-with-mic
debug3: preferred gssapi-with-mic,publickey,keyboard-interactive,password
debug3: authmethod_lookup gssapi-with-mic
debug3: remaining preferred: publickey,keyboard-interactive,password
debug3: authmethod_is_enabled gssapi-with-mic
debug1: Next authentication method: gssapi-with-mic
debug1: No credentials were supplied, or the credentials were unavailable or inaccessible
No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)


debug1: No credentials were supplied, or the credentials were unavailable or inaccessible
No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)


debug2: we did not send a packet, disable method
debug3: authmethod_lookup publickey
debug3: remaining preferred: keyboard-interactive,password
debug3: authmethod_is_enabled publickey
debug1: Next authentication method: publickey
debug1: Offering public key: /home/fmaxance/.ssh/id_rsa RSA SHA256:kC4bPcRWPV8lcxpMqLB5kiNy4AChBEF4T9wh5Qhk9Yc
debug3: send packet: type 50
debug2: we sent a publickey packet, wait for reply
debug3: receive packet: type 60
debug1: Server accepts key: /home/fmaxance/.ssh/id_rsa RSA SHA256:kC4bPcRWPV8lcxpMqLB5kiNy4AChBEF4T9wh5Qhk9Yc
debug3: sign_and_send_pubkey: using publickey with RSA SHA256:kC4bPcRWPV8lcxpMqLB5kiNy4AChBEF4T9wh5Qhk9Yc
debug3: sign_and_send_pubkey: signing using rsa-sha2-512 SHA256:kC4bPcRWPV8lcxpMqLB5kiNy4AChBEF4T9wh5Qhk9Yc
Enter passphrase for key '/home/fmaxance/.ssh/id_rsa': 
debug3: send packet: type 50
debug3: receive packet: type 52
Authenticated to 192.168.57.3 ([192.168.57.3]:22) using "publickey".
debug1: channel 0: new session [client-session] (inactive timeout: 0)
debug3: ssh_session2_open: channel_new: 0
debug2: channel 0: send open
debug3: send packet: type 90
debug1: Requesting no-more-sessions@openssh.com
debug3: send packet: type 80
debug1: Entering interactive session.
debug1: pledge: filesystem
debug3: client_repledge: enter
debug3: receive packet: type 80
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug3: client_input_hostkeys: received RSA key SHA256:1+yYr/8sPyzAfBya4BiYSAXJVaryS0J0eCXgrJRbbiI
debug3: client_input_hostkeys: received ECDSA key SHA256:Qo2Sxasc9AyfkWYXVFb/9ehsV7Xx3g+VEiwXmdwczFA
debug3: client_input_hostkeys: received ED25519 key SHA256:Pu68IMCzfs/658FYeor7Sv3Yv67Z7AQ1DIrl/bYLC/0
debug1: client_input_hostkeys: searching /home/fmaxance/.ssh/known_hosts for 192.168.57.3 / (none)
debug3: hostkeys_foreach: reading file "/home/fmaxance/.ssh/known_hosts"
debug3: hostkeys_find: found ssh-ed25519 key under different name/addr at /home/fmaxance/.ssh/known_hosts:6
debug3: hostkeys_find: found ssh-rsa key under different name/addr at /home/fmaxance/.ssh/known_hosts:7
debug3: hostkeys_find: found ecdsa-sha2-nistp256 key under different name/addr at /home/fmaxance/.ssh/known_hosts:8
debug3: hostkeys_find: found ssh-ed25519 key under different name/addr at /home/fmaxance/.ssh/known_hosts:9
debug3: hostkeys_find: found ssh-ed25519 key under different name/addr at /home/fmaxance/.ssh/known_hosts:10
debug3: hostkeys_find: found ssh-ed25519 key under different name/addr at /home/fmaxance/.ssh/known_hosts:11
debug3: hostkeys_find: found ssh-ed25519 key at /home/fmaxance/.ssh/known_hosts:12
debug1: client_input_hostkeys: searching /home/fmaxance/.ssh/known_hosts2 for 192.168.57.3 / (none)
debug1: client_input_hostkeys: hostkeys file /home/fmaxance/.ssh/known_hosts2 does not exist
debug3: client_input_hostkeys: 3 server keys: 2 new, 18446744073709551615 retained, 2 incomplete match. 0 to remove
debug1: client_input_hostkeys: host key found matching a different name/address, skipping UserKnownHostsFile update
debug3: client_repledge: enter
debug3: receive packet: type 4
debug1: Remote: /home/fmaxance/.ssh/authorized_keys:1: key options: port-forwarding pty user-rc
debug3: receive packet: type 4
debug1: Remote: /home/fmaxance/.ssh/authorized_keys:1: key options: port-forwarding pty user-rc
debug3: receive packet: type 91
debug2: channel_input_open_confirmation: channel 0: callback start
debug2: fd 3 setting TCP_NODELAY
debug3: set_sock_tos: set socket 3 IP_TOS 0x10
debug2: client_session2_setup: id 0
debug2: channel 0: request pty-req confirm 1
debug3: send packet: type 98
debug1: Sending environment.
debug3: Ignored env SHELL
debug3: Ignored env SESSION_MANAGER
debug3: Ignored env WINDOWID
debug3: Ignored env QT_ACCESSIBILITY
debug3: Ignored env COLORTERM
debug3: Ignored env XDG_CONFIG_DIRS
debug3: Ignored env SSH_AGENT_LAUNCHER
debug3: Ignored env XDG_SESSION_PATH
debug3: Ignored env LANGUAGE
debug3: Ignored env SSH_AUTH_SOCK
debug3: Ignored env SHELL_SESSION_ID
debug3: Ignored env DESKTOP_SESSION
debug3: Ignored env GTK_RC_FILES
debug3: Ignored env XCURSOR_SIZE
debug3: Ignored env GTK_MODULES
debug3: Ignored env XDG_SEAT
debug3: Ignored env PWD
debug3: Ignored env XDG_SESSION_DESKTOP
debug3: Ignored env LOGNAME
debug3: Ignored env XDG_SESSION_TYPE
debug3: Ignored env SYSTEMD_EXEC_PID
debug3: Ignored env XAUTHORITY
debug3: Ignored env XKB_DEFAULT_MODEL
debug3: Ignored env GTK2_RC_FILES
debug3: Ignored env HOME
debug1: channel 0: setting env LANG = "en_US.UTF-8"
debug2: channel 0: request env confirm 0
debug3: send packet: type 98
debug3: Ignored env LS_COLORS
debug3: Ignored env XDG_CURRENT_DESKTOP
debug3: Ignored env KONSOLE_DBUS_SERVICE
debug3: Ignored env WAYLAND_DISPLAY
debug3: Ignored env KONSOLE_DBUS_SESSION
debug3: Ignored env PROFILEHOME
debug3: Ignored env XDG_SEAT_PATH
debug3: Ignored env QTWEBENGINE_DICTIONARIES_PATH
debug3: Ignored env INVOCATION_ID
debug3: Ignored env KONSOLE_VERSION
debug3: Ignored env MANAGERPID
debug3: Ignored env KDE_SESSION_UID
debug3: Ignored env XKB_DEFAULT_LAYOUT
debug3: Ignored env XDG_ACTIVATION_TOKEN
debug3: Ignored env XDG_SESSION_CLASS
debug3: Ignored env TERM
debug3: Ignored env USER
debug3: Ignored env COLORFGBG
debug3: Ignored env PLASMA_USE_QT_SCALING
debug3: Ignored env KDE_SESSION_VERSION
debug3: Ignored env PAM_KWALLET5_LOGIN
debug3: Ignored env QT_WAYLAND_FORCE_DPI
debug3: Ignored env DISPLAY
debug3: Ignored env SHLVL
debug3: Ignored env XDG_VTNR
debug3: Ignored env XDG_SESSION_ID
debug3: Ignored env XDG_RUNTIME_DIR
debug3: Ignored env XKB_DEFAULT_VARIANT
debug3: Ignored env QT_AUTO_SCREEN_SCALE_FACTOR
debug3: Ignored env JOURNAL_STREAM
debug3: Ignored env XCURSOR_THEME
debug3: Ignored env XDG_DATA_DIRS
debug3: Ignored env KDE_FULL_SESSION
debug3: Ignored env PATH
debug3: Ignored env DBUS_SESSION_BUS_ADDRESS
debug3: Ignored env KDE_APPLICATIONS_AS_SCOPE
debug3: Ignored env KONSOLE_DBUS_WINDOW
debug3: Ignored env _
debug2: channel 0: request shell confirm 1
debug3: send packet: type 98
debug3: client_repledge: enter
debug1: pledge: fork
debug2: channel_input_open_confirmation: channel 0: callback done
debug2: channel 0: open confirm rwindow 0 rmax 32768
debug3: receive packet: type 99
debug2: channel_input_status_confirm: type 99 id 0
debug2: PTY allocation request accepted on channel 0
debug2: channel 0: rcvd adjust 2097152
debug3: receive packet: type 99
debug2: channel_input_status_confirm: type 99 id 0
debug2: shell request accepted on channel 0
Last login: Fri Jan 19 09:30:39 2024 from 192.168.57.1
```

## 4. DoT

Ca commence à faire quelques années maintenant que plusieurs acteurs poussent pour qu'on fasse du DNS chiffré, et qu'on arrête d'envoyer des requêtes DNS en clair dans tous les sens.

Le Dot est une techno qui va dans ce sens : DoT pour DNS over TLS. On fait nos requêtes DNS dans des tunnels chiffrés avec le protocole TLS.

🌞 **Configurer la machine pour qu'elle fasse du DoT**

- installez `systemd-networkd` sur la machine pour ça
- activez aussi DNSSEC tant qu'on y est
- référez-vous à cette doc qui est cool par exemple
- utilisez le serveur public de CloudFlare : 1.1.1.1 (il supporte le DoT)

🌞 **Prouvez que les requêtes DNS effectuées par la machine...**

- ont une réponse qui provient du serveur que vous avez conf (normalement c'est `127.0.0.1` avec `systemd-networkd` qui tourne)
  - quand on fait un `dig ynov.com` on voit en bas quel serveur a répondu
- mais qu'en réalité, la requête a été forward vers 1.1.1.1 avec du TLS
  - je veux une capture Wireshark à l'appui !

## 5. AIDE

Un truc demandé au point 1.3.1 du guide CIS c'est d'installer AIDE.

AIDE est un IDS ou *Intrusion Detection System*. Les IDS c'est un type de programme dont les fonctions peuvent être multiples.

Dans notre cas, AIDE, il surveille que certains fichiers du disque n'ont pas été modifiés. Des fichiers comme `/etc/shadow` par exemple.

🌞 **Installer et configurer AIDE**

- et bah incroyable mais [une très bonne ressource ici](https://www.it-connect.fr/aide-utilisation-et-configuration-dune-solution-de-controle-dintegrite-sous-linux/)
- configurez AIDE pour qu'il surveille (fichier de conf en compte-rendu)
  - le fichier de conf du serveur SSH
  - le fichier de conf du client chrony (le service qui gère le temps)
  - le fichier de conf de `systemd-networkd`

🌞 **Scénario de modification**

- introduisez une modification dans le fichier de conf du serveur SSH
- montrez que AIDE peut la détecter

🌞 **Timer et service systemd**

- créez un service systemd qui exécute un check AIDE
  - il faut créer un fichier `.service` dans le dossier `/etc/systemd/system/`
  - contenu du fichier à montrer dans le compte rendu
- créez un timer systemd qui exécute un check AIDE toutes les 10 minutes
  - il faut créer un fichier `.timer` dans le dossier `/etc/systemd/system/`
  - il doit porter le même nom que le service, genre `aide.service` et `aide.timer`
  - c'est complètement irréaliste 10 minutes, mais ça vous permettra de faire des tests (vous pouvez même raccourcir encore)
