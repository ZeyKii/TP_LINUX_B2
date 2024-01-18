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

![SSH](./img/ssh.jpg)

🌞 **Chiffrement fort côté serveur**

- trouver une ressource de confiance (je veux le lien en compte-rendu)
- configurer le serveur SSH pour qu'il utilise des paramètres forts en terme de chiffrement (je veux le fichier de conf dans le compte-rendu)
  - conf dans le fichier de conf
  - regénérer des clés pour le serveur ?
  - regénérer les paramètres Diffie-Hellman ? (se renseigner sur Diffie-Hellman ?)

🌞 **Clés de chiffrement fortes pour le client**

- trouver une ressource de confiance (je veux le lien en compte-rendu)
- générez-vous une paire de clés qui utilise un chiffrement fort et une passphrase
- ne soyez pas non plus absurdes dans le choix du chiffrement quand je dis "fort" (genre pas de RSA avec une clé de taile 98789080932083209 bytes)

🌞 **Connectez-vous en SSH à votre VM avec cette paire de clés**

- prouvez en ajoutant `-vvvv` sur la commande `ssh` de connexion que vous utilisez bien cette clé là

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
