# TP4 : Hardening Script

# I. Setup initial

| Machine      | IP          | Rôle                       |
| ------------ | ----------- | -------------------------- |
| `rp.tp5.b2`  | `10.5.1.11` | reverse proxy (NGINX)      |
| `web.tp5.b2` | `10.5.1.12` | serveur Web (NGINX oci) |

🌞 **Setup `web.tp5.b2`**

```
[fmaxance@webtp4b2 ~]$ sudo cat /var/www/app_nulle/index.html

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>My Website</title>
    <link rel="stylesheet" href="./style.css">
    <link rel="icon" href="./favicon.ico" type="image/x-icon">
  </head>
  <body>
    <main>
        <h1>Welcome to My Website</h1>  
    </main>
        <script src="index.js"></script>
  </body>
</html>
```

```
[fmaxance@webtp4b2 ~]$ ls -ld /var/www/app_nulle/
drwxr-x---. 2 nginx nginx 24 Jan 19 11:04 /var/www/app_nulle/
[fmaxance@webtp4b2 ~]$ ls -l /var/www/app_nulle/index.html
ls: cannot access '/var/www/app_nulle/index.html': Permission denied
[fmaxance@webtp4b2 ~]$ sudo ls -l /var/www/app_nulle/index.html
-rw-r-----. 1 nginx nginx 477 Jan 19 11:04 /var/www/app_nulle/index.html
```

```
[fmaxance@webtp4b2 ~]$ cd /etc/nginx/conf.d/
[fmaxance@webtp4b2 conf.d]$ ls
app_nulle.conf
[fmaxance@webtp4b2 conf.d]$ cat app_nulle.conf 
server {
    listen 80;
    server_name localhost; # Remplacez par votre nom de domaine si applicable

    location / {
        root /var/www/app_nulle/;
        index index.html;
    }

    # Autres configurations si nécessaires...
}
```

```
[fmaxance@webtp4b2 ~]$ systemctl status nginx
● nginx.service - The nginx HTTP and reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; preset: disabled)
     Active: active (running) since Fri 2024-01-19 11:11:35 CET; 8min ago
    Process: 32074 ExecStartPre=/usr/bin/rm -f /run/nginx.pid (code=exited, status=0/>
    Process: 32075 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
    Process: 32076 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
   Main PID: 32077 (nginx)
      Tasks: 5 (limit: 23080)
     Memory: 4.7M
        CPU: 17ms
     CGroup: /system.slice/nginx.service
             ├─32077 "nginx: master process /usr/sbin/nginx"
             ├─32078 "nginx: worker process"
             ├─32079 "nginx: worker process"
             ├─32080 "nginx: worker process"
             └─32081 "nginx: worker process"

Jan 19 11:11:35 webtp4b2 systemd[1]: Starting The nginx HTTP and reverse proxy server>
Jan 19 11:11:35 webtp4b2 nginx[32075]: nginx: the configuration file /etc/nginx/nginx>
Jan 19 11:11:35 webtp4b2 nginx[32075]: nginx: configuration file /etc/nginx/nginx.con>
Jan 19 11:11:35 webtp4b2 systemd[1]: Started The nginx HTTP and reverse proxy server.
```

🌞 **Setup `rp.tp5.b2`**

```
[fmaxance@rptp4b2 ~]$ cd /etc/nginx/conf.d/
[fmaxance@rptp4b2 conf.d]$ ls
reverse_proxy.conf
[fmaxance@rptp4b2 conf.d]$ cat reverse_proxy.conf 
server {
    listen 80;
    server_name app.tp5.b2;

    location / {
        proxy_pass http://10.5.1.12;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```
[fmaxance@rptp4b2 ~]$ systemctl status nginx
● nginx.service - The nginx HTTP and reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; preset: disabled)
     Active: active (running) since Fri 2024-01-19 11:22:50 CET; 4min 33s ago
   Main PID: 31882 (nginx)
      Tasks: 5 (limit: 23080)
     Memory: 4.7M
        CPU: 18ms
     CGroup: /system.slice/nginx.service
             ├─31882 "nginx: master process /usr/sbin/nginx"
             ├─31883 "nginx: worker process"
             ├─31884 "nginx: worker process"
             ├─31885 "nginx: worker process"
             └─31886 "nginx: worker process"

Jan 19 11:22:50 rptp4b2 systemd[1]: Starting The nginx HTTP and reverse proxy server...
Jan 19 11:22:50 rptp4b2 nginx[31880]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Jan 19 11:22:50 rptp4b2 nginx[31880]: nginx: configuration file /etc/nginx/nginx.conf test is successful
Jan 19 11:22:50 rptp4b2 systemd[1]: Started The nginx HTTP and reverse proxy server.
```

```
fmaxance@ZeyKiiPC:~$ sudo cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       ZeyKiiPC.lan    ZeyKiiPC

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.5.1.11    app.tp5.b2
```

🌞 **HTTPS `rp.tp5.b2`**

```
[fmaxance@rptp4b2 ~]$ sudo cat /etc/nginx/conf.d/reverse_proxy.conf
server {
    listen 443 ssl;
    server_name app.tp5.b2;

    ssl_certificate     /etc/pki/tls/certs/server.crt;
    ssl_certificate_key /etc/pki/tls/private/server.key;

    location / {
        proxy_pass http://10.5.1.12;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```
[fmaxance@rptp4b2 ~]$ systemctl status nginx
● nginx.service - The nginx HTTP and reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; preset: disabled)
     Active: active (running) since Fri 2024-01-19 11:36:31 CET; 2min 15s ago
    Process: 32036 ExecStartPre=/usr/bin/rm -f /run/nginx.pid (code=exited, status=0/SUCCESS)
    Process: 32037 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
    Process: 32038 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
   Main PID: 32039 (nginx)
      Tasks: 5 (limit: 23080)
     Memory: 5.0M
        CPU: 18ms
     CGroup: /system.slice/nginx.service
             ├─32039 "nginx: master process /usr/sbin/nginx"
             ├─32040 "nginx: worker process"
             ├─32041 "nginx: worker process"
             ├─32042 "nginx: worker process"
             └─32043 "nginx: worker process"

Jan 19 11:36:31 rptp4b2 systemd[1]: Starting The nginx HTTP and reverse proxy server...
```

# II. Hardening script

Dans cette section, le coeur du sujet, vous allez développer un script `bash` qui permet de renforcer la sécurité de ces deux machines.

➜ **Votre script doit permettre de :**

- **configurer l'OS** ✅
  - tout ce qui va être relatif au kernel
  - et tous les services basiques du système, comme la gestion de l'heure
  - éventuellement de la conf systemd, sudo, etc.
- **configurer l'accès à distance** ✅
  - on pose une conf SSH robuste
- **gérer la conf NGINX** ✅
  - votre script doit aussi proposer un fichier de conf NGINX maîtrisé et robuste
- **ajouter et configurer des services de sécurité** ✅
  - on pense à fail2ban, AIDE, ou autres

[HardeningScript](/HardeningScript.sh)