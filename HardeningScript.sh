#!/bin/bash

# Affiche les messages de succès
function success_message {
    echo -e "\e[32m[Success]\e[0m $1"
}

# Affiche les messages d'erreur
function error_message {
    echo -e "\e[31m[Error]\e[0m $1"
}

# Configure le kernel et les services de base
function configure_os {
    sudo dnf update -y
    sudo dnf install -y dnf-automatic
    sudo systemctl enable --now dnf-automatic.timer

    # Désactive le chargement de modules non signés
    echo "install usb-storage /bin/true" | sudo tee /etc/modprobe.d/usb-storage.conf >/dev/null
    sudo chmod 600 /etc/modprobe.d/usb-storage.conf

    # On s'assure que le service Chrony est installé
    sudo dnf install -y chrony
    sudo systemctl start chronyd
    sudo systemctl enable chronyd

    # On active un audit de sécurité
    sudo dnf install -y audit
    sudo systemctl enable --now auditd

    # Configure sudo
    echo "%admin ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/admin >/dev/null

    success_message "OS configured successfully"
}

# Configure l'accès à distance (SSH)
function configure_ssh {
    sudo dnf install -y openssh-server
    sudo systemctl start sshd
    sudo systemctl enable sshd

    # Configure SSH (désactive la connexion par root, par mot de passe)
    sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    success_message "SSH configured successfully"
}

# Gère la configuration de NGINX
function configure_nginx {
    sudo dnf install -y nginx

    # Génère une clé privée et un certificat auto-signé avec RSA
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/nginx.key -out /etc/nginx/nginx.crt -subj "/CN=localhost"

    # Configure NGINX (SSL/TLS)
sudo tee /etc/nginx/nginx.conf > /dev/null <<EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    server {
        listen 80;
        server_name localhost;

        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
    }

    server {
        listen 443 ssl;
        server_name localhost;

        ssl_certificate /etc/nginx/nginx.crt;
        ssl_certificate_key /etc/nginx/nginx.key;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
        ssl_prefer_server_ciphers off;

        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
    }
}
EOF

    # Redémarre NGINX
    sudo systemctl restart nginx

    success_message "NGINX configured successfully with SSL/TLS"
}

# Ajoute et configure les services de sécurité
function configure_security_services {
    # Installer fail2ban
    sudo dnf install -y epel-release
    sudo dnf install -y fail2ban

    # Configure fail2ban
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban

    # Installer firewalld
    sudo dnf install -y firewalld
    sudo systemctl enable --now firewalld

    # Configure firewalld
    sudo firewall-cmd --permanent --add-service=ssh
    sudo firewall-cmd --reload

    success_message "Security services configured successfully"
}

# Désactive des services inutiles
function desactive_services {
    sudo systemctl disable cups

    sudo systemctl disable bluetooth

    sudo systemctl disable avahi-daemon

    sudo systemctl disable canna

    sudo systemctl disable ModemManager

    sudo systemctl disable isdn

    sudo systemctl disable rpcbind

    sudo systemctl disable sendmail

    sudo systemctl disable smb
    sudo systemctl disable nmb
}

# Appel des fonctions
configure_os
configure_ssh
configure_nginx
configure_security_services
desactive_services

# Fin du script
echo "Hardening script completed."