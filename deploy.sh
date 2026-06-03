#!/bin/bash
set -e

echo "╔══════════════════════════════════════╗"
echo "║       Mini-IdP Deployment            ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
  echo "📦 Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

NODE_VER=$(node -v)
echo "✅ Node.js: $NODE_VER"

# Install directory
INSTALL_DIR="/opt/mini-idp"
echo ""
echo "Install directory: $INSTALL_DIR"

# Copy files
sudo mkdir -p $INSTALL_DIR
sudo cp -r ./* $INSTALL_DIR/
sudo chown -R $USER:$USER $INSTALL_DIR

cd $INSTALL_DIR

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
npm install --production 2>&1 | tail -3

# Run setup
echo ""
echo "🔧 Running setup..."
node setup.js

# Create systemd service
echo ""
echo "📋 Creating systemd service..."
sudo tee /etc/systemd/system/mini-idp.service > /dev/null << SVCEOF
[Unit]
Description=Mini-IdP SAML Identity Provider
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
SVCEOF

sudo systemctl daemon-reload
sudo systemctl enable mini-idp
sudo systemctl start mini-idp

echo ""
echo "✅ Mini-IdP is running!"
echo ""
echo "Check status:    sudo systemctl status mini-idp"
echo "View logs:       sudo journalctl -u mini-idp -f"
echo "Restart:         sudo systemctl restart mini-idp"
echo ""

# Update Nginx config
read -p "Update Nginx config to proxy to Mini-IdP? [Y/n]: " UPDATE_NGINX
if [ "$UPDATE_NGINX" != "n" ] && [ "$UPDATE_NGINX" != "N" ]; then
  DOMAIN=$(grep "^HOSTNAME=" .env | cut -d= -f2)
  if [ -z "$DOMAIN" ]; then
    read -p "Enter your domain: " DOMAIN
  fi

  sudo tee /etc/nginx/sites-available/mini-idp > /dev/null << NGXEOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
    }
}
NGXEOF

  # Remove old keycloak config if exists
  sudo rm -f /etc/nginx/sites-enabled/keycloak
  sudo ln -sf /etc/nginx/sites-available/mini-idp /etc/nginx/sites-enabled/

  sudo nginx -t && sudo systemctl reload nginx
  echo "✅ Nginx updated for $DOMAIN"
fi

echo ""
echo "🎉 All done! Visit https://$DOMAIN/admin to manage your IdP."
