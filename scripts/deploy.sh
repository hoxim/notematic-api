#!/bin/bash

# Deployment script for Notematic API
# This script should be run on the server

set -e

# Configuration
APP_NAME="notematic-api"
APP_DIR="/opt/$APP_NAME"
BACKUP_DIR="$APP_DIR/backup"
SERVICE_NAME="$APP_NAME"
USER_NAME="notematic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root"
   exit 1
fi

log "Starting deployment of $APP_NAME"

# Create directories if they don't exist
sudo mkdir -p "$APP_DIR"
sudo mkdir -p "$BACKUP_DIR"

# Stop the service if it's running
log "Stopping $SERVICE_NAME service..."
sudo systemctl stop "$SERVICE_NAME" || warn "Service was not running"

# Create backup of current version
if [ -f "$APP_DIR/$APP_NAME" ]; then
    log "Creating backup of current version..."
    sudo cp "$APP_DIR/$APP_NAME" "$BACKUP_DIR/$APP_NAME.$(date +%Y%m%d_%H%M%S)"
fi

# Extract new version
log "Extracting new version..."
cd "$APP_DIR"
sudo tar -xzf notematic-api.tar.gz
sudo cp release/notematic-api .
sudo chmod +x notematic-api

# Create systemd service file
log "Creating systemd service..."
sudo tee /etc/systemd/system/"$SERVICE_NAME".service > /dev/null <<EOF
[Unit]
Description=Notematic API
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/notematic-api
Restart=always
RestartSec=5
Environment=RUST_LOG=info
Environment=API_PORT=8080
Environment=RUST_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Create user if not exists
log "Setting up user..."
sudo useradd -r -s /bin/false "$USER_NAME" || warn "User $USER_NAME already exists"

# Set proper permissions
log "Setting permissions..."
sudo chown -R "$USER_NAME:$USER_NAME" "$APP_DIR"

# Reload systemd and start service
log "Starting service..."
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"

# Wait a moment for service to start
sleep 3

# Check service status
log "Checking service status..."
if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Service is running successfully!"
    sudo systemctl status "$SERVICE_NAME" --no-pager -l
else
    error "Service failed to start!"
    sudo systemctl status "$SERVICE_NAME" --no-pager -l
    sudo journalctl -u "$SERVICE_NAME" --no-pager -l -n 20
    exit 1
fi

# Cleanup
log "Cleaning up..."
sudo rm -rf release notematic-api.tar.gz

# Keep only last 5 backups
log "Cleaning old backups..."
cd "$BACKUP_DIR"
sudo ls -t | tail -n +6 | sudo xargs -r rm

log "Deployment completed successfully!" 