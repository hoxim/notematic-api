# Deployment Guide for Notematic API

## Overview

This guide explains how to set up automatic deployment of the Notematic API to your server using GitHub Actions.

## Prerequisites

### Server Requirements
- Linux server (Ubuntu 20.04+ recommended)
- SSH access with sudo privileges
- Rust installed (optional, as we'll build on GitHub Actions)
- CouchDB installed and configured

### GitHub Repository Setup
- Repository with the API code
- GitHub Actions enabled

## Setup Instructions

### 1. Server Preparation

#### Install CouchDB (if not already installed)
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install couchdb

# Or using Docker
docker run -d --name couchdb \
  -p 5984:5984 \
  -e COUCHDB_USER=admin \
  -e COUCHDB_PASSWORD=your_secure_password \
  couchdb:latest
```

#### Create application directory
```bash
sudo mkdir -p /opt/notematic-api
sudo mkdir -p /opt/notematic-api/backup
```

### 2. GitHub Secrets Configuration

Go to your GitHub repository → Settings → Secrets and variables → Actions, and add the following secrets:

- `SERVER_HOST`: Your server's IP address or domain
- `SERVER_USERNAME`: SSH username (e.g., `ubuntu`, `root`)
- `SERVER_SSH_KEY`: Your private SSH key (the entire key content)
- `SERVER_PORT`: SSH port (usually `22`)

#### Generate SSH Key (if needed)
```bash
# On your local machine
ssh-keygen -t rsa -b 4096 -C "github-actions@your-domain.com"

# Copy public key to server
ssh-copy-id -i ~/.ssh/id_rsa.pub username@your-server

# Copy private key content to GitHub secret
cat ~/.ssh/id_rsa
```

### 3. Environment Configuration

#### Update production configuration
Edit `config.production.toml` with your actual values:

```toml
[server]
port = 8080
host = "0.0.0.0"

[environment]
rust_env = "production"
rust_log = "info"

[database]
couchdb_url = "http://localhost:5984"
couchdb_username = "admin"
couchdb_password = "your_actual_password"

[jwt]
secret = "your_actual_jwt_secret_key"
access_expiry = 3600
refresh_expiry = 2592000

[rate_limit]
requests = 100
window = 900
```

### 4. Firewall Configuration

Ensure port 8080 is open on your server:

```bash
# UFW (Ubuntu)
sudo ufw allow 8080

# iptables
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

### 5. First Deployment

1. Push your code to the `main` or `master` branch
2. GitHub Actions will automatically:
   - Build the API
   - Run tests
   - Deploy to your server
   - Start the service

### 6. Verify Deployment

Check if the service is running:

```bash
# Check service status
sudo systemctl status notematic-api

# Check logs
sudo journalctl -u notematic-api -f

# Test API endpoint
curl http://your-server:8080/health
```

## Manual Deployment

If you need to deploy manually:

1. Build the API locally:
```bash
cd notematic-api
cargo build --release
```

2. Create deployment package:
```bash
mkdir -p release
cp target/release/notematic-api release/
cp Cargo.toml release/
cp -r src release/
tar -czf notematic-api.tar.gz release/
```

3. Upload to server and run deployment script:
```bash
scp notematic-api.tar.gz username@your-server:/opt/notematic-api/
ssh username@your-server
cd /opt/notematic-api
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

## Monitoring and Maintenance

### Service Management
```bash
# Start service
sudo systemctl start notematic-api

# Stop service
sudo systemctl stop notematic-api

# Restart service
sudo systemctl restart notematic-api

# Check status
sudo systemctl status notematic-api

# View logs
sudo journalctl -u notematic-api -f
```

### Backup and Rollback
```bash
# Manual backup
sudo cp /opt/notematic-api/notematic-api /opt/notematic-api/backup/manual-backup-$(date +%Y%m%d_%H%M%S)

# Rollback to previous version
sudo systemctl stop notematic-api
sudo cp /opt/notematic-api/backup/notematic-api.YYYYMMDD_HHMMSS /opt/notematic-api/notematic-api
sudo systemctl start notematic-api
```

### Log Rotation
Create `/etc/logrotate.d/notematic-api`:
```
/var/log/notematic-api/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 notematic notematic
    postrotate
        systemctl reload notematic-api
    endscript
}
```

## Troubleshooting

### Common Issues

1. **Service won't start**
   - Check logs: `sudo journalctl -u notematic-api -n 50`
   - Verify permissions: `sudo chown -R notematic:notematic /opt/notematic-api`
   - Check configuration: `sudo cat /etc/systemd/system/notematic-api.service`

2. **Port already in use**
   - Check what's using port 8080: `sudo netstat -tlnp | grep :8080`
   - Kill process or change port in configuration

3. **Database connection issues**
   - Verify CouchDB is running: `sudo systemctl status couchdb`
   - Check credentials in configuration
   - Test connection: `curl http://localhost:5984`

4. **Permission denied**
   - Ensure user has proper permissions: `sudo chown -R notematic:notematic /opt/notematic-api`
   - Check SSH key permissions: `chmod 600 ~/.ssh/id_rsa`

### Debug Mode
To run in debug mode temporarily:

```bash
sudo systemctl stop notematic-api
cd /opt/notematic-api
RUST_LOG=debug ./notematic-api
```

## Security Considerations

1. **Firewall**: Only open necessary ports
2. **SSH**: Use key-based authentication only
3. **Secrets**: Store sensitive data in environment variables
4. **Updates**: Keep system and dependencies updated
5. **Monitoring**: Set up log monitoring and alerting
6. **Backups**: Regular backups of configuration and data

## Performance Tuning

1. **System limits**: Increase file descriptor limits
2. **Memory**: Monitor memory usage and adjust accordingly
3. **CPU**: Consider using multiple workers
4. **Database**: Optimize CouchDB configuration
5. **Network**: Use reverse proxy (nginx) for SSL termination 