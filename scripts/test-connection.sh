#!/bin/bash

# Test connection script for deployment
# This script tests SSH connection and basic server setup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="notematic-api"
APP_DIR="/opt/$APP_NAME"

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

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if required environment variables are set
check_env() {
    log "Checking environment variables..."
    
    if [ -z "$SERVER_HOST" ]; then
        error "SERVER_HOST is not set"
        exit 1
    fi
    
    if [ -z "$SERVER_USERNAME" ]; then
        error "SERVER_USERNAME is not set"
        exit 1
    fi
    
    if [ -z "$SERVER_SSH_KEY" ]; then
        error "SERVER_SSH_KEY is not set"
        exit 1
    fi
    
    if [ -z "$SERVER_PORT" ]; then
        warn "SERVER_PORT not set, using default 22"
        SERVER_PORT=22
    fi
    
    log "Environment variables OK"
}

# Test SSH connection
test_ssh() {
    log "Testing SSH connection..."
    
    # Create temporary SSH key file
    SSH_KEY_FILE=$(mktemp)
    echo "$SERVER_SSH_KEY" > "$SSH_KEY_FILE"
    chmod 600 "$SSH_KEY_FILE"
    
    # Test connection
    if ssh -i "$SSH_KEY_FILE" -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p "$SERVER_PORT" "$SERVER_USERNAME@$SERVER_HOST" "echo 'SSH connection successful'"; then
        log "SSH connection test passed"
    else
        error "SSH connection test failed"
        rm -f "$SSH_KEY_FILE"
        exit 1
    fi
    
    # Cleanup
    rm -f "$SSH_KEY_FILE"
}

# Test server requirements
test_server() {
    log "Testing server requirements..."
    
    # Create temporary SSH key file
    SSH_KEY_FILE=$(mktemp)
    echo "$SERVER_SSH_KEY" > "$SSH_KEY_FILE"
    chmod 600 "$SSH_KEY_FILE"
    
    # Test commands
    ssh -i "$SSH_KEY_FILE" -o StrictHostKeyChecking=no -p "$SERVER_PORT" "$SERVER_USERNAME@$SERVER_HOST" "
        echo 'Testing sudo access...'
        if sudo -n true 2>/dev/null; then
            echo 'SUDO: OK'
        else
            echo 'SUDO: FAILED - User needs passwordless sudo'
            exit 1
        fi
        
        echo 'Testing systemctl...'
        if command -v systemctl >/dev/null 2>&1; then
            echo 'SYSTEMCTL: OK'
        else
            echo 'SYSTEMCTL: FAILED - systemctl not available'
            exit 1
        fi
        
        echo 'Testing useradd...'
        if command -v useradd >/dev/null 2>&1; then
            echo 'USERADD: OK'
        else
            echo 'USERADD: FAILED - useradd not available'
            exit 1
        fi
        
        echo 'Testing tar...'
        if command -v tar >/dev/null 2>&1; then
            echo 'TAR: OK'
        else
            echo 'TAR: FAILED - tar not available'
            exit 1
        fi
        
        echo 'Testing directory creation...'
        if sudo mkdir -p $APP_DIR 2>/dev/null; then
            echo 'DIRECTORY: OK'
        else
            echo 'DIRECTORY: FAILED - Cannot create application directory'
            exit 1
        fi
        
        echo 'Testing port availability...'
        if ! sudo netstat -tlnp | grep :8080 >/dev/null 2>&1; then
            echo 'PORT: OK - Port 8080 is available'
        else
            echo 'PORT: WARNING - Port 8080 is already in use'
        fi
    "
    
    # Cleanup
    rm -f "$SSH_KEY_FILE"
}

# Test CouchDB connection
test_couchdb() {
    log "Testing CouchDB connection..."
    
    # Create temporary SSH key file
    SSH_KEY_FILE=$(mktemp)
    echo "$SERVER_SSH_KEY" > "$SSH_KEY_FILE"
    chmod 600 "$SSH_KEY_FILE"
    
    # Test CouchDB
    ssh -i "$SSH_KEY_FILE" -o StrictHostKeyChecking=no -p "$SERVER_PORT" "$SERVER_USERNAME@$SERVER_HOST" "
        echo 'Testing CouchDB availability...'
        if curl -s http://localhost:5984 >/dev/null 2>&1; then
            echo 'COUCHDB: OK - CouchDB is running'
        else
            echo 'COUCHDB: WARNING - CouchDB is not running or not accessible'
            echo 'You may need to install and configure CouchDB'
        fi
    "
    
    # Cleanup
    rm -f "$SSH_KEY_FILE"
}

# Main function
main() {
    log "Starting connection test..."
    
    check_env
    test_ssh
    test_server
    test_couchdb
    
    log "All tests completed successfully!"
    info "Server is ready for deployment"
}

# Run main function
main "$@" 