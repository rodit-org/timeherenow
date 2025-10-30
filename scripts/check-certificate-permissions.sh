#!/bin/bash

# Script: check-certificate-permissions.sh
# Description: Checks certificate file permissions across all application directories
# Usage: ./check-certificate-permissions.sh [--help]

# Help function
show_help() {
    cat << EOF
Certificate Permissions Checker

DESCRIPTION:
    This script checks SSL/TLS certificate file permissions across all application 
    directories (*-app and *-rodit) in the /home/icarus35 directory. It verifies 
    that certificate files have appropriate permissions for secure operation.

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help    Show this help message and exit

WHAT IT CHECKS:
    - fullchain.pem permissions and ownership
    - privkey.pem permissions and ownership  
    - cert.pem permissions and ownership (if exists)
    - chain.pem permissions and ownership (if exists)
    - Certificate directory permissions

RECOMMENDED PERMISSIONS:
    - fullchain.pem: 644 (rw-r--r--)
    - privkey.pem: 600 (rw-------) or 640 (rw-r-----)
    - Directories: 755 (rwxr-xr-x) or 750 (rwxr-x---)

EXAMPLES:
    $0              # Run permission check
    $0 --help       # Show this help

EOF
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    "")
        # No arguments, proceed with normal execution
        ;;
    *)
        echo "Error: Unknown option '$1'"
        echo "Use --help for usage information."
        exit 1
        ;;
esac

echo "========== CERTIFICATE PERMISSIONS CHECK =========="
echo "Checking certificate permissions in all -app directories..."
echo ""

# Find all -app directories with certs subdirectory
APP_DIRS=$(find /home/icarus35 -type d -name "*-app" -o -name "*-rodit" | sort)

for DIR in $APP_DIRS; do
    CERT_DIR="$DIR/certs"
    
    if [ -d "$CERT_DIR" ]; then
        echo "===== Directory: $CERT_DIR ====="
        
        # Check fullchain.pem
        if [ -f "$CERT_DIR/fullchain.pem" ]; then
            OWNER=$(stat -c "%U:%G" "$CERT_DIR/fullchain.pem")
            PERMS=$(stat -c "%a" "$CERT_DIR/fullchain.pem")
            echo "fullchain.pem:"
            echo "  Owner: $OWNER"
            echo "  Permissions: $PERMS"
            ls -la "$CERT_DIR/fullchain.pem"
        else
            echo "fullchain.pem: FILE NOT FOUND"
        fi
        
        # Check privkey.pem
        if [ -f "$CERT_DIR/privkey.pem" ]; then
            OWNER=$(stat -c "%U:%G" "$CERT_DIR/privkey.pem")
            PERMS=$(stat -c "%a" "$CERT_DIR/privkey.pem")
            echo "privkey.pem:"
            echo "  Owner: $OWNER"
            echo "  Permissions: $PERMS"
            ls -la "$CERT_DIR/privkey.pem"
        else
            echo "privkey.pem: FILE NOT FOUND"
        fi
        
        # Check cert.pem if exists
        if [ -f "$CERT_DIR/cert.pem" ]; then
            OWNER=$(stat -c "%U:%G" "$CERT_DIR/cert.pem")
            PERMS=$(stat -c "%a" "$CERT_DIR/cert.pem")
            echo "cert.pem:"
            echo "  Owner: $OWNER"
            echo "  Permissions: $PERMS"
            ls -la "$CERT_DIR/cert.pem"
        fi
        
        # Check chain.pem if exists
        if [ -f "$CERT_DIR/chain.pem" ]; then
            OWNER=$(stat -c "%U:%G" "$CERT_DIR/chain.pem")
            PERMS=$(stat -c "%a" "$CERT_DIR/chain.pem")
            echo "chain.pem:"
            echo "  Owner: $OWNER"
            echo "  Permissions: $PERMS"
            ls -la "$CERT_DIR/chain.pem"
        fi
        
        # Check if the directory itself is readable/accessible
        OWNER=$(stat -c "%U:%G" "$CERT_DIR")
        PERMS=$(stat -c "%a" "$CERT_DIR")
        echo "Certificate directory permissions:"
        echo "  Owner: $OWNER"
        echo "  Permissions: $PERMS"
        ls -la "$CERT_DIR" | head -n 2
        
        echo "----------------------------------------"
    else
        echo "===== Directory: $DIR ====="
        echo "No certs directory found"
        echo "----------------------------------------"
    fi
done

echo ""
echo "========== SUMMARY =========="
echo "Total directories checked: $(echo "$APP_DIRS" | wc -l)"
echo "Ensure that your application has appropriate read permissions for certificate files."
echo "Recommended permissions:"
echo "  - fullchain.pem: 644 (rw-r--r--)"
echo "  - privkey.pem: 600 (rw-------) or 640 (rw-r-----)"
echo "  - Directories: 755 (rwxr-xr-x) or 750 (rwxr-x---)"[]
