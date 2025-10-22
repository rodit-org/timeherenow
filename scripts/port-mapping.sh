#!/bin/bash

# Port mapping script - manages bidirectional iptables port forwarding
# Usage: ./port-mapping.sh [enable|disable|status] [permanent|temporary] [source_port] [dest_port]

# Default ports (SOURCE_PORT is the external port, DEST_PORT is where the service listens)
DEFAULT_SOURCE_PORT=443
DEFAULT_DEST_PORT=8443

# Parse arguments
ACTION=${1:-status}
MODE=${2:-temporary}
SOURCE_PORT=${3:-$DEFAULT_SOURCE_PORT}
DEST_PORT=${4:-$DEFAULT_DEST_PORT}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [enable|disable|status] [permanent|temporary] [source_port] [dest_port]

Actions:
  enable     Enable inbound port mapping (external -> local service)
  disable    Disable inbound port mapping
  status     Show current port mapping status (default)

Modes:
  temporary  Changes apply until reboot (default)
  permanent  Changes survive reboot

Ports:
  source_port  First port (default: $DEFAULT_SOURCE_PORT)
  dest_port    Second port (default: $DEFAULT_DEST_PORT)

Examples:
  $0                                    # Show status
  $0 enable                             # Enable temporary mapping (443 -> 8443)
  $0 enable permanent                   # Enable permanent mapping (443 -> 8443)
  $0 disable permanent                  # Disable and save permanently
  $0 enable temporary 80 8080           # Enable temporary mapping (80 -> 8080)
EOF
}

# If called without arguments or with status, show status
if [ "$ACTION" = "status" ]; then
    echo "Port Mapping Status"
    echo "==================="
    echo ""
    echo "Default ports: $DEFAULT_SOURCE_PORT <-> $DEFAULT_DEST_PORT"
    echo ""
    echo "Current NAT PREROUTING rules:"
    iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "(Chain|REDIRECT)" || echo "  No REDIRECT rules found"
    echo ""
    echo "Current NAT OUTPUT rules:"
    iptables -t nat -L OUTPUT -n -v --line-numbers | grep -E "(Chain|REDIRECT)" || echo "  No REDIRECT rules found"
    echo ""
    show_usage
    exit 0
fi

# Validate action
if [[ "$ACTION" != "enable" && "$ACTION" != "disable" ]]; then
    echo "Error: Action must be 'enable', 'disable', or 'status'"
    echo ""
    show_usage
    exit 1
fi

# Validate mode
if [[ "$MODE" != "permanent" && "$MODE" != "temporary" ]]; then
    echo "Error: Mode must be 'permanent' or 'temporary'"
    echo ""
    show_usage
    exit 1
fi

# Validate ports
if ! [[ "$SOURCE_PORT" =~ ^[0-9]+$ ]] || ! [[ "$DEST_PORT" =~ ^[0-9]+$ ]]; then
    echo "Error: Ports must be numeric"
    exit 1
fi

if [ "$SOURCE_PORT" -lt 1 ] || [ "$SOURCE_PORT" -gt 65535 ] || [ "$DEST_PORT" -lt 1 ] || [ "$DEST_PORT" -gt 65535 ]; then
    echo "Error: Ports must be between 1 and 65535"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Function to add iptables rules
add_rules() {
    echo "Adding inbound port mapping: $SOURCE_PORT -> $DEST_PORT"
    
    # PREROUTING: Redirect incoming traffic from SOURCE_PORT to DEST_PORT
    # This allows external clients to connect to SOURCE_PORT (e.g., 443) 
    # and be redirected to DEST_PORT (e.g., 8443) where the service listens
    iptables -t nat -A PREROUTING -p tcp --dport $SOURCE_PORT -j REDIRECT --to-port $DEST_PORT
    
    # OUTPUT: Redirect locally generated traffic from SOURCE_PORT to DEST_PORT
    # This allows local processes to connect to SOURCE_PORT and reach the service on DEST_PORT
    iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport $SOURCE_PORT -j REDIRECT --to-port $DEST_PORT
    iptables -t nat -A OUTPUT -p tcp -d ::1 --dport $SOURCE_PORT -j REDIRECT --to-port $DEST_PORT
    
    # NOTE: We do NOT redirect outbound traffic to external hosts on port 443
    # This would break HTTPS connections to external services (e.g., NEAR RPC, APIs)
    
    echo "Inbound port mapping enabled: $SOURCE_PORT -> $DEST_PORT"
}

# Function to remove iptables rules
remove_rules() {
    echo "Removing port mapping: $SOURCE_PORT -> $DEST_PORT"
    
    # Remove PREROUTING rule
    iptables -t nat -D PREROUTING -p tcp --dport $SOURCE_PORT -j REDIRECT --to-port $DEST_PORT 2>/dev/null || true
    
    # Remove OUTPUT rules (both old bidirectional and new localhost-only)
    iptables -t nat -D OUTPUT -p tcp --dport $SOURCE_PORT -j REDIRECT --to-port $DEST_PORT 2>/dev/null || true
    iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport $SOURCE_PORT -j REDIRECT --to-port $DEST_PORT 2>/dev/null || true
    iptables -t nat -D OUTPUT -p tcp -d ::1 --dport $SOURCE_PORT -j REDIRECT --to-port $DEST_PORT 2>/dev/null || true
    
    # Remove old bidirectional rules (DEST_PORT -> SOURCE_PORT) if they exist
    iptables -t nat -D PREROUTING -p tcp --dport $DEST_PORT -j REDIRECT --to-port $SOURCE_PORT 2>/dev/null || true
    iptables -t nat -D OUTPUT -p tcp --dport $DEST_PORT -j REDIRECT --to-port $SOURCE_PORT 2>/dev/null || true
    
    echo "Port mapping disabled: $SOURCE_PORT -> $DEST_PORT"
}

# Function to save iptables rules permanently
save_permanent() {
    if command -v iptables-save &> /dev/null && command -v netfilter-persistent &> /dev/null; then
        echo "Saving iptables rules with netfilter-persistent..."
        netfilter-persistent save
    elif command -v iptables-save &> /dev/null && [ -d /etc/iptables ]; then
        echo "Saving iptables rules to /etc/iptables/rules.v4..."
        iptables-save > /etc/iptables/rules.v4
    elif command -v service &> /dev/null; then
        echo "Saving iptables rules with service..."
        service iptables save 2>/dev/null || true
    else
        echo "Warning: Could not find a method to save iptables rules permanently"
        echo "Rules will be lost on reboot unless you manually save them"
        return 1
    fi
    echo "Rules saved permanently"
}

# Main logic
case "$ACTION" in
    enable)
        # Remove existing rules first (if any) to avoid duplicates
        remove_rules 2>/dev/null || true
        
        # Add new rules
        add_rules
        
        # Save permanently if requested
        if [ "$MODE" = "permanent" ]; then
            save_permanent
            echo "Port mapping is now permanent (survives reboot)"
        else
            echo "Port mapping is temporary (will be lost on reboot)"
        fi
        ;;
        
    disable)
        # Remove rules
        remove_rules
        
        # Save permanently if requested
        if [ "$MODE" = "permanent" ]; then
            save_permanent
            echo "Port mapping removal is now permanent"
        else
            echo "Port mapping removed temporarily"
        fi
        ;;
esac

# Show current status after changes
echo ""
echo "Current NAT PREROUTING rules:"
iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "(Chain|REDIRECT)" || echo "  No REDIRECT rules found"
echo ""
echo "Current NAT OUTPUT rules:"
iptables -t nat -L OUTPUT -n -v --line-numbers | grep -E "(Chain|REDIRECT)" || echo "  No REDIRECT rules found"

exit 0
