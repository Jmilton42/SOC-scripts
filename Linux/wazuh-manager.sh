#!/bin/sh
# TTU CCDC | Joey Milton

set -e

sys=$(command -v systemctl || command -v service || command -v rc-service)

add-apt-repository ppa:oisf/suricata-stable -y
apt-get update
apt-get install -y suricata

# Download and extract rules
cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz || wget https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz || fetch https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
tar -xvzf emerging.rules.tar.gz && mkdir -p /etc/suricata/rules && mv rules/* /etc/suricata/rules/ 2>/dev/null || true

# Set permissions on rules files if they exist
if [ -n "$(ls -A /etc/suricata/rules/*.rules 2>/dev/null)" ]; then
  chmod 644 /etc/suricata/rules/*.rules
fi

CONF="/etc/suricata/suricata.yaml"

# Backup original config
if [ ! -f "${CONF}.bak" ]; then
  cp "$CONF" "${CONF}.bak"
fi

# Detect network interface
IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')

if [ -z "$IFACE" ]; then
  IFACE="eth0"
fi

# Verify interface exists
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: Interface $IFACE does not exist. Please configure manually."
  exit 1
fi

IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet / {print $2; exit}')
HOST_IP=${IP%%/*}

if [ -z "$HOST_IP" ]; then
  echo "ERROR: Could not detect IP address for interface $IFACE"
  exit 1
fi

echo "[*] Detected interface: $IFACE with IP: $HOST_IP"

# Update HOME_NET
sed -i -e "s|^ *HOME_NET:.*|HOME_NET: \"${HOST_IP}\"|" "$CONF"

# Uncomment and set EXTERNAL_NET: "any"
sed -i -e "s|^ *# *EXTERNAL_NET:.*|EXTERNAL_NET: \"any\"|" "$CONF"
sed -i -e "s|^ *EXTERNAL_NET:.*|EXTERNAL_NET: \"any\"|" "$CONF"

# Add "*.rules" to rule-files if not already present
if grep -q "^ *rule-files:" "$CONF"; then
  if ! grep -A 10 "^ *rule-files:" "$CONF" | grep -q "\"*.rules\""; then
    sed -i -e "/^ *rule-files:/a\  - \"*.rules\"" "$CONF"
  fi
fi

# Update interface in af-packet section only (not DPDK section)
# Only modify lines with exactly 2-space indentation (af-packet format)
# and ensure we're in af-packet context by checking preceding lines
in_afpacket=0
while IFS= read -r line || [ -n "$line" ]; do
  if echo "$line" | grep -q "^af-packet:"; then
    in_afpacket=1
    echo "$line"
  elif echo "$line" | grep -q "^[a-z]" && ! echo "$line" | grep -q "^  "; then
    in_afpacket=0
    echo "$line"
  elif [ $in_afpacket -eq 1 ] && echo "$line" | grep -q "^  - interface:"; then
    echo "  - interface: ${IFACE}"
  else
    echo "$line"
  fi
done < "$CONF" > "${CONF}.tmp" && mv "${CONF}.tmp" "$CONF"

echo "[+] Updated $CONF:"
echo "    HOME_NET: \"${HOST_IP}\""
echo "    EXTERNAL_NET: \"any\""
echo "    rule-files: \"*.rules\""
echo "    af-packet -> interface: ${IFACE}"

# Validate configuration before starting
echo "[*] Validating Suricata configuration..."
if suricata -T -c "$CONF" >/dev/null 2>&1; then
  echo "[+] Configuration is valid"
else
  echo "ERROR: Suricata configuration validation failed. Restoring backup..."
  if [ -f "${CONF}.bak" ]; then
    cp "${CONF}.bak" "$CONF"
    echo "Configuration restored from backup. Please fix manually."
  fi
  echo "Validation errors:"
  suricata -T -c "$CONF" 2>&1 | head -20 || true
  exit 1
fi

# Reload systemd and start service
$sys daemon-reload 2>/dev/null || true
$sys enable suricata 2>/dev/null || $sys suricata enable 2>/dev/null || true

# Stop any existing instance before starting
$sys stop suricata 2>/dev/null || $sys suricata stop 2>/dev/null || true
sleep 2

# Start the service
if $sys start suricata 2>/dev/null || $sys suricata start 2>/dev/null; then
  echo "[+] Suricata service started successfully"
  sleep 2
  if $sys status suricata >/dev/null 2>&1 || $sys suricata status >/dev/null 2>&1; then
    echo "[+] Suricata is running"
  else
    echo "ERROR: Suricata service failed to start. Check logs with: journalctl -u suricata -n 50"
    exit 1
  fi
else
  echo "ERROR: Failed to start Suricata service. Check logs with: journalctl -u suricata -n 50"
  exit 1
fi