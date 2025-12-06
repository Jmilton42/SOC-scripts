add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata

cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz || wget https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz || fetch https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
tar -xvzf emerging.rules.tar.gz && mkdir -p /etc/suricata/rules && mv rules/* /etc/suricata/rules/
chmod 777 /etc/suricata/rules/*.rules
set -e

CONF="/etc/suricata/suricata.yaml"

IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')

if [ -z "$IFACE" ]; then
  IFACE="eth0"
fi

IP=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2; exit}')
HOST_IP=${IP%%/*}

echo "[*] Detected interface: $IFACE with IP: $HOST_IP"

sed -i -e "s|^ *HOME_NET:.*|HOME_NET: \"${HOST_IP}\"|" "$CONF"

# Uncomment and set EXTERNAL_NET: "any"
sed -i -e "s|^ *# *EXTERNAL_NET:.*|EXTERNAL_NET: \"any\"|" "$CONF"
sed -i -e "s|^ *EXTERNAL_NET:.*|EXTERNAL_NET: \"any\"|" "$CONF"

# Add "*.rules" to rule-files
if grep -q "^ *rule-files:" "$CONF"; then
  sed -i -e "/^ *rule-files:/a\  - \"*.rules\"" "$CONF"
fi

  sed -i -e "s|^ *- interface: .*|  - interface: ${IFACE}|" "$CONF"

  echo "[+] Updated $CONF:"
  echo "    HOME_NET: \"${HOST_IP}\""
  echo "    EXTERNAL_NET: \"any\""
  echo "    rule-files: \"*.rules\""
  echo "    af-packet -> interface: ${IFACE}"

  $sys daemon-reload 2>/dev/null
  $sys enable suricata 2>/dev/null || $sys suricata enable 2>/dev/null
  $sys start suricata 2>/dev/null || $sys suricata start 2>/dev/null