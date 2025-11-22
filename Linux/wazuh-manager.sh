add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata

cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz || wget https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz || fetch https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
tar -xvzf emerging.rules.tar.gz && mkdir /etc/suricata/rules && mv rules/* /etc/suricata/rules/
chmod 777 /etc/suricata/rules/*.rules
set -e
CONF="/etc/suricata/suricata.yaml"
IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
if [ -z "$IFACE" ]; then
  IFACE="eth0"
fi
IP=$(ip -4 addr show "$IFACE" | awk '/inet / {print $2}; exit')
HOST_IP=${IP%%/*}
if [ ! -f "${CONF}.bak" ]; then
  cp "$CONF" "${CONF}.bak"
fi
echo "[*] Detected interface: $IFACE with IP: $HOST_IP"
sed -i -e "s|^ *HOME_NET:.*|HOME_NET: \"${HOST_IP}\"|" "$CONF"
sed -i -e "s|^ *- interface: .*|  - interface: ${IFACE}|" "$CONF"
echo "[+] Updated $CONF:"
echo "    HOME_NET: \"${HOST_IP}\""
echo "    af-packet -> interface: ${IFACE}"
$sys daemon-reload 2>/dev/null
$sys enable suricata 2>/dev/null || $sys suricata enable 2>/dev/null
$sys start suricata 2>/dev/null || $sys suricata start 2>/dev/null