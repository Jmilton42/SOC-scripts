#!/bin/sh
# TTU CCDC | Joey Milton

if [ -z "$WAZUH_MANAGER" ]; then
  echo "ERROR: You must set WAZUH_MANAGER."
  exit 1
fi

if [ -z "$WAZUH_REGISTRATION_PASSWORD" ]; then
  WAZUH_REGISTRATION_PASSWORD=""
fi

ARCH=$(uname -m)


ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
sys=$(command -v systemctl || command -v service || command -v rc-service)

# If wazuh-manager service is running, exit
if $sys status wazuh-manager >/dev/null 2>&1 || $sys wazuh-manager status >/dev/null 2>&1; then
  echo "ERROR: Wazuh manager is running. You cannot install the agent on the same host."
  exit 1
fi

DPKG() {
  if [ $ARCH = x86_64 ]; then
    ARCH_PKG="amd64"
  elif [ $ARCH = i386 ] || [ ARCH = i686 ]; then
    ARCH_PKG="i386"
  else
    echo "ERROR: Unsupported architecture."
    exit 1
  fi

  DOWNLOAD_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent"
  package="wazuh-agent_4.14.1-1_${ARCH_PKG}.deb"

  ( wget --no-check-certificate -O $package $DOWNLOAD_URL/$package || \
    curl -k -o $package $DOWNLOAD_URL/$package || \
    fetch --no-verify-peer -o $package $DOWNLOAD_URL/$package )

  if ( test -f $package ); then
    InstallCommand="WAZUH_MANAGER=$WAZUH_MANAGER dpkg -i $package"
    if [ -n $WAZUH_REGISTRATION_PASSWORD ]; then
      InstallCommand="WAZUH_REGISTRATION_PASSWORD=$WAZUH_REGISTRATION_PASSWORD $InstallCommand"
    fi
    eval "$InstallCommand"
  else
    echo "ERROR: Failed to download the package."
    exit 1
  fi

  add-apt-repository ppa:oisf/suricata-stable -y
  apt-get update -y
  apt-get install -y suricata
  echo ""

}

RPM() {
  if [ $ARCH = x86_64 ]; then
    ARCH_PKG="x86_64"
  elif [ $ARCH = i386 ] || [ $ARCH = i686 ]; then
    ARCH_PKG="i386"
  else
    echo "ERROR: Unsupported architecture."
    exit 1
  fi

  DOWNLOAD_URL="https://packages.wazuh.com/4.x/yum"
  package="wazuh-agent-4.14.1-1.${ARCH_PKG}.rpm"

  ( wget -O $package $DOWNLOAD_URL/$package || \
    curl -o $package $DOWNLOAD_URL/$package || \
    fetch -o $package $DOWNLOAD_URL/$package )

  if ( test -f $package ); then
    InstallCommand="WAZUH_MANAGER=$WAZUH_MANAGER rpm -vi $package"
    if [ -n $WAZUH_REGISTRATION_PASSWORD ]; then
      InstallCommand="WAZUH_REGISTRATION_PASSWORD=$WAZUH_REGISTRATION_PASSWORD $InstallCommand"
    fi
	 eval "$InstallCommand"
  else
    echo "ERROR: Failed to download the package."
    exit 1
  fi

  yum install epel-release yum-plugin-copr -y
  yum copr enable @oisf/suricata-7.0 -y
  yum install suricata -y

}

enable_and_start() {
  $sys daemon-reload 2>/dev/null
  $sys enable wazuh-agent 2>/dev/null || $sys wazuh-agent enable 2>/dev/null
  $sys start wazuh-agent 2>/dev/null || $sys wazuh-agent start 2>/dev/null
}

is_agent_running() {
  # check if wazuh-agent service is up, if so, print 3 lines of equals, then Wazuh Agent is running, three more lines of equals and exit
  if $sys status wazuh-agent 2>/dev/null || $sys wazuh-agent status 2>/dev/null; then
    echo "==================================================================="
    echo "==================================================================="
    echo "==================================================================="
    echo "Wazuh Agent is running"
  else
    echo "==================================================================="
    echo "==================================================================="
    echo "==================================================================="
    echo "Wazuh Agent is NOT running"
  fi
  echo "==================================================================="
  echo "==================================================================="
  echo "==================================================================="
}

suricata() {
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

  # Detect network interface - try multiple methods
  IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
  
  # If no default route, try to find first non-loopback interface
  if [ -z "$IFACE" ]; then
    IFACE=$(ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | head -1 | awk -F': ' '{print $2}' | awk '{print $1}')
  fi

  # If still no interface, try common names
  if [ -z "$IFACE" ]; then
    for test_iface in eth0 ens33 ens3 enp0s3 enp0s8; do
      if ip link show "$test_iface" >/dev/null 2>&1; then
        IFACE="$test_iface"
        break
      fi
    done
  fi

  # Verify interface exists
  if [ -z "$IFACE" ] || ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "ERROR: Could not detect a valid network interface."
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  - " $2}'
    echo "Please set SURICATA_INTERFACE environment variable or configure manually."
    return 1
  fi

  IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet / {print $2; exit}')
  HOST_IP=${IP%%/*}

  if [ -z "$HOST_IP" ]; then
    echo "WARNING: Interface $IFACE has no IP address. Suricata may not work correctly."
    HOST_IP="any"
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
  else
    # If rule-files doesn't exist, add it after default-rule-path or HOME_NET
    if grep -q "^ *default-rule-path:" "$CONF"; then
      sed -i -e "/^ *default-rule-path:/a\\
rule-files:\\
  - \"*.rules\"" "$CONF"
    else
      sed -i -e "/^ *HOME_NET:/a\\
EXTERNAL_NET: \"any\"\\
rule-files:\\
  - \"*.rules\"" "$CONF"
    fi
  fi

  # Update interface in af-packet section only (not DPDK section)
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
    return 1
  fi

  # Reload systemd and start service
  echo "[*] Reloading systemd daemon..."
  $sys daemon-reload 2>/dev/null || true
  
  echo "[*] Enabling Suricata service..."
  $sys enable suricata 2>/dev/null || $sys suricata enable 2>/dev/null || true

  # Stop any existing instance before starting
  echo "[*] Stopping any existing Suricata instances..."
  $sys stop suricata 2>/dev/null || $sys suricata stop 2>/dev/null || true
  sleep 2

  # Start the service
  echo "[*] Starting Suricata service..."
  if $sys start suricata 2>/dev/null || $sys suricata start 2>/dev/null; then
    echo "[+] Suricata service start command executed"
    sleep 3
    echo "[*] Checking Suricata service status..."
    if $sys status suricata >/dev/null 2>&1 || $sys suricata status >/dev/null 2>&1; then
      echo "[+] Suricata is running"
    else
      echo "WARNING: Suricata service may have failed to start."
      echo "Checking service status..."
      $sys status suricata 2>&1 || $sys suricata status 2>&1 || true
      echo "Check logs with: journalctl -u suricata -n 50"
    fi
  else
    echo "ERROR: Failed to start Suricata service."
    echo "Attempting to get error details..."
    $sys status suricata 2>&1 || $sys suricata status 2>&1 || true
    echo "Check logs with: journalctl -u suricata -n 50"
  fi
  echo "[*] Suricata configuration complete"
}


if command -v dpkg >/dev/null ; then
  DPKG
elif command -v rpm >/dev/null ; then
  RPM
else
  echo "ERROR: Unsupported package manager."
  exit 1
fi


suricata
enable_and_start
is_agent_running