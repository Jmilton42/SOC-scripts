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

  if [ ! -f "${CONF}.bak" ]; then
    cp "$CONF" "${CONF}.bak"
  fi

  echo "[*] Detected interface: $IFACE with IP: $HOST_IP"

  sed -i -e "s|^ *HOME_NET:.*|HOME_NET: \"${HOST_IP}\"|" "$CONF"

  sed -i -e "s|^ *EXTERNAL_NET:.*|EXTERNAL_NET: \"any\"|" "$CONF"

  # Add "*.rules" to rule-files
  if grep -q "^ *rule-files:" "$CONF"; then
    # Check if "*.rules" already exists in rule-files
    if ! grep -A 10 "^ *rule-files:" "$CONF" | grep -q "\"*.rules\""; then
      # Add "*.rules" to the rule-files list
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

  sed -i -e "s|^ *- interface: .*|  - interface: ${IFACE}|" "$CONF"

  echo "[+] Updated $CONF:"
  echo "    HOME_NET: \"${HOST_IP}\""
  echo "    EXTERNAL_NET: \"any\""
  echo "    rule-files: \"*.rules\""
  echo "    af-packet -> interface: ${IFACE}"

  $sys daemon-reload 2>/dev/null
  $sys enable suricata 2>/dev/null || $sys suricata enable 2>/dev/null
  $sys start suricata 2>/dev/null || $sys suricata start 2>/dev/null
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