#!/bin/bash

# Parse command-line arguments
while getopts o:a:i:g:n:h: flag
do
    case "${flag}" in
        o) OTP=${OPTARG};;
        a) ARM_MODE=${OPTARG};;
        i) IP=${OPTARG};;
        g) GATEWAY=${OPTARG};;
        n) DNS=${OPTARG};;
        h) HOSTNAME=${OPTARG};;
        *) echo "Invalid option"; exit 1;;
    esac
done

# Check if all required arguments are provided
if [ -z "$OTP" ] || [ -z "$ARM_MODE" ] || [ -z "$IP" ] || [ -z "$GATEWAY" ] || [ -z "$DNS" ] || [ -z "$HOSTNAME" ]; then
    echo "Usage: $0 -o OTP -a ARM_MODE -i INET_IP -g INET_GW -n INET_DNS -h HOSTNAME"
    exit 1
fi

# Get the current date and time
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create the output file name based on the hostname and timestamp
OUTPUT_FILE="${HOSTNAME}_cloud_config_${TIMESTAMP}.txt"

# Create the cloud-config file with the user's input
cat <<EOF > $OUTPUT_FILE
#cloud-config
disable_root: true
preserve_hostname: false
manage_etc_hosts: true
hostname: ${HOSTNAME}
users:
  - name: cbrink
    gecos: cbrink
    lock_passwd: false
    passwd: '\$6\$vKYvmnAylWRioKY3\$IwI36.Bdjf8xsntVHVEEoGBchPIlZcAvE5595fOexgpIg5h.g/o9I3Dku.yNmzr18VjzpyRZHq3B5SB7rdi65/'
    groups: [adm, systemd-journal, systemd-coredump, netdev, sudo]
    sudo: ALL=(ALL:ALL) NOPASSWD:ALL
    shell: /bin/bash
bootcmd:
  - [rm, -f, /etc/cloud/cloud.cfg.d/99-defaults.cfg]
  - [sed, -i, 's/^.*"provider":.*$/    "provider": "PVT",/', /opt/dwnldagent/config]
  - [sed, -i, 's/^.*"flags":.*$/    "flags": "wren",/', /opt/dwnldagent/config]
  - systemctl daemon-reload && systemctl enable dwnldagent
write_files:
  - path: /etc/brink/otp
    permissions: '0644'
    content: |
      ${OTP}
  - path: /etc/brink/netconf
    permissions: '0644'
    content: |
      {"config": [{"interface": {"name": "ens3", "ip": "${IP}/24", "gateway": "${GATEWAY}", "dns": "${DNS}", "ipv6": "", "ipv6_gw": "", "ipv6_dns": ""}}], "arm_mode": ${ARM_MODE}, "provider": "AHV"}
  - path: /etc/ssh/sshd_config.d/99-connector.conf
    owner: root:root
    permissions: '0644'
    content: |
      ListenAddress ${IP}
  - path: /etc/systemd/resolved.conf.d/dns_servers.conf
    owner: root:root
    permissions: '0644'
    content: |
      [Resolve]
      DNS=${DNS}
  - path: /etc/netplan/99-cb-connector.yaml
    owner: root:root
    permissions: '0640'
    content: |
      network:
        version: 2
        ethernets:
          ens3:
            dhcp4: false
            addresses: [${IP}/24]
            gateway4: ${GATEWAY}
            nameservers:
              addresses: [${DNS}]
ntp:
  enabled: true
  ntp_client: auto
package_update: true
package_upgrade: true
packages:
  - linux-cloud-tools-generic
  - linux-tools-generic
  - linux-generic
  - whois
package_reboot_if_required: false
runcmd:
  - systemctl start dwnldagent
EOF

echo "Cloud-config file created: $OUTPUT_FILE"