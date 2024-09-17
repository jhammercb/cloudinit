#!/bin/bash

# script input arguments
CB_OTP=""
ARM_MODE=0
INET_IP=""
INET_GW=""
DC_IP=""
DC_GW=""
NAME_SERVERS_INET=""
NAME_SERVERS_DC=""
DC_IPV6=""
DC_IPV6_GW=""
DC_IPV6_DNS=""
CLOUD_PROVIDER=""
SAAS_FLAG=""
CONNECTOR_VERSION=""
CONN_PILOT_VERSION=""
HOSTNAME="connector-image"  # Default hostname

# global scope variables
TEMP_DIR="/tmp/CB-SETUP"
ISO_DIR="${TEMP_DIR}/ca-iso"
UD_FILE="${ISO_DIR}/user-data"
MD_FILE="${ISO_DIR}/meta-data"
NC_FILE="${ISO_DIR}/network-config"
ISO_FILE=""
DEFAULT_IPV4_DNS_SERVER="8.8.8.8"
DEFAULT_IPV6_DNS_SERVER="2001:4860:4860::8888"
DEFAULT_CLOUDPROVIDER="PVT"
DEFAULT_SAASFLAG="wren"
DLAGENT_CONF_FILE="/opt/dwnldagent/config"
SSH_LISTEN_ADDRESS=""
#PREREQ_PKGS=("getisoimage" "govc")

# task summary variables
T_TOTAL=4
T_ABORTED=0
T_SUCCESS=0
T_SKIPPED=0
T_FAILURE=0

function help_message() {
    echo "usage: $0 -o OTP -a ARM_MODE -i INET_IP -g INET_GW [-d DC_IP] [-w DC_GW] [-n INET_IF_DNS] [-m DC_IF_DNS] [-f DC_IPV6] [-y DC_IPV6_GW] [-r DC_IPV6_DNS] [-p CLOUD_PROVIDER] [-e SAAS_FLAG] [-c CONNECTOR_VERSION] [-b CONN_PILOT_VERSION] [-h HOSTNAME]"
    echo "-o OTP string"
    echo "-a ARM Mode refers the number of network interfaces (1 or 2)"
    echo "-i Internet interface ip (x.x.x.x/x)"
    echo "-g Internet interface gateway (x.x.x.x)"
    echo "-d Datacenter interface ip (x.x.x.x/x)"
    echo "-w Datacenter interface gateway (x.x.x.x)"
    echo "-n DNS IPs for Internet interface (x.x.x.x or x.x.x.x, x.x.x.x, ...)"
    echo "-m DNS IPs for Datacenter interface (x.x.x.x or x.x.x.x, x.x.x.x, ...)"
    echo "-f IPV6 Datacenter interface ip (xxxx:xxxx:xxxx:xxxx/x)"
    echo "-y IPV6 Datacenter gateway (xxxx:xxxx:xxxx:xxxx)"
    echo "-r IPV6 Datacenter DNS (xxxx:xxxx:xxxx:xxxx)"
    echo "-p Connector Deployment Environment (Private Cloud/Datacenter. Default value 'PVT')"
    echo "-e Cloudbrink SaaS Environment"
    echo "-c CB-Connector Package Version"
    echo "-b Connector Pilot Package Version"
    echo "-h Hostname for the VM (default: connector-image)"
}

function exit_on_error() {
    help_message
    exit 1
}

function log_message() {
    echo -e "$(date +'%F %T') :: $1"
}

function check_packages() {
    PKG_NAME="$1"
    command -v "${PKG_NAME}" >/dev/null 2>&1 || { log_message "Prerequisite package ${PKG_NAME} is not available. Please install the package and rerun the script"; T_ABORTED=$((T_ABORTED + 1)); exit 1;}
}

function task_summary() {
    echo -ne "### TASK SUMMARY ###\n"
    echo -ne "Total Tasks :\t\t ${T_TOTAL}\n"
    echo -ne "Tasks Succeeded :\t ${T_SUCCESS}/${T_TOTAL}\n"
    echo -ne "Tasks Failed: \t\t ${T_FAILURE}/${T_TOTAL}\n"
    echo -ne "Tasks Skipped\t\t ${T_SKIPPED}/${T_TOTAL}\n"
    echo -ne "Tasks Aborted\t\t ${T_ABORTED}/${T_TOTAL}\n"
}

function gen_userdata() {
    BASE_DIR="/etc/brink"
    OTP_FILE="${BASE_DIR}/otp"
    NETPLAN_CONF_FILE="/etc/netplan/99-installer-config.yaml"
    CB_CONF_FILE="${BASE_DIR}/netconf"

    log_message "Task 1/4 :: Generating the content for network-config"
    mkdir -p ${ISO_DIR}

    NP_APPEND_DNS_IPV6=""
    IPV6_ENABLED=0
    if [[ ${ARM_MODE} -eq 1 ]]; then
        if [[ -z "${NAME_SERVERS_INET}" ]]; then
                NAME_SERVERS_INET="${DEFAULT_IPV4_DNS_SERVER}"
        fi

        if [[ -n "${DC_IPV6}" ]]; then
            IPV6_ENABLED=1
            if [[ -n "${DC_IPV6_DNS}" ]]; then
                NP_APPEND_DNS_IPV6=", ${DC_IPV6_DNS}"
            else
                NP_APPEND_DNS_IPV6=", ${DEFAULT_IPV6_DNS_SERVER}"
            fi
        fi

        if [[ ${IPV6_ENABLED} -eq 1 ]]; then
            NP_DNS_SERVERS="${NAME_SERVERS_INET}${NP_APPEND_DNS_IPV6}"
        else
            NP_DNS_SERVERS="${NAME_SERVERS_INET}"
        fi

        DNS_ENTRY_INET="nameservers:
        addresses: [${NP_DNS_SERVERS}]"

    elif [[ ${ARM_MODE} -eq 2 ]]; then
        if [[ -z "${NAME_SERVERS_INET}" ]]; then
            NAME_SERVERS_INET="${DEFAULT_IPV4_DNS_SERVER}"
        fi

        if [[ -z "${NAME_SERVERS_DC}" ]]; then
            NAME_SERVERS_DC="${DEFAULT_IPV4_DNS_SERVER}"
        fi

        if [[ -n "${DC_IPV6}" ]]; then
            IPV6_ENABLED=1
            if [[ -n "${DC_IPV6_DNS}" ]]; then
                NP_APPEND_DNS_IPV6=", ${DC_IPV6_DNS}"
           else
               NP_APPEND_DNS_IPV6=", ${DEFAULT_IPV6_DNS_SERVER}"
            fi
        fi

        if [[ ${IPV6_ENABLED} -eq 1 ]]; then
            NP_DNS_SERVERS="${NAME_SERVERS_DC}${NP_APPEND_DNS_IPV6}"
        else
            NP_DNS_SERVERS="${NAME_SERVERS_DC}"
        fi

        DNS_ENTRY_INET="nameservers:
        addresses: [${NAME_SERVERS_INET}]"

        DNS_ENTRY_DC="nameservers:
        addresses: [${NP_DNS_SERVERS}]"
    else
        log_message "Invalid arm mode specified : ${ARM_MODE}. It should be either 1 or 2."
    fi

    NP_ENABLE_IPV6=""
    NP_APPEND_IPV6=""
    if [[ -n "${DC_IPV6}" ]]; then
        NP_ENABLE_IPV6="dhcp6: true"
        NP_APPEND_IPV6=", ${DC_IPV6}"
    fi

    NP_GW_IPV6=""
    if [[ -n "${DC_IPV6}" ]]; then
        if [[ -n "${DC_IPV6_GW}" ]]; then
            NP_GW_IPV6="gateway6: ${DC_IPV6_GW}"
        fi
    fi

    TWO_ARM=$(cat << NPEOF
network:
  version: 2
  ethernets:
    ens18:
      dhcp4: false
      addresses: [${INET_IP}]
      gateway4: ${INET_GW}
      ${DNS_ENTRY_INET}
    ens19:
      dhcp4: false
      ${NP_ENABLE_IPV6}
      addresses: [${DC_IP}${NP_APPEND_IPV6}]
      gateway4: ${DC_GW}
      ${NP_GW_IPV6}
      ${DNS_ENTRY_DC}
NPEOF
)

    ONE_ARM=$(cat << NPEOF
network:
  version: 2
  ethernets:
    ens18:
      dhcp4: false
      ${NP_ENABLE_IPV6}
      addresses: [${INET_IP}${NP_APPEND_IPV6}]
      gateway4: ${INET_GW}
      ${NP_GW_IPV6}
      ${DNS_ENTRY_INET}
NPEOF
)

    if [[ ${ARM_MODE} -eq 2 ]]; then
        SSH_LISTEN_ADDRESS="${DC_IP%%/*}"
        NP_CONTENT=${TWO_ARM}
        NC_CONTENT='{"config": [{"interface": {"name": "ens18", "type": "wan", "ip": "'${INET_IP}'", "gateway": "'${INET_GW}'", "dns": "'${NAME_SERVERS_INET}'"}}, {"interface": {"name": "eth1", "type": "lan", "ip": "'${DC_IP}'", "gateway": "'${DC_GW}'", "dns": "'${NAME_SERVERS_DC}'", "ipv6": "'${DC_IPV6}'", "ipv6_gw": "'${DC_IPV6_GW}'", "ipv6_dns": "'${DC_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "HYV"}'
    elif [[ ${ARM_MODE} -eq 1 ]]; then
        SSH_LISTEN_ADDRESS="${INET_IP%%/*}"
        NP_CONTENT=${ONE_ARM}
        NC_CONTENT='{"config": [{"interface": {"name": "ens18", "ip": "'${INET_IP}'", "gateway": "'${INET_GW}'", "dns": "'${NAME_SERVERS_INET}'", "ipv6": "'${DC_IPV6}'", "ipv6_gw": "'${DC_IPV6_GW}'", "ipv6_dns": "'${DC_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "HYV"}'
    else
        log_message "Specified ARM mode is invalid. It should be either '1' or '2'"
    fi

    if [[ -z "${CLOUD_PROVIDER}" ]]; then
        CLOUD_PROVIDER="${DEFAULT_CLOUDPROVIDER}"
    fi

    if [[ -z "${SAAS_FLAG}" ]]; then
        SAAS_FLAG="${DEFAULT_SAASFLAG}"
    fi

cat << NCEOF > ${NC_FILE}
${NP_CONTENT}
NCEOF

    NP_STRING=$(echo "${NP_CONTENT}" | awk '{printf "%s\\n", $0}')

    log_message "Task 2/4 :: Generating the content for meta-data"
    cat << MDEOF > ${MD_FILE}
instance-id: ${HOSTNAME}
local-hostname: ${HOSTNAME}
MDEOF

    log_message "Task 3/4 :: Generating the content for user-data"
    cat << UDEOF > ${UD_FILE}
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
  - [sed, -i, 's/^.*"provider":.*$/    "provider": "${CLOUD_PROVIDER}",/', ${DLAGENT_CONF_FILE}]
  - [sed, -i, 's/^.*"flags":.*$/    "flags": "${SAAS_FLAG}",/', ${DLAGENT_CONF_FILE}]
  - systemctl daemon-reload && systemctl enable dwnldagent
write_files:
  - path: ${OTP_FILE}
    permissions: '0644'
    content: |
      ${CB_OTP}
  - path: ${CB_CONF_FILE}
    permissions: '0644'
    content: |
      ${NC_CONTENT}
  - path: /etc/ssh/sshd_config.d/99-connector.conf
    owner: root:root
    permissions: '0644'
    content: |
      ListenAddress ${SSH_LISTEN_ADDRESS}
  - path: /etc/systemd/resolved.conf.d/dns_servers.conf
    owner: root:root
    permissions: '0644'
    content: |
      [Resolve]
      DNS=${NAME_SERVERS_INET} ${NAME_SERVERS_DC}
  - path: /etc/netplan/99-cb-connector.yaml
    owner: root:root
    permissions: '0640'
    content: |
      network:
        version: 2
        ethernets:
          ens18:
            dhcp4: false
            ${NP_ENABLE_IPV6}
            addresses: [${INET_IP}${NP_APPEND_IPV6}]
            gateway4: ${INET_GW}
            ${NP_GW_IPV6}
            nameservers:
              addresses: [${NP_DNS_SERVERS}]
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
UDEOF

    if [[ -f "${MD_FILE}" ]]; then
        log_message "meta-data content has been generated in the file ${MD_FILE}";
        T_SUCCESS=$((T_SUCCESS + 1));
        cat "${MD_FILE}"
    else
        log_message "Failed to generate the meta-data content in ${MD_FILE}";
        T_FAILURE=$((T_FAILURE + 1));
        T_SKIPPED=$((T_SKIPPED + 2));
    fi

    if [[ -f "${UD_FILE}" ]]; then
        log_message "user-data content has been generated in the file ${UD_FILE}";
        T_SUCCESS=$((T_SUCCESS + 1));
        cat "${UD_FILE}"
    else
        log_message "Failed to generate the user-data content in ${UD_FILE}";
        T_FAILURE=$((T_FAILURE + 1));
        T_SKIPPED=$((T_SKIPPED + 2));
    fi

    if [[ -f "${NC_FILE}" ]]; then
        log_message "network-config content has been generated in the file ${NC_FILE}";
        T_SUCCESS=$((T_SUCCESS + 1));
        cat "${NC_FILE}"
    else
        log_message "Failed to generate the network-config content in ${NC_FILE}";
        T_FAILURE=$((T_FAILURE + 1));
        T_SKIPPED=$((T_SKIPPED + 2));
    fi
}

function create_iso() {
    log_message "Task 4/4 :: Creating new iso image with meta-data, user-data and network-config content"

    TIMESTAMP=$(date +"%m%d%Y_%H%M%S")
    ISO_FILE="${TEMP_DIR}/cbuserdata_${TIMESTAMP}.iso"

    if [[ -x /usr/bin/genisoimage ]]; then
        log_message "Package genisoimage installed"
    else
        log_message "Installing genisoimage package"
        sudo apt install -y genisoimage >/dev/null 2>&1
    fi

    if [[ -f "${ISO_DIR}/user-data" ]]; then
        genisoimage -o "${ISO_FILE}" -J -V cidata -r "${ISO_DIR}/" >/dev/null 2>&1
        result=$?
        if [[ ${result} -eq 0 ]]; then
            if [[ -f "${ISO_FILE}" ]]; then
                ## to be uploaded into the data store
                log_message "ISO image ${ISO_FILE} has been created"
                T_SUCCESS=$((T_SUCCESS + 1))
            else
                log_message "Created iso image ${ISO_FILE} is not found in the path"
                T_FAILURE=$((T_FAILURE + 1))
                T_SKIPPED=$((T_SKIPPED + 1))
            fi
        else
            log_message "Failed to create the iso image ${ISO_FILE}"
            T_FAILURE=$((T_FAILURE + 1))
            T_SKIPPED=$((T_SKIPPED + 1))
        fi
    else
        log_message "Failed to find the content to create user-data iso image"
        T_FAILURE=$((T_FAILURE + 1))
        T_SKIPPED=$((T_SKIPPED + 1))
    fi

    if [[ -x /usr/bin/genisoimage ]]; then
        log_message "Uninstalling genisoimage"
        sudo apt remove -y genisoimage >/dev/null 2>&1
    fi
}

function main_setup() {
    echo -e "#######################################################"
    echo -e "#####   CloudBrink's Connector-Agent Deployment   #####"
    echo -e "#######################################################"

    while getopts ":o:a:i:g:d:w:s:n:m:f:y:r:p:e:c:b:h:" options; do
        case "${options}" in
            o) CB_OTP="$OPTARG"
                if [[ -z "${CB_OTP}" ]]; then
                    log_message "OTP value should not be empty"
                    exit_on_error
                fi
                ;;
            a) ARM_MODE="$OPTARG"
                re_isanum='^[1-2]+$'
                if ! [[ ${ARM_MODE} =~ ${re_isanum} ]] ; then
                    log_message "ARM_MODE should be either 1 or 2"
                    exit_on_error
                fi
                ;;
            i) INET_IP="$OPTARG"
                if [[ -z "${INET_IP}" ]]; then
                    log_message "External IP (Internet) should not be empty"
                    exit_on_error
                fi
                ;;
            g) INET_GW="$OPTARG"
                if [[ -z "${INET_GW}" ]]; then
                    log_message "External Gateway (Internet) should not be empty"
                    exit_on_error
                fi
                ;;
            d) DC_IP="$OPTARG"
                if [[ ${ARM_MODE} -eq 2 ]]; then
                    if [[ -z "${DC_IP}" ]]; then
                        log_message "Internal IP (Datacenter) should not be empty"
                        exit_on_error
                    fi
                fi
                ;;
            w) DC_GW="$OPTARG"
                if [[ ${ARM_MODE} -eq 2 ]]; then
                    if [[ -z "${DC_GW}" ]]; then
                        log_message "Internal Gateway (Datacenter) should not be empty"
                        exit_on_error
                    fi
                fi
                ;;
            n) NAME_SERVERS_INET="$OPTARG"
                ;;
            m) NAME_SERVERS_DC="$OPTARG"
                ;;
            f) DC_IPV6="$OPTARG"
                ;;
            y) DC_IPV6_GW="$OPTARG"
                ;;
            r) DC_IPV6_DNS="$OPTARG"
                ;;
            p) CLOUD_PROVIDER="$OPTARG"
                ;;
            e) SAAS_FLAG="$OPTARG"
                ;;
            c) CONNECTOR_VERSION="$OPTARG"
                ;;
            b) CONN_PILOT_VERSION="$OPTARG"
                ;;
            h)
                HOSTNAME="$OPTARG"
                ;;
            :) echo "Error: -${OPTARG} requires an argument."
               exit_on_error
                ;;
            *) exit_on_error
                ;;
        esac
    done
    #shift "$(($OPTIND -1))"

    log_message "Initializing Deployment and Checking Prerequisites"
    #check_package "getisoimage"
    #check_package "govc"

    log_message ":: Input Parameters ::"
    log_message "CB_OTP = ${CB_OTP} || ARM_MODE = ${ARM_MODE} || WAN_IP = ${INET_IP} || WAN_GW = ${INET_GW} || WAN_DNS = ${NAME_SERVERS_INET}"
    log_message "LAN_IP = ${DC_IP} || LAN_GW = ${DC_GW} || LAN_DNS = ${NAME_SERVERS_DC} || LAN_IPV6 = ${DC_IPV6} || LAN_IPV6_GW = ${DC_IPV6_GW} || LAN_IPV6_DNS = ${DC_IPV6_DNS}"
    log_message "CLOUD_PROVIDER = ${CLOUD_PROVIDER} || SAAS_FLAG = ${SAAS_FLAG} || CONNECTOR_VERSION = ${CONNECTOR_VERSION} || CONN_PILOT_VERSION = ${CONN_PILOT_VERSION} || HOSTNAME = ${HOSTNAME}"

    gen_userdata
    create_iso

    task_summary
    log_message "Exiting Deployment script"
}

### main call ###
main_setup "$@"
