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
DS_NAME=""
CLOUD_PROVIDER=""
SAAS_FLAG=""
CONNECTOR_VERSION=""
CONN_PILOT_VERSION=""
HOSTNAME="connector-image"  # Default hostname

# global scope variables
SETUP_DIR="/tmp/CB-SETUP"
ISO_DIR="${SETUP_DIR}/ca-iso"
UD_FILE="${ISO_DIR}/user-data.txt"
ISO_FILE=""
DEFAULT_IPV4_DNS_SERVER="8.8.8.8"
DEFAULT_IPV6_DNS_SERVER="2001:4860:4860::8888"
DEFAULT_CLOUDPROVIDER="PVT"
DEFAULT_SAASFLAG="wren"
SYSTEMD_RESOLVE_CONF_FILE="/etc/systemd/resolve.conf"
DLAGENT_CONF_FILE="/opt/dwnldagent/config"
SSHD_CONF_FILE="/etc/ssh/sshd_config"
SSH_LISTEN_ADDRESS=""

# task summary variables
T_TOTAL=3
T_ABORTED=0
T_SUCCESS=0
T_SKIPPED=0
T_FAILURE=0

function usage() {
    echo "usage: $0 -o OTP -a ARM_MODE -i INET_IP -g INET_GW [-d DC_IP] [-w DC_GW] [-n INET_IF_DNS] [-m DC_IF_DNS] [-f DC_IPV6] [-y DC_IPV6_GW] [-r DC_IPV6_DNS] [-p CLOUD_PROVIDER] [-e SAAS_FLAG] [-c CONNECTOR_VERSION] [-b CONN_PILOT_VERSION] [-s VSPHERE_DATASTORE_NAME] [-h HOSTNAME]"
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
    echo "-s vSphere datastore name"
    echo "-h Hostname for the VM (default: connector-image)"
}

function exit_on_error() {
    usage
    exit 1
}

function log_message() {
    echo -e "$(date +'%F %T') :: $1"
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

    log_message "Preflight checks"
    if [ ! -d ${ISO_DIR} ]; then
        log_message "${ISO_DIR} does not exist. Creating."
        mkdir -p ${ISO_DIR}
    else
        if [ "$(ls -A ${ISO_DIR})" ]; then
            log_message "${ISO_DIR} exists and is not empty. Deleting contents."
            rm -rf ${ISO_DIR:?}/*
        fi
    fi

    log_message "Task 1/3 :: Generating user-data.txt"
    NP_APPEND_DNS_IPV6=""
    IPV6_ENABLED=0
    if [ "${ARM_MODE}" -eq 1 ]; then
        if [ -z "${NAME_SERVERS_INET}" ]; then
                NAME_SERVERS_INET="${DEFAULT_IPV4_DNS_SERVER}"
        fi

        if [ -n "${DC_IPV6}" ]; then
            IPV6_ENABLED=1
            if [ -n "${DC_IPV6_DNS}" ]; then
                NP_APPEND_DNS_IPV6=", ${DC_IPV6_DNS}"
            else
                NP_APPEND_DNS_IPV6=", ${DEFAULT_IPV6_DNS_SERVER}"
            fi
        fi

        if [ "${IPV6_ENABLED}" -eq 1 ]; then
            NP_DNS_SERVERS="${NAME_SERVERS_INET}${NP_APPEND_DNS_IPV6}"
        else
            NP_DNS_SERVERS="${NAME_SERVERS_INET}"
        fi

        DNS_ENTRY_INET=$(printf "nameservers:\n                addresses: [%s]\n" "${NP_DNS_SERVERS}")

    elif [ "${ARM_MODE}" -eq 2 ]; then
        if [ -z "${NAME_SERVERS_INET}" ]; then
            NAME_SERVERS_INET="${DEFAULT_IPV4_DNS_SERVER}"
        fi

        if [ -z "${NAME_SERVERS_DC}" ]; then
            NAME_SERVERS_DC="${DEFAULT_IPV4_DNS_SERVER}"
        fi

        if [ -n "${DC_IPV6}" ]; then
            IPV6_ENABLED=1
            if [ -n "${DC_IPV6_DNS}" ]; then
                NP_APPEND_DNS_IPV6=", ${DC_IPV6_DNS}"
            else
                NP_APPEND_DNS_IPV6=", ${DEFAULT_IPV6_DNS_SERVER}"
            fi
        fi

        if [ "${IPV6_ENABLED}" -eq 1 ]; then
            NP_DNS_SERVERS="${NAME_SERVERS_DC}${NP_APPEND_DNS_IPV6}"
        else
            NP_DNS_SERVERS="${NAME_SERVERS_DC}"
        fi

        DNS_ENTRY_INET=$(printf "nameservers:\n                addresses: [%s]\n" "${NAME_SERVERS_INET}")
        DNS_ENTRY_DC=$(printf "nameservers:\n                addresses: [%s]\n" "${NP_DNS_SERVERS}")
    else
        log_message "Invalid arm mode specified : ${ARM_MODE}. It should be either 1 or 2."
    fi

    NP_ENABLE_IPV6=""
    NP_APPEND_IPV6=""
    if [ -n "${DC_IPV6}" ]; then
        NP_ENABLE_IPV6="dhcp6: true"
        NP_APPEND_IPV6=", ${DC_IPV6}"
    fi

    NP_GW_IPV6=""
    if [ -n "${DC_IPV6}" ]; then
        if [ -n "${DC_IPV6_GW}" ]; then
            NP_GW_IPV6=$(printf "gateway6: %s" "${DC_IPV6_GW}")
        fi
    fi

    TWO_ARM=$(cat << NPEOF
network:
    version: 2
    ethernets:
        ens192:
            dhcp4: false
            addresses: [${INET_IP}]
            gateway4: ${INET_GW}
            ${DNS_ENTRY_INET}
        ens224:
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
        ens192:
            dhcp4: false
            ${NP_ENABLE_IPV6}
            addresses: [${INET_IP}${NP_APPEND_IPV6}]
            gateway4: ${INET_GW}
            ${NP_GW_IPV6}
            ${DNS_ENTRY_INET}
NPEOF
)

    if [ "${ARM_MODE}" -eq 2 ]; then
        SSH_LISTEN_ADDRESS="${DC_IP%%/*}"
        NP_CONTENT=$(echo "${TWO_ARM}" | grep -v '^ *$' | awk '{print "      "$0}')
        NC_CONTENT='{"config": [{"interface": {"name": "ens192", "type": "wan", "ip": "'${INET_IP}'", "gateway": "'${INET_GW}'", "dns": "'${NAME_SERVERS_INET}'"}}, {"interface": {"name": "ens224", "type": "lan", "ip": "'${DC_IP}'", "gateway": "'${DC_GW}'", "dns": "'${NAME_SERVERS_DC}'", "ipv6": "'${DC_IPV6}'", "ipv6_gw": "'${DC_IPV6_GW}'", "ipv6_dns": "'${DC_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "VMW"}'
    elif [ "${ARM_MODE}" -eq 1 ]; then
        SSH_LISTEN_ADDRESS="${INET_IP%%/*}"
        NP_CONTENT=$(echo "${ONE_ARM}" | grep -v '^ *$' | awk '{print "      "$0}')
        NC_CONTENT='{"config": [{"interface": {"name": "ens192", "ip": "'${INET_IP}'", "gateway": "'${INET_GW}'", "dns": "'${NAME_SERVERS_INET}'", "ipv6": "'${DC_IPV6}'", "ipv6_gw": "'${DC_IPV6_GW}'", "ipv6_dns": "'${DC_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "VMW"}'
    else
        log_message "Specified ARM mode is invalid. It should be either '1' or '2'"
    fi

    if [ -z "${CLOUD_PROVIDER}" ]; then
        CLOUD_PROVIDER="${DEFAULT_CLOUDPROVIDER}"
    fi

    if [ -z "${SAAS_FLAG}" ]; then
        SAAS_FLAG="${DEFAULT_SAASFLAG}"
    fi

    #log_message ":: ${CLOUD_PROVIDER} || ${DEFAULT_CLOUDPROVIDER}"
    #log_message ":: ${SAAS_FLAG} || ${DEFAULT_SAASFLAG}"

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
  - [netplan, apply]
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
  - path: /etc/netplan/99-connector.yaml
    owner: root:root
    permissions: '0640'
    content: |
${NP_CONTENT}
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
  - [rm, -f, /etc/cloud/cloud.cfg.d/99-defaults.cfg]
  - [rm, -f, /etc/cloud/cloud.cfg.d/99-disable-dhcp.cfg]
  - [rm, -f, /etc/netplan/50-cloud-init.yaml]
  - [sed, -i, 's/^.*"provider":.*$/    "provider": "${CLOUD_PROVIDER}",/', ${DLAGENT_CONF_FILE}]
  - [sed, -i, 's/^.*"flags":.*$/    "flags": "${SAAS_FLAG}",/', ${DLAGENT_CONF_FILE}]
  - systemctl daemon-reload && systemctl enable dwnldagent
  - [systemctl, start, dwnldagent]
UDEOF
# #!/bin/bash

# echo "Update and upgrade packages"
# apt update
# apt upgrade -y -s
# echo "Creating the dir ${BASE_DIR}"
# mkdir -p ${BASE_DIR}
# echo "${CB_OTP}" > "${OTP_FILE}"
# rm -rf /etc/netplan/*
# ${NP_CONTENT}
# echo "Executing 'netplan apply'"
# netplan apply
# echo '${NC_CONTENT}' > "${CB_CONF_FILE}"
# systemctl stop ntp

# # Fix for bi-directional connectivity
# function update_sshd_config() {
#         log_message "Updating the listen address as ${SSH_LISTEN_ADDRESS} in the file ${SSHD_CONF_FILE}."
#         GREP_EXISTING_VALUE=\$(grep -i "^.*ListenAddress 0.0.0.0" "${SSHD_CONF_FILE}")

#         if [ -z "\${GREP_EXISTING_VALUE}" ]; then
#                 echo "ListenAddress ${SSH_LISTEN_ADDRESS}" >> "${SSHD_CONF_FILE}"
#         else
#                 sed -i "/^.*ListenAddress 0.0.0.0/a ListenAddress ${SSH_LISTEN_ADDRESS}" "${SSHD_CONF_FILE}"
#         fi

#         GREP_NEW_VALUE=\$(grep -i "^.*ListenAddress ${SSH_LISTEN_ADDRESS}" "${SSHD_CONF_FILE}")
#         if [ "\${GREP_NEW_VALUE}" == "ListenAddress ${SSH_LISTEN_ADDRESS}" ]; then
#                 log_message "Successfully updated the sshd listen address from defaut(0.0.0.0) to ${SSH_LISTEN_ADDRESS}."
#                 log_message "Restarting the sshd service"
#                 RCODE=\$(systemctl restart sshd)

#                 if [ "\${RCODE}" -eq 0 ]; then
#                         SSHD_SVC_STATUS_OUT=\$(systemctl is-active sshd)
#                         if [ "\${SSHD_SVC_STATUS_OUT}" == "active" ]; then
#                                 NSTAT_SSH_OUT=\$(netstat -anlp | grep "${SSH_LISTEN_ADDRESS}:22" | awk '{print \$4}')
#                                 if [ "\${NSTAT_SSH_OUT}" == "${SSH_LISTEN_ADDRESS}:22" ]; then
#                                         log_message "sshd service successfully restarted and listening on \${NSTAT_SSH_OUT}."
#                                 else
#                                         log_message "sshd service restarted but listening on \${NSTAT_SSH_OUT}."
#                                 fi
#                         else
#                                 log_message "sshd service is \${SSHD_SVC_STATUS_OUT} state and not in expected state 'active' after updating the listen address from default value."
#                         fi
#                 else
#                         log_message "Couldn't restart the sshd service after updating the listen address as ${SSH_LISTEN_ADDRESS}. Returned the error code: \${RCODE}."
#                 fi
#         else
#             log_message "Failed to update the sshd listen address ${SSH_LISTEN_ADDRESS} in the ${SSHD_CONF_FILE}."
#         fi
# }

# # update the default sshd listen address value
# update_sshd_config
# #to wait for ens224 come alive
# sleep 5

# if [ "${ARM_MODE}" -eq 2 ]; then
#     echo "Deleting the LAN gateway default route"
#     ip route del 0.0.0.0/0 dev ens224
# fi

# # extend the password expiry date for `cbrink` user
# echo "Extending passwd expiry : chage -m 0 -M 99999 -I -1 -E -1 -W 30 cbrink"
# chage -m 0 -M 99999 -I -1 -E -1 -W 30 cbrink

# function update_systemd_resolve_config() {
#     # updating the /etc/systemd/resolve.conf to update global dns for the connector vm
#     # the sed commands here used could appened replacements twice (its a known trivial issue)

#     echo "Updating the systemd-resolve config file"
#     if [ -f "${SYSTEMD_RESOLVE_CONF_FILE}" ]; then
#         sed -e "/^DNS=.*/s/^/#/" -i "${SYSTEMD_RESOLVE_CONF_FILE}"
#         sed -e "/^FallbackDNS=.*/s/^/#/" -i "${SYSTEMD_RESOLVE_CONF_FILE}"

#         IFS=","
#         expanded_dns_list=""
#         inet_dns_list=( $(echo "${NAME_SERVERS_INET}") )
#         dc_dns_list=( $(echo "${NAME_SERVERS_DC}") )

#         if [ "${#inet_dns_list[@]}" -gt 1 ]; then
#             echo "iterating inet dns list"
#             for ns in ${inet_dns_list[@]}; do
#                 expanded_dns_list+="DNS=${ns}\n"
#             done
#             echo "${expanded_dns_list}"
#             sed -e "/^#FallbackDNS=.*/i ${expanded_dns_list}" -i "${SYSTEMD_RESOLVE_CONF_FILE}"
#         fi
#         expanded_dns_list=""

#         if [ "${#dc_dns_list[@]}" -gt 1 ]; then
#             echo "iterating dc dns list"
#             for ns in ${dc_dns_list[@]}; do
#                 expanded_dns_list+="DNS=${ns}\n"
#             done
#             echo "${expanded_dns_list}"
#             sed -e "/^#FallbackDNS=.*/i ${expanded_dns_list}" -i "${SYSTEMD_RESOLVE_CONF_FILE}"
#         fi
#         expanded_dns_list=""
#         IFS=" "

#         if [ "${#inet_dns_list[@]}" -eq 1 ] && [ ${#dc_dns_list[@]} -eq 1 ]; then
#             sed -e "/^#FallbackDNS=.*/i DNS=${NAME_SERVERS_INET}\nDNS=${NAME_SERVERS_DC}" -i "${SYSTEMD_RESOLVE_CONF_FILE}"
#         fi

#         echo "Config has been updated as follows:"
#         cat "${SYSTEMD_RESOLVE_CONF_FILE}"
#     else
#         echo "${SYSTEMD_RESOLVE_CONF_FILE} is not present. Installation could be corrupted or incomplete."
#         echo "Try remove and install the package."
#     fi
# }

# function update_dl_config() {
#     # updating the downloadagent config file
#     echo "Updating the downloadagent config file"
#     if [ -f "${DLAGENT_CONF_FILE}" ]; then
#         sed -i "s/^.*\"provider\"\:.*$/    \"provider\"\: \"${CLOUD_PROVIDER}\"\,/" "${DLAGENT_CONF_FILE}"
#         sed -i "s/^.*\"flags\"\:.*$/    \"flags\"\: \"${SAAS_FLAG}\"\,/" "${DLAGENT_CONF_FILE}"

#                 if [ -n "${CONNECTOR_VERSION}" ]; then
#                     sed -i "s/^.*\"pkgver\"\:.*$/  \"pkgver\"\: \"${CONNECTOR_VERSION}\"\,/" "${DLAGENT_CONF_FILE}"
#                 fi

#                 if [ -n "${CONN_PILOT_VERSION}" ]; then
#                     sed -i "s/^.*\"agntver\"\:.*$/  \"agntver\"\: \"${CONN_PILOT_VERSION}\"\,/" "${DLAGENT_CONF_FILE}"
#                 fi

#         echo "Config has been updated as follows:"
#         cat "${DLAGENT_CONF_FILE}"
#     else
#         echo "${DLAGENT_CONF_FILE} is not present. Installation could be corrupted or incomplete."
#         echo "Try remove and install the package."
#     fi
# }

# update_systemd_resolve_config
# update_dl_config
# # enabling and starting the download agent service
# echo "Enabling and starting the download agent service"
# systemctl enable dwnldagent
# systemctl start dwnldagent
# echo "Updated the configurations..."

    if [ -f "${UD_FILE}" ]; then
        log_message "user-data content has been generated in the file ${UD_FILE}";
        T_SUCCESS=$((T_SUCCESS + 1));
        cat "${UD_FILE}"
    else
        log_message "Failed to generate the user-data content in ${UD_FILE}";
        T_FAILURE=$((T_FAILURE + 1));
        T_SKIPPED=$((T_SKIPPED + 2));
    fi
}

function create_iso() {
    log_message "Task 2/3 :: Creating new ISO image with user-data.txt content"

    TIMESTAMP=$(date +"%m%d%Y_%H%M%S")
    ISO_FILE="${SETUP_DIR}/cbuserdata_${TIMESTAMP}.iso"

    if [ -x /usr/bin/genisoimage ]; then
        log_message "Package genisoimage installed"
    else
        log_message "Installing genisoimage package"
        sudo apt install -y genisoimage >/dev/null 2>&1
    fi

    if [ -f "${UD_FILE}" ]; then
        genisoimage -o "${ISO_FILE}" -input-charset utf-8 -joliet -rock -rational-rock "${ISO_DIR}/" >/dev/null 2>&1
        result=$?
        if [ "${result}" -eq 0 ]; then
            if [ -f "${ISO_FILE}" ]; then
                ## to be uploaded into the data store
                log_message "ISO image ${ISO_FILE} has been created"
                T_SUCCESS=$((T_SUCCESS + 1))
            else
                log_message "Created iso image ${ISO_FILE} is not found in the path"
                T_FAILURE=$((T_FAILURE + 1))
                T_SKIPPED=$((T_SKIPPED + 1))
            fi
        else
            log_message "Failed to create the ISO image ${ISO_FILE}"
            T_FAILURE=$((T_FAILURE + 1))
            T_SKIPPED=$((T_SKIPPED + 1))
        fi
    else
        log_message "Failed to find the content to create user-data iso image"
        T_FAILURE=$((T_FAILURE + 1))
        T_SKIPPED=$((T_SKIPPED + 1))
    fi

    if [ -x /usr/bin/genisoimage ]; then
        log_message "Uninstalling genisoimage"
        sudo apt remove -y genisoimage >/dev/null 2>&1
    fi
}

function upload_iso() {
    if [ -x /usr/local/bin/govc ]; then
        log_message "Binary govc installed"
    else
        log_message "Installing govc"
        curl -sL https://github.com/vmware/govmomi/releases/download/v0.35.0/govc_Linux_x86_64.tar.gz | sudo tar zxf - -C /usr/local/bin govc
    fi

    DS_ISO_DIR="/CB-USERDATA-ISO"
    DS_ISO_FILE="${DS_ISO_DIR}/cbuserdata_${TIMESTAMP}.iso"
    log_message "Task 3/3 :: Uploading the userdata ISO image into datastore"
    govc datastore.upload -ds "${DS_NAME}" "${ISO_FILE}" "${DS_ISO_FILE}" >/dev/null 2>&1
    result=$?

    if [ "${result}" -eq 0 ]; then
        log_message "ISO file uploaded into datastore /${DS_NAME}${DS_ISO_FILE}"
        T_SUCCESS=$((T_SUCCESS + 1))
    else
        log_message "Failed to upload the ISO ${ISO_FILE} file into datastore ${DS_NAME}"
        T_FAILURE=$((T_FAILURE + 1))
    fi

    log_message "Uninstalling govc"
    sudo rm -rf /usr/local/bin/govc >/dev/null 2>&1
}

function main_setup() {
    echo -e "#######################################################"
    echo -e "#####   CloudBrink's Connector-Agent Deployment   #####"
    echo -e "#######################################################"

    while getopts ":o:a:i:g:d:w:s:n:m:f:y:r:p:e:c:b:h:" arg; do
        case "${arg}" in
            o)
                CB_OTP=${OPTARG}
                ;;
            a)
                ARM_MODE=${OPTARG}
                ;;
            i)
                INET_IP=${OPTARG}
                ;;
            g)
                INET_GW=${OPTARG}
                ;;
            d)
                DC_IP=${OPTARG}
                ;;
            w)
                DC_GW=${OPTARG}
                ;;
            s)
                DS_NAME=${OPTARG}
                ;;
            n)
                NAME_SERVERS_INET=${OPTARG}
                ;;
            m)
                NAME_SERVERS_DC=${OPTARG}
                ;;
            f)
                DC_IPV6=${OPTARG}
                ;;
            y)
                DC_IPV6_GW=${OPTARG}
                ;;
            r)
                DC_IPV6_DNS=${OPTARG}
                ;;
            p)
                CLOUD_PROVIDER=${OPTARG}
                ;;
            e)
                SAAS_FLAG=${OPTARG}
                ;;
            c)
                CONNECTOR_VERSION=${OPTARG}
                ;;
            b)
                CONN_PILOT_VERSION=${OPTARG}
                ;;
            h)
                HOSTNAME=${OPTARG}
                ;;
            *)
                usage
                ;;
        esac
    done
    shift "$((OPTIND-1))"

    if [ -z "${CB_OTP}" ]; then
        log_message "OTP value should not be empty"
        exit_on_error
    fi

    if [ "${ARM_MODE}" -lt 1 ] || [ "${ARM_MODE}" -gt 2 ]; then
        log_message "ARM_MODE should be either 1 or 2"
        exit_on_error
    fi

    if [ -z "${INET_IP}" ]; then
        log_message "External IP (Internet) should not be empty"
        exit_on_error
    fi

    if [ -z "${INET_GW}" ]; then
        log_message "External Gateway (Internet) should not be empty"
        exit_on_error
    fi

    if [ "${ARM_MODE}" -eq 2 ]; then
        if [ -z "${DC_IP}" ]; then
            log_message "Internal IP (Datacenter) should not be empty"
            exit_on_error
        fi
        if [ -z "${DC_GW}" ]; then
            log_message "Internal Gateway (Datacenter) should not be empty"
            exit_on_error
        fi
    fi

    log_message "Initializing Deployment and Checking Prerequisites"
    log_message ":: Input Parameters ::"
    log_message "CB_OTP = ${CB_OTP} || ARM_MODE = ${ARM_MODE} || WAN_IP = ${INET_IP} || WAN_GW = ${INET_GW} || WAN_DNS = ${NAME_SERVERS_INET}"
    log_message "LAN_IP = ${DC_IP} || LAN_GW = ${DC_GW} || LAN_DNS = ${NAME_SERVERS_DC} || LAN_IPV6 = ${DC_IPV6} || LAN_IPV6_GW = ${DC_IPV6_GW} || LAN_IPV6_DNS = ${DC_IPV6_DNS}"
    log_message "CLOUD_PROVIDER = ${CLOUD_PROVIDER} || SAAS_FLAG = ${SAAS_FLAG} || CONNECTOR_VERSION = ${CONNECTOR_VERSION} || CONN_PILOT_VERSION = ${CONN_PILOT_VERSION} || VMWARE_DATASTORE = ${DS_NAME} || HOSTNAME = ${HOSTNAME}"

    gen_userdata
    create_iso
    if [ -z "${DS_NAME}" ]; then
            log_message "Task 3/3 :: Skipping uploading the userdata ISO image into datastore"
            T_SKIPPED=$((T_SKIPPED + 1))
    else
            upload_iso
    fi

    task_summary
    log_message "Exiting Deployment script"
}

### main call ###
main_setup "$@"