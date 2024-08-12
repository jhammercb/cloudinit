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

# global scope variables
TEMP_DIR="/tmp/CB-SETUP"
ISO_DIR="${TEMP_DIR}/ca-iso"
UD_FILE="${ISO_DIR}/user-data.txt"
ISO_FILE=""
DEFAULT_CLOUDPROVIDER="PVT"
DEFAULT_SAASFLAG="wren"
DLAGENT_CONF_FILE="/opt/dwnldagent/config"
SSHD_CONF_FILE="/etc/ssh/sshd_config"
SSH_LISTEN_ADDRESS=""
PREREQ_PKGS=("getisoimage" "govc")

# task summary variables
T_TOTAL=3
T_ABORTED=0
T_SUCCESS=0
T_SKIPPED=0
T_FAILURE=0


function help_message() {

    echo "usage: $0 -o OTP -a ARM_MODE -i INET_IP -g INET_GW [-d DC_IP] [-w DC_GW] [-n INET_IF_DNS] [-m DC_IF_DNS] [-f DC_IPV6] [-y DC_IPV6_GW] [-r DC_IPV6_DNS] [-p CLOUD_PROVIDER] [-e SAAS_FLAG] [-s VSPHERE_DATASTORE_NAME]"
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
    echo "-s vSphere datastore name"
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
    NETPLAN_CONF_FILE="/etc/netplan/00-installer-config.yaml"
    CB_CONF_FILE="${BASE_DIR}/netconf"
    #ARM_TYPE=${ARM_MODE}

    log_message "Task 1/3 :: Generating the content for user-data.txt"
    mkdir -p ${ISO_DIR}

    NP_APPEND_DNS_IPV6=""
    if [[ -z "${NAME_SERVERS_INET}" ]]; then
        DNS_ENTRY_INET=""
    else
        if [[ -n "${DC_IPV6}" ]]; then
            if [[ "$ARM_MODE" -eq 1 ]]; then
                if [[ -n "${DC_IPV6_DNS}" ]]; then
                    NP_APPEND_DNS_IPV6=", ${DC_IPV6_DNS}"
                fi
            fi
        fi
        DNS_ENTRY_INET="nameservers:
        addresses: [${NAME_SERVERS_INET}${NP_APPEND_DNS_IPV6}]"
    fi

    if [[ -z "${NAME_SERVERS_DC}" ]]; then
        DNS_ENTRY_DC=""
    else
        if [[ -n "${DC_IPV6}" ]]; then
            if [[ -n "${DC_IPV6_DNS}" ]]; then
                NP_APPEND_DNS_IPV6=", ${DC_IPV6_DNS}"
            fi
        fi
        DNS_ENTRY_DC="nameservers:
        addresses: [${NAME_SERVERS_DC}${NP_APPEND_DNS_IPV6}]"
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


    TWO_ARM="cat << NPEOF > ${NETPLAN_CONF_FILE}
network:
  ethernets:
    ens160:
      addresses: [${INET_IP}]
      gateway4: ${INET_GW}
      ${DNS_ENTRY_INET}
    ens192:
      ${NP_ENABLE_IPV6}
      addresses: [${DC_IP}${NP_APPEND_IPV6}]
      gateway4: ${DC_GW}
      ${NP_GW_IPV6}
      ${DNS_ENTRY_DC}
  version: 2
NPEOF"


    ONE_ARM="cat << NPEOF > ${NETPLAN_CONF_FILE}
network:
  ethernets:
    ens160:
      ${NP_ENABLE_IPV6}
      addresses: [${INET_IP}${NP_APPEND_IPV6}]
      gateway4: ${INET_GW}
      ${NP_GW_IPV6}
      ${DNS_ENTRY_INET}
  version: 2
NPEOF"


    if [[ ${ARM_MODE} -eq 2 ]]; then
        SSH_LISTEN_ADDRESS="${DC_IP%%/*}"
        NP_CONTENT=${TWO_ARM}
        NC_CONTENT='{"config": [{"interface": {"name": "ens160", "type": "wan", "ip": "'${INET_IP}'", "gateway": "'${INET_GW}'", "dns": "'${NAME_SERVERS_INET}'"}}, {"interface": {"name": "ens192", "type": "lan", "ip": "'${DC_IP}'", "gateway": "'${DC_GW}'", "dns": "'${NAME_SERVERS_DC}'", "ipv6": "'${DC_IPV6}'", "ipv6_gw": "'${DC_IPV6_GW}'", "ipv6_dns": "'${DC_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "VMW"}'
    elif [[ ${ARM_MODE} -eq 1 ]]; then
        SSH_LISTEN_ADDRESS="${INET_IP%%/*}"
        NP_CONTENT=${ONE_ARM}
        NC_CONTENT='{"config": [{"interface": {"name": "ens160", "ip": "'${INET_IP}'", "gateway": "'${INET_GW}'", "dns": "'${NAME_SERVERS_INET}'", "ipv6": "'${DC_IPV6}'", "ipv6_gw": "'${DC_IPV6_GW}'", "ipv6_dns": "'${DC_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "VMW"}'
    else
        log_message "Specified ARM mode is invalid. It should be either '1' or '2'"
    fi

    if [[ -z "${CLOUD_PROVIDER}" ]]; then
        CLOUD_PROVIDER="${DEFAULT_CLOUDPROVIDER}"
    fi

    if [[ -z "${SAAS_FLAG}" ]]; then
        SAAS_FLAG="${DEFAULT_SAASFLAG}"
    fi

    #log_message ":: ${CLOUD_PROVIDER} || ${DEFAULT_CLOUDPROVIDER}"
    #log_message ":: ${SAAS_FLAG} || ${DEFAULT_SAASFLAG}"

cat << UDEOF > ${UD_FILE}
#!/bin/bash

echo "creating the dir ${BASE_DIR}"
mkdir -p ${BASE_DIR}
echo "${CB_OTP}" > "${OTP_FILE}"
${NP_CONTENT}
echo "executing 'netplan apply'"
netplan apply
echo '${NC_CONTENT}' > "${CB_CONF_FILE}"
systemctl stop ntp

# Fix for bi-directional connectivity
function update_sshd_config() {
        log_message "Updating the listen address as ${SSH_LISTEN_ADDRESS} in the file ${SSHD_CONF_FILE}."
        GREP_EXISTING_VALUE=\$(grep -i "^.*ListenAddress 0.0.0.0" "${SSHD_CONF_FILE}")

        if [[ -z "\${GREP_EXISTING_VALUE}" ]]; then
                echo "ListenAddress ${SSH_LISTEN_ADDRESS}" >> "${SSHD_CONF_FILE}"
        else
                sed -i "/^.*ListenAddress 0.0.0.0/a ListenAddress ${SSH_LISTEN_ADDRESS}" "${SSHD_CONF_FILE}"
        fi

        GREP_NEW_VALUE=\$(grep -i "^.*ListenAddress ${SSH_LISTEN_ADDRESS}" "${SSHD_CONF_FILE}")
        if [[ "\${GREP_NEW_VALUE}" == "ListenAddress ${SSH_LISTEN_ADDRESS}" ]]; then
                log_message "Successfully updated the sshd listen address from defaut(0.0.0.0) to ${SSH_LISTEN_ADDRESS}."
                log_message "Restarting the sshd service"
                RCODE=\$(systemctl restart sshd)

                if [[ \${RCODE} -eq 0 ]]; then
                        SSHD_SVC_STATUS_OUT=\$(systemctl is-active sshd)
                        if [[ "\${SSHD_SVC_STATUS_OUT}" == "active" ]]; then
                                NSTAT_SSH_OUT=\$(netstat -anlp | grep "${SSH_LISTEN_ADDRESS}:22" | awk '{print \$4}')
                                if [[ "\${NSTAT_SSH_OUT}" == "${SSH_LISTEN_ADDRESS}:22" ]]; then
                                        log_message "sshd service successfully restarted and listening on \${NSTAT_SSH_OUT}."
                                else
                                        log_message "sshd service restarted but listening on \${NSTAT_SSH_OUT}."
                                fi
                        else
                                log_message "sshd service is \${SSHD_SVC_STATUS_OUT} state and not in expected state 'active' after updating the listen address from default value."
                        fi
                else
                        log_message "Couldn't restart the sshd service after updating the listen address as ${SSH_LISTEN_ADDRESS}. Returned the error code: \${RCODE}."
                fi
        else
            log_message "Failed to update the sshd listen address ${SSH_LISTEN_ADDRESS} in the ${SSHD_CONF_FILE}."
        fi
}

# update the default sshd listen address value
update_sshd_config

#to wait for ens192 come alive
sleep 5

if [[ ${ARM_MODE} -eq 2 ]]; then
    echo "deleting the lan gateway default route"
    ip route del 0.0.0.0/0 dev ens192
fi

#echo "Updating ntp date"
#ntpdate ntp.ubuntu.com

#echo "Updating the ntpd service config"
#update_ntp_conf

function update_dl_config() {

    # updating the downloadagent config file
    echo "Updating the downloadagent config file"

    if [[ -f "${DLAGENT_CONF_FILE}" ]]; then
        sed -i "s/^.*\"provider\"\:.*$/    \"provider\"\: \"${CLOUD_PROVIDER}\"\,/" "${DLAGENT_CONF_FILE}"
        sed -i "s/^.*\"flags\"\:.*$/    \"flags\"\: \"${SAAS_FLAG}\"\,/" "${DLAGENT_CONF_FILE}"
        echo "Config has been updated as follows:"
        cat "${DLAGENT_CONF_FILE}"
    else
        echo "${DLAGENT_CONF_FILE} is not present. Installation could be courrupted or incomplete."
        echo "Try remove and install the package."
    fi

}

update_dl_config

# enabling and starting the download agent service
echo "Enabling and starting the download agent service"
systemctl enable dwnldagent
systemctl start dwnldagent

echo "Updated the configurations..."
UDEOF

    if [[ -f "${UD_FILE}" ]]; then
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

    log_message "Task 2/3 :: Creating new iso image with user-data.txt content"

    TIMESTAMP=$(date +"%m%d%Y_%H%M%S")
    ISO_FILE="${TEMP_DIR}/cbuserdata_${TIMESTAMP}.iso"

    if [[ -f "${ISO_DIR}/user-data.txt" ]]; then
        result=$(genisoimage -o "${ISO_FILE}" -r "${ISO_DIR}/")
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
        log_message "Failed to find the conent to create user-data iso image"
        T_FAILURE=$((T_FAILURE + 1))
        T_SKIPPED=$((T_SKIPPED + 1))
    fi
}


function upload_iso() {

    DS_ISO_DIR="/CB-USERDATA-ISO"
    DS_ISO_FILE="${DS_ISO_DIR}/cbuserdata_${TIMESTAMP}.iso"
    log_message "Task 3/3 :: Uploading the userdata iso image into datastore"
    govc datastore.upload -ds "${DS_NAME}" "${ISO_FILE}" "${DS_ISO_FILE}"

    if [[ $? -eq 0 ]]; then
        log_message "ISO file uploaded into datastore /${DS_NAME}${DS_ISO_FILE}"
        T_SUCCESS=$((T_SUCCESS + 1))
    else
        log_message "Failed to upload the iso ${ISO_FILE} file into datastore ${DS_NAME}"
        T_FAILURE=$((T_FAILURE + 1))
    fi

}


function main_setup() {

    echo -e "#######################################################"
    echo -e "#####   CloudBrink's Connector-Agent Deployment   #####"
    echo -e "#######################################################"

    while getopts ":o:a:i:g:d:w:s:n:m:f:y:r:p:e:" options; do
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
            s) DS_NAME="$OPTARG"
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
    log_message "CLOUD_PROVIDER = ${CLOUD_PROVIDER} || SAAS_FLAG = ${SAAS_FLAG} || VMWARE_DATASTORE = ${DS_NAME}"

    gen_userdata
    create_iso
    if [[ -z "${DS_NAME}" ]]; then
            log_message "Task 3/3 :: Skipping uploading the userdata iso image into datastore"
            T_SKIPPED=$((T_SKIPPED + 1))
    else
            upload_iso
    fi

    task_summary
    log_message "Exiting Deployment script"

}

### main call ###
main_setup "$@"
