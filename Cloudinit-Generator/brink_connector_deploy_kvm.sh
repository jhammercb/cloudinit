#!/bin/bash

# Input Variables
CB_OTP=""
ARM_MODE=1
INET_IPV4=""
INET_IPV4_GW=""
INET_IPV4_DNS=""
INET_IPV6=""
INET_IPV6_GW=""
INET_IPV6_DNS=""
CLOUD_PROVIDER=""
SAAS_FLAG=""
HOST_NAME=""
DEPLOY_VM=1
NET_INTERFACE=""
VIRSH_NET_NAME=""

# global/Default Variables
BASE_DIR="/deployment/kvm"
CONF_DIR="${BASE_DIR}/conf"
BUILD_DIR="${BASE_DIR}/build"
IMAGE_DIR="${BASE_DIR}/image"
RUN_DIR="${BASE_DIR}/run"
LOG_DIR="${BASE_DIR}/logs"
SCRIPT_LOG_FILE="${LOG_DIR}/kvm-deployment.log"

AGENT_VERSION="latest"
DEF_IPV4_DNS="8.8.8.8,1.1.1.1"
DEF_IPV6_DNS=""
DEF_PASSWD="cbrink4U"
DEF_CLOUDPROVIDER="PVT"
DEF_SAASFLAG="wren"
DEF_HOSTNAME="kvm-connector1"
HASHED_PASSWD=""
SSH_LISTEN_ADDRESS=""

# KVM DEF HW CONFIG
CPU="host"
VCPU=4
VMEM=8192
VDSIZE=50 # unit size in GB
VIRT_TYPE="kvm"
BOOT_OPTS="hd,menu=on"
OS_TYPE="linux"
OS_VARIANT="ubuntu20.04"
VM_GRPAHICS="vnc"
VM_NETWORK=""
VM_SERIALPORT="pty,target_port=0"
VM_CONSOLE="pty,target_type=serial"
VM_CHECK="all=off"

# Log level variables
LEVEL_INFO="[INFO]"
LEVEL_WARN="[WARN]"
LEVEL_ERROR="[ERROR]"

### functions ###
function help_message() {
    echo "usage: $0 -o OTP -a ARM_MODE -i INET_IPV4 [-g INET_IPV4_GW] [-n INET_IPV4_DNS] [-f INET_IPV6] [-y INET_IPV6_GW] [-r INET_IPV6_DNS] [-p PROVIDER] [-e SAAS_FLAG] [ -h HOST_NAME] [-v DEPLOY_VM] -b VIRSH_NET_NAME"
    echo "-o OTP string"
    echo "-a ARM Mode refers the number of network interfaces (1 or 2)"
    echo "-i Internet interface ip (x.x.x.x/x)"
    echo "-g Internet interface gateway (x.x.x.x)"
    echo "-n DNS IPs for Internet interface (x.x.x.x or x.x.x.x, x.x.x.x, ...)"
    echo "-f IPV6 Datacenter interface ip (xxxx:xxxx:xxxx:xxxx/x)"
    echo "-y IPV6 Datacenter gateway (xxxx:xxxx:xxxx:xxxx)"
    echo "-r IPV6 Datacenter DNS (xxxx:xxxx:xxxx:xxxx)"
    echo "-p Connector Deployment Environment (Private Cloud/Datacenter. Default value 'PVT')"
    echo "-e Cloudbrink SaaS Environment"
    echo "-h Connector VM Hostname"
    echo "-v Deploy Connector VM (Either 0 [no] or 1 [yes]. Default value: 1)"
    echo "-b Name of the existing Virtual Network in kvm (Can be obtained from command 'virsh net-list'. Not Optional)"
}

function exit_on_error() {
    help_message
    exit 1
}

function log_titles() {
    echo -e "$1" | tee -a "${SCRIPT_LOG_FILE}"
}

function log_message() {
    CB_LOG_LEVEL="${2:-$LEVEL_INFO}"
    echo -e "$(date +'%F %T') :: ${CB_LOG_LEVEL} :: $1" | tee -a "${SCRIPT_LOG_FILE}"
}

function make_all_dirs() {
    log_message "creating necessary directories for generating kvm seed image."
    mkdir -p "${BASE_DIR}"
    mkdir -p "${CONF_DIR}"
    mkdir -p "${BUILD_DIR}"
    mkdir -p "${LOG_DIR}"
}

function generate_passwd() {
    log_message "Generating hashed password for setting user's password in cloud-init config"
    HASHED_PASSWD=$(mkpasswd --method=SHA-512 "${DEF_PASSWD}")
}

function check_network_inputs() {

    if [[ -z "${INET_IPV4_DNS}" ]]; then
        INET_IPV4_DNS="${DEF_IPV4_DNS}"
        log_message "Setting default value for IPV4_DNS as ${INET_IPV4_DNS}"
    fi

    if [[ -n "${INET_IPV6}" ]]; then
        if [[ -z "${INET_IPV6_DNS}" ]]; then
            INET_IPV6_DNS="${DEF_IPV6_DNS}"
            log_message "Setting default value for IPV6_DNS as ${INET_IPV6_DNS}"
        fi
    fi
}

function check_dlconfig_inputs() {

    if [[ -z "${CLOUD_PROVIDER}" ]]; then
        CLOUD_PROVIDER="${DEF_CLOUDPROVIDER}"
        log_message "Setting default value for CLOUD_PROVIDER as ${CLOUD_PROVIDER}"
    fi

    if  [[ -z "${SAAS_FLAG}" ]]; then
        SAAS_FLAG="${DEF_SAASFLAG}"
        log_message "Setting default value for SAAS_FLAG as ${SAAS_FLAG}"
    fi
}

function update_network_conf() {

    log_message "Updating the netplan yaml template with actual values for configuring network"

    IP_ADDRESSES="__IP_ADDRESSES__"
    IPV4_GATEWAY="__IPV4_GATEWAY__"
    IPV6_GATEWAY="__IPV6_GATEWAY__"
    NAME_SERVERS="__NAME_SERVERS__"

    IP_ADDRESSES_REPL=""
    IPV4_GATEWAY_REPL=""
    IPV6_GATEWAY_REPL=""
    NAME_SERVERS_REPL=""

    NETPLAN_CONF_TEMPLATE="${CONF_DIR}/network.cfg.template"
    NETPLAN_CONF_FILE="${BUILD_DIR}/${HOST_NAME}/network.cfg"
    cp "${NETPLAN_CONF_TEMPLATE}" "${NETPLAN_CONF_FILE}"

    if [[ -f "${NETPLAN_CONF_FILE}" ]]; then
        log_message "Netplan yaml template ${NETPLAN_CONF_TEMPLATE} copied as ${NETPLAN_CONF_FILE} to update values."
    else
        log_message "Failed to copy the template ${NETPLAN_CONF_TEMPLATE} as ${NETPLAN_CONF_FILE} to update the value." "${LOG_ERROR}"
        exit 1;
    fi

    # set default values for network config attributes if inputs are empty
    check_network_inputs

    if [[ -n "${INET_IPV4}" ]]; then
        IP_ADDRESSES_REPL="${INET_IPV4}"
    fi

    if [[ -n "${INET_IPV6}" ]]; then
        IP_ADDRESSES_REPL="${IP_ADDRESSES_REPL}, ${INET_IPV6}"
    fi

    if [[ -n "${INET_IPV4_GW}" ]]; then
        IPV4_GATEWAY_REPL="${INET_IPV4_GW}"
    fi

    if [[ -n "${INET_IPV6_GW}" ]]; then
        IPV6_GATEWAY_REPL="${INET_IPV6_GW}"
    fi

    if [[ -n "${INET_IPV4_DNS}" ]]; then
        NAME_SERVERS_REPL="${INET_IPV4_DNS}"
    fi

    if [[ -n "${INET_IPV6_DNS}" ]]; then
        NAME_SERVERS_REPL="${NAME_SERVERS_REPL}, ${INET_IPV6_DNS}"
    fi

    # Update the placeholders using SED with replacement values in the network conf file
    # Used '#' as the separator instead of '/' for all sed operations to avoid parsing error
    RC_STATUS=0

    # ipv4 & ipv6(if provided) will be updated
    sed -i "s#${IP_ADDRESSES}#${IP_ADDRESSES_REPL}#" "${NETPLAN_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 1 ))
    fi
    # ipv4 gateway will be updated
    sed -i "s#${IPV4_GATEWAY}#${IPV4_GATEWAY_REPL}#" "${NETPLAN_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 2 ))
    fi
    # ipv6 (if provided) will ve updated
    ##sed -i "s/${IPV6_GATEWAY}/${IPV6_GATEWAY_REPL}/" "${NETPLAN_CONF_FILE}"
    # ipv4 & ipv6(if provided) dns will be updated
    sed -i "s#${NAME_SERVERS}#${NAME_SERVERS_REPL}#" "${NETPLAN_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 4 ))
    fi

    if [[ ${RC_STATUS} -eq 7 ]]; then
        log_message "All network parameters are successfully updated in the netplan conf template file:"
    else
        log_message "Failed to update network parameters in the netplan conf template file:"
        cat "${NETPLAN_CONF_FILE}"
        exit 2;
    fi

    cat "${NETPLAN_CONF_FILE}"
}

function update_cloudinit_conf() {

    log_message "updating cloud-init config to generate seed image"

    HOSTNAME_PHTEXT="__HOST_NAME__"
    HASHED_PASSWD_PHTEXT="__HASHED_PASSWD__"
    OTP_VALUE_PHTEXT="__OTP_VALUE__"
    NETCONF_JSON_PHTEXT="__NETCONF_JSON__"
    RUNCMD1_PHTEXT="__RUN_CMD1__"
    RUNCMD2_PHTEXT="__RUN_CMD2__"
    RUNCMD3_PHTEXT="__RUN_CMD3__"

    HOSTNAME_REPL=""
    HASHED_PASSWD_REPL=""
    OTP_VALUE_REPL=""
    NETCONF_JSON_REPL="{}"
    RUNCMD1_REPL=""
    RUNCMD2_REPL=""
    RUNCMD3_REPL=""

    SSHD_CONF_FILE="/etc/ssh/sshd_config"
    DLAGENT_CONF_FILE="/opt/dwnldagent/config"
    DLAGENT_CONF_UPDATED_FILE="/opt/dwnldagent/updated_config"
    CLOUDINIT_CONF_TEMPLATE="${CONF_DIR}/cloud_init.cfg.template"
    CLOUDINIT_CONF_FILE="${BUILD_DIR}/${HOST_NAME}/cloud_init.cfg"
    cp "${CLOUDINIT_CONF_TEMPLATE}" "${CLOUDINIT_CONF_FILE}"

    if [[ -f "${CLOUDINIT_CONF_FILE}" ]]; then
        log_message "cloud-init template ${CLOUDINIT_CONF_TEMPLATE} copied as ${CLOUDINIT_CONF_FILE} to update values."
    else
        log_message "Failed to copy the cloud-init template ${CLOUDINIT_CONF_TEMPLATE} as ${CLOUDINIT_CONF_FILE} to update the value." "${LOG_ERROR}"
        exit 3;
    fi

    # set hostname in the cloudconfg
    HOSTNAME_REPL="${HOST_NAME}"

    # generate salted password(default) for ssh user
    generate_passwd
    HASHED_PASSWD_REPL="${HASHED_PASSWD}"

    if [[ -n "${CB_OTP}" ]]; then
        OTP_VALUE_REPL="${CB_OTP}"
    fi

    if [[ ${ARM_MODE} -eq 1  ]]; then
        SSH_LISTEN_ADDRESS="${INET_IPV4%%/*}"
        NETCONF_JSON_REPL='{"config": [{"interface": {"name": "enp1s0", "ip": "'${INET_IPV4}'", "gateway": "'${INET_IPV4_GW}'", "dns": "'${INET_IPV4_DNS}'", "ipv6": "'${INET_IPV6}'", "ipv6_gw": "'${INET_IPV6_GW}'", "ipv6_dns": "'${INET_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "KVM"}'
    elif [[ ${ARM_MODE} -eq 2 ]]; then
        SSH_LISTEN_ADDRESS="${PVT_IPV4%%/*}"
        NETCONF_JSON_REPL='{"config": [{"interface": {"name": "enp1s0", "type": "wan", "ip": "'${INET_IPV4}'", "gateway": "'${INET_IPV4_GW}'", "dns": "'${INET_IPV4_DNS}'"}}, {"interface": {"name": "enp2s0", "type": "lan", "ip": "'${PVT_IPV4}'", "gateway": "'${PVT_IPV4_GW}'", "dns": "'${PVT_IPV4_DNS}'", "ipv6": "'${INET_IPV6}'", "ipv6_gw": "'${INET_IPV6_GW}'", "ipv6_dns": "'${INET_IPV6_DNS}'"}}], "arm_mode": '${ARM_MODE}', "provider": "KVM"}'
    else
        NETCONF_JSON_REPL='{"config": [], "arm_mode": '${ARM_MODE}', "provider": "KVM"}'
    fi

    # update the dwmldagent config to default values if its not provided
    check_dlconfig_inputs
    RUNCMD1_REPL="\"jq '(.flags=\\\\\"${SAAS_FLAG}\\\\\") | (.provider=\\\\\"${CLOUD_PROVIDER}\\\\\")' ${DLAGENT_CONF_FILE} > ${DLAGENT_CONF_UPDATED_FILE}\""  ### working ###
    RUNCMD2_REPL="\"cp ${DLAGENT_CONF_UPDATED_FILE} ${DLAGENT_CONF_FILE}\""
    RUNCMD3_REPL="echo \"ListenAddress ${SSH_LISTEN_ADDRESS}\" >> ${SSHD_CONF_FILE}"

    # Update the placeholders using SED with replacement values in the cloud-init conf file
    RC_STATUS=0

    # update the hostname
    sed -i "s#${HOSTNAME_PHTEXT}#${HOSTNAME_REPL}#" "${CLOUDINIT_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 1 ))
    fi

    # replace the generated hashed password
    sed -i "s#${HASHED_PASSWD_PHTEXT}#${HASHED_PASSWD_REPL}#" "${CLOUDINIT_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 2 ))
    fi

    #
    sed -i "s#${OTP_VALUE_PHTEXT}#${OTP_VALUE_REPL}#" "${CLOUDINIT_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 3 ))
    fi

    sed -i "s#${NETCONF_JSON_PHTEXT}#${NETCONF_JSON_REPL}#" "${CLOUDINIT_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 4 ))
    fi

    # updating the downloadagent config file
    echo "Updating the downloadagent config file"
    echo "${RUNCMD1_PHTEXT} || ${RUNCMD1_REPL}"
    sed -i "s#${RUNCMD1_PHTEXT}#${RUNCMD1_REPL}#" "${CLOUDINIT_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 5 ))
    fi

    sed -i "s#${RUNCMD2_PHTEXT}#${RUNCMD2_REPL}#" "${CLOUDINIT_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 6 ))
    fi

    sed -i "s#${RUNCMD3_PHTEXT}#${RUNCMD3_REPL}#" "${CLOUDINIT_CONF_FILE}"
    if [[ $? -eq 0 ]]; then
        RC_STATUS=$(( RC_STATUS + 7 ))
    fi

    if [[ ${RC_STATUS} -eq 28 ]]; then
        log_message "All placeholders are successfully updated in the cloud-init conf template file:"
    else
        log_message "Failed to update placeholders with actual values in the cloud-init conf template file:"
        cat "${CLOUDINIT_CONF_FILE}"
        exit 4;
    fi

    cat "${CLOUDINIT_CONF_FILE}"
}

function create_seed_image() {

    #TIMESTAMP=$(date +"%m%d%Y_%H%M%S")

    NETPLAN_CONF_FILE="${BUILD_DIR}/${HOST_NAME}/network.cfg"
    CLOUDINIT_CONF_FILE="${BUILD_DIR}/${HOST_NAME}/cloud_init.cfg"
    SEED_IMG_FILE="${BUILD_DIR}/${HOST_NAME}/${HOST_NAME}-seed.img"
    #SEED_IMG_FILE="${BUILD_DIR}/cbuser-${TIMESTAMP}-seed.img"

    log_message " ${NETPLAN_CONF_FILE} || ${CLOUDINIT_CONF_FILE} || ${SEED_IMG_FILE} "
    if [[ ! -f "${NETPLAN_CONF_FILE}" || ! -f "${CLOUDINIT_CONF_FILE}" ]]; then
        log_message "Either network config file or cloud-init config file has not been copied/updated. Exiting..." "${LEVEL_ERROR}"
        exit 5;
    else
        log_message "cloud-localds -v --network-config=${NETPLAN_CONF_FILE} ${SEED_IMG_FILE} ${CLOUDINIT_CONF_FILE}"
        if cloud-localds -v --network-config="${NETPLAN_CONF_FILE}" "${SEED_IMG_FILE}" "${CLOUDINIT_CONF_FILE}"; then
            if [[ -f "${SEED_IMG_FILE}" ]]; then
                log_message "Seed image for connagent deployment in kvm has successfully generated."
            else
                log_message "Generate seed image command executed bt file is not found..." "${LEVEL_ERROR}"
            fi
        else
            log_message "Failed to generate seed image for connagent deployment in kvm." "${LEVEL_ERROR}"
        fi
    fi
}

function identify_net_interface() {

    BRIDGES=( $(ip link show type bridge | grep "mtu" | cut -d ':' -f2 | tr -d ' ') )
    BR_SLAVES=( $(ip link show type bridge_slave | grep "mtu" | cut -d ':' -f2 | tr -d ' ') )

    TYPE_IDENTIFIED=0
    for Bridge in "${BRIDGES[@]}"; do
        if [[ "${NET_INTERFACE}" == "${Bridge}" ]]; then
            IPS=( $(ip addr show "${NET_INTERFACE}" | grep inet | awk '{print $2}' ) )
            log_message "Net Interface ${NET_INTERFACE} type Bridge exists with ip addresses: ${IPS[*]} mapped with KVM Virtual Network ${VIRSH_NET_NAME}"
            TYPE_IDENTIFIED=1
            #VM_NETWORK="bridge=${NET_INTERFACE}"
	    VM_NETWORK="network=${VIRSH_NET_NAME}"
            break;
        fi
    done;

    if [[ ${TYPE_IDENTIFIED} -eq 0 ]]; then
        for BrSlave in "${BR_SLAVES[@]}"; do
            if [[ "${NET_INTERFACE}" == "${BrSlave}" ]]; then
                IPS=( $(ip addr show "${NET_INTERFACE}" | grep inet | awk '{print $2}' ) )
                log_message "Net Interface ${NET_INTERFACE} type Bridge_Slave exists with ip addresses: ${IPS[*]} mapped with KVM Virtual Network ${VIRSH_NET_NAME}"
                TYPE_IDENTIFIED=1
                VM_NETWORK="network=${VIRSH_NET_NAME}"
                break;
            fi
        done
    fi

    if [[ ${TYPE_IDENTIFIED} -eq 0 ]]; then
        log_message "Net Interface ${NET_INTERFACE} is not created/mapped with ${VIRSH_NET_NAME}. Cannot proceed the deployment further. Exiting with Error code: 1";
        exit 1;
    fi
}

function identify_virtual_network() {
    log_message "Verifying the presence of virtual network \"${VIRSH_NET_NAME}\" in the kvm"
	
	VNET_INFO_OUT_ACTIVE=$(virsh net-info "${VIRSH_NET_NAME}" | grep "Active:")
	RET_CODE=$?
	if [[ ${RET_CODE} -eq 0 && -n "${VNET_INFO_OUT_ACTIVE}" ]]; then
	    VNET_ACTIVE_STATE=$(echo "${VNET_INFO_OUT_ACTIVE}" | cut -d':' -f2 | tr -d ' ')
	    if [[ "${VNET_ACTIVE_STATE}" == "yes" ]]; then
		    VNET_INFO_OUT_BRIDGE=$(virsh net-info "${VIRSH_NET_NAME}" | grep "Bridge:")
			VNET_BRIDGE_NAME=$(echo "${VNET_INFO_OUT_BRIDGE}" | cut -d':' -f2 | tr -d ' ')
			NET_INTERFACE="${VNET_BRIDGE_NAME}"
			
			# calling this function to identify the binded net interface with virtual network 
			identify_net_interface
			log_message "Virtual Network ${VIRSH_NET_NAME} binded with Network Interface ${VNET_BRIDGE_NAME} in the host."
		else
		    log_message "Virtual Network ${VIRSH_NET_NAME} is in ${VNET_ACTIVE_STATE} state rather than 'active' state. Could not proceed the deployment in this network state" "${LEVEL_ERROR}"
			exit 1
		fi
	else
	    log_message "Virtual Network with the name ${VIRSH_NET_NAME} does not exists in the host. Please ensure the given network name is present in the virtual network list using the command \"virsh net-list --all\"." "${LEVEL_ERROR}"
	    exit 1
	fi
}


function destroy_vm() {

    log_message "Cleaningup the VM ${HOST_NAME} if exists" "${LEVEL_WARN}"
    VmState=$(virsh list  | grep "${HOST_NAME}" | awk '{print $3}')
    if [[ -z "${VmState}" ]]; then
        VmState="Unknown"
    fi

    ErrorStr="error: failed to get domain '${HOST_NAME}'"

    # check and delete if the vm is not destroyed/undefined
    DestOut=$(virsh destroy "${HOST_NAME}")
    DestRC=$?
    sleep 1;
    UndefOut=$(virsh undefine "${HOST_NAME}")
    UndefRC=$?
    sleep 1;
    NewVmState=$(virsh list  | grep "${HOST_NAME}" | awk '{print $3}')

    log_message "Ignore the error message from kvm delete command. It'll throw if the object doesn't exists..."

    if [[ -z "${NewVmState}" && ${DestRC} -eq 0 && ${UndefRC} -eq 0 ]]; then
        log_message "VM ${HOST_NAME} in ${VmState} state has been successfully deleted"
    else
        log_message "VM ${HOST_NAME} has already destoryed/undefined"
    fi
}

function deploy_connector_vm() {

    log_message "Creating Connector-Agent VM..."
    METADATA_DIR="${BUILD_DIR}/${HOST_NAME}"
    IMG_DIR=${IMAGE_DIR}/
    VM_DIR="${RUN_DIR}/${HOST_NAME}"

    IMAGE_NAME="connector-${AGENT_VERSION}.qcow2"
    SEED_DISK="${METADATA_DIR}/${HOST_NAME}-seed.img"
    DATA_DISK="${VM_DIR}/${HOST_NAME}.qcow2"

    # check and cleanup the vm from kvm and delete the vm dir if exists
    destroy_vm
    rm -rf ${VM_DIR}

    # create the vm dir and copy the connector image as data disk
    mkdir -p ${VM_DIR}

    if [[ -f "${IMG_DIR}/${IMAGE_NAME}" ]]; then
        log_message "copying ${IMAGE_DIR}/${IMAGE_NAME} to ${DATA_DISK}"
        cp "${IMG_DIR}/${IMAGE_NAME}" "${DATA_DISK}"

        if [[ -f "${DATA_DISK}" ]]; then
            log_message "Data disk copied to destination successfully."
        else
            log_message "Failed to copy the data disk to destination. Exiting with Code: 1"
            exit 1;
        fi
    else
        log_message "Copying Data disk ${IMG_DIR}/${IMAGE_NAME} failed due the file went missing."
        exit 1;
    fi

	# identify the virtual network and set it in the create-vm command's option #
	identify_virtual_network

    if [[ -z "${VM_NETWORK}" ]]; then
        log_message "Network interface for kvm config has not set. Couldn't continue the vm deployment. Exit with Error code: 1"
        exit 1;
    fi

    # creating connector vm using virt-install command with default kvm hw configs
    nohup virt-install \
        --name "${HOST_NAME}" \
        --cpu "${CPU}" \
        --vcpus "${VCPU}" \
        --ram "${VMEM}" \
        --virt-type "${VIRT_TYPE}" \
        --boot "${BOOT_OPTS}" \
        --os-type "${OS_TYPE}" \
        --os-variant "${OS_VARIANT}" \
        --disk path="${SEED_DISK},device=cdrom" \
        --disk path="${DATA_DISK},device=disk,size=${VDSIZE}" \
        --network "${VM_NETWORK}" \
        --graphics "${VM_GRPAHICS}" \
        --check "${VM_CHECK}" \
        --autostart \
        --import \
        --noautoconsole &

        #--serial ${VM_SERIALPORT} \
        #--console ${VM_CONSOLE} \


    #echo "Create VM command ${CREATE_VM_CMD}"
    #"${CREATE_VM_CMD}"
    RetCode=$?

    # sleep for a while to system gets up & running
    log_message "Checking the VM status. Kindly wait for 1min..."
    sleep 60;
    VirshListOut=( $(virsh list | grep "${HOST_NAME}") )

    if [[ ${RetCode} -eq 0 && ${#VirshListOut[*]} -gt 1 ]]; then
        if [[ "${VirshListOut[2]}" == "running" ]]; then
            log_message "The vm ${HOST_NAME} is in ${VirshListOut[2]}. use SSH or Console to accesss the vm."
            log_message "ssh cbrink@${INET_IPV4%%/*} or virsh console ${VirshListOut[1]}"
        else
            log_message "The vm ${HOST_NAME} is in ${VirshListOut[2]}. Use Console to check the issue in the vm."
        fi
    else
        log_message "Failed to create the connector vm ${HOST_NAME}. The Create-VM(virt-install) command returned Exit code : ${RetCode}" "${LEVEL_ERROR}"
        log_message "${VirshListOut[*]}"
        exit 1;
    fi
}

function get_options_cli() {
    log_message "Options are getting from cli arguments"

    while getopts ":o:a:i:g:n:f:y:r:p:e:h:v:b:" options; do
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
            i) INET_IPV4="$OPTARG"
                if [[ -z "${INET_IPV4}" ]]; then
                    log_message "External IP (Internet) should not be empty"
                    exit_on_error
                fi
                ;;
            g) INET_IPV4_GW="$OPTARG"
                ;;
            n) INET_IPV4_DNS="$OPTARG"
                ;;
            f) INET_IPV6="$OPTARG"
                ;;
            y) INET_IPV6_GW="$OPTARG"
                ;;
            r) INET_IPV6_DNS="$OPTARG"
                ;;
            p) CLOUD_PROVIDER="$OPTARG"
                ;;
            e) SAAS_FLAG="$OPTARG"
                ;;
            h) HOST_NAME="$OPTARG"
                ;;
            v) DEPLOY_VM="$OPTARG"
                ;;
            b) VIRSH_NET_NAME="$OPTARG"
                if [[ -z "${VIRSH_NET_NAME}" ]]; then
                    log_message "Virtual Network name should not be empty"
                    exit_on_error
                fi
                ;;
            :) echo "Error: -${OPTARG} requires an argument."
               exit_on_error
                ;;
            *) exit_on_error
                ;;
        esac
    done
}

function main_setup() {
    log_titles "##############################################################"
    log_titles "#####   CloudBrink's Connector-Agent Deployment for KVM  #####"
    log_titles "##############################################################"

    # create all required directories if not created
    make_all_dirs

    # Get the inputs via cli arguments
    get_options_cli "$@"
    log_message "|| CB_OTP = ${CB_OTP} || ARM_MODE = ${ARM_MODE} || PROVIDER = ${PROVIDER} || SAAS_FLAG = ${SAAS_FLAG} || HOST_NAME = ${HOST_NAME} || VIRSH_NET_NAME = ${VIRSH_NET_NAME}"
    log_message "|| INET_IP = ${INET_IPV4} || INET_IPV4_GW = ${INET_IPV4_GW} || INET_IPV4_DNS = ${INET_IPV4_DNS} ||"
    log_message "|| INET_IPV6 = ${INET_IPV6} || INET_IPV6_GW = ${INET_IPV6_GW} || INET_IPV6_DNS = ${INET_IPV6_DNS} ||"

    # set hostname to default if not given by user
    if [[ -z "${HOST_NAME}" ]]; then
        HOST_NAME="${DEF_HOSTNAME}"
        log_message "Setting default value for HOSTNAME as ${HOST_NAME}"
    fi

    # delete host dir and recreate it
    rm -rf "${BUILD_DIR:?}/${HOST_NAME}"
    mkdir -p "${BUILD_DIR}/${HOST_NAME}"


    # update the netplan conf template
    update_network_conf

    # update the cloud-init conf template
    update_cloudinit_conf

    # generate the seed image
    create_seed_image
    log_message "Seed image for kvm connector has been successfully generated in the path ${BUILD_DIR}/${HOST_NAME}"

    if [[ ${DEPLOY_VM} -eq 1 ]]; then
        deploy_connector_vm
    fi
}

main_setup "$@"

