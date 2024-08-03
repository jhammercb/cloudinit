from flask import Flask, render_template, request, send_file, jsonify
import subprocess
import os
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    hypervisor = request.form['HYPERVISOR']
    CB_OTP = request.form['CB_OTP']
    ARM_MODE = request.form['ARM_MODE']
    INET_IP = request.form['INET_IP']
    INET_GW = request.form['INET_GW']
    DC_IP = request.form.get('DC_IP', '')
    DC_GW = request.form.get('DC_GW', '')
    NAME_SERVERS_INET = request.form.get('NAME_SERVERS_INET', '')
    NAME_SERVERS_DC = request.form.get('NAME_SERVERS_DC', '')
    DC_IPV6 = request.form.get('DC_IPV6', '')
    DC_IPV6_GW = request.form.get('DC_IPV6_GW', '')
    DC_IPV6_DNS = request.form.get('DC_IPV6_DNS', '')
    SAAS_FLAG = request.form.get('SAAS_FLAG', 'wren')

    if hypervisor == 'cloud':
        # Generate cloud-config content
        cloud_config = f"""#cloud-config
runcmd:
- [bash, /home/cb/flask-apps/cloudinit-generator/brink_connector_deploy_cloud.sh, -o, "{CB_OTP}", -a, "{ARM_MODE}"]"""
        return jsonify({"cloud_config": cloud_config})

    # Determine the script to use based on the hypervisor selection
    if hypervisor == 'hyperv':
        script = '/home/cb/flask-apps/cloudinit-generator/brink_connector_deploy_hyperv.sh'
    elif hypervisor == 'prox':
        script = '/home/cb/flask-apps/cloudinit-generator/brink_connector_deploy_proxmox.sh'
    else:
        script = '/home/cb/flask-apps/cloudinit-generator/brink_connector_deploy_vmware.sh'

    # Get sudo password from environment variable
    sudo_password = os.environ.get('SUDO_PASSWORD')
    if sudo_password is None:
        return "Error: SUDO_PASSWORD environment variable is not set"

    sudo_password_bytes = sudo_password.encode() + b'\n'

    # Prepare the command to run the shell script with sudo
    command = [
        'sudo', '-S', 'bash', script,
        '-o', CB_OTP,
        '-a', ARM_MODE,
        '-i', INET_IP,
        '-g', INET_GW
    ]

    if DC_IP:
        command.extend(['-d', DC_IP])
    if DC_GW:
        command.extend(['-w', DC_GW])
    if NAME_SERVERS_INET:
        command.extend(['-n', NAME_SERVERS_INET])
    if NAME_SERVERS_DC:
        command.extend(['-m', NAME_SERVERS_DC])
    if DC_IPV6:
        command.extend(['-f', DC_IPV6])
    if DC_IPV6_GW:
        command.extend(['-y', DC_IPV6_GW])
    if DC_IPV6_DNS:
        command.extend(['-r', DC_IPV6_DNS])
    command.extend(['-e', SAAS_FLAG])

    # Run the command and capture the output
    result = subprocess.run(command, input=sudo_password_bytes, capture_output=True)
    output = result.stdout.decode() + result.stderr.decode()

    # Print the captured output for debugging
    print("Script output:")
    print(output)

    # Save the captured output to a file for further inspection
    with open('/tmp/flask_app_output.log', 'w') as log_file:
        log_file.write(output)

    # Extract the ISO file path from the output using regex
    match = re.search(r'ISO image (\/tmp\/CB-SETUP\/cbuserdata_\d{8}_\d{6}\.iso) has been created', output)
    if match:
        iso_file = match.group(1)
        if os.path.exists(iso_file):
            # Send the ISO file to the user
            response = send_file(iso_file, as_attachment=True)

            # Clean up the /tmp/CB-SETUP/ca-iso/ directory using sudo
            ca_iso_dir = '/tmp/CB-SETUP/ca-iso/'
            if os.path.exists(ca_iso_dir):
                cleanup_command = ['sudo', '-S', 'rm', '-rf', ca_iso_dir + '*']
                subprocess.run(cleanup_command, input=sudo_password_bytes)

            return response
        else:
            return "Error: File not found"
    else:
        return f"Error: Unable to determine the generated file path. Output was: {output}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)