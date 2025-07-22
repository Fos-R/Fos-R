# Dependencies

    vagrant plugin install winrm winrm-elevated winrm-fs
    ansible-galaxy collection install community.windows
    ansible-galaxy collection install ansible.windows
    ansible-galaxy collection install chocolatey.chocolatey

# Start the dev environment

    vagrant up

On each machine, run as super-user:

    fosr inject -p dev/profile -t
