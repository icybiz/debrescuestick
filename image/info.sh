#!/bin/bash
# Read-only connection summary for the physical console and interactive SSH.
set -u

key_file=${DRS_KEY_FILE:-/root/.ssh/authorized_keys}
hostkey_dir=${DRS_HOSTKEY_DIR:-/etc/ssh}

active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

show_info() {
    local announced line address key state
    network_ready=false
    ssh_ready=false
    mdns_ready=false
    announced='debrstick.local'
    if active avahi-daemon.service; then
        line=$(busctl --system --timeout=1s call org.freedesktop.Avahi / \
            org.freedesktop.Avahi.Server GetHostNameFqdn 2>/dev/null) || line=''
        line=${line#s \"}
        line=${line%\"}
        case "$line" in
            ''|*[!a-zA-Z0-9.-]*) ;;
            *) announced=$line ;;
        esac
        state=$(busctl --system --timeout=1s call org.freedesktop.Avahi / \
            org.freedesktop.Avahi.Server GetState 2>/dev/null) || state=''
        if [ "$state" = 'i 2' ]; then
            mdns_ready=true
            printf 'Network name: %s (mDNS ready)\n' "$announced"
        else
            printf 'Network name: %s (mDNS is starting)\n' "$announced"
        fi
    else
        printf 'Network name: %s (mDNS is starting)\n' "$announced"
    fi

    printf '\nNetwork addresses:\n'
    ip -brief address show up 2>/dev/null || true
    addresses=$(ip -o -4 address show up scope global 2>/dev/null | awk '{print $4}')
    if [ -n "$addresses" ]; then
        network_ready=true
    else
        printf 'Waiting for a network address. Connect Ethernet to a DHCP network.\n'
    fi

    printf '\nSSH access: '
    if [ ! -s "$key_file" ]; then
        printf 'unavailable: the owner key has not been loaded.\n'
    elif active ssh.service; then
        ssh_ready=true
        printf 'ready (your matching private key is required).\n'
        if active avahi-daemon.service; then
            printf '  ssh root@%s\n' "$announced"
        fi
        for address in $addresses; do
            printf '  ssh root@%s\n' "${address%/*}"
        done
    else
        printf 'starting; password login is disabled.\n'
    fi

    printf '\nSSH host fingerprints (compare when connecting):\n'
    for key in "$hostkey_dir"/ssh_host_*_key.pub; do
        [ -f "$key" ] || continue
        ssh-keygen -l -E sha256 -f "$key" 2>/dev/null | awk '{print "  " $2 " " $NF}'
    done
    if [ -s "$key_file" ]; then
        printf '\nOwner key fingerprint:\n'
        ssh-keygen -l -E sha256 -f "$key_file" 2>/dev/null | awk '{print "  " $2 " " $NF}'
    fi
}

boot=false
if [ "${1:-}" = '--boot' ] && [ -t 0 ] && [ -t 1 ]; then
    boot=true
fi
trap 'exit 130' INT TERM
end=$((SECONDS + 30))
while :; do
    if $boot && [ "${TERM:-dumb}" != dumb ]; then
        printf '\033[H\033[2J'
    fi
    printf 'DebRescueStick - local rescue console\n'
    printf '===================================\n\n'
    show_info
    if ! $boot || { $network_ready && $ssh_ready && $mdns_ready; } || [ "$SECONDS" -ge "$end" ]; then
        printf '\nLocal rescue shell ready. Run debrstick-info to show this again.\n\n'
        break
    fi
    printf '\nStatus updates during startup. Press Enter for the rescue shell.\n'
    if read -r -t 1; then
        printf '\n'
        break
    fi
done
