#!/bin/sh
set -eu

# virt-customize creates this marker only inside the target image.
if [ "$(cat /etc/debrescuestick-build-marker 2>/dev/null || true)" != 'guestfs-image-v1' ] ||
   ! systemd-detect-virt --chroot >/dev/null 2>&1; then
    echo 'Image configuration may run only inside its isolated guestfs target.' >&2
    exit 64
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y --with-new-pkgs upgrade
set --
while IFS= read -r drs_package; do
    set -- "$@" "$drs_package"
done </usr/local/share/debrescuestick/packages.txt
apt-get -y --no-install-recommends install "$@"
apt-get clean

mkdir -p /etc/systemd/network /etc/ssh/sshd_config.d /root/.ssh
cat >/etc/systemd/network/05-debrescuestick.network <<'EOF'
[Match]
Type=ether

[Network]
DHCP=yes
IPv6AcceptRA=yes
EOF
cat >/etc/ssh/sshd_config.d/00-debrescuestick.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding yes
EOF

# No implicit operator access is inherited from the machine that builds this image.
: >/root/.ssh/authorized_keys
chmod 0700 /root/.ssh
chmod 0600 /root/.ssh/authorized_keys
if [ -d /home/debian/.ssh ]; then
    : >/home/debian/.ssh/authorized_keys
fi
rm -f /etc/ssh/ssh_host_*
: >/etc/machine-id
if [ -f /var/lib/dbus/machine-id ] && [ ! -L /var/lib/dbus/machine-id ]; then
    : >/var/lib/dbus/machine-id
fi
passwd -l root
touch /etc/cloud/cloud-init.disabled

cat >/etc/systemd/system/debrescuestick-hostkeys.service <<'EOF'
[Unit]
Description=Create this rescue stick's SSH host identity on first boot
After=systemd-remount-fs.service
Before=ssh.service

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /etc/systemd/system/getty@tty1.service.d
cat >/etc/systemd/system/getty@tty1.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
EOF
install -m 0755 /usr/local/share/debrescuestick/info.sh /usr/local/sbin/debrstick-info
install -m 0644 /usr/local/share/debrescuestick/mdns.conf /etc/avahi/avahi-daemon.conf
mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/debrescuestick-mdns.conf <<'EOF'
[Resolve]
MulticastDNS=no
EOF
cat >/etc/profile.d/debrescuestick.sh <<'EOF'
if [ "$(id -u)" = 0 ] && [ -t 1 ]; then
    case "$(tty 2>/dev/null)" in
        /dev/tty1) /usr/local/sbin/debrstick-info --boot || true ;;
        *) /usr/local/sbin/debrstick-info || true ;;
    esac
fi
EOF
cat >/etc/issue <<'EOF'
DebRescueStick - Debian-based USB rescue environment
Local rescue console available. SSH accepts the owner's key only.
Network name: debrstick.local (IP addresses are shown after startup).

EOF

systemctl enable systemd-networkd.service systemd-resolved.service ssh.service
systemctl enable debrescuestick-hostkeys.service getty@tty1.service avahi-daemon.service
ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# Retain storage/USB drivers even though configuration happens in a VM appliance.
cat >/etc/initramfs-tools/conf.d/debrescuestick <<'EOF'
MODULES=most
EOF
update-initramfs -u -k all
update-grub
dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' \
    >/usr/local/share/debrescuestick/installed-packages.txt
rm -f /etc/debrescuestick-build-marker
