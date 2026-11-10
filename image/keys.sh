#!/bin/sh
# Read data only from the configuration partition of this boot disk.
set -efu
umask 077
mkdir -p /root/.ssh /run/debrescuestick
chmod 0700 /root/.ssh /run/debrescuestick
# A missing or invalid partition must never leave a previous owner's access.
: >/root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys
rootdev=$(findmnt -n -o SOURCE /)
rootdev=$(readlink -f "$rootdev")
test -b "$rootdev"
parent=$(lsblk -dn -o PKNAME "$rootdev")
case "$parent" in ''|*[!a-zA-Z0-9_-]*) exit 65;; esac
test -b "/dev/$parent"
config=$(lsblk -rno PATH,PARTLABEL "/dev/$parent" | awk '$2=="DRSKEYS" {print $1}')
test -b "$config"
mount -t vfat -o ro,nosuid,nodev,noexec,umask=0077 "$config" /run/debrescuestick
trap 'umount /run/debrescuestick' EXIT
key=/run/debrescuestick/OWNER.PUB
test -f "$key"
test "$(wc -c <"$key")" -le 16384
test "$(wc -l <"$key")" -eq 1
set -- $(cat "$key")
test "$#" -eq 2
case "$1" in ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;; *) exit 65;; esac
ssh-keygen -l -E sha256 -f "$key" >/dev/null
install -m 0600 "$key" /root/.ssh/authorized_keys
