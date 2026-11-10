"""Check mDNS from a separate network stack inside the disposable QA guest.

The probe never creates interfaces or namespaces on the production host. Its
peer exists only inside the guest's snapshot and also checks the SSH banner.
"""
import inspect
import shlex
import socket
import struct

HOST_NAME = 'debrstick.local'


def request_packet(hostname):
    """Build an IPv4 mDNS question requesting a unicast response."""
    labels = hostname.rstrip('.').split('.')
    if any(not part or len(part.encode('ascii')) > 63 for part in labels):
        raise ValueError('Invalid DNS name')
    question = b''.join(bytes([len(part)]) + part.encode('ascii') for part in labels)
    if len(question) + 1 > 255:
        raise ValueError('DNS name exceeds wire limit')
    return struct.pack('!6H', 0, 0, 1, 0, 0, 0) + question + b'\0' + struct.pack('!HH', 1, 0x8001)


def read_name(packet, offset):
    """Decode DNS labels and compression pointers without loops or overreads."""
    labels = []
    seen = set()
    end = None
    length = 0
    while True:
        if offset >= len(packet) or offset in seen:
            raise ValueError('Truncated or cyclic DNS name')
        seen.add(offset)
        size = packet[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError('Truncated DNS pointer')
            if end is None:
                end = offset + 2
            offset = ((size & 0x3f) << 8) | packet[offset + 1]
            continue
        if size & 0xc0:
            raise ValueError('Reserved DNS label encoding')
        offset += 1
        if not size:
            return '.'.join(labels).lower(), end if end is not None else offset
        if offset + size > len(packet):
            raise ValueError('Truncated DNS label')
        length += size + 1
        if length > 254:
            raise ValueError('DNS name exceeds wire limit')
        labels.append(packet[offset:offset + size].decode('ascii'))
        offset += size


def addresses(packet, hostname):
    """Return only live IN/A records for exactly the requested host."""
    if len(packet) < 12:
        raise ValueError('Truncated DNS header')
    _, flags, questions, answers, authority, additional = struct.unpack_from('!6H', packet)
    if not flags & 0x8000 or flags & 0x000f:
        raise ValueError('A successful DNS response is required')
    if questions + answers + authority + additional > 512:
        raise ValueError('Excessive DNS record count')
    offset = 12
    for _ in range(questions):
        _, offset = read_name(packet, offset)
        offset += 4
        if offset > len(packet):
            raise ValueError('Truncated DNS question')
    found = []
    for _ in range(answers + authority + additional):
        name, offset = read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError('Truncated DNS record')
        kind, family, ttl, size = struct.unpack_from('!HHIH', packet, offset)
        offset += 10
        if offset + size > len(packet):
            raise ValueError('Truncated DNS data')
        if name == hostname.rstrip('.').lower() and kind == 1 and family & 0x7fff == 1 and ttl and size == 4:
            found.append(socket.inet_ntoa(packet[offset:offset + size]))
        offset += size
    return found


def client_source():
    """Use the exact unit-tested parser in the guest, without installing files."""
    parts = ['import json,socket,struct,time', 'HOST_NAME=' + repr(HOST_NAME)]
    parts.extend(inspect.getsource(fn) for fn in (request_packet, read_name, addresses))
    parts.append('''
peer = '192.0.2.2'
server = '192.0.2.1'
query = request_packet(HOST_NAME)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as client:
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.bind(('', 5353))
    client.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                      socket.inet_aton('224.0.0.251') + socket.inet_aton(peer))
    client.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(peer))
    client.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    client.settimeout(1)
    end = time.monotonic() + 12
    found = False
    while time.monotonic() < end:
        client.sendto(query, ('224.0.0.251', 5353))
        receive_until = min(end, time.monotonic() + 1)
        while time.monotonic() < receive_until:
            client.settimeout(max(.001, receive_until - time.monotonic()))
            try:
                packet, origin = client.recvfrom(65535)
            except socket.timeout:
                break
            if origin[0] != server:
                continue
            try:
                answer = addresses(packet, HOST_NAME)
            except (ValueError, UnicodeError):
                continue
            if server in answer:
                found = True
                break
        if found:
            break
    if not found:
        raise RuntimeError('No mDNS A answer from the rescue system')
with socket.create_connection((server, 22), timeout=3) as connection:
    banner = connection.recv(256)
if not banner.startswith(b'SSH-2.0-'):
    raise RuntimeError('Resolved mDNS address did not provide SSH')
print(json.dumps({'success': True, 'hostname': HOST_NAME, 'address': server,
                  'independent_network_stack': True, 'ssh_banner': True}))
''')
    return '\n'.join(parts)


def probe_script():
    """Create a temporary peer only inside the dedicated guest."""
    client = shlex.join(['python3', '-c', client_source()])
    return '''
set -eu
printf 'DRS_HOSTNAME\n'
test "$(hostname)" = debrstick
hostname
timeout 20 sh -c 'until systemctl is-active --quiet avahi-daemon.service; do sleep 1; done'
timeout 20 sh -c 'until getent ahostsv4 debrstick.local; do sleep 1; done'
printf 'DRS_MDNS_PEER\n'
test ! -e /run/netns/drs-mdns-peer
if ip link show dev drs-mdns-server >/dev/null 2>&1; then exit 1; fi
test ! -e /run/systemd/network/00-drs-mdns-test.network
mkdir -p /run/systemd/network
cat >/run/systemd/network/00-drs-mdns-test.network <<'EOF'
[Match]
Name=drs-mdns-server
[Link]
Unmanaged=yes
EOF
networkctl reload
ip netns add drs-mdns-peer
cleanup() {
    ip netns delete drs-mdns-peer 2>/dev/null || true
    ip link delete drs-mdns-server 2>/dev/null || true
    rm -f /run/systemd/network/00-drs-mdns-test.network
    networkctl reload
}
trap cleanup EXIT
ip link add drs-mdns-server type veth peer name drs-mdns-client
ip link set drs-mdns-client netns drs-mdns-peer
ip address add 192.0.2.1/24 dev drs-mdns-server
ip link set drs-mdns-server up
ip -n drs-mdns-peer link set lo up
ip -n drs-mdns-peer address add 192.0.2.2/24 dev drs-mdns-client
ip -n drs-mdns-peer link set drs-mdns-client up
sleep 2
# Capture only multicast diagnostics within this disposable guest.
timeout 16 tcpdump -c 80 -n -l -vv -i any udp port 5353 >/run/drs-mdns-packets.txt 2>&1 &
capture=$!
if ip netns exec drs-mdns-peer ''' + client + '''; then peer_ok=true; else peer_ok=false; fi
wait "$capture" || true
if ! $peer_ok; then
    cat /run/drs-mdns-packets.txt >&2
    journalctl --no-pager -b -u avahi-daemon.service -n 60 >&2
    ip -details address show dev drs-mdns-server >&2
    ip -n drs-mdns-peer route show >&2
    exit 1
fi
cleanup
trap - EXIT
printf 'DRS_CONSOLE\n'
/usr/local/sbin/debrstick-info
printf 'DRS_NETWORK_END\n'
'''
