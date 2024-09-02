from django.shortcuts import render

# Create your views here.
# from scapy.all import ARP, Ether, srp
from scapy.all import ARP, Ether, srp, conf, socket

def scan_network(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Process the response and extract IP and MAC addresses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def network_scan_view(request):
    devices = scan_network("192.168.128.1/24")  # Adjust the IP range as needed
    return render(request, 'scanner/scan_results.html', {'devices': devices})

# Example usage
if __name__ == "__main__":
    # Change the IP range according to your network
    devices = scan_network("192.168.128.1/24")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
