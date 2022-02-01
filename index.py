import scapy.all as scapy
import argparse
import requests

def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('--online', '-o', dest="isOnline", default=False, help="by using this flag the tool will search for the MAC vendor", action="store_true")  
  parser.add_argument('--ip', '-i', dest="ip", required=True, help="the IP address to scan: 192.168.1.0/24 is an example")
  return parser.parse_args()

def scan(ip):
  arp_request = scapy.ARP(pdst=ip)
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  broadcast_arp = broadcast/arp_request
  answered_list = scapy.srp(broadcast_arp,timeout=1, verbose=False)[0]
  return answered_list

def print_information(answered_list, isOnline):
  print("IP\t\t\tMAC Addresss\t\t\tMAC Vendor\n")
  for answer in answered_list:
    if isOnline:
      mac_vendor = get_vendor(answer[1].hwsrc)
    else:
      mac_vendor = "not online (check -h)"
    print(answer[1].psrc + "\t\t" +answer[1].hwsrc + "\t\t" + mac_vendor)

def get_vendor(mac):
  request = requests.get(f'https://www.macvendorlookup.com/oui.php?mac={mac}')
  if request.status_code == 204:
    return 'unable to find'
  return request.json()[0]['company']

def main():

  options = parse_args()
  answered_list = scan(options.ip)
  print_information(answered_list,options.isOnline)

main()