import uuid
import re


# def get_mac_address():
#     node = uuid.getnode()
#     mac = uuid.UUID(int = node).hex[-12:]
#     return mac


# address = hex(uuid.getnode())[2:]
# b=re.findall(r'.{2}',address.upper())
# c=':'.join(b)
# print(c)
# print(address)
# a=''
# i=0
# while i < len(address):
#     a = a + address[i:i+2].upper()
#     a = a+':'
#     i+=2

# print(a)
# # address = str_to_hex(address)
# # for s in str_to_hex(address).split(' '):
# #     print(hex(int(s,16)))
# address = int(address, base=16)
# # address+=1
# print(address)
# print(hex(address))
# # print('-'.join(address[i:i+2] for i in range(0, len(address), 2)))
# print(get_mac_address())

# import requests

# r = requests.get(url='https://github.com/',timeout=5)
# print(r.status_code)

# mac = hex(uuid.getnode())[2:]

# mac = int(mac, base=16)
# mac += 1
# mac = hex(mac)[2:]

# print(mac)

# b = re.findall(r'.{2}', mac.upper())
# a = ':'.join(b)

# print(a)

from scapy.all import *

print(RandMAC().upper())