# -*- coding:UTF-8 -*-
from time import sleep
import uuid
import requests
import re
import time
import random
from Crypto.Hash import SHA
from requests import exceptions
from scapy.all import *

pwdtext = ''


def login(pwdtext):
    # home page
    url = 'http://192.168.31.1/cgi-bin/luci/web'
    r = requests.get(url=url)

    key = re.findall(r'key: \'(.*)\',', r.text)[0]
    mac = re.findall(r'deviceId = \'(.*)\';', r.text)[0]
    nonce = "0_" + mac + "_" + \
        str(int(time.time())) + "_"+str(random.randint(1000, 10000))

    # Encrypt passwd
    pwd = SHA.new()
    pwd.update((pwdtext+key).encode('utf-8'))
    hexpwd1 = pwd.hexdigest()

    pwd2 = SHA.new()
    pwd2.update((nonce+hexpwd1).encode('utf-8'))
    hexpwd2 = pwd2.hexdigest()

    data = {
        'username': 'admin',
        'password': hexpwd2,
        'logtype': 2,
        'nonce': nonce
    }

    # login
    url = 'http://192.168.31.1/cgi-bin/luci/api/xqsystem/login'
    r = requests.post(url=url, data=data, timeout=5)

    # save token
    resjson = r.json()
    if resjson['code'] == 0:
        print('Login Success! Token is '+resjson['token'])
        return resjson['token']
    elif resjson['code'] == 401:
        print('Maybe wrong password?')
        return 1
    else:
        print('Login Failed! Code is '+str(resjson['code']))
        return 0


def changeMac(stock):
    # original mac
    # based on current devices' mac, can change to what you want in a string
    # uncomment random to generate random mac
    mac = hex(uuid.getnode())[2:]
    cnt = 1
    # loop
    while True:
        # get new mac
        # mac = int(mac, base=16)
        # mac -= 1
        # mac = hex(mac)[2:]

        # # change to XX:XX:XX:XX
        # b = re.findall(r'.{2}', mac.upper())
        # a = ':'.join(b)
        # a = {'mac': a}

        # use random generate
        a = {'mac': RandMAC().upper()}

        url = 'http://192.168.31.1/cgi-bin/luci/;stok='+stock+'/api/xqnetwork/mac_clone?'
        r = requests.get(url=url, params=a)
        resjson = r.json()
        # print(r.url)
        # print(r.content.decode('utf-8'))

        if resjson['code'] == 0:
            print()
            print(str(cnt)+'th try')
            print('mac address has been changed to ' + a['mac'])
            print('wait for dhcp to give a new ip address')
        elif resjson['code'] == 401:
         # resjson['code'] == 401
         # invalid token, login again
            print('change failed, the reason is list below:')
            print('login time exceed: the program will automatically try login again later, no additional operation needed')
            print(
                'something unexpected happend: please stop the program to see if something wrong')
            return False
        else:
            continue
        sleep(5)

        print('testing network')
        urls = ['https://www.baidu.com/', 'https://www.speedtest.cn/', 'https://cn.bing.com/', 'http://www.gamersky.com/', 'https://www.ifanr.com/',
                'https://www.csdn.net/', 'https://cn.vuejs.org/', 'https://store.steampowered.com/', 'https://github.com/', 'https://avatars2.githubusercontent.com/']
        # try 2 times
        c = 0
        for url in urls:
            flag = 2
            c = 0
            while flag > 0:
                try:
                    print(str(3-flag)+' time try accessing ' + url)
                    r = requests.get(url=url, timeout=1)
                except exceptions.Timeout:
                    # print(str(e))
                    flag -= 1
                    sleep(1)
                except exceptions.ConnectionError:
                    flag -= 1
                    sleep(1)
                else:
                    if r.status_code == 200:
                        c = 1
                        print('connection to ' + url + ' success')
                        break
                    else:
                        flag -= 1
                        print('failed ' + str(r.status_code))
            if c != 1:
                print('connection to ' + url + ' failed')
                break
        if c == 1:
            return True
        else:
            print('network failed')
            print('========')
        cnt += 1


if __name__ == '__main__':
    pwdtext = input('please input password: ')
    while True:
        stock = login(pwdtext=pwdtext)
        if stock not in (0, 1):
            # flag = input('Start change mac? Y/n ')
            flag = 'y'
            if (flag == 'Y' or flag == 'y') and changeMac(stock):
                print('The network ok, exit program')
                break
            elif(flag == 'n' or flag == 'N'):
                break
            else:
                continue
        elif stock == 1:
            pwdtext = input('please input password: ')
