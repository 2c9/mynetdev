#!/bin/python3

import redis
import re
import yaml
import requests
import paramiko
import sys
import time
import json
import textfsm
import socket
import ipaddress
from tabulate import tabulate
import pprint

class Switch3Com:
    def __init__(self, swname, ipaddr, username, password, cmdmode='512900'):
        self.avail = 1
        self.result = {}
        self.cmdprompt='<'+swname+'>'
        try:
            ip = str(ipaddress.ip_address(ipaddr))
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect( hostname=ip, username=user, password=password, look_for_keys=False, allow_agent=False)
            self.ssh = client.invoke_shell()
            self.devModeOn()
        except ValueError:
            self.avail = 0
            print('IP address is invalid')
        except:
            self.avail = 0
            print('%s is unavail' % ip )
    def read(self):
        self.ssh.settimeout(5)
        output=''
        part=''
        while True:
            try:
                part=self.ssh.recv(3000).decode('utf-8')
                output+=part
                if output[-1*len(self.cmdprompt):] == self.cmdprompt:
                    break
            except socket.timeout:
                break
        return output
    def devModeOn(self):
        self.ssh.send('_cmdline-mode on\n')
        time.sleep(0.5)
        self.ssh.send('Y\n')
        time.sleep(0.5)
        self.ssh.send('Jinhua1920unauthorized\n')
        #self.ssh.send('512900\n')
        time.sleep(0.5)
        result = self.read()
        if result.find('Error: Invalid password.') > 0:
            print('Wrong password')
            self.avail = 0
            return
        self.ssh.send('screen-length disable\n')
        time.sleep(0.5)
        self.read()
    def getLldp(self):
        self.ssh.send('display lldp neighbor-information\n')
        result = self.read()
        with open('./textfsm/3com/3com2928sfp_lldp_tmpl') as f:
            re_table = textfsm.TextFSM(f)
            result = { item[0]: dict( zip(re_table.header[1:], item[1:])) for item in re_table.ParseText(result) }
        return result
    def getMacs(self):
        self.ssh.send('display mac-address\n')
        result = self.read()
        with open('./textfsm/3com/3com2928sfp_macs_tmpl') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
        return result
    def getVlans(self):
        self.ssh.send('display vlan all\n')
        result = self.read().replace('\r\n\r\n','\r\n#####\r\n')
        with open('./textfsm/3com/3com2928sfp_vlans_tmpl') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
        return [ dict( zip( re_table.header, item ) ) for item in result ]
    def getIntStatus(self):
        self.ssh.send('display interface brief\n')
        result = self.read()
        with open('./textfsm/3com/3com2928sfp_status_tmpl') as f:
            # Link: ADM - administratively down; Stby - standby
            # Speed or Duplex: (a)/A - auto; H - half; F - full
            # Type: A - access; T - trunk; H - hybrid
            re_table = textfsm.TextFSM(f)
            result = { item[0].replace('GE','GigabitEthernet'): dict( zip(re_table.header[1:], item[1:]) ) for item in re_table.ParseText(result) }
        return result

def toMac(mac, fmt='dot'):
    mac = mac.lower()
    mac = re.sub('[\:\-\.]', '', mac)
    if fmt == 'col':
        return ':'.join([ ch1+ch2 for ch1,ch2 in zip(mac[0::2],mac[1::2])])
    elif fmt == 'dash':
        return '-'.join([ ch1+ch2 for ch1,ch2 in zip(mac[0::2],mac[1::2])])
    else:
        return '.'.join( [ str(mac[i:i+4]) for i in range(0,12,4)] )

# --------------------------------------------------------------------------------------------------------------------------

with open('settings.yaml') as f:
    setup = yaml.safe_load(f)
    #print(setup)

# Netbox Authorizantion headers
netbox_token = setup['global']['token']
headers = {'Authorization': 'Token '+ netbox_token, 'Accept': 'application/json', 'Content-Type': 'application/json'}

# Location
site_slug = setup['global']['site']

# Vendor
vendor_slugs = [ 'hp', '3com' ]

# Get fqdn of Netbox
domain_name = setup['global']['domain']

# Device Credentials
user=setup['global']['username']
password=setup['global']['password']

# Test web redis
webdis = 'http://172.16.3.174:7379'

# Get Sites info from Netbox
r = requests.get('https://'+domain_name+'/api/dcim/sites/', headers=headers)
sites = { site['slug']: site for site in json.loads(r.text)['results']}
#print(sites)

# Get known VLANs from Netbox
r = requests.get('https://'+domain_name+'/api/ipam/vlans/?limit=0&site='+site_slug, headers=headers)
vlan_by_vid = {}
for vlan in json.loads(r.text)['results']:
    vlan_by_vid[str(vlan['vid'])] = { 'id': str(vlan['id']), 'name': vlan['name'] }

devices = {}
# Get devices from the site
r = requests.get('https://'+domain_name+'/api/dcim/devices/?limit=0&site='+site_slug, headers=headers)
devices = json.loads(r.text)

for dev in devices['results']:
    # Get IPv4 address of the device
    if dev['device_type']['manufacturer']['slug'] not in vendor_slugs:
        continue
    r = requests.get('https://'+domain_name+'/api/dcim/devices/'+str(dev['id'])+'/', headers=headers)
    ip = json.loads(r.text)['primary_ip4']['address']
    ip = ip.split('/')[0]
    print('---------------------------------------------------')
    print(str(dev['id'])+' '+dev['name']+' '+ip)
    # Get interfaces of the switch from Netbox
    r = requests.get('https://'+domain_name+'/api/dcim/interfaces/?limit=0&device_id='+str(dev['id']), headers=headers)
    interfaces = json.loads(r.text)['results']
    # Get data from the switch
    tst = Switch3Com(dev['name'], ip, user, password)
    if tst.avail == 0:
        print('Device is unavailable')
        continue
    print('Device is available')
    ints_state = tst.getIntStatus()
    neighbors = tst.getLldp()
    vlans = tst.getVlans()
    macs = tst.getMacs()
    int_macs = { item[3]: [] for item in macs }
    for item in macs:
        mac = toMac(item[0])
        int_macs[item[3]].append(mac)
    #
    # Combine data about known vlans and interfaces
    #
    for vlan in vlans:
        vid = vlan['VLAN_ID']
        if vlan['VLAN_ID'] not in vlan_by_vid.keys():
            print(vlan['VLAN_ID'] + ' ('+vlan['VLAN_NAME']+') doesn\'t exist')
            raw_data = '{"site": '+str(sites[site_slug]['id'])+',"vid":'+ vlan['VLAN_ID'] +',"name":"'+vlan['VLAN_NAME']+'" }'
            r = requests.post('https://'+domain_name+'/api/ipam/vlans/', data=raw_data, headers=headers)
            vlan_by_vid[str(vlan['VLAN_ID'])] = { 'id': str(json.loads(r.text)['id']) , 'name': vlan['VLAN_NAME'] }
        for interface in vlan['TAGGED']:
            if 'tvids' not in ints_state[interface].keys():
                ints_state[interface]['tvids'] = vlan_by_vid[vid]['id']
            else:
                ints_state[interface]['tvids'] += ','+vlan_by_vid[vid]['id']
        for interface in vlan['UNTAGGED']:
            if 'avids' not in ints_state[interface].keys():
                ints_state[interface]['avids'] = vlan_by_vid[vid]['id']
            else:
                ints_state[interface]['avids'] += ','+vlan_by_vid[vid]['id']
    #
    # Iterate over interfaces of the device and send information to Netbox
    #
    for interface in interfaces:
        if interface['type']['value'] == 'virtual': continue
        int_name = interface['name']
        # Define mode of the interface
        mode = ints_state[interface['name']]['TYPE']
        if mode == 'A':
            mode = 'access'
        elif mode == 'T' or mode == 'H':
            mode = 'tagged'
        # Define tags and pvid on the interface
        raw_data = '{"mode": "'+ mode +'"'
        if 'tvids' in ints_state[interface['name']]:
            raw_data += ',"tagged_vlans": ['+ ints_state[interface['name']]['tvids'] +']'
        if 'avids' in ints_state[interface['name']]:
            raw_data += ',"untagged_vlan": '+ ints_state[interface['name']]['avids']
        raw_data += '}'
        # Update information about the interface
        r = requests.patch('https://'+domain_name+'/api/dcim/interfaces/'+str(interface['id'])+'/',data=raw_data, headers=headers)
        descr = ''
        # Macs
        if interface['description'] == '' or True:
            if int_name in int_macs.keys() and len(int_macs[int_name]) == 1:
                mac_addr = int_macs[int_name][0]
                r = requests.get(webdis+'/GET/'+mac_addr)
                if r.status_code == 200:
                    clientname = json.loads(r.text)['GET']
                    if clientname:
                        #clientname = clientname.encode('ascii', 'replace')
                        descr = 'MAC/DHCP: '+mac_addr+' -> '+clientname
                        print(descr)
        else:
            descr = interface['description']
        # Set interface's description based on LLDP neighbors infromation
        if interface['name'] in neighbors:
            sysname = neighbors[interface['name']]['SYSTEM_NAME']
            if neighbors[interface['name']]['REMOTE_PORT_TYPE'] == 'MAC address':
                rem_id = toMac(neighbors[interface['name']]['REMOTE_PORT'])
            else:
                rem_id = neighbors[interface['name']]['REMOTE_PORT']
            descr  = 'LLDP: '+sysname+' '+rem_id
        raw_data = '{ "description": "'+descr+'" }'
        r = requests.patch('https://'+domain_name+'/api/dcim/interfaces/'+str(interface['id'])+'/',data=raw_data.encode('utf-8'), headers=headers)
print('The end\n')
