#!/bin/python3

import re
import requests
import yaml
import paramiko
import sys
import time
import json
import textfsm
import socket
import ipaddress
from tabulate import tabulate
import pprint

class Cisco:
    def __init__(self, swname, ipaddr, username, password):
        self.avail = 1
        self.result = {}
        self.interfaces = {}
        self.vlans = []
        self.cmdprompt=swname+'#'
        try:
            ip = str(ipaddress.ip_address(ipaddr))
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect( hostname=ip, username=user, password=password, look_for_keys=False, allow_agent=False)
            self.ssh = client.invoke_shell(width=512)
            self.ssh.settimeout(5)
            self.ssh.send("terminal length 0\n")
            time.sleep(0.5)
            self.ssh.send("terminal width 512\n")
            time.sleep(0.5)
            self.ssh.recv(3000)
        except ValueError:
            self.avail = 0
            print('IP address is invalid')
        except:
            self.avail = 0
            print('%s is unavail' % ip )
    def enable(self):
        pass
    def ssh_read(self):
        self.ssh.settimeout(5)
        output=''
        part=''
        while True:
            try:
                part=self.ssh.recv(3000).decode('utf-8')
                time.sleep(0.5)
                output+=part
                if output[-1*len(self.cmdprompt):] == self.cmdprompt:
                    break
            except socket.timeout:
                    break
        return output
    def getVlans(self):
        self.ssh.send('show vlan\n')
        result = self.ssh_read()
        with open('./textfsm/cisco/sh_vlan') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
            for vlan in result:
                self.vlans.append( {'vid': vlan[0], 'name': vlan[1] } )
        return self.vlans
    def getCDP(self):
        self.ssh.send('sh cdp neigh detail\n')
        result = self.ssh_read()
        with open('./textfsm/cisco/cdp_neigh_detail') as f:
            re_table = textfsm.TextFSM(f)
            ints = { }
            for neighbor in re_table.ParseText(result):
                int_name = neighbor[2]
                if int_name not in self.interfaces.keys():
                    self.interfaces[int_name] = {}
                ints[int_name] = { 'devicename': neighbor[0], 'remote_port': neighbor[3] }
                self.interfaces[int_name]['neigh_name'] = neighbor[0]
                self.interfaces[int_name]['neigh_port'] = neighbor[3]
        return ints
    def getLLDP(self):
        self.ssh.send('sh lldp neigh detail\n')
        result = self.ssh_read()
        with open('./textfsm/cisco/lldp_neigh_detail') as f:
            re_table = textfsm.TextFSM(f)
            ints = { }
            for neighbor in re_table.ParseText(result):
                int_name = neighbor[1].replace('Gi','GigabitEthernet')
                if int_name not in self.interfaces.keys():
                    self.interfaces[int_name] = {}
                self.interfaces[int_name]['neigh_name'] = neighbor[0]
                self.interfaces[int_name]['neigh_port'] = neighbor[2]
                ints[int_name] = { 'devicename': neighbor[0], 'remote_port': neighbor[2] }
        return ints
    def getIntStatus(self):
        self.ssh.send('sh interface status\n')
        result = self.ssh_read()
        ints = {}
        with open('./textfsm/cisco/sh_int_status') as f:
            re_table = textfsm.TextFSM(f)
            for interface in re_table.ParseText(result):
                if interface[0][:2] == 'Gi':
                    int_name = interface[0].replace('Gi','GigabitEthernet')
                if interface[0][:2] == 'Po':
                    int_name = interface[0].replace('Po','Port-channel')
                if int_name not in self.interfaces.keys():
                    self.interfaces[int_name] = {}
                if interface[3] == 'trunk':
                    self.interfaces[int_name]['mode'] = 'trunk'
                elif interface[3] == 'routed':
                    self.interfaces[int_name]['mode'] = 'routed'
                else:
                    self.interfaces[int_name]['mode'] = 'access'
                    self.interfaces[int_name]['vlan'] = interface[3]
    def getInts(self):
        self.ssh.send('sh interfaces\n')
        result = self.ssh_read()
        with open('./textfsm/cisco/sh_ints') as f:
            re_table = textfsm.TextFSM(f)
            for interface in re_table.ParseText(result):
                int_name = interface[0]
                int_mac = interface[1]
                if int_name not in self.interfaces.keys():
                    self.interfaces[int_name] = {}
                if 'SVI' in interface[2]:
                    int_type = 'virtual'
                elif 'EtherChannel' == interface[2]:
                    int_type = 'lag'
                elif 'Gigabit Ethernet' in interface[2]:
                    int_type = 'physical'
                else:
                    int_type = 'unknown'
                int_ip = interface[3]
                self.interfaces[int_name]['mac_address'] = int_mac
                self.interfaces[int_name]['type'] = int_type
                self.interfaces[int_name]['ip'] = int_ip
                #print(int_name+' '+str(self.interfaces[int_name]))
            #sys.exit()

def toMac(mac, fmt='dot'):
    mac = mac.lower()
    mac = re.sub('[\:\-\.]', '', mac)
    if fmt == 'col':
        return ':'.join([ ch1+ch2 for ch1,ch2 in zip(mac[0::2],mac[1::2])])
    elif fmt == 'dash':
        return '-'.join([ ch1+ch2 for ch1,ch2 in zip(mac[0::2],mac[1::2])])
    else:
        return '.'.join( [ str(mac[i:i+4]) for i in range(0,12,4)] )

with open('settings.yaml') as f:
    setup = yaml.safe_load(f)

# Netbox Authorizantion headers
netbox_token = setup['global']['token']
headers = {'Authorization': 'Token '+ netbox_token, 'Accept': 'application/json', 'Content-Type': 'application/json'}

# Location
site_slug = setup['global']['site']

# Get fqdn of Netbox
domain_name = setup['global']['domain']

# Device Credentials
user=setup['global']['username']
password=setup['global']['password']

# Get Sites info from Netbox
r = requests.get('https://'+domain_name+'/api/dcim/sites/', headers=headers)
sites = { site['slug']: site for site in json.loads(r.text)['results']}

# Get known VLANs from Netbox
r = requests.get('https://'+domain_name+'/api/ipam/vlans/?limit=0&site='+site_slug, headers=headers)
vlan_by_vid = {}
for vlan in json.loads(r.text)['results']:
    vlan_by_vid[str(vlan['vid'])] = { 'id': str(vlan['id']), 'name': vlan['name'] }

# Get cisco switches from Netbox
r = requests.get('https://'+domain_name+'/api/dcim/devices/?site='+site_slug+'&manufacturer=cisco&role=core', headers=headers)
devices = json.loads(r.text)

for dev in devices['results']:
    # Get IPv4 address of the device
    r = requests.get('https://'+domain_name+'/api/dcim/devices/'+str(dev['id'])+'/', headers=headers)
    ip = json.loads(r.text)['primary_ip4']['address']
    ip = ip.split('/')[0]
    print('---------------------------------------------------')
    print(str(dev['id'])+' '+dev['name']+' '+ip)

    # Get interfaces of the switch from Netbox
    r = requests.get('https://'+domain_name+'/api/dcim/interfaces/?limit=0&device_id='+str(dev['id']), headers=headers)
    interfaces = json.loads(r.text)['results']

    # Get data from the switch
    switch = Cisco(dev['name'], ip, user, password)
    if switch.avail == 0:
        print('Device is unavailable')
        continue
    print('Device is available')

    switch.getInts()          # show interfaces
    switch.getIntStatus()     # show interfaces status
    vlans = switch.getVlans() # show vlan
    cdp = switch.getCDP()     # show cdp neighbors detail
    lldp = switch.getLLDP()   # show lldp neighbors detail
    
    # Add new vlans to Netbox
    for vlan in switch.vlans:
        if vlan['vid'] not in vlan_by_vid.keys():
            print(vlan['vid']+' ('+vlan['name']+') doesn\'t exist')
            raw_data = '{"site": '+str(sites[site_slug]['id'])+',"vid":'+ vlan['vid'] +',"name":"'+vlan['name']+'" }'
            r = requests.post('https://'+domain_name+'/api/ipam/vlans/', data=raw_data, headers=headers)
            vlan_by_vid[vlan['vid']] = { 'id': str(json.loads(r.text)['id']) , 'name': vlan['name'] }
    #
    # Let's find undocument interfaces and create them in Netbox
    #
    dev_ints = switch.interfaces.keys()
    known_ints = [ interface['name'] for interface in interfaces]
    unknown_ints = list(set(dev_ints) - set(known_ints))
    for interface in unknown_ints:
        # We will be add only virtual interfaces and message to stdout about others
        if switch.interfaces[interface]['type'] == 'virtual':
            raw_int_data = ''
            raw_int_data = '{"device": '+str(dev['id'])+', '
            raw_int_data += '"name": "'+interface+'", '
            raw_int_data += '"type": "virtual", "enabled": "true", '
            raw_int_data += '"mac_address": "'+switch.interfaces[interface]['mac_address']+'" }'
            # Add new interface to Netbox
            #r = requests.post('https://'+domain_name+'/api/dcim/interfaces/', data=raw_int_data, headers=headers)
            #new_int = json.loads(r.text) # Save the interface data
        else:
            print('An unknown interface is founded... It\'s name is '+interface)
    #
    # Update interfaces list
    #
    if len(unknown_ints)>0:
        r = requests.get('https://'+domain_name+'/api/dcim/interfaces/?limit=0&device_id='+str(dev['id']), headers=headers)
        interfaces = json.loads(r.text)['results']
    #
    # Update info about interfaces
    #
    for interface in interfaces:
        int_name = interface['name']
        raw_data = ''
        if 'neigh_name' in switch.interfaces[int_name] and 'neigh_port' in switch.interfaces[int_name]:
            descr = switch.interfaces[int_name]['neigh_name']+' '+switch.interfaces[int_name]['neigh_port']
            raw_data += '"description": "'+ descr+'", '
        if 'mac_address' in switch.interfaces[int_name].keys():
            raw_data += '"mac_address": "'+switch.interfaces[int_name]['mac_address']+'", '
        if 'mode' in switch.interfaces[int_name].keys():
            if switch.interfaces[int_name]['mode'] == 'access':
                raw_data += '"mode": "access", "untagged_vlan": '+vlan_by_vid[switch.interfaces[int_name]['vlan']]['id']+', '
            elif switch.interfaces[int_name]['mode'] == 'trunk':
                raw_data += '"mode": "tagged", '
        raw_data = raw_data.strip(' ,')
        r = requests.patch('https://'+domain_name+'/api/dcim/interfaces/'+str(interface['id'])+'/',data='{ '+raw_data+' }', headers=headers)
        if 'ip' in switch.interfaces[int_name].keys() and switch.interfaces[int_name]['ip'] != '':
            ip = switch.interfaces[int_name]['ip']
            # Check if the prefix exists
            prefix = json.loads(requests.get('https://'+domain_name+'/api/ipam/prefixes/?q='+switch.interfaces[int_name]['ip'], headers=headers).text)
            if prefix['count'] == 0:
                net = str(ipaddress.IPv4Interface(switch.interfaces[int_name]['ip']).network)
                raw_pref_data = '{"prefix":"'+net+'","is_pool":true,"site":'+str(sites[site_slug]['id'])+',"vrf":1,"description":"'+int_name+'"}'
                r = requests.post('https://'+domain_name+'/api/ipam/prefixes/', data=raw_pref_data, headers=headers)
            result = requests.get('https://'+domain_name+'/api/ipam/ip-addresses/?q='+switch.interfaces[int_name]['ip'], headers=headers)
            result = json.loads(result.text)
            raw_ip_addr = '{ "address": "'+ip+'", "vrf": 1, "status": "active", '
            raw_ip_addr += '"interface": '+str(interface['id'])+' }'
            # Check if the IP address exists
            if result['count'] == 0:
                # Add ip address if it doesn't
                r = requests.post('https://'+domain_name+'/api/ipam/ip-addresses/', data=raw_ip_addr, headers=headers)
            else:
                # Otherwise let's write a message to stdout
                if len(result['results']) == 1:
                    nb_dev_id = result['results'][0]
                    nb_dev_id = nb_dev_id['assigned_object']['device']['id']
                    if nb_dev_id == dev['id']:
                        #print('Is already assigned to the device')
                        pass
                    else:
                        print(ip+' is already in use on another device')
                else:
                    print('There are more then one item for '+ip+' in Netbox database!')
