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

cams = {}
with open('/mnt/c/linux/cams.txt') as f: 
    lines = f.readlines()
    for line in lines:
        data = line.split(';')
        if data[1] not in cams.keys():
            cams[data[1]] = data[2].strip('\n').replace('"','')+'('+data[0].strip()+')'

def parse_ports(str_ports):
    rports = []
    if len(str_ports)>0:
        ports = str_ports.strip().split(',')
        for port in ports:
            if '-' in port:
                p_range = port.split('-')
                for pid in range(int(p_range[0]), int(p_range[1])+1):
                    rports.append(str(pid))
            else:
                rports.append(port)
    return rports

def toMac(mac, fmt='dot'):
    mac = mac.lower()
    mac = re.sub('[\:\-\.]', '', mac)
    if fmt == 'col':
        return ':'.join([ ch1+ch2 for ch1,ch2 in zip(mac[0::2],mac[1::2])])
    elif fmt == 'dash':
        return '-'.join([ ch1+ch2 for ch1,ch2 in zip(mac[0::2],mac[1::2])])
    else:
        return '.'.join( [ str(mac[i:i+4]) for i in range(0,12,4)] )

class Dlink:
    def __init__(self, swname, ipaddr, username, password):
        self.avail = 1
        self.result = {}
        self.interfaces = {}
        self.vlans = []
        self.cmdprompt='DGS-1210-10P/ME:5#'
        try:
            ip = str(ipaddress.ip_address(ipaddr))
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect( hostname=ip, username=user, password=password, look_for_keys=False, allow_agent=False)
            self.ssh = client.invoke_shell(width=512)
            self.ssh.settimeout(5)
            self.ssh.send("disable clipaging\n")
            time.sleep(0.5)
            self.ssh.recv(3000)
        except ValueError:
            self.avail = 0
            print('IP address is invalid')
        except:
            self.avail = 0
            print('%s is unavail' % ip )
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
        with open('./textfsm/dlink/sh_vlan') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
            for vlan in result:
                vid = vlan[0]
                vname = vlan[1]
                tagged_ports = vlan[2]
                untagged_ports = vlan[3]
                ports = parse_ports(tagged_ports)
                if len(ports)>0:
                    for port in ports:
                        if port not in self.interfaces.keys():
                            self.interfaces[port] = {}
                        if 'tagged_vlans' not in self.interfaces[port].keys():
                            self.interfaces[port]['tagged_vlans'] = vid
                        else:
                            self.interfaces[port]['tagged_vlans'] += ','+vid
                ports = parse_ports(untagged_ports)
                if len(ports)>0:
                    for port in ports:
                        if port not in self.interfaces.keys():
                            self.interfaces[port] = {}
                        if 'untagged_vlans' not in self.interfaces[port].keys():
                            self.interfaces[port]['untagged_vlans'] = vid
                        else:
                            self.interfaces[port]['untagged_vlans'] += ','+vid
                self.vlans.append( {'vid': vlan[0], 'name': vlan[1] } )
        return self.vlans
    def getLLDP(self):
        self.ssh.send('show lldp remote_ports\n')
        result = self.ssh_read()
        with open('./textfsm/dlink/lldp_neigh') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
            for neighbor in result:
                lport = neighbor[0]
                neigh_port = neighbor[1]
                neigh_name = neighbor[2]
                if lport not in self.interfaces.keys():
                    self.interfaces[lport] = {}
                self.interfaces[lport]['neigh_port'] = neigh_port
                self.interfaces[lport]['neigh_name'] = neigh_name
    def getMacs(self):
        self.ssh.send('show fdb\n')
        result = self.ssh_read()
        port_macs = {}
        with open('./textfsm/dlink/sh_fdb') as f:
            re_table = textfsm.TextFSM(f)
            results = re_table.ParseText(result)
            for item in results:
                mac = item[2]
                port = item[3]
                if port not in port_macs.keys():
                    port_macs[port] = []
                port_macs[port].append(mac)
        for port, mac in port_macs.items():
            if len(mac) == 1:
                if port not in switch.interfaces.keys():
                    switch.interfaces[port] = {}
                mac = toMac(mac[0])
                switch.interfaces[port]['mac_neigh'] = mac
                if mac in cams.keys():
                    switch.interfaces[port]['mac_descr'] = cams[mac]
        #pprint.pprint(self.interfaces)
        return result

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
r = requests.get('https://'+domain_name+'/api/dcim/devices/?site='+site_slug+'&manufacturer=d-link&model=dgs-1210-10pme', headers=headers)
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
    switch = Dlink(dev['name'], ip, user, password)
    if switch.avail == 0:
        print('Device is unavailable')
        continue
    print('Device is available')

    #switch.getInts()          # show interfaces
    #switch.getIntStatus()     # show interfaces status
    switch.getVlans() # show vlan
    switch.getLLDP()   # show lldp neighbors detail
    switch.getMacs()
    #pprint.pprint(switch.interfaces)
    
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
        raw_int_data = ''
        raw_int_data = '{"device": '+str(dev['id'])+', '
        raw_int_data += '"name": "'+interface+'", '
        raw_int_data += '"type": "1000base-t", "enabled": "true" } '
        # Add new interface to Netbox
        r = requests.post('https://'+domain_name+'/api/dcim/interfaces/', data=raw_int_data, headers=headers)
        new_int = json.loads(r.text) # Save the interface data
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
        raw_data = ''
        int_name = interface['name']
        descr = ''
        if interface['type']['value'] == 'virtual':
            continue
        if 'neigh_name' in switch.interfaces[int_name].keys() and 'neigh_port' in switch.interfaces[int_name].keys():
            descr = 'LLDP: '+switch.interfaces[int_name]['neigh_name']+' port('+switch.interfaces[int_name]['neigh_port']+')'
        if 'mac_neigh' in switch.interfaces[int_name].keys():
            descr = 'Mac: '+switch.interfaces[int_name]['mac_neigh']
            if 'mac_descr' in switch.interfaces[int_name].keys():
                descr += ' ('+switch.interfaces[int_name]['mac_descr']+')'
        print(descr)
        raw_data += '"description": "'+descr+'"'
        r = requests.patch('https://'+domain_name+'/api/dcim/interfaces/'+str(interface['id'])+'/',data='{ '+raw_data+' }', headers=headers)
