#!/usr/bin/env python3

import os, time, sys, yaml
import paramiko
import ipaddress
import pynetbox
import textfsm
from schema import Schema, And, Use, Optional, SchemaError
# Debug
from tabulate import tabulate
from pprint import pprint


class Switch:
    
    cmdprompt = '#'

    def connect(self, ipaddr, username, password):
        try:
            ip = str(ipaddress.ip_address(ipaddr))
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect( hostname=ip, username=username, password=password, look_for_keys=False, allow_agent=False)
            self.ssh = client.invoke_shell(width=512)
            self.ssh.settimeout(5)
            self.ssh.recv(3000)
        except:
            raise Exception('SSHConnectionFailed')
    
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

class Cisco(Switch):
    
    def __init__(self, swname, ipaddr, username, password):
        self.cmdprompt=swname+'#'
        self.connect( ipaddr, username, password )
        self.ssh.send( "terminal length 0\n" + \
                       "terminal width 512\n"    )
    
    def show_ver(self):
        self.ssh.send('show ver\n')
        return self.ssh_read()

    def show_vlan(self):
        self.ssh.send('show vlan\n')
        result = self.ssh_read()
        with open('textfsm/cisco/sh_vlan') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
            return { key: value for (key, value) in result}

    def getNeighbors(self):
        self.ssh.send('sh lldp neigh\n')
        result = self.ssh_read()
        neighs = {}
        with open('textfsm/cisco/show_lldp') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
            for item in result:
                intname = item[1].replace('Gi','GigabitEthernet')
                if intname not in neighs.keys():
                    neighs[intname] = [ [ item[0], item[2]] ]
                else:
                    neighs[intname].append([ item[0],item[2] ])
            return neighs

    def getInterfaces(self):
        schema_ints = Schema( { 'type': str,
                                Optional('mac_address'): str,
                                Optional('ipaddress'): str,
                                Optional('mode'): And(str, Use(str.lower), lambda s: s in ("access", "tagged") ),
                                Optional('untagged_vlan'): int,
                                Optional('tagged'): list
                              } )
        interfaces = {}

        self.ssh.send('sh interfaces\n')
        result = self.ssh_read()

        with open('./textfsm/cisco/sh_ints') as f:
            re_table = textfsm.TextFSM(f)
            parsed_out = re_table.ParseText(result)
            for interface in filter( lambda x: x[2] != 'EtherChannel', parsed_out ):
                name, macaddr, itype, ipaddr = interface
                intf = { 'mac_address': macaddr, 'type': convert_interface_type(itype), 'ipaddress': ipaddr }
                schema_ints.validate(intf)
                interfaces.update( { name: intf } )

        self.ssh.send('sh interface switchport\n')
        result = self.ssh_read()
        
        with open('./textfsm/cisco/sh_int_switchport') as f:
            re_table = textfsm.TextFSM(f)
            for interface in re_table.ParseText(result):
                name, mode, untagged, native = interface
                name = convert_interface_name(name)
                mode = "tagged" if mode == "trunk" else "access"
                if not name.startswith("PortChannel"):
                    if ( mode == 'access' or mode =='tagged' ):
                        untagged = netbox_vlans[untagged].id
                        native = netbox_vlans[native].id
                        if mode == 'access':
                            intf = { 'mode': mode, 'untagged_vlan': int(untagged) }
                        else:
                            intf = {'mode': mode, 'untagged_vlan': int(native) }
                        interfaces[name].update( intf )
                        schema_ints.validate(interfaces[name])

        return interfaces

def convert_interface_name( int_name ):
    names = {
                "gi": "GigabitEthernet",
                "fa": "FastEthernet",
                "po": "PortChannel"
            }
    intf = int_name.lower()
    short = intf[0:2]
    return intf.replace( short, names[short] )

def convert_interface_type( int_type ):
    types = {
                "RP management port": "1000base-t",
                "Gigabit Ethernet": "1000base-t",
                "Fast Ethernet": "100base-tx",
                "virtual": "virtual",
                "EtherChannel": "virtual",
                "Ethernet SVI": "virtual",
                "EtherSVI": "virtual",
                "PowerPC FastEthernet": "100base-tx",
                "Gigabit Ethernet": "1000base-t"
            }
    return types[int_type]

def diff_vlans(nb_vlans, sw_vlans, update=False):
    for vid, name in sw_vlans.items():
        if vid in nb_vlans.keys():
            if nb_vlans[vid].name != name and update == True:
                nb_vlans[vid].update( { "name": name } )
                print( "Updating vlan name: " + nb_vlans[vid].name + " to " + name )
        else:
            netbox.ipam.vlans.create( name=name, vid=vid, site=site_id )
            print( "Adding new vlan " + vid + "(" + name + ")" )

if __name__ == "__main__":

    with open('settings.yaml') as f:
        setup = yaml.safe_load(f)
    
    # Get netbox token
    netbox_token = setup['global']['token']
    # Get site slug
    site_slug = setup['global']['site']
    # Get fqdn of Netbox
    domain_name = setup['global']['domain']
    # Device Credentials
    user=setup['global']['username']
    password=setup['global']['password']
    # Connect to netbox
    netbox = pynetbox.api( "https://"+domain_name, netbox_token )

    site_id = netbox.dcim.sites.get(slug=site_slug).id
    netbox_vlans = { str(item.vid) : item for item in netbox.ipam.vlans.filter(site=site_slug) }
    
    devices = netbox.dcim.devices.filter(site=site_slug, manufacturer='cisco', role=['core-switch'])

    for device in devices:
        print("#### "+device.name+" ####")

        dev_ip = ipaddress.IPv4Interface(device.primary_ip).ip
        try:
            sw = Cisco(device.name, dev_ip, user, password)
        except:
            print("Connection failed!!!")

        sw_vlans = sw.show_vlan()
        update_flag = True if device.name == '3T-MAIN' else False
        diff_vlans(netbox_vlans, sw_vlans, update=update_flag)
        netbox_vlans = { str(item.vid) : item for item in netbox.ipam.vlans.filter(site=site_slug) }
        
        netbox_interfaces = { item.name : item for item in netbox.dcim.interfaces.filter(device=device.name) }
        device_interfaces = sw.getInterfaces()

        for interface_name, sw_int in device_interfaces.items():
            if interface_name in netbox_interfaces.keys():
                netbox_interface = netbox_interfaces[interface_name]
                netbox_interface.update( sw_int )
        
        neighbors = sw.getNeighbors()
        for interface_name, sw_int in device_interfaces.items():
            if interface_name in neighbors.keys():
                descr = ', '.join( "Neigh: "+item[0]+"("+item[1]+")" for item in neighbors[interface_name])
                netbox_interfaces[interface_name].update({ "description": descr })
                print( 'Update description on ' + interface_name + ': ' + descr )

