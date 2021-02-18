#!/usr/bin/env python3

import os, sys, yaml
import ipaddress
import pynetbox
from models.cisco import Cisco

# Debug
from tabulate import tabulate
from pprint import pprint

def diff_vlans(nb_vlans, sw_vlans, update=False):
    for vid, name in sw_vlans.items():
        if vid in nb_vlans.keys():
            if nb_vlans[vid].name != name and update == True:
                nb_vlans[vid].update( { "name": name } )
                print( " [o] VLAN name is updated from " + nb_vlans[vid].name + " to " + name )
        else:
            netbox.ipam.vlans.create( name=name, vid=vid, site=site_id )
            print( " [+] New VLAN " + vid + "(" + name + ") was added to netbox" )

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
        print( "> " + device.name)

        dev_ip = str(ipaddress.IPv4Interface(device.primary_ip).ip)
        sw = Cisco(device.name, dev_ip, user, password)

        sw_vlans = sw.getVlans()
        update_flag = True if device.name == '3T-MAIN' else False
        diff_vlans(netbox_vlans, sw_vlans, update=update_flag)
        netbox_vlans = { str(item.vid) : item for item in netbox.ipam.vlans.filter(site=site_slug) }
        
        netbox_interfaces = { item.name : item for item in netbox.dcim.interfaces.filter(device=device.name) }
        device_interfaces = sw.getInterfaces( netbox_vlans )

        for interface_name, sw_int in device_interfaces.items():
            if interface_name in netbox_interfaces.keys():
                netbox_interface = netbox_interfaces[interface_name]
                netbox_interface.update( sw_int )

                if 'ipaddress' in sw_int.keys() and sw_int['ipaddress'] != '':
                    ipaddr = sw_int['ipaddress']
                    prefix = str(ipaddress.IPv4Interface( ipaddr ).network)
                    
                    if netbox.ipam.prefixes.get(prefix=prefix, site=site_slug) == None:
                        netbox.ipam.prefixes.create(prefix=prefix, site=site_id)
                        print( " [+] The prefix " + prefix + " was added to Netbox")

                    nb_ipaddr = netbox.ipam.ip_addresses.get(address=ipaddr, site=site_slug)

                    if nb_ipaddr == None:
                        netbox.ipam.ip_addresses.create(address=ipaddr, assigned_object_type='dcim.interface', assigned_object_id=netbox_interface.id, site=site_id)
                        print( " [+] IP address " + ipaddr + " was added to Netbox")
        
        neighbors = sw.getNeighbors()
        for interface_name, sw_int in device_interfaces.items():
            if interface_name in neighbors.keys():
                descr = ', '.join( "Neigh: "+item[0]+"("+item[1]+")" for item in neighbors[interface_name])
                if descr != netbox_interfaces[interface_name].description:
                    netbox_interfaces[interface_name].update({ "description": descr })
                    print( '  [o] The description of ' + interface_name + ' was updated to "' + descr + "'" )

