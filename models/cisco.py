
from models.switch import Switch
import textfsm
from schema import Schema, And, Use, Optional, SchemaError

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


class Cisco(Switch):
    
    def __init__(self, swname, ipaddr, username, password):
        self.cmdprompt=swname+'#'
        self.connect( ipaddr, username, password )
        self.ssh.send( "terminal length 0\n" + \
                       "terminal width 512\n"    )
    
    def show_ver(self):
        self.ssh.send('show ver\n')
        return self.ssh_read()

    def getVlans(self):
        self.ssh.send('show vlan\n')
        result = self.ssh_read()
        with open('textfsm/cisco/sh_vlan') as f:
            re_table = textfsm.TextFSM(f)
            result = re_table.ParseText(result)
            return { key: value for (key, value) in result}

    def getNeighbors(self):
        schema_neighs = Schema({ str: list })
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
            schema_neighs.validate(neighs)
            return neighs

    def getInterfaces( self, netbox_vlans ):
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
