
from models.switch import Switch
import textfsm
from schema import Schema, And, Use, Optional, SchemaError

class HP(Switch):
    
    def __init__(self, swname, ipaddr, username, password):
        self.cmdprompt=swname+'#'
        self.connect( ipaddr, username, password )

    def getVlans(self):
        pass
    
    def getNeighbors(self):
        schema_neighs = Schema({ str: list })
        neighs = {}
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
        return interfaces
