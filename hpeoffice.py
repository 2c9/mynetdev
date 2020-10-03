import requests, pickle, redis
import json, yaml
import re
import sys

headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}

# Device Credentials
with open('settings.yaml') as f:
    setup = yaml.safe_load(f)

user=setup['global']['username']
password=setup['global']['password']

login_data = { 'username': user, 'password': password }

webdis = 'http://172.16.3.174:7379'
rd = redis.StrictRedis(host='172.16.3.174', port=6379, db=0)
s = requests.Session()

dev = '172.28.77.2'

pobj = rd.get(dev)
if not pobj:
    r = s.post('http://'+dev+'/htdocs/login/login.lua', data=login_data)
    rd.set(dev, pickle.dumps(r.cookies))
    rd.expire(dev, 30)
else:
    cookies = pickle.loads(pobj)
    s.cookies.update(cookies)

r = s.get('http://'+dev+'/htdocs/pages/switching/lldp_remote.lsp')
values = re.findall(r'var aDataSet = \s*(.*?);', r.text, re.DOTALL | re.MULTILINE)
js = ' '.join(values).replace('\n','').replace('"','\\"').replace('\'','"')
neighbors = json.loads(js)
# interface, remote id, chassis id, port id, port description, system name, capabillities, system id
for lldp in neighbors:
    print('my port: '+lldp[0])
    print('remote port: '+lldp[3])
    print('remote system name: '+lldp[5])

r = s.get('http://'+dev+'/htdocs/pages/base/mac_address_table.lsp')
values = re.findall(r'var aDataSet = \s*(.*?);', r.text, re.DOTALL | re.MULTILINE)
js = ' '.join(values).replace('\n','').replace('"','\\"').replace('\'','"')
# VID, MAC, INTERFACE, INTERFACE INDEX, STATUS
macs = json.loads(js)
int_macs = { item[3]: [] for item in macs }
for item in macs:
    if item[-1] == 'Learned':
        mac = item[1]
        int_macs[item[3]].append(mac)
for port in int_macs.keys():
    if 0 < len(int_macs[port]) < 2:
        mac_addr = int_macs[port][0]
        r = requests.get(webdis+'/GET/'+mac_addr)
        if r.status_code == 200:
            clientname = json.loads(r.text)['GET']
            if clientname:
                descr = 'MAC/DHCP: '+mac_addr+' -> '+clientname
                print(descr)
        print(port+': '+mac_addr)
