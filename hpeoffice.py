import requests, pickle, redis
import json
import re
import sys

headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}

# Device Credentials
with open('settings.yaml') as f:
    setup = yaml.safe_load(f)

user=setup['global']['username']
password=setup['global']['password']

login_data = { 'username': user, 'password': password }

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
# interface, remote id, port id, port description, system name, capabillities, system id
lldp = json.loads(js)

r = s.get('http://'+dev+'/htdocs/pages/base/mac_address_table.lsp')
values = re.findall(r'var aDataSet = \s*(.*?);', r.text, re.DOTALL | re.MULTILINE)
js = ' '.join(values).replace('\n','').replace('"','\\"').replace('\'','"')
# VID, MAC, INTERFACE, INTERFACE INDEX, STATUS
macs = json.loads(js)

print(macs)
