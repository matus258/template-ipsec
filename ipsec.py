#!/usr/bin/python
import subprocess
import json
import sys
import re

text_output = ''
json_output = {}
ipsec = subprocess.check_output(['sudo','ipsec','statusall'])
pages = ['Status', 'Listening', 'Connections', 'Routed', 'Security'] 
confs = ['local', 'child', 'remote']
page = ''
row = 0
default = 'NONE'

for line in ipsec.split('\n'):
  parsed_line = re.split(r'\s+', re.sub(r'(:|=|,|{.*}|\[\d+\])', '', line))  
  while('' in parsed_line):
    parsed_line.remove("")

  if parsed_line:
    if parsed_line[0] in pages:
      page = parsed_line[0]
      if (page == 'Listening'):
        json_output[page.lower()] = []
      else:
        json_output[page.lower()] = {}
      row = 0
    text_output = '{} {}\n'.format(text_output, parsed_line)
    if page == 'Status':
      if row == 0:
        json_output['status']['deamon'] = parsed_line[5].replace('(','')
        json_output['status']['version'] = parsed_line[6]
        json_output['status']['os'] = ' '.join(parsed_line[7:10]).replace(')','')
      if row == 1:
        json_output['status']['uptime'] = '{} {}'.format(parsed_line[1], parsed_line[2])
        json_output['status']['since'] = '{} {} {}:{}:{} {}'.format(parsed_line[4], parsed_line[5], parsed_line[6][0:2], parsed_line[6][2:4], parsed_line[6][4:6], parsed_line[7])
      if row == 2:
        json_output['status']['malloc'] = {}
        json_output['status']['malloc']['sbrk'] = parsed_line[2]
        json_output['status']['malloc']['mmap'] = parsed_line[4]
        json_output['status']['malloc']['used'] = parsed_line[6]
        json_output['status']['malloc']['free'] = parsed_line[8]
      if row == 3:
        json_output['status']['workers'] = {}
        json_output['status']['workers']['threads'] = parsed_line[2]
        json_output['status']['workers']['total'] = parsed_line[4]
        json_output['status']['workers']['working'] = parsed_line[6]
        json_output['status']['workers']['queue'] = parsed_line[10]
        json_output['status']['workers']['scheduled'] = parsed_line[12]
      if row == 4:
        json_output['status']['plugins'] = parsed_line[2:]

    elif page == 'Listening':
      if row > 0:
        json_output['listening'].append(parsed_line[0])

    elif page == 'Connections':
      if row > 0:
        if not json_output['connections'].get(parsed_line[0]): 
          json_output['connections'][parsed_line[0]] = {}
        if parsed_line[1] in confs:
          if parsed_line[1] == 'child':
            json_output['connections'][parsed_line[0]][parsed_line[1]] = {}
            json_output['connections'][parsed_line[0]][parsed_line[1]]['from'] = parsed_line[2]
            json_output['connections'][parsed_line[0]][parsed_line[1]]['to'] = parsed_line[3]
            json_output['connections'][parsed_line[0]][parsed_line[1]]['type'] = parsed_line[4]
            json_output['connections'][parsed_line[0]][parsed_line[1]]['dpdaction'] = parsed_line[5].replace('dpdaction', '')
          else:
            json_output['connections'][parsed_line[0]][parsed_line[1]] = {
              'from': parsed_line[2].replace('[','').replace(']', ''),
              'security': parsed_line[3:]
            }

    elif page == 'Routed':
      if row > 0:
        if not json_output['routed'].get(parsed_line[0]): 
          json_output['routed'][parsed_line[0]] = {}
        if 'reqid' in parsed_line:
          json_output['routed'][parsed_line[0]]['type'] = ' '.join(parsed_line[1:3])
          json_output['routed'][parsed_line[0]]['reqid'] = parsed_line[-1]
        else:
          json_output['routed'][parsed_line[0]]['from'] = parsed_line[1]
          json_output['routed'][parsed_line[0]]['to'] = parsed_line[2]

    elif page == 'Security':
      if row > 0:
        print(parsed_line)
        if 'ESTABLISHED' in parsed_line:
          json_output['security'][parsed_line[0]] = 'ESTABLISHED'
        elif 'INSTALLED' in parsed_line:
          json_output['security'][parsed_line[0]] = 'INSTALLED'
      else:
        json_output['security']['status'] = {}
        json_output['security']['status']['up'] = parsed_line[2].replace('(','')
        json_output['security']['status']['connecting'] = parsed_line[4]

    row += 1


# if (len(sys.argv) > 4):
#   print(json_output.get(sys.argv[1], {}).get(sys.argv[2], {}).get(sys.argv[3], {}).get(sys.argv[4], default))
# elif (len(sys.argv) > 3):
#   print(json_output.get(sys.argv[1], {}).get(sys.argv[2], {}).get(sys.argv[3], default))
# elif (len(sys.argv) > 2):
#   print(json_output.get(sys.argv[1], {}).get(sys.argv[2], default))
# elif (len(sys.argv) > 1):
#   if sys.argv[1] == 'discovery':
#     discovery = {'data':[]}
#     for conn in json_output['connections'].keys():
#       discovery['data'].append({'{#CONN}': conn})
#     print(json.dumps(discovery))
#   elif sys.argv[1] == 'json':
#     print(json.dumps(json_output))
# else:
#   print(text_output)
