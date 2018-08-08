# --
# File: parse_fields.py
#
# Copyright (c) 2016-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --

import json

in9 = open('fields_9.json', 'r').read()
in10 = open('fields_10.json', 'r').read()

json9 = json.loads(in9)
json10 = json.loads(in10)

list9 = []
for field in json9['return']:
    list9.append(field['name'])

list10 = []
for field in json10:
    list10.append(field['name'])

print '9 only:\n'
for field in list9:
    if field not in list10:
        print field
print '\n\n'

print '10 only:\n'
for field in list10:
    if field not in list9:
        print field
print '\n\n'

print 'both:\n'
for field in list10:
    if field in list9:
        print field
