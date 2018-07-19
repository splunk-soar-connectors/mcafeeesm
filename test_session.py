import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()

base_url = 'https://10.1.16.156'
base_url9 = 'https://10.1.16.77'

body = {
        'username': 'YXBpLXVzZXI=',
        'password': 'UGg0bnQwbSE=',
        'locale': 'en_US'
    }

auth = ('NGCP', 'Ph4nt0m!')

r = s.post(base_url + '/rs/esm/v2/login/', json=body, verify=False)
# r = s.post(base_url9 + '/rs/esm/login/', auth=auth, verify=False)

headers = {'X-Xsrf-Token': r.headers['Xsrf-Token']}

r = s.post(base_url + '/rs/esm/v2/qryGetSelectFields?type=EVENT&groupType=NO_GROUP', headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/qryGetSelectFields?type=EVENT&groupType=NO_GROUP', verify=False)

# r = s.post(base_url + '/rs/esm/v2/qryGetFilterFields', json=body, verify=False)
# r = s.post(base_url9 + '/rs/esm/qryGetFilterFields', verify=False)

# print r.status_code
# print r.text

# for filt in r.json():
#     if filt['name'] == 'EventCount':
#         print ['filt.name']
#         print ['filt.types']

# r = s.post(base_url + '/rs/esm/v2/sysGetWatchlists?hidden=true&dynamic=true&writeOnly=true&indexedOnly=true', headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/sysGetWatchlists', verify=False)

# body = {}
# body['id'] = 4
# r = s.post(base_url + '/rs/esm/v2/sysGetWatchlistDetails', json=body, headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/sysGetWatchlistDetails', json=body, verify=False)

body = {
    "config": {
        "fields": [
            {
                "name": "AlarmTriggerDate"
            }
        ],
        "limit": 100,
        "order": [
            {
                "field": {
                    "name": "AlarmTriggerDate"
                },
                "direction": "ASCENDING"
            }
        ],
        "filters": [
            {
                "type": "EsmFieldFilter",
                "field": "AlarmStatus",
                "operator": "DOES_NOT_EQUAL",
                "values": [
                    {
                        "type": "EsmBasicValue",
                        "value": "cheese"
                    }
                ]
            }
        ]
    }
}

# r = s.post(base_url + '/rs/esm/v2/qryExecuteDetail?type=TRIGGERED_ALARMS_QUERY&reverse=false', json=body, headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/qryExecuteDetail?type=EVENT&reverse=false', json=body, verify=False)

# print r.status_code
# print r.text

# body = {"resultID": r.json()['resultID']}
# body = {"resultID": {'value': r.json()['resultID']}}

# r = s.post(base_url + '/rs/esm/v2/qryGetStatus', json=body, headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/qryGetStatus', json=body, verify=False)

# print r.status_code
# print r.text

# r = s.post(base_url + '/rs/esm/v2/qryGetResults?startPos=0&numRows=100&reverse=false', json=body, headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/qryGetResults?startPos=0&numRows=0&reverse=false', json=body, verify=False)

# r = s.post(base_url + '/rs/esm/v2/alarmGetTriggeredAlarms?triggeredTimeRange=CUSTOM&customStart=2018-07-01T23:41:43Z&customEnd=2018-07-16T23:42:37Z',
#         params=body, headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/qryGetResults?startPos=0&numRows=0&reverse=false', json=body, verify=False)

body = {
        "eventId": '306-50',
        "fields": [
            {
                "name": "Message_Text"
            },
            {
                "name": "EventCount"
            }
        ]
    }

# r = s.post(base_url + '/rs/esm/v2/qryGetCorrEventDataForID?queryType=EVENT', json=body, headers=headers, verify=False)
# r = s.post(base_url9 + '/rs/esm/qryGetResults?startPos=0&numRows=0&reverse=false', json=body, verify=False)

print r.status_code
print r.text
