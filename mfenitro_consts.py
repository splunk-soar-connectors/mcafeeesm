# File: mfenitro_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --

# NITRO_JSON_POLL_HOURS = "poll_hours"
NITRO_JSON_POLL_TIME = "poll_time"
NITRO_JSON_LAST_DATE_TIME_EVENTS = "last_date_time_events"
NITRO_JSON_LAST_DATE_TIME_ALARMS = "last_date_time_alarms"
NITRO_JSON_TIMEZONE = "timezone"
NITRO_JSON_MAX_CONTAINERS = "max_containers"
NITRO_JSON_FIRST_MAX_CONTAINERS = "first_run_max_events"
NITRO_JSON_FILTERS = "filters"
NITRO_JSON_QUERY_TIMEOUT = "query_timeout"

NITRO_BASE_URL = "{0}/rs/esm/"
GET_STATUS_URL = "qryGetStatus"
GET_EVENTS_URL = "qryGetCorrEventDataForID?queryType=EVENT"
TEST_QUERY = "qryGetSelectFields?type=EVENT&groupType=NO_GROUP"
EXECUTE_QUERY_URL = "qryExecuteDetail?type=EVENT&reverse=false"
GET_ALARMS_URL = "alarmGetTriggeredAlarms"
GET_RESULTS_URL = "qryGetResults?startPos=0&numRows=1000000&reverse=false"
GET_WATCHLISTS_URL = "sysGetWatchlists?hidden=true&dynamic=true&writeOnly=true&indexedOnly=true"

CEF_MAP = {"dstMac": "destinationMacAddress", "dstIP": "destinationAddress", "srcIP": "sourceAddress", "srcMac": "sourceMacAddress"}
QUERY_MAX_WAIT_TIME = 5
CEF_EXCLUDE = [u'', '', "0", u'0']
ID_DICT = {'name': 'Alert.ID'}
FIRST_DICT = {'name': 'Alert.FirstTime'}
MSG_DICT = {'name': 'Rule.msg'}
DEFAULT_FIELD_LIST = ["LastTime", "Rule.msg", "DSIDSigID", "SrcIP", "DstIP"]
cef_field_list = ['startTime', 'destinationUserName', 'destinationAddress', 'destinationMacAddress',
        'destinationPort', 'receiptTime', 'transportProtocol', 'sourceMacAddress',
        'sourcePort', 'applicationProtocol', 'deviceExternalId', 'sourceUserName',
        'sourceAddress', 'fileHash', 'message', 'src', 'sourceUserId', 'filePath',
        'fileSize', 'fileType', 'fileName', 'bytesIn', 'bytesOut', 'requestCookies',
        'destinationUserId', 'destinationHostName', 'deviceAddress']
CREATE_CONTAINER_RESPONSE = "save_container returns, value: {0}, reason: {1}, id: {2}"
NITRO_DEFAULT_TIMEOUT_SECS = 20
NITRO_QUERY_TIMEOUT_ERR = "Query not completed in the configured time. Please increase the query_timeout value in the asset config and try again."
NITRO_QUERY_COUNT = 50000

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NITRO_RESP_DATETIME_FORMAT = "%m/%d/%Y %H:%M:%S"

NITRO_DEFAULT_MAX_CONTAINERS = 10
NITRO_CEF_CONTAINS = {
        'nDDeviceNDDevIDDstManagementIP': ['ip'],
        'nDDeviceNDDevIDSrcManagementIP': ['ip'],
        'alertDstIP': ['ip'],
        'alertSrcIP': ['ip'],
        'alertDstMac': ['mac address'],
        'alertSrcMac': ['mac address'],
        'userIDSrc': ['user name'],
        'alertAlertID': ['esm event id']}
NITRO_POLL_TIME_DEFAULT = 2

# Error message constants
NITRO_ERR_CODE_MSG = "Error code unavailable"
NITRO_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
NITRO_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Validate int parameters msg
MAX_CONTAINERS_KEY = "'max containers' configuration parameter"
FIRST_MAX_CONTAINERS_KEY = "'first run max events' configuration parameter"
POLL_TIME_KEY = "'poll time' configuration parameter"
QUERY_TIMEOUT_KEY = "'query timeout' configuration parameter"
WATCHLIST_ID_KEY = "'watchlist id' action parameter"
