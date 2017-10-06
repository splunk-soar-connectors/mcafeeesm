# --
# File: mfenitro_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# NITRO_JSON_POLL_HOURS = "poll_hours"
NITRO_JSON_POLL_TIME = "poll_time"
NITRO_JSON_LAST_DATE_TIME = "last_date_time"
NITRO_JSON_TIMEZONE = "timezone"
NITRO_JSON_MAX_CONTAINERS = "max_containers"
NITRO_JSON_FIRST_MAX_CONTAINERS = "first_run_max_events"
NITRO_JSON_FILTERS = "filters"
NITRO_JSON_QUERY_TIMEOUT = "query_timeout"

TEST_QUERY = "qryGetSelectFields?type=EVENT&groupType=NO_GROUP"
NITRO_BASE_URL = "%s/rs/esm/"
LOGIN_URL = '%s/rs/esm/login'
EXECUTE_QUERY_URL = "qryExecuteDetail?type=EVENT&reverse=false"
CEF_MAP = {"dstMac": "destinationMacAddress", "dstIP": "destinationAddress", "srcIP": "sourceAddress", "srcMac": "sourceMacAddress"}
QUERY_MAX_WAIT_TIME = 5
GET_RESULTS_URL = "qryGetResults?startPos=0&numRows=1000000&reverse=false"
GET_STATUS_URL = "qryGetStatus"
GET_EVENTS_URL = "qryGetCorrEventDataForID?queryType=EVENT"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000%z"
NITRO_RESP_DATETIME_FORMAT = "%m/%d/%Y %H:%M:%S"
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

NITRO_DEFAULT_MAX_CONTAINERS = 10
# NITRO_DEFAULT_POLL_HOURS = 1
NITRO_CEF_CONTAINS = {
        'nDDeviceNDDevIDDstManagementIP': ['ip'],
        'nDDeviceNDDevIDSrcManagementIP': ['ip'],
        'alertDstIP': ['ip'],
        'alertSrcIP': ['ip'],
        'alertDstMac': ['mac address'],
        'alertSrcMac': ['mac address'],
        'userIDSrc': ['user name'],
        'alertAlertID': ['esm event id']}
NITRO_POLL_TIME_DEFAULT = "2"
