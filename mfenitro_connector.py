# --
# File: mfenitro_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --
# Phantom App imports

import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import re
import time
from mfenitro_consts import *
from datetime import datetime, timedelta
import requests
import json
from pytz import timezone
import pytz
from copy import deepcopy

import request_fields

_container_common = {
    "description": "Container added by Phantom McAfee ESM App",
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

_artifact_common = {
    "label": "artifact",
    "type": "network",
    "description": "Artifact added by Phantom McAfee ESM App",
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}


class MFENitroConnector(BaseConnector):

    ACTION_ID_TEST_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_LIST_FIELDS = "list_fields"

    def __init__(self):

        super(MFENitroConnector, self).__init__()
        self._state = {}
        self._headers = None

    def _handle_error_response(self, response, result):

        data = response.text

        if ('application/json' in response.headers.get('Content-Type')) and (data):
            data = data.replace('{', '[').replace('}', ']')

        message = "Status Code: {0}. Data: {1}".format(response.status_code, data if data else 'Not Specified')

        self.debug_print("Rest error: {0}".format(message))

        return result.set_status(phantom.APP_ERROR, message)

    def _make_rest_call(self, action_result, endpoint, data=None, method="post"):

        config = self.get_config()
        base_url = NITRO_BASE_URL % config["base_url"]

        request_func = getattr(requests, method)

        # handle the error in case the caller specified a non-existant method
        if (not request_func):
            return (action_result.set_status(phantom.APP_ERROR, "API Unsupported method: {0}".format(method)), None)

        """
        headers = dict(self._headers)
        if (method == 'delete'):
            del(headers['Content-Type'])
        """

        try:
            result = request_func(base_url + endpoint, json=data if data else None, headers=self._headers, verify=config["verify_server_cert"])
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Error connecting to Device: {0}".format(e)), None)

        # The only status code that is success for posts is 200
        if result.status_code != 200:
            return (self._handle_error_response(result, action_result), None)

        if method == "delete":
            return (phantom.APP_SUCCESS, None)

        try:
            resp_json = result.json()
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Error converting response to json"), None)

        return (phantom.APP_SUCCESS, resp_json)

    def _delete_session(self):

        if (not self._headers):
            return phantom.APP_SUCCESS

        if ('Authorization' not in self._headers):
            return phantom.APP_SUCCESS

        ret_val, ack_data = self._make_rest_call(ActionResult(), "logout", method="delete")

        if (phantom.is_fail(ret_val)):
            self.save_progress("Unable to logout, non-fatal, ignoring")

        return ret_val

    def _test_connection(self, param):

        config = self.get_config()

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._validate_my_config(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Config Validation failed")
            return action_result.get_status()

        # sessions are created to ensure continuous api calls
        ret_val = self._create_session(config, param, action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity falied")
            return self.get_status()

        self.save_progress("Session created, testing Query")

        ret_val, response = self._make_rest_call(action_result, TEST_QUERY)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity falied")
            return action_result.get_status()

        self.save_progress("Query done, Logging out")

        self.save_progress("Test connectivity Passed")

        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def initialize(self):
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        self._delete_session()

        return phantom.APP_SUCCESS

    def _create_session(self, config, param, action_result):

        self.save_progress("Creating Session")

        # create session usnig the credentials
        login_url = LOGIN_URL % config["base_url"]

        login_headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        try:
            login_response = requests.post(login_url, headers=login_headers, auth=(config['username'], config['password']), verify=config["verify_server_cert"])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error creating session", e)

        if (not (200 <= login_response.status_code < 300)):
            return self._handle_error_response(login_response, action_result)

        try:
            session = login_response.headers['location']
        except:
            return self.set_status(phantom.APP_ERROR, "Error creating session. Response does not contain required field 'location'")

        # the returned session variable should be used as header instead of auth
        self._headers = {'Authorization': 'Session ' + session, 'Content-Type': 'application/json', 'Accept': 'application/json'}

        return phantom.APP_SUCCESS

    def _clean_response(self, input_dict):

        if (input_dict is None):
            return 'Input dict is None'

        string = json.dumps(input_dict)

        return string.replace('{', '-').replace('}', '-')

    def _check_query_status(self, action_result, result_id, query_timeout):

        result_req_json = {"resultID": {"value": result_id}}

        EWS_SLEEP_SECS = 2

        self.send_progress("Query complete: 0 %")
        for retry in xrange(0, query_timeout, EWS_SLEEP_SECS):
            time.sleep(EWS_SLEEP_SECS)
            ret_val, ret_data = self._make_rest_call(action_result, GET_STATUS_URL, data=result_req_json)

            if (phantom.is_fail(ret_val)):
                # The query to get the status of the query failed, treat it as a transient issue and try again
                self.debug_print("The query to get the status of the query failed, non fatal error")
                continue

            # parse the response
            percent_complete = ret_data.get('return', {}).get('percentComplete', 'Unknown')
            self.send_progress("Query complete: {0} %".format(percent_complete))
            is_complete = ret_data.get('return', {}).get('complete')
            if (is_complete):
                self.send_progress("Processing")
                return (phantom.APP_SUCCESS, True, "Query finished")

        self.debug_print("Query in-complete")
        return (phantom.APP_SUCCESS, False, NITRO_QUERY_TIMEOUT_ERR)

    def _perform_calls(self, req_json, action_result, query_timeout):

        # Execute Query
        ret_val, ack_data = self._make_rest_call(action_result, EXECUTE_QUERY_URL, data=req_json)
        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        # the result id is mentioned in the response of the query
        # the result id and session header are the keys for the result retrieval
        result_id = ack_data.get('return', {}).get("resultID", {}).get("value")
        if not result_id:
            return (action_result.set_status(phantom.APP_ERROR, "Response did not contain required key resultID or value"), None)

        # check the status of the query
        # Error occurs if try to fetch without checking status
        ret_val, query_finished, message = self._check_query_status(action_result, result_id, query_timeout)
        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        if (not query_finished):
            return (action_result.set_status(phantom.APP_ERROR, message), None)

        # Ignoring the results of the status as a failed query will be handled with no result
        result_req_json = {"resultID": {"value": result_id}}
        ret_val, ret_data = self._make_rest_call(action_result, GET_RESULTS_URL, data=result_req_json)

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, ret_data)

    def _get_next_start_time(self, last_time):

        config = self.get_config()
        device_tz_sting = config[NITRO_JSON_TIMEZONE]
        to_tz = timezone(device_tz_sting)

        # get the time string passed into a datetime object
        last_time = datetime.strptime(last_time, DATETIME_FORMAT)
        last_time = last_time.replace(tzinfo=to_tz)

        # add a second to it
        last_time = last_time + timedelta(seconds=1)

        # format it
        return last_time.strftime(DATETIME_FORMAT)

    def _get_first_start_time(self):

        config = self.get_config()

        # Get the poll time in minutes
        poll_time = config.get(NITRO_JSON_POLL_TIME, NITRO_POLL_TIME_DEFAULT)

        # get the device timezone
        device_tz_sting = config[NITRO_JSON_TIMEZONE]
        to_tz = timezone(device_tz_sting)

        # get the start time to use, i.e. current - poll minutes in UTC
        start_time = datetime.utcnow() - timedelta(minutes=poll_time)
        start_time = start_time.replace(tzinfo=pytz.utc)

        # convert it to the timezone of the device
        to_dt = to_tz.normalize(start_time.astimezone(to_tz))

        return to_dt.strftime(DATETIME_FORMAT)

    def _get_end_time(self):

        config = self.get_config()

        # get the timezone of the device
        device_tz_sting = config[NITRO_JSON_TIMEZONE]
        to_tz = timezone(device_tz_sting)

        # get the current time
        end_time = datetime.utcnow().replace(tzinfo=pytz.utc)

        # convert it to the timezone of the device
        to_dt = to_tz.normalize(end_time.astimezone(to_tz))

        return to_dt.strftime(DATETIME_FORMAT)

    def _get_query_params(self, param):

        # function to separate on poll and poll now
        config = self.get_config()
        limit = config["max_containers"]
        query_params = dict()
        last_time = self._state.get(NITRO_JSON_LAST_DATE_TIME)

        if self.is_poll_now():
            limit = param.get("container_count", 100)
            query_params["customStart"] = self._get_first_start_time()
        elif (self._state.get('first_run', True)):
            self._state['first_run'] = False
            limit = config.get("first_run_max_events", 100)
            query_params["customStart"] = self._get_first_start_time()
        elif (last_time):
            query_params["customStart"] = last_time
        else:
            query_params["customStart"] = self._get_first_start_time()

        query_params["limit"] = limit
        query_params["customEnd"] = self._get_end_time()

        if (not self.is_poll_now()):
            self._state[NITRO_JSON_LAST_DATE_TIME] = query_params["customEnd"]

        return query_params

    def _validate_my_config(self, action_result):

        config = self.get_config()

        # validate the query timeout
        query_timeout = config.get(NITRO_JSON_QUERY_TIMEOUT, int(NITRO_DEFAULT_TIMEOUT_SECS))

        try:
            query_timeout = int(query_timeout)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid query timeout value", e)

        if (query_timeout < int(NITRO_DEFAULT_TIMEOUT_SECS)):
            return action_result.set_status(phantom.APP_ERROR, "Please specify a query timeout value greater or equal to {0}".format(NITRO_DEFAULT_TIMEOUT_SECS))

        config[NITRO_JSON_QUERY_TIMEOUT] = query_timeout

        poll_time = config.get(NITRO_JSON_POLL_TIME, int(NITRO_POLL_TIME_DEFAULT))

        try:
            poll_time = int(poll_time)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid Poll Time value", e)

        if (poll_time < int(NITRO_POLL_TIME_DEFAULT)):
            return action_result.set_status(phantom.APP_ERROR, "Please specify the poll time interval value greater than {0}".format(NITRO_POLL_TIME_DEFAULT))

        config[NITRO_JSON_POLL_TIME] = poll_time

        max_containers = config.get(NITRO_JSON_MAX_CONTAINERS, int(NITRO_DEFAULT_MAX_CONTAINERS))

        try:
            max_containers = int(max_containers)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid {0} value".format(NITRO_JSON_MAX_CONTAINERS), e)

        if (max_containers < int(NITRO_DEFAULT_MAX_CONTAINERS)):
            return action_result.set_status(phantom.APP_ERROR,
                    "Please specify the {0} value greater than {1}. Ideally this value should be greater than the max events generated within a second on the device.".format(
                        NITRO_JSON_MAX_CONTAINERS, NITRO_DEFAULT_MAX_CONTAINERS))

        config[NITRO_JSON_MAX_CONTAINERS] = max_containers

        first_max_containers = config.get(NITRO_JSON_FIRST_MAX_CONTAINERS, int(NITRO_DEFAULT_MAX_CONTAINERS))

        try:
            first_max_containers = int(first_max_containers)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid {0} value".format(NITRO_JSON_FIRST_MAX_CONTAINERS), e)

        if (first_max_containers < int(NITRO_DEFAULT_MAX_CONTAINERS)):
            return action_result.set_status(phantom.APP_ERROR,
                    "Please specify the {0} value greater than {1}. Ideally this value should be greater than the max events generated within a second on the device.".format(
                        NITRO_JSON_FIRST_MAX_CONTAINERS, NITRO_DEFAULT_MAX_CONTAINERS))

        config[NITRO_JSON_FIRST_MAX_CONTAINERS] = first_max_containers

        return phantom.APP_SUCCESS

    def _get_filter_fields(self, action_result):

        ret_val, resp_data = self._make_rest_call(action_result, 'qryGetFilterFields', method="get")

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        return_value = resp_data.get('return')

        if (not return_value):
            return (action_result.set_status(phantom.APP_ERROR, "Response does not contain required key 'return'"), None)

        return (phantom.APP_SUCCESS, return_value)

    def _parse_filter(self, action_result):

        """
           "filters": [{
            "type": "EsmFieldFilter",
            "field": {"name": "Action"},
            "operator": "EQUALS",
            "values": [{
                "type": "EsmBasicValue",
                "value": "8"
            }]
           }],
           """

        config = self.get_config()

        filters = config.get(NITRO_JSON_FILTERS)

        if (not filters):
            return (phantom.APP_SUCCESS, None)

        # try to load the filters as a json

        try:
            filters = json.loads(filters)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR,
                    "Unable to parse the filter json string Error: {0}".format(str(e))), None)

        if (type(filters) != list):
            return action_result.set_status(phantom.APP_ERROR,
                    "Filters need to be a list, even in the case of a single filter, please specify a list with one item")

        ret_val, resp_data = self._get_filter_fields(action_result)
        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        try:
            valid_filter_fields = [x['name'] for x in resp_data]
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to extract allowed filter fields from response JSON"), None)

        for i, curr_filter in enumerate(filters):

            filter_type = curr_filter.get('type')
            if (not filter_type):
                return (action_result.set_status(phantom.APP_ERROR, "Filter # {0} missing 'type' key".format(i)), None)

            filter_field = curr_filter.get('field')
            if (not filter_field):
                return (action_result.set_status(phantom.APP_ERROR, "Filter # {0} missing 'field' key".format(i)), None)

            field_name = filter_field.get('name')
            if (not field_name):
                return (action_result.set_status(phantom.APP_ERROR, "Filter # {0} missing 'field.name' key".format(i)), None)

            if (field_name not in valid_filter_fields):
                return (action_result.set_status(phantom.APP_ERROR, "Filter # {0} field name '{1}' cannot be filtered upon".format(i, field_name)), None)

            values = curr_filter.get('values')
            if (not values):
                return (action_result.set_status(phantom.APP_ERROR, "Filter # {0} missing 'values' key".format(i)), None)

            if (type(values) != list):
                return (action_result.set_status(phantom.APP_ERROR,
                        "Filter # {0} 'values' key needs to be a list, even in the case of a single value, please specify a list with one item".format(i)), None)

            for j, curr_value in enumerate(values):

                value_type = curr_value.get('type')
                if (not value_type):
                    return (action_result.set_status(phantom.APP_ERROR, "Filter # {0}, value # {1} missing 'type' key".format(i, j)), None)

                value_value = curr_value.get('value')
                if (not value_value):
                    return (action_result.set_status(phantom.APP_ERROR, "Filter # {0}, value # {1} missing 'value' key".format(i, j)), None)

        # the filter seems to be fine
        return (phantom.APP_SUCCESS, filters)

    def _list_fields(self, param):

        config = self.get_config()

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._validate_my_config(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # create a session to start the action
        ret_val = self._create_session(config, param, action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Failed to create the session. Cannot continue")
            return self.get_status()

        ret_val, resp_data = self._get_filter_fields(action_result)
        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        [action_result.add_data(x) for x in resp_data]

        action_result.set_summary({'total_fields': len(resp_data)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_request_blocks(self, query_dict, filter_dict):

        """This function could be implemented in fewer + complicated + tough_to_read lines of code
        but breaking things into multiple lines to keep things simple
        """

        def _update_block(req_block, field_list):
            req_block['config'].update(query_dict)
            req_block['config']['fields'].extend(field_list)
            req_block['config']['fields'].extend(request_fields.common_fields)

            if (filter_dict):
                req_block['config']['filters'] = filter_dict

        block_length = 50 - len(request_fields.common_fields)

        # first get the field blocks
        field_blocks = [request_fields.fields_list[i:i + block_length] for i in xrange(0, len(request_fields.fields_list), block_length)]

        # create request blocks from the base
        request_blocks = [deepcopy(request_fields.req_part_base) for x in field_blocks]

        # request_blocks = [x['config']['fields'] = y for x in request_blocks, y in fields_blocks]
        # Add the query_dict to the blocks
        # map(lambda x: x['config'].update(query_dict), request_blocks)

        # Add the fields
        # map(lambda x, y: x['config']['fields'].extend(y), request_blocks, field_blocks)
        map(_update_block, request_blocks, field_blocks)

        return (phantom.APP_SUCCESS, request_blocks)

    def _on_poll(self, param):

        config = self.get_config()

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._validate_my_config(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # create a session to start the action
        ret_val = self._create_session(config, param, action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Failed to create the session. Cannot continue")
            return self.get_status()

        # Get the query_params based on the type of poll
        query_params = self._get_query_params(param)

        # Get the filters if configured
        ret_val, filter_dict = self._parse_filter(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        ret_val, request_blocks = self._create_request_blocks(query_params, filter_dict)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Unable to break fields into multiple request blocks, Polling Failed")
            return action_result.get_status()

        # now make as many queries as required

        message = "Getting max {0} event(s) between {1} and {2}".format(
                query_params.get('limit', '-'),
                query_params.get('customStart', '-').replace('T', ' ').replace('Z', ''),
                query_params.get('customEnd', '-').replace('T', ' ').replace('Z', ''))
        self.save_progress(message)

        query_timeout = config[NITRO_JSON_QUERY_TIMEOUT]

        total_parts = len(request_blocks)

        result_rows = []

        for i, request_block in enumerate(request_blocks):

            self.send_progress("Polling the event fields in part {0} of {1}".format(i + 1, total_parts))

            ret_val, curr_result = self._perform_calls(request_block, action_result, query_timeout)

            if (phantom.is_fail(ret_val)):
                self.save_progress("Unable to fetch event details for 1st Part, Polling Failed")
                return action_result.get_status()

            # The response is like a table, with columns and rows
            # every column = {'name': 'Column Name'}
            # every row = {'values': ['Column Name Value']}
            # So basically we have to take the Column Name and the respective Value and if a value exists then add it to a dictionary.
            # We will create a dictionary of key value pair for every row, since that's how containers and artifacts are Diced.
            # Also if the rows array is empty that means no events were matched

            rows = curr_result.get('return', {}).get('rows')
            columns = curr_result.get('return', {}).get('columns')

            no_of_events = len(rows)

            if (i == 0):
                self.save_progress("Got {0} event{1}", no_of_events, '' if (no_of_events == 1) else 's')

            if (not rows):
                return action_result.set_status(phantom.APP_SUCCESS)

            if (i == 0):
                result_rows = [dict() for x in range(0, no_of_events)]

            # The app makes multiple queries to the device, each time asking for a list of fields for max number of events that occured between a time range
            # What that means is that in the Nth iteration where N > 0 we might get more events, than when N == 0.
            # This means there was a new event generated in the same time range that we are querying, since we are sorting it ASCENDING it will be at the end
            # and should be dropped.
            if (len(rows) > len(result_rows)):
                self.debug_print("Need to trim the rows")
                del rows[len(result_rows)]
                no_of_events = len(rows)

            for i, curr_row in enumerate(rows):

                curr_row_dict = {}

                values = curr_row.get('values')

                # The columns list contains the column names and the values list contains the value of each column
                # Map this into a dictionary that has the column name as the key and the value is picked from the values list.
                # Basically use the item at index N of the columns list as the name of the key and the item at index N of the values
                # list as the value, _only_ if a value exists. So during the mapping ignore keys that have an empty value.
                map(lambda x, y: curr_row_dict.update({x['name']: y}) if y else False, columns, values)

                # curr_row_dict = {k: v for k, v in curr_row_dict.iteritems() if v}
                result_rows[i].update(curr_row_dict)

        self.send_progress("Event fields acquired successfully. Closing session")

        ret_val = self._handle_result_rows(result_rows)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Polling Failed")
            return action_result.set_status(phantom.APP_ERROR, "Polling failed")

        self.save_progress("Event polling successful")

        return action_result.set_status(phantom.APP_SUCCESS, "Polling event success")

    def _handle_result_rows(self, events):

        for i, curr_event in enumerate(events):

            self.send_progress("Working on Event # {0}".format(i + 1))

            # framing the cef dict
            cef_dict = self._frame_cef_dict(curr_event)

            # create the container
            self._create_container(curr_event, cef_dict)

        # store the date time of the last event
        if (events and (not self.is_poll_now())):

            config = self.get_config()

            last_date_time = events[-1]["Alert.FirstTime"]

            # convert what we got into ZULU, This is a bit whack, Nitro requires the string to contain T and Z
            # but the time between these 2 chars has to be in the timezone configured on the device
            self._state[NITRO_JSON_LAST_DATE_TIME] = datetime.strptime(last_date_time, NITRO_RESP_DATETIME_FORMAT).strftime(DATETIME_FORMAT)

            date_strings = [x["Alert.FirstTime"] for x in events]

            date_strings = set(date_strings)

            if (len(date_strings) == 1):
                self.debug_print("Getting all containers with the same date, down to the second." +
                        " That means the device is generating max_containers=({0}) per second.".format(config[NITRO_JSON_MAX_CONTAINERS]) +
                        " Skipping to the next second to not get stuck.")
                self._state[NITRO_JSON_LAST_DATE_TIME] = self._get_next_start_time(self._state[NITRO_JSON_LAST_DATE_TIME])

        return phantom.APP_SUCCESS

    def _frame_cef_keys(self, key):

        # changing the nitro keys to camel case to match cef formatting
        name = re.sub('[^A-Za-z0-9]+', '', key)
        name = name[0].lower() + name[1:]
        if name in CEF_MAP.keys():
            name = CEF_MAP[name]
        return name

    def _frame_cef_dict(self, raw_event_data):

        # framing the cef dict
        cef_dict = {}

        for key, v in raw_event_data.iteritems():

            if (v == '0'):
                # A bit dangerous to ignore keys with '0' in them, however the older versions of the app
                # would do it and no one complained, in any case the raw data is present in the container
                # we are removing this key only from the cef dictionary, so should be fine
                continue
            # change the keys to cef format
            name = self._frame_cef_keys(key)
            # pick the corresponding entry from the combined raw event data
            cef_dict[name] = raw_event_data[key]

        return cef_dict

    def _create_container(self, event_data, cef_dict):

        container = {}

        # create the source data identifier
        """
        sdi_part1 = event_data["columns"].index(FIRST_DICT)
        sdi_part2 = event_data["columns"].index(MSG_DICT)
        sdidentifier = event_data["values"][sdi_part2] + event_data["values"][sdi_part1]
        sdi = event_data["values"][event_data["columns"].index(ID_DICT)] + sdidentifier
        """
        rule_msg = event_data.get('Rule.msg', 'Unknown.Rule.Msg')
        first_time = event_data.get('Alert.FirstTime', '')
        sdi = "{0}{1}{2}".format(event_data.get('Alert.ID', ''), rule_msg, first_time)

        container.update(_container_common)
        container['source_data_identifier'] = sdi
        container['name'] = rule_msg + " at " + first_time
        container['data'] = {'raw_event': event_data}
        ret_val, message, container_id = self.save_container(container)
        self.debug_print(CREATE_CONTAINER_RESPONSE.format(ret_val, message, container_id))

        if (phantom.is_fail(ret_val)):
            message = "Failed to add Container error msg: {0}".format(message)
            self.debug_print(message)
            return phantom.APP_ERROR, "Failed Creating container"

        if (not container_id):
            message = "save_container did not return a container_id"
            self.debug_print(message)
            return phantom.APP_ERROR, "Failed creating container"

        artifact = {}
        artifact.update(_artifact_common)
        artifact['container_id'] = container_id
        artifact['source_data_identifier'] = 0  # We are only going to add a single artifact
        artifact['cef'] = cef_dict
        artifact['cef_types'] = NITRO_CEF_CONTAINS
        artifact['name'] = "Event Artifact"
        artifact['run_automation'] = True
        ret_val, status_string, artifact_id = self.save_artifact(artifact)

        if (phantom.is_fail(ret_val)):
            return phantom.APP_ERROR, "Failed to add artifact"

        return phantom.APP_SUCCESS, "Successfully created container and added artifact"

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()

        if (action_id == self.ACTION_ID_TEST_CONNECTIVITY):
            ret_val = self._test_connection(param)
        elif (action_id == self.ACTION_ID_ON_POLL):
            ret_val = self._on_poll(param)
        elif (action_id == self.ACTION_ID_LIST_FIELDS):
            ret_val = self._list_fields(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = MFENitroConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
