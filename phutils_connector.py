# File: phutils_connector.py
# Copyright (c) 2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.import datetime
from phantom.action_result import ActionResult
import phantom.app as phantom
from phantom.base_connector import BaseConnector
import requests
from requests.auth import HTTPBasicAuth
import json
import re
from datetime import datetime
from datetime import timedelta
import time
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta

class phutilities_connector(BaseConnector):
    
    def initialize(self):

        return phantom.APP_SUCCESS

    def finalize(self):
        return

    def handle_exception(self, exception_object):
        """All the code within BaseConnector::_handle_action is within a 'try:
        except:' clause. Thus if an exception occurs during the execution of
        this code it is caught at a single place. The resulting exception
        object is passed to the AppConnector::handle_exception() to do any
        cleanup of it's own if required. This exception is then added to the
        connector run result and passed back to spawn, which gets displayed
        in the Phantom UI.
        """

        return

    def handle_action(self, param):

            action_id = self.get_action_identifier()

            supported_actions = {
                'test_connectivity': self._test_connectivity,
                'add_to_datapath': self._add_to_datapath,
                'format_string': self._format_string,
                'modify_date': self._modify_date,
                'replace_partial_string': self._replace_partial_string
            #    'format string': self._format_string,
            #    'do nothing': self._do_nothing
            }

            run_action = supported_actions[action_id]

            return run_action(param, action_id)

    def _test_connectivity(self, param, action_id):
        
        config = self.get_config()

        try:
            response = self._send_request(config, '/rest/cef_metadata', 'get')
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                (
                    'Could not connect to Phantom REST API endpoint. Details - ' + err.message
                )
            )
        else:
            return self.set_status_save_progress(
                phantom.APP_SUCCESS,
                (
                    'Successfully connected to Phantom REST API endpoint /rest/cef_metadata.'
                )
            )

    def _add_to_datapath(self, param, action_id):
        config = self.get_config()
        
        data_list = param.get('data_list')
        contains = param.get('contains')
        data_type = param.get('data_type')
        data_dict = param.get('data_dict')

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(data_dict) and not(data_list):
           return action_result.set_status(
                    phantom.APP_ERROR,
                    'Either data_dict or data_list parameter must be provided.'
                ) 

        if data_dict:
            if (contains or data_type):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Cannot set both ("contains" or "data type") and "data dicitonary." Please use one or the other.'
                )
            else:
                try:
                    data_dict = json.loads(data_dict)
                except Exception:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        'Invalid json in data_dict field'
                    )    
                contains = [dict_item['contains'] for dict_item in data_dict if dict_item.get('contains')]
                data_type = [dict_item['data_type'] for dict_item in data_dict if dict_item['data_type']]
        else:
            try:
                data_list = json.loads(data_list)
            except Exception:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Unable to conver data_list to list.'
                )
            contains = [contains] if contains else []
            data_type = [data_type]
        
        response = self._send_request(config, '/rest/cef_metadata', 'get')
        contains_master_list = response['all_contains']

        invalid_contains = set(contains) - set(contains_master_list)

        if len(invalid_contains) > 0:
            return action_result.set_status(
                phantom.APP_ERROR,
                ', '.join(invalid_contains) + ' not valid for "contains." Use '
                + 'api endoint /rest/cef_metadata to see complete valid list.'
            ) 

        results_data = {'added_data': []}

        if data_list:
            field_name = contains[0].lower().replace(' ','_') if contains else data_type[0].lower().replace(' ', '_')

            for datum in data_list:
                results_data['added_data'].append({field_name: datum})

        else:
            for dict_item in data_dict:
                field_name = (
                    dict_item['contains'].lower().replace(' ', '_') 
                    if dict_item.get('contains') 
                    else dict_item['data_type'].lower().replace(' ', '_')
                )
                results_data['added_data'].append({field_name: dict_item['data']})

        item_count = len(data_dict) if data_dict else len(data_list)

        action_result.add_data(results_data)
        action_result.update_summary({'items_added': item_count})

        return(action_result.set_status(phantom.APP_SUCCESS))

    def _format_string(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        string_to_format = param['string_to_format']
        string_regex = param.get('regex')

        if string_regex:
            string_regex = re.compile(string_regex)
            string_to_format = string_regex.findall(string_to_format)
        else:
            string_to_format = [string_to_format]

        output_string = param.get('output_string') 

        if len(string_to_format) < 1:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Either no input string was provided or the regex parttern did not match as expected. Details - ' + err.message 
            ) 
        elif string_regex:
            string_to_format = string_to_format[0]

        try:
            output_string = output_string.format(*string_to_format)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to format string. Likely the string placeholder is out of range. Details - ' + err.message 
            ) 

        action_result.add_data({'formatted_string': output_string})

        return(action_result.set_status(phantom.APP_SUCCESS, 'Successfully modified string.'))

    def _replace_partial_string(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))

        target_string = param['target_string']
        find_str = param['find']
        replace_str = param.get('replace', '')
        ignore_case = param['ignore_case']

        case_ignore = None

        if(ignore_case):
            case_ignore = re.IGNORECASE
        
        target_string = re.sub(find_str, replace_str, target_string, flags=case_ignore)

        action_result.add_data({'replaced_string': target_string})

        return(action_result.set_status(phantom.APP_SUCCESS, 'Successfully replaced string.'))
        
    def _modify_date(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        date_value = param['date_value']
        date_format_input = param.get('date_format_input')
        mod_units = param.get('mod_units')
        mod_value = param.get('mod_value')
        date_format_output = param.get('date_format_output')

        td_units = {
            'microseconds': 0,
            'seconds': 0,
            'minutes': 0,
            'hours': 0,
            'days': 0,
            'weeks': 0,
            'months': 0,
            'years': 0
        }

        if mod_units not in (td_units.keys()):
            return action_result.set_status(
                phantom.APP_ERROR,
                (
                    'Date modification units must be one of the following: ' + ', '.join(td_units.keys())
                )
            )
        
        if date_value.lower() != 'now':
            if date_format_input:
                try:
                    parsed_date = datetime.strptime(date_value, date_format_input)
                except Exception as err:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        (
                            'Unable to parse date. Details - ' + err.message
                        )
                    )
            else:
                try:
                    parsed_date = parse(date_value, fuzzy=True)
                except Exception as err:
                    try:
                        parsed_date = datetime.fromtimestamp(int(date_value))
                    except Exception as err2:
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            (
                                'Unable to parse date. Details - Parse message: ' + err.message
                                + '\n\nfromTimestamp Attempt: ' + err2.message
                            )
                    )
        else:
            parsed_date = datetime.now()

        if(mod_units and mod_value):
            td_units[mod_units] = int(mod_value)
            parsed_date = parsed_date + relativedelta(
                days=td_units['days'],
                seconds=td_units['seconds'],
                microseconds=td_units['microseconds'],
                minutes=td_units['minutes'],
                hours=td_units['hours'],
                weeks=td_units['weeks'],
                months=td_units['months'],
                years=td_units['years']
            )
        
        if(date_format_output):
            try:
                date_string = parsed_date.strftime(date_format_output)
            except Exception as err:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        'Unable to format date. Details - ' + err.message
                    )
                )
        else:
            date_string = str(parsed_date)

        date_int = time.mktime(parsed_date.timetuple())

        results = {
            'timestamp': date_int,
            'date_string': date_string
        }

        action_result.add_data(results)

        return(action_result.set_status(phantom.APP_SUCCESS, 'Successfully formatted date.'))

    def _send_request(self, config, url, method, payload=None, content_type=None):
        url = 'https://' + config['base_url'] + url
        request_func = getattr(requests, method.lower())

        header = None
        auth=None

        if config.get('auth_token'):
            header = {
                'ph-auth-token': config['auth_token']
            }

        if 'audit' in url or 'ph_user' in url or 'action_run' in url or header is None:
            auth=(config['username'], config['password'])
        
        if request_func is None:
            raise ValueError('Incorrect requests action specified')

        try:
            r = request_func(
                url,
                headers=header,
                data=payload,
                verify=config['verify_certificate'],
                auth=auth
            )

            r.raise_for_status
        except requests.exceptions.SSLError as err:
            raise Exception(
                'Error connecting to API - '
                'Likely due to the "validate server certificate" option. '
                'Details: ' + str(err)
            )
        except requests.exceptions.HTTPError as err:
            raise Exception(
                'Error calling - ' + url + ' - \n'
                'HTTP Status: ' + r.status
                + 'Reason: ' + r.reason
                + 'Details: ' + str(err)
            )
        except requests.exceptions.RequestException as err:
            raise Exception(
                'Error calling - ' + url + ' - Details: ' + str(err)
            )

        try:
            results = r.json()
        except ValueError:
            results = r.text

        return results

    