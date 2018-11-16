# File: phutils_connector.py
# Copyright (c) 2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
from phantom.action_result import ActionResult
import phantom.app as phantom
from phantom.base_connector import BaseConnector
import phantom.utils as ph_utils
import ast
import requests
import json
import re
from datetime import datetime
import time
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
import hashlib
from py_expression_eval import Parser


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
                'replace_partial_string': self._replace_partial_string,
                'multi_collect': self._multi_collect,
                'hash_text': self._hash_text,
                'split_string': self._split,
                'modify_number': self._modify_number,
                'convert_to_dict': self._convert_to_dict
            }

            run_action = supported_actions[action_id]

            return run_action(param, action_id)

    def _test_connectivity(self, param, action_id):

        config = self.get_config()

        try:
            self._send_request(config, '/rest/cef_metadata', 'get')
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                (
                    'Could not connect to Phantom REST API endpoint. '
                    + 'Details - ' + err.message
                )
            )
        else:
            return self.set_status_save_progress(
                phantom.APP_SUCCESS,
                (
                    'Successfully connected to Phantom REST API endpoint '
                    + '/rest/cef_metadata.'
                )
            )

    def _modify_number(self, param, action_id):
        num_to_modify = param.get("number", param.get("default_number"))
        expression = param["expression"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not num_to_modify:
            return action_result.set_status(
                phantom.APP_ERROR,
                'A "number to modify" or "default number" must be provided'
            )

        parser = Parser()

        try:
            result = parser.parse(
                expression.format(num_to_modify)
            ).evaluate({})
        except Exception as err:
            try:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        'Error evaluating expression '
                        + expression.format(num_to_modify)
                        + '. Error Details - ' + err.message
                    )
                )
            except Exception as err2:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        'Expression format is invalid. '
                        + 'Error Details - ' + err2.message
                    )
                )

        data = {
            'expression': expression.format(num_to_modify),
            'result': result
        }

        action_result.update_summary({'result': result})
        action_result.add_data(data)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Operation successfully completed.'
        )

    def _convert_to_dict(self, param, action_id):
        list_data = param['list']
        key_name = param['field_name'].split(',')
        result_dict = {'result_dict': []}

        action_result = self.add_action_result(ActionResult(dict(param)))

        if type(list_data) != list:
            try:
                list_data = ast.literal_eval(list_data)
            except Exception as err:
                try:
                    list_data = self._custom_split(
                        {
                            'string_to_split': list_data,
                            'delimiter': ',',
                            'qualifier': '"'
                        }
                    )
                except Exception as err2:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        (
                            'Unable to convert list to dict. '
                            + 'Error Details - ' + err.message + '. '
                            + err2.message
                        )
                    )

        for data_val in list_data:
            if type(data_val) == list:
                sub_dict = {}
                for i, key in enumerate(key_name):
                    if len(data_val) >= len(key_name):
                        sub_dict[key_name[i].strip()] = data_val[i]

                result_dict['result_dict'].append(sub_dict)
            else:
                result_dict['result_dict'].append({key_name[0]: data_val})

        action_result.update_summary(
            {
                'item_count': len(result_dict['result_dict'])
            }
        )

        action_result.add_data(result_dict)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Successfully converted list to dict.'
        )

    def _custom_split(self, param):
        delimiter = param['delimiter']
        qualifier = param.get('qualifier', '')
        string_to_split = param['string_to_split']

        true_delimiter_match = re.compile(
            r'{0}\s*{1}\s*{0}'.format(qualifier, delimiter)
        )

        if qualifier != '':
            qualifier_strip = re.compile(r'(^{0})|({0}$)'.format(qualifier))
            string_to_split = qualifier_strip.sub('', string_to_split)

        list_data = true_delimiter_match.sub(
            qualifier + delimiter + qualifier,
            string_to_split
        ).split(qualifier + delimiter + qualifier)

        return list_data

    def _split(self, param, action_id):
        key_name = param['field_name']
        result_dict = {'result_dict': []}

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            list_data = self._custom_split(param)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Unable to split string. Error details - ' + err.message
            )

        for data_val in list_data:
            result_dict['result_dict'].append({key_name: data_val})

        action_result.update_summary(
            {'item_count': len(result_dict['result_dict'])}
        )
        action_result.add_data(result_dict)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Successfully split string.'
        )

    def _hash_text(self, param, action_id):
        string_to_hash = param["text"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            md5 = hashlib.md5(string_to_hash).hexdigest()
            sha1 = hashlib.sha1(string_to_hash).hexdigest()
            sha256 = hashlib.sha256(string_to_hash).hexdigest()
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                'Error creating hash. Details - ' + err.message
            )

        action_result.add_data({
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256
        })

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Hash successfully created'
        )

    def _multi_collect(self, param, action_id):
        config = self.get_config()

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']
        data_paths = param['data_paths'].split(',')
        field_name = param['field_name']

        if len(data_paths) < 2:
            return phantom.set_status(
                phantom.APP_ERROR,
                'Do not use multi_collect to collect from only one datapath.'
            )

        collected_data = []

        artifacts = self._send_request(
            config,
            (
                '/rest/artifact?page_size=0&_filter_container_id='
                + str(container_id)
            ),
            'get'
        )
        artifacts = [artifacts['data']]

        for data_path in data_paths:

            data_path = data_path.split(':')
            if len(data_path) != 2:
                return phantom.set_status(
                    phantom.APP_ERROR,
                    (
                        'data_path incorrectly formatted - should look like '
                        + 'artifact:*.cef.field_name. Remember that multi '
                        + 'collect only works on artifacts, not on filter '
                        + 'output or action_results.'
                    )
                )

            if 'action_result' in data_path[0]:
                return phantom.set_status(
                    phantom.APP_ERROR,
                    (
                        '"multi collect" only works with artifact data, '
                        + 'action_results/filter results cannot be collected. '
                        + 'Suggest multi collecting first, and the running '
                        + 'action and/or filter.'
                    )
                )
            else:
                artifact_id = '*.id'

            paths = [data_path[1]]
            paths.append(artifact_id)

            collected_data = collected_data + ph_utils.extract_data_paths(
                artifacts,
                paths
            )

        if param.get('de_dupe'):
            unique_list = set([val[0] for val in collected_data if val[0]])
            collected_data = [
                {
                    'added_data': {
                        field_name: val,
                        'artifact_ids': [
                            {'artifact_id': item[1]}
                            for item in collected_data
                            if item[0] == val
                        ]
                    }
                } for val in unique_list
            ]
        else:
            collected_data = [
                {
                    'added_data': {
                        field_name: val[0],
                        'artifact_ids': [
                            {'artifact_id': val[1]}
                        ]
                    }
                } for val in collected_data if val[0]
            ]

        for data in collected_data:
            action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS, 'Collected data')

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
                    (
                        'Cannot set both ("contains" or "data type") and '
                        + '"data dictionary." Please use one or the '
                        + 'other.'
                    )
                )
            else:
                try:
                    data_dict = json.loads(data_dict)
                except Exception:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        'Invalid json in data_dict field'
                    )
                contains = [
                    dict_item['contains']
                    for dict_item in data_dict
                    if dict_item.get('contains')
                ]

                data_type = [
                    dict_item['data_type']
                    for dict_item in data_dict
                    if dict_item['data_type']
                ]
        else:
            try:
                data_list = json.loads(data_list)
            except Exception:
                try:
                    data_list = re.sub(
                        r'(^\[)|(\]$)',
                        '',
                        data_list
                    ).replace('", ', '",').split('","')
                except Exception:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        'Unable to convert data_list to list.'
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

        item_count = 0

        if data_list:
            field_name = param.get('field_name') or 'added_field'

            for datum in data_list:
                action_result.add_data({
                    'added_data': {
                        field_name: re.sub(r'(^")|("$)', '', datum)
                    }
                })
                item_count += 1

        else:
            for dict_item in data_dict:
                field_name = (
                    dict_item.get('field_name') or 'added_field'
                )
                action_result.add_data({
                    'added_data': {
                        field_name: dict_item['data']
                    }
                })
                item_count += 1

        item_count = len(data_dict) if data_dict else len(data_list)

        action_result.update_summary({'items_added': item_count})

        return(action_result.set_status(phantom.APP_SUCCESS))

    def _format_string(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))

        string_to_format = param['string_to_format']
        string_regex = param.get('regex')
        ignore_case = (param.get('ignore_case') or True)

        string_found = True

        if string_regex:
            if ignore_case:
                string_regex = re.compile(string_regex, re.IGNORECASE)
            else:
                string_regex = re.compile(string_regex)
            string_to_format = string_regex.findall(string_to_format)
        else:
            string_to_format = [string_to_format]

        output_string = param.get('output_string')

        if len(string_to_format) < 1:
            # regex was not found
            string_found = False
        elif string_regex:
            string_to_format = string_to_format[0]
            if type(string_to_format) != 'tuple':
                string_to_format = (string_to_format, '')

        if string_found:
            try:
                output_string = output_string.format(*string_to_format)
            except Exception as err:
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    (
                        'Pattern was found, but index in ouput_string '
                        + 'does not exist. Details - ' + err.message
                    )
                )
        else:
            output_string = None

        action_result.add_data({
            'formatted_string': output_string,
            'string_found': string_found
        })

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Successfully modified string.'
        )

    def _replace_partial_string(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))

        target_string = param['target_string']
        find_str = param['find']
        replace_str = param.get('replace', '')
        ignore_case = param['ignore_case']

        case_ignore = None

        if(ignore_case):
            case_ignore = re.IGNORECASE

        target_string = re.sub(
            find_str,
            replace_str,
            target_string,
            flags=case_ignore
        )

        action_result.add_data({'replaced_string': target_string})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Successfully replaced string.'
        )

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

        if mod_units not in td_units.keys() and mod_value:
            return action_result.set_status(
                phantom.APP_ERROR,
                (
                    'Date modification units must be one of the following: '
                    + ', '.join(td_units.keys())
                )
            )

        if date_value.lower() != 'now':
            if date_format_input:
                try:
                    parsed_date = datetime.strptime(
                        date_value,
                        date_format_input
                    )
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
                        try:
                            parsed_date = datetime.fromtimestamp(
                                long(date_value)/1000.0
                            )
                        except Exception as err3:
                            return action_result.set_status(
                                phantom.APP_ERROR,
                                (
                                    'Unable to parse date. Details - Parse '
                                    + 'message: '
                                    + err.message
                                    + '\n\nfromTimestamp Attempt: '
                                    + err2.message
                                    + '\n\nepoch Attempt: '
                                    + err3.message
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

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Successfully formatted date.'
        )

    def _send_request(
        self, config, url, method,
        payload=None, content_type=None
    ):
        url = 'https://' + config['base_url'] + url
        request_func = getattr(requests, method.lower())

        header = None
        auth = None

        if config.get('auth_token'):
            header = {
                'ph-auth-token': config['auth_token']
            }

        if(
            'audit' in url
            or 'ph_user' in url
            or 'action_run' in url
            or header is None
        ):
            auth = (config['username'], config['password'])

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
