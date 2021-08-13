# File: phutils_connector.py
# Copyright (c) 2018-2020 Splunk Inc.
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
from bs4 import UnicodeDammit
from urllib.parse import urlparse


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
            "test_connectivity": self._test_connectivity,
            "add_to_datapath": self._add_to_datapath,
            "format_string": self._format_string,
            "modify_date": self._modify_date,
            "replace_partial_string": self._replace_partial_string,
            "multi_collect": self._multi_collect,
            "hash_text": self._hash_text,
            "split_string": self._split,
            "modify_number": self._modify_number,
            "convert_to_dict": self._convert_to_dict,
            "unshorten_url": self._unshorten_url,
            "change_encoding": self._change_encoding,
            "make_table": self._make_table,
            "get_pin": self._get_pin,
            "parse_url": self._parse_url,
            "get_indicator": self._handle_get_ioc,
            "add_indicator_tag": self._add_ioc_tag,
            "update_artifact": self._update_artifact,
            "modify_string": self._modify_string,
            "update_container": self._update_container,
            "assess_risk": self._assess_risk,
        }

        run_action = supported_actions[action_id]

        return run_action(param, action_id)

    def _test_connectivity(self, param, action_id):

        config = self.get_config()

        try:
            self._send_request(config, "/rest/cef_metadata", "get")
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                (
                    "Could not connect to Phantom REST API endpoint. "
                    + "Details - "
                    + str(err)
                ),
            )
        else:
            return self.set_status_save_progress(
                phantom.APP_SUCCESS,
                (
                    "Successfully connected to Phantom REST API endpoint "
                    + "/rest/cef_metadata."
                ),
            )

    def _modify_string(self, param, action_id):
        action_result = self.add_action_result(ActionResult(dict(param)))

        output = ""

        try:
            if param["action"] == "lower":
                output = param["string"].lower()
            else:
                output = param["string"].upper()
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR, 'Unable to parse "data" field - ' + str(err)
            )

        action_result.add_data({"modified_string": output})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully {}'d string ({})".format(param["action"], param["string"]),
        )

    def _get_pin(self, param, action_id):

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param["container_id"]
        query = param.get("query", "")

        endpoint = (
            "/rest/container_pin?_filter_container_id="
            + str(container_id)
            + ("&" + query if query else "")
        )

        config = self.get_config()

        resp_data = self._send_request(config, endpoint, "get")

        if "data" not in resp_data:
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to retreive pins"
            )

        for data in resp_data["data"]:
            action_result.add_data(
                {
                    "pin_type": data["pin_type"],
                    "container_id": data["container"],
                    "author": data["author"],
                    "modified_time": data["modified_time"],
                    "create_time": data["create_time"],
                    "playbook": data["playbook"],
                    "message": data["message"],
                    "data": data["data"],
                    "id": data["id"],
                    "pin_style": data["pin_style"],
                }
            )

        action_result.update_summary({"pins_found": resp_data["count"]})

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully retrieved pins"
        )

    def _make_table(self, param, action_id):
        # TODO - Implement this code
        container_id = param["container_id"]
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_info = self.get_container_info(container_id)

        fields = []

        self.debug_print(str(container_info))

        return self.set_status_save_progress(phantom.APP_ERROR)

    def _field_updater(self, data, update_data, overwrite):
        if type(update_data) == list:
            if not (overwrite):
                return list(set((data or []) + update_data))
            else:
                return update_data
        elif type(update_data) == dict:
            for keya in list(update_data.keys()):
                data[keya] = self._field_updater(
                    data.get(keya, {}), update_data[keya], overwrite
                )
        else:
            if (overwrite and data) or not (data):
                return update_data

        return data

    def _update_container(self, param, action_id):
        config = self.get_config()
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param["container_id"]
        data = param["data"]

        try:
            update_data = json.loads(data)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR, 'Unable to parse "data" field - ' + str(err)
            )

        try:
            post_data = self._send_request(
                config,
                "/rest/container/{}".format(container_id),
                "POST",
                payload=json.dumps(update_data),
            )
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to save container data - " + str(err)
            )

        if not (post_data.get("success")):
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to save container data - " + str(post_data)
            )

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully updated container (ID: {})".format(container_id),
        )

    def _update_artifact(self, param, action_id):
        config = self.get_config()
        action_result = self.add_action_result(ActionResult(dict(param)))

        artifact_id = param["artifact_id"]
        data = param["data"]
        overwrite = param.get("overwrite")

        try:
            data = json.loads(data)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR, 'Unable to parse "data" field - ' + str(err)
            )

        try:
            artifact_data = self._send_request(
                config, "/rest/artifact/{}".format(artifact_id), "GET"
            )
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to retrieve artifact data - " + str(err)
            )

        if not (artifact_data):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Artifact not found with id {} - {}".format(artifact_id),
            )
        update_data = {}

        for key in list(data.keys()):
            update_data[key] = self._field_updater(
                artifact_data.get(key, {}), data[key], overwrite
            )

        self.debug_print("artifacto", update_data)

        try:
            post_data = self._send_request(
                config,
                "/rest/artifact/{}".format(artifact_id),
                "POST",
                payload=json.dumps(update_data),
            )
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to save artifact data - " + str(err)
            )

        if not (post_data.get("success")):
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to save artifact data - " + str(post_data)
            )

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully updated artifact (ID: {})".format(artifact_id),
        )

    def _get_ioc(self, config, ioc_value, ioc_id):
        params = {}

        if ioc_id:
            endpoint = "/rest/indicator/{0}".format(ioc_id)
        else:
            params = {"indicator_value": ioc_value}
            endpoint = "/rest/indicator_by_value"

        resp_data = self._send_request(config, endpoint, "get", params=params)

        return resp_data

    def _assess_risk(self, param, action_id):
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        ioc_tag_prefix = config.get("ioc_tag_prefix")
        ioc_threshold = config.get("ioc_score_threshold", 5)
        ioc_max_value = config.get("ioc_max_value", 10)
        custom_field_risk = config.get("custom_field_risk_score")
        custom_field_related = config.get("custom_field_related")

        params = {"_filter_container_id": self.get_container_id()}
        resp_data = self._send_request(config, "/rest/artifact", "get", params=params)

        if resp_data.get("data") is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to get IOC data from current container. Details - {}".format(
                    str(resp_data)
                ),
            )

        ioc_list = []

        for artifact in resp_data["data"]:
            ioc_list += [
                v.replace("\\", "\\\\").replace('"', '\\"')
                for k, v in list(artifact["cef"].items())
            ]

        ioc_list = list(set(ioc_list))
        ioc_regex_search = '"{}"'.format("|".join(ioc_list))

        risk_range = list(range(int(ioc_threshold), int(ioc_max_value) + 1))
        risk_regex = '"{}({}\\")"'.format(
            ioc_tag_prefix, '\\"|'.join(str(i) for i in risk_range if i)
        )

        indicator_params = {"_filter_value__iregex": ioc_regex_search}

        indicator_resp_data = self._send_request(
            config, "/rest/indicator", "get", params=indicator_params
        )

        self.debug_print("monkey2", str(resp_data))

        if indicator_resp_data.get("data") is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to get IOC data from current container. Details - {}".format(
                    str(resp_data)
                ),
            )

        related_count = 0
        top_risk_score = 0

        indicator_list = {indicator: 0 for indicator in ioc_list}

        if indicator_resp_data.get("count") > 0:
            for indicator in indicator_resp_data["data"]:
                for tag in indicator["tags"]:
                    if tag.startswith(ioc_tag_prefix):
                        print(indicator)
                        risk_score = int(tag.replace(ioc_tag_prefix, ""))
                        indicator_list[indicator["value"]] = risk_score

                        # if int(risk_score) >= ioc_threshold:
                        #     indicator_list.append(indicator['value'])
                        if int(risk_score) > top_risk_score:
                            top_risk_score = risk_score
                            print(top_risk_score)

            risky_indicator_list = [
                k for k, v in list(indicator_list.items()) if v >= int(ioc_threshold)
            ]
            self.debug_print("cowabunga", str(risky_indicator_list))
            if len(risky_indicator_list) > 0:
                indicator_regex = '"({}\\")"'.format('\\"|'.join(risky_indicator_list))

                risky_ioc_params = {"_filter_artifact__cef__iregex": indicator_regex}

                resp_data = self._send_request(
                    config, "/rest/container", "get", params=risky_ioc_params
                )

                if not (resp_data.get("data")):
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "Unable to get IOC data from related containers. Details - {}".format(
                            str(resp_data)
                        ),
                    )

                related_count = (
                    len(
                        list(
                            set([item.get("id") for item in resp_data.get("data", [])])
                        )
                    )
                    - 1
                )

                counter = 0
                for indicator in risky_indicator_list:
                    counter += 1
                    pin_data = {
                        "container_id": self.get_container_id(),
                        "name": "{} {}".format(
                            config.get("risky_ioc_card", "High Risk IOC"), counter
                        ),
                        "pin_type": "manual card",
                        "pin_style": "red",
                        "message": config.get("risky_ioc_card", "High Risk IOC"),
                        "data": indicator,
                    }

                    resp_data = self._send_request(
                        config,
                        "/rest/container_pin",
                        "post",
                        payload=json.dumps(pin_data),
                    )

                    if not (resp_data.get("data")):
                        return action_result.set_status(
                            phantom.APP_ERROR,
                            "Unable to save PIN. Details - {}".format(st(resp_data)),
                        )

        custom_field_data = {
            "custom_fields": {
                custom_field_related: related_count,
                custom_field_risk: top_risk_score,
            }
        }

        resp_data = self._send_request(
            config,
            "/rest/container/{}".format(self.get_container_id()),
            "post",
            payload=json.dumps(custom_field_data),
        )

        if not (resp_data.get("success")):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to update risk assessment. Details - {}".format(str(resp_data)),
            )

        action_result.update_summary(
            {
                "related_events": (related_count or 0),
                "risk_score": (top_risk_score or 0),
            }
        )

        action_result.add_data(
            {
                "indicator_results": [
                    {"indicator": k, "score": v}
                    for k, v in list(indicator_list.items())
                ]
            }
        )

        return action_result.set_status(
            phantom.APP_SUCCESS, "Risk Assessment completed successfully"
        )

    def _get_artifact_data_with_ioc(self, config, page_size, order, ioc_id):
        params = {
            "indicator_id": ioc_id,
            "order": order,
            "page": 0,
            "page_size": page_size,
        }
        endpoint = "/rest/indicator_artifact"

        resp_data = self._send_request(config, endpoint, "get", params=params)

        return resp_data

    def _handle_get_ioc(self, param, action_id):
        ioc_value = param.get("ioc_value")
        ioc_id = param.get("ioc_id")

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not (ioc_value or ioc_id):
            return action_result.set_status(
                phantom.APP_ERROR, "Either and ioc_value or ioc_id must be provided"
            )

        config = self.get_config()

        resp_data = self._get_ioc(config, ioc_value, ioc_id)

        if "id" not in resp_data:
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to find indicator"
            )

        if param.get("include_artifact_data"):
            artifact_resp_data = self._get_artifact_data_with_ioc(
                config,
                param.get("artifact_limit", 10),
                param.get("artifact_sort", "desc"),
                resp_data["id"],
            )
            if "data" not in artifact_resp_data:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to get artifact data related to indicator",
                )
            self.debug_print("awesomeo", artifact_resp_data)
            resp_data["artifacts"] = artifact_resp_data["data"]

        summary = {
            "ioc_id": resp_data["id"],
            "ioc_value": resp_data["value"],
            "tags": resp_data["tags"],
        }

        resp_data["tags"] = [{"tag": tag} for tag in resp_data["tags"]]

        action_result.update_summary(summary)

        action_result.add_data(resp_data)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved indicator (" + resp_data["value"] + ")",
        )

    def _add_ioc_tag(self, param, action_id):
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        ioc_list = param.get("ioc_list")
        ioc_value = param.get("ioc_value")
        ioc_id = param.get("ioc_id")

        if ioc_list:
            try:
                ioc_list = json.loads(ioc_list)
            except Exception as err:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Could not load ioc_list parmater. Details - {}".format(str(err)),
                )
        print(str(ioc_list))
        if not (ioc_value or ioc_id or ioc_list):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Either an ioc_value, ioc_id, ioc_list must be provided",
            )

        if ioc_list and (ioc_value or ioc_id):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Cannot supply ioc list and either ioc_id or ioc_value.",
            )

        if ioc_value:
            ioc_list = [{"ioc_value": ioc_value}]
        elif ioc_id:
            ioc_list = [{"ioc_id": ioc_id}]

        tags_to_add = param.get("tags_to_add", "").split(",")
        regex_remove = param.get("regex_remove", "")
        tags_to_remove = param.get("tags_to_remove", "").split(",")

        for item in ioc_list:
            print("in here")
            if not (
                item.get("tags_to_add")
                or item.get("tags_to_remove")
                or tags_to_add
                or tags_to_remove
            ):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Either tags_to_add or tags_to_remove must be provided. If using the ioc_list parameter these can be provided in list (e.g. {"ioc_value": "http://www.splunk.com", "tags_to_add": "tag_name"})',
                )
            if not (item.get("tags_to_add")):
                item["tags_to_add"] = tags_to_add
            if not (item.get("tags_to_remove")):
                item["tags_to_remove"] = tags_to_remove

            resp_data = self._get_ioc(config, item.get("ioc_value"), item.get("ioc_id"))

            if "id" not in resp_data:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to find indicator - {}".format(
                        (item.get("ioc_value") or item.get("ioc_id"))
                    ),
                )

            endpoint = "/rest/indicator/{0}".format(resp_data["id"])
            item["tags_to_remove"] = [
                remover
                for remover in item["tags_to_remove"]
                if remover not in item["tags_to_add"]
            ]
            tags = [
                tag
                for tag in list(set(item["tags_to_add"] + resp_data["tags"]))
                if tag not in item["tags_to_remove"]
            ]

            payload = {"tags": tags}

            tag_resp_data = self._send_request(
                config, endpoint, "post", payload=json.dumps(payload)
            )

            if not (tag_resp_data.get("success")):
                return action_result.set_status(
                    phantom.APP_ERROR, "Unable to add tag: " + str(tag_resp_data)
                )

            action_result.add_data(
                {
                    "ioc_id": resp_data["id"],
                    "ioc_value": resp_data["value"],
                    "tags": tags,
                }
            )

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully updated tags"
        )

    def _change_encoding(self, param, action_id):
        start_text = param["text"]
        encoding = param["encoding"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            encoded_text = start_text.encode(encoding)
        except Exception as err:
            return self.set_status_save_progress(
                phantom.APP_ERROR,
                (
                    "Could not encode text with "
                    + encoding
                    + ". "
                    + "Details - "
                    + str(err)
                ),
            )

        action_result.add_data({"encoded_text": encoded_text})

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully encoded string with " + encoding + "."
        )

    def _unshorten_url(self, param, action_id):
        shortened_url = param["url"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        message = "Successfully unshortened url"

        try:
            response = requests.get(shortened_url)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                (
                    'Error unshortening url "'
                    + shortened_url
                    + ". Details - "
                    + str(err)
                ),
            )

        if response.url and response.url.lower() == shortened_url.lower():
            message = "Unable to unshorten url."

        data = {"unshortened_url": response.url}

        action_result.update_summary({"unshortened_url": response.url})
        action_result.add_data(data)

        return action_result.set_status(
            phantom.APP_SUCCESS, message + " - " + response.url
        )

    def _modify_number(self, param, action_id):
        num_to_modify = param.get("number", param.get("default_number"))
        expression = param["expression"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not num_to_modify:
            return action_result.set_status(
                phantom.APP_ERROR,
                'A "number to modify" or "default number" must be provided',
            )

        parser = Parser()

        try:
            result = parser.parse(expression.format(num_to_modify)).evaluate({})
        except Exception as err:
            try:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        "Error evaluating expression "
                        + expression.format(num_to_modify)
                        + ". Error Details - "
                        + str(err)
                    ),
                )
            except Exception as err2:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        "Expression format is invalid. "
                        + "Error Details - "
                        + err2.message
                    ),
                )

        data = {"expression": expression.format(num_to_modify), "result": result}

        action_result.update_summary({"result": result})
        action_result.add_data(data)

        return action_result.set_status(
            phantom.APP_SUCCESS, "Operation successfully completed."
        )

    def _convert_to_dict(self, param, action_id):
        list_data = param["list"]
        key_name = param["field_name"].split(",")
        result_dict = {"result_dict": []}

        action_result = self.add_action_result(ActionResult(dict(param)))

        if type(list_data) != list:
            try:
                list_data = ast.literal_eval(list_data)
            except Exception as err:
                try:
                    list_data = self._custom_split(
                        {
                            "string_to_split": list_data,
                            "delimiter": ",",
                            "qualifier": '"',
                        }
                    )
                except Exception as err2:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        (
                            "Unable to convert list to dict. "
                            + "Error Details - "
                            + str(err)
                            + ". "
                            + err2.message
                        ),
                    )

        for data_val in list_data:
            if type(data_val) == list:
                sub_dict = {}
                for i, key in enumerate(key_name):
                    if len(data_val) >= len(key_name):
                        sub_dict[key_name[i].strip()] = data_val[i]

                result_dict["result_dict"].append(sub_dict)
            else:
                result_dict["result_dict"].append({key_name[0]: data_val})

        action_result.update_summary({"item_count": len(result_dict["result_dict"])})

        action_result.add_data(result_dict)

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully converted list to dict."
        )

    def _custom_split(self, param):
        delimiter = (
            param["delimiter"]
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("[", "")
            .replace("]", "")
        )
        qualifier = param.get("qualifier", "")
        string_to_split = param["string_to_split"]

        true_delimiter_match = re.compile(
            r"{0}\s*{1}\s*{0}".format(qualifier, delimiter)
        )

        if qualifier != "":
            qualifier_strip = re.compile(r"(^{0})|({0}$)".format(qualifier))
            string_to_split = qualifier_strip.sub("", string_to_split)

        list_data = true_delimiter_match.sub(
            qualifier + delimiter + qualifier, string_to_split
        ).split(qualifier + delimiter + qualifier)

        return list_data

    def _parse_url(self, param, action_id):
        url_to_parse = param["url_to_parse"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        parsed_url = urlparse(url_to_parse)

        results = parsed_url._asdict()

        action_result.add_data(results)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully parsed URL.")

    def _split(self, param, action_id):
        key_name = param["field_name"].split(",")
        result_dict = {"result_dict": []}

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            list_data = self._custom_split(param)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to split string. Error details - " + str(err),
            )

        multi_label_dict = {}

        for i, data_val in enumerate(list_data):
            if len(key_name) > 0 and len(key_name) >= len(list_data):
                multi_label_dict[key_name[i]] = data_val
            else:
                result_dict["result_dict"].append({key_name[0]: data_val})

        if len(list(multi_label_dict.keys())) > 0:
            result_dict["result_dict"].append(multi_label_dict)
            action_result.update_summary(
                {"item_count": len(list(multi_label_dict.keys()))}
            )
        else:
            action_result.update_summary(
                {"item_count": len(result_dict["result_dict"])}
            )

        action_result.add_data(result_dict)

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully split string."
        )

    def _hash_text(self, param, action_id):
        string_to_hash = param["text"].encode("utf-8")

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            md5 = hashlib.md5(string_to_hash).hexdigest()
            sha1 = hashlib.sha1(string_to_hash).hexdigest()
            sha256 = hashlib.sha256(string_to_hash).hexdigest()
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR, "Error creating hash. Details - " + str(err)
            )

        action_result.add_data({"md5": md5, "sha1": sha1, "sha256": sha256})

        return action_result.set_status(
            phantom.APP_SUCCESS, "Hash successfully created"
        )

    def _multi_collect(self, param, action_id):
        config = self.get_config()

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param["container_id"]
        data_paths = param["data_paths"].split(",")
        field_name = param["field_name"]

        if len(data_paths) < 2:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Do not use multi_collect to collect from only one datapath.",
            )

        collected_data = []

        artifacts = self._send_request(
            config,
            ("/rest/artifact?page_size=0&_filter_container_id=" + str(container_id)),
            "get",
        )
        artifacts = [artifacts["data"]]

        for data_path in data_paths:

            data_path = data_path.split(":")
            if len(data_path) != 2:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        "data_path incorrectly formatted - should look like "
                        + "artifact:*.cef.field_name. Remember that multi "
                        + "collect only works on artifacts, not on filter "
                        + "output or action_results."
                    ),
                )

            if "action_result" in data_path[0]:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    (
                        '"multi collect" only works with artifact data, '
                        + "action_results/filter results cannot be collected. "
                        + "Suggest multi collecting first, and the running "
                        + "action and/or filter."
                    ),
                )
            else:
                artifact_id = "*.id"

            paths = [data_path[1]]
            paths.append(artifact_id)

            collected_data = collected_data + ph_utils.extract_data_paths(
                artifacts, paths
            )

        if param.get("de_dupe"):
            unique_list = set([val[0] for val in collected_data if val[0]])
            collected_data = [
                {
                    "added_data": {
                        field_name: val,
                        "artifact_ids": [
                            {"artifact_id": item[1]}
                            for item in collected_data
                            if item[0] == val
                        ],
                    }
                }
                for val in unique_list
            ]
        else:
            collected_data = [
                {
                    "added_data": {
                        field_name: val[0],
                        "artifact_ids": [{"artifact_id": val[1]}],
                    }
                }
                for val in collected_data
                if val[0]
            ]

        for data in collected_data:
            action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS, "Collected data")

    def _add_to_datapath(self, param, action_id):
        action_result = self.add_action_result(ActionResult(dict(param)))

        data_dict = param["data_dict"]

        try:
            data_dict = json.loads(data_dict)
        except Exception:
            return action_result.set_status(
                phantom.APP_ERROR, "Invalid json in data_dict field"
            )

        item_count = 1

        if type(data_dict) == list:
            item_count = len(data_dict)

        action_result.update_summary({"items_added": item_count})

        action_result.add_data({"added_data": data_dict})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _format_string(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))

        string_to_format = param["string_to_format"]
        string_regex = param.get("regex")
        ignore_case = param.get("ignore_case") or True

        string_found = True

        if string_regex:
            if ignore_case:
                string_regex = re.compile(string_regex, re.IGNORECASE)
            else:
                string_regex = re.compile(string_regex)
            string_to_format = string_regex.findall(string_to_format)
        else:
            string_to_format = [string_to_format]

        output_string = param.get("output_string")

        if len(string_to_format) < 1:
            # regex was not found
            string_found = False
        elif string_regex:
            string_to_format = string_to_format[0]
            if type(string_to_format) != "tuple":
                string_to_format = (string_to_format, "")

        if string_found:
            try:
                output_string = output_string.format(*string_to_format)
            except Exception as err:
                return action_result.set_status(
                    phantom.APP_SUCCESS,
                    (
                        "Pattern was found, but index in output_string "
                        + "does not exist. Details - "
                        + str(err)
                    ),
                )
        else:
            output_string = None

        action_result.add_data(
            {"formatted_string": output_string, "string_found": string_found}
        )

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully modified string."
        )

    def _replace_partial_string(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))

        target_string = param["target_string"]
        find_str = param["find"].replace("\\n", "\n").replace("\\r", "\r")
        replace_str = param.get("replace", "")
        ignore_case = param.get("ignore_case")

        case_ignore = 0

        if ignore_case:
            case_ignore = re.IGNORECASE

        target_string = re.sub(find_str, replace_str, target_string, flags=case_ignore)

        action_result.add_data({"replaced_string": target_string})

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully replaced string."
        )

    def _modify_date(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))

        date_value = param["date_value"]
        date_format_input = param.get("date_format_input")
        mod_units = param.get("mod_units")
        mod_value = param.get("mod_value")
        date_format_output = param.get("date_format_output")

        td_units = {
            "microseconds": 0,
            "seconds": 0,
            "minutes": 0,
            "hours": 0,
            "days": 0,
            "weeks": 0,
            "months": 0,
            "years": 0,
        }

        if mod_units not in list(td_units.keys()) and mod_value:
            return action_result.set_status(
                phantom.APP_ERROR,
                (
                    "Date modification units must be one of the following: "
                    + ", ".join(list(td_units.keys()))
                ),
            )

        if date_value.lower() != "now":
            if date_format_input:
                try:
                    parsed_date = datetime.strptime(date_value, date_format_input)
                except Exception as err:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        ("Unable to parse date. Details - " + str(err)),
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
                                int(date_value) / 1000.0
                            )
                        except Exception as err3:
                            return action_result.set_status(
                                phantom.APP_ERROR,
                                (
                                    "Unable to parse date. Details - Parse "
                                    + "message: "
                                    + str(err)
                                    + "\n\nfromTimestamp Attempt: "
                                    + err2.message
                                    + "\n\nepoch Attempt: "
                                    + err3.message
                                ),
                            )
        else:
            parsed_date = datetime.now()

        if mod_units and mod_value:
            td_units[mod_units] = int(mod_value)
            parsed_date = parsed_date + relativedelta(
                days=td_units["days"],
                seconds=td_units["seconds"],
                microseconds=td_units["microseconds"],
                minutes=td_units["minutes"],
                hours=td_units["hours"],
                weeks=td_units["weeks"],
                months=td_units["months"],
                years=td_units["years"],
            )

        if date_format_output:
            try:
                date_string = parsed_date.strftime(date_format_output)
            except Exception as err:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ("Unable to format date. Details - " + str(err)),
                )
        else:
            date_string = str(parsed_date)

        date_int = time.mktime(parsed_date.timetuple())

        results = {"timestamp": date_int, "date_string": date_string}

        action_result.add_data(results)

        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully formatted date."
        )

    def _send_request(
        self, config, url, method, payload=None, content_type=None, params=None
    ):
        url = "https://" + config["base_url"] + url
        request_func = getattr(requests, method.lower())

        header = {}
        auth = None

        if config.get("auth_token"):
            header = {"ph-auth-token": config["auth_token"]}

        if "audit" in url or "ph_user" in url or "action_run" in url or not (header):
            auth = (config["username"], config["password"])

        header["Content-Type"] = "application/json"

        if request_func is None:
            raise ValueError("Incorrect requests action specified")

        try:
            r = request_func(
                url,
                headers=header,
                data=payload,
                params=params,
                verify=config.get("verify_certificate") or False,
                auth=auth,
            )

            r.raise_for_status
        except requests.exceptions.SSLError as err:
            raise Exception(
                "Error connecting to API - "
                'Likely due to the "validate server certificate" option. '
                "Details: " + str(err)
            )
        except requests.exceptions.HTTPError as err:
            raise Exception(
                "Error calling - " + url + " - \n"
                "HTTP Status: "
                + r.status
                + "Reason: "
                + r.reason
                + "Details: "
                + str(err)
            )
        except requests.exceptions.RequestException as err:
            raise Exception("Error calling - " + url + " - Details: " + str(err))

        try:
            results = r.json()
        except ValueError:
            results = r.text

        return results
