import json
import re
import requests
import boto3
import secrets
import base64
import hashlib
from bs4 import BeautifulSoup
import paho.mqtt.client as mqtt
import warnings
from urllib.parse import urlparse, parse_qs
import urllib

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def getConfig(home, jsonKeys):
    lambda_client = boto3.client('lambda')
    event = {'requestContext': {'http':{'method':'GET'}}}
    event['rawPath'] = '/config'
    event['body'] = {'home': home, 'jsonKeys': jsonKeys}
    
    response = lambda_client.invoke(
        FunctionName='domuxConfig',
        InvocationType='RequestResponse',
        Payload=json.dumps(event)
    )
    response_payload = json.loads(response['Payload'].read().decode("utf-8"))
    return response_payload['body']

def publish_to_mqtt(mqtt_config, topic, value):
    try:
        mqtt_client = mqtt.Client()
        mqtt_client.username_pw_set(mqtt_config['user'], mqtt_config['password'])
        mqtt_client.connect(mqtt_config['broker'], int(mqtt_config['port']), 60)
        mqtt_client.publish(topic, value)
        mqtt_client.disconnect()
    except Exception:
        pass

def response(values = None):
    if values is None:
        values = []
    resp = {}
    resp['body']= f'{{"status": "OK","description":"", "values":{json.dumps(values)}}}'
    resp["statusCode"] = 200
    resp["headers"] = {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,authorizationToken',X-Api-Key,X-Requested-With",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS"
        }
    return resp

class BoeschWP:
    def __init__(self, home, jsonKeys):
        config = json.loads(getConfig(home, jsonKeys))
        self.config = config['boesch']
        self.mqtt_config = config['mqtt']
        self.access_token = None

    def generate_pkce_and_state(self):
        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode("ascii")
        return state, code_verifier, code_challenge

    def get_login_csrf_token(self, session, state, code_challenge):
        return_url_params = {
            "client_id": self.config["client_id"],
            "redirect_uri": self.config["redirect_uri"],
            "response_type": "code",
            "scope": self.config["scope"],
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "ui_locales": self.config.get("ui_locales", "en-DE")
        }
        encoded_return_url = urllib.parse.quote(
            f"/openid/connect/authorize?{urllib.parse.urlencode(return_url_params)}"
        )
        login_url_with_return = f'{self.config["openid_url"]}/Account/Login?ReturnUrl={encoded_return_url}'
        
        resp = session.get(login_url_with_return, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        token_input = soup.find("input", {"name": "__RequestVerificationToken"})
        csrf_token = token_input.get("value") if token_input else None
        return csrf_token, encoded_return_url
    
    def submit_login_credentials(self, session, csrf_token, encoded_return_url):
        form_data = {
            "Login": self.config["user"],
            "Password": self.config["pass"],
            "__RequestVerificationToken": csrf_token
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        actual_post_url_for_login = f'{self.config["openid_url"]}/Account/Login?ReturnUrl={encoded_return_url}' 
        login_response = session.post(
            actual_post_url_for_login, data=form_data, headers=headers, allow_redirects=True, verify=False
        )
        return login_response

    def exchange_code_for_tokens(self, session, login_response_url, initial_state, code_verifier):
        parsed_callback_url = urllib.parse.urlparse(login_response_url)
        query_params_callback = urllib.parse.parse_qs(parsed_callback_url.query)
        code = query_params_callback.get("code", [None])[0]
        state_from_url = query_params_callback.get("state", [None])[0]
        token_endpoint_url = f'{self.config["portal"]}{self.config.get("token_endpoint_path", "/openid/connect/token")}' 
        token_exchange_payload = {
            'grant_type': 'authorization_code',
            'redirect_uri': self.config["redirect_uri"],
            'code': code,
            'code_verifier': code_verifier,
            'client_id': self.config["client_id"]
        }
        token_request_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        token_response = session.post(
            token_endpoint_url, data=token_exchange_payload, headers=token_request_headers,
            allow_redirects=False, verify=False
        )
        return token_response.json().get("access_token")
        
    def perform_pkce_login_and_get_token(self, session):
        initial_state, verifier, challenge = self.generate_pkce_and_state()
        csrf, final_encoded_return_url = self.get_login_csrf_token(session, initial_state, challenge)
        login_resp = self.submit_login_credentials(session, csrf, final_encoded_return_url)
        access_token = self.exchange_code_for_tokens(session, login_resp.url, initial_state, verifier)
        return access_token
        
    def _validate_datapoint_config(self, datapoint_name):
        if "setDatapoints" not in self.config:
            raise ValueError("setDatapoints configuration not found")
        if datapoint_name not in self.config["setDatapoints"]:
            raise ValueError(f"{datapoint_name} datapoint configuration not found")
        datapoint_config = self.config["setDatapoints"][datapoint_name]
        required_keys = ["datapoint", "unit", "values", "dpType"]
        missing_keys = [key for key in required_keys if key not in datapoint_config]
        if missing_keys:
            raise ValueError(f"Missing required keys in {datapoint_name} configuration: {', '.join(missing_keys)}")
        if not isinstance(datapoint_config["values"], list) or len(datapoint_config["values"]) < 2:
            raise ValueError(f"{datapoint_name} configuration must have a 'values' array with at least 2 elements")
        return datapoint_config

    def get_datapoint(self, session, access_token, datapoint_name):
        datapoint_config = self._validate_datapoint_config(datapoint_name)
        if len(datapoint_config["values"]) != 2:
            raise ValueError(f"{datapoint_name} configuration for get_datapoint must have a 'values' array with exactly 2 elements [min, max]")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json"
            }
        datapoint_id = datapoint_config["datapoint"]
        unit = datapoint_config["unit"]
        dpType = datapoint_config["dpType"]
        payload = {"DatapointValues":
                    [{"$type":dpType,
                        "Value": 0,
                        "DatapointConfigId":datapoint_id,
                        "DeviceId":self.config["device_id"],"Flags":0}
                    ]}
        response = requests.post(self.config["read_value_url"] + self.config["home_server_id"], 
                                    data=json.dumps(payload), headers=headers, verify=False)
        data_points = response.json()['ResponseData']
        datapoint_value = next((item for item in data_points if item["DatapointConfigId"] == datapoint_id), None)
        if datapoint_value is None:
            raise ValueError(f"{datapoint_name} datapoint {datapoint_id} not found in response or value missing")
        value = round(float(datapoint_value['Value']), 2)
        return value
    
    def set_datapoint(self, session, access_token, datapoint_name, value):
        datapoint_config = self._validate_datapoint_config(datapoint_name)
        values = datapoint_config["values"]
        if len(values) == 2 and values[0] < values[1]:
            min_value, max_value = values
            if value < min_value or value > max_value:
                raise ValueError(f"{datapoint_name} value must be between {min_value} and {max_value}")
        else:
            if value not in values:
                raise ValueError(f"{datapoint_name} value must be one of: {values}")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json"
            }
        datapoint_id = datapoint_config["datapoint"]
        unit = datapoint_config["unit"]
        dpType = datapoint_config["dpType"]
        raw_value = int(value) if "Int32" in dpType else float(value) if "Single" in dpType or "Double" in dpType else value
        payload = {"DatapointValues":
                    [{"$type": dpType,
                        "Value": raw_value,
                        "DatapointConfigId": datapoint_id,
                        "DeviceId": self.config["device_id"], "Flags": 0}
                    ]}
        response = requests.post(self.config["write_value_url"] + self.config["home_server_id"], 
                                    data=json.dumps(payload), headers=headers, verify=False)
        if response.json().get('StatusCode') == 1:
            raise ValueError(f"Failed to set {datapoint_name} value: {response.json()}")
        return True
    
    def _read_datapoints_from_api(self, session, access_token, datapoints_config_key, datapoints_group_name):
        specific_datapoints = self.config[datapoints_config_key]
        read_values_url = f'{self.config["read_value_url"]}{self.config["home_server_id"]}'
        datapoints_to_read = [
            {"DatapointConfigId": dp_id, "DeviceId": self.config["device_id"]}
            for dp_id in specific_datapoints.keys()
        ]
        read_payload = {"DatapointValues": datapoints_to_read}
        api_headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json"
        }
        api_response = session.post(read_values_url, json=read_payload, headers=api_headers, verify=False)
        return api_response.json()

    def monitor(self, session, access_token):
        api_response_data = self._read_datapoints_from_api(session, access_token, "monitorDatapoints", "monitor")
        returned_datapoints = api_response_data.get('ResponseData', [])
        results = {}
        for dp_data in returned_datapoints:
            dp_id = dp_data.get('DatapointConfigId')
            raw_value = dp_data.get('Value')
            if dp_id and raw_value is not None:
                results[dp_id] = raw_value
                dp_mqtt_config = self.config["monitorDatapoints"].get(dp_id)
                if dp_mqtt_config and all(k in dp_mqtt_config for k in ['device', 'type', 'unit', 'factor']):
                    device, type_, unit, factor = [
                        dp_mqtt_config['device'], 
                        dp_mqtt_config['type'], 
                        dp_mqtt_config['unit'], 
                        float(dp_mqtt_config['factor'])
                    ]
                    actual_value = round(float(raw_value) * factor, 2)
                    topic = f"sensors/{type_}/WP/TR/{device}/{unit}"
                    publish_to_mqtt(self.mqtt_config, topic, actual_value)
        return results

    def status(self, session, access_token):
        api_response_data = self._read_datapoints_from_api(session, access_token, "statusDatapoints", "status")
        returned_datapoints = api_response_data.get('ResponseData', [])
        results = {}
        for dp_data in returned_datapoints:
            dp_id = dp_data.get('DatapointConfigId')
            raw_value = dp_data.get('Value')
            if dp_id and raw_value is not None:
                results[dp_id] = raw_value
        return results
            
def main(event, context):
    body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
    home = body.get('home')
    jsonKeys = body.get('jsonKeys', [])
    current_session = requests.Session()
    wp = BoeschWP(home, jsonKeys)
    wp.access_token = wp.perform_pkce_login_and_get_token(current_session)

    if event['path'] == '/boesch/monitor':
        values = wp.monitor(current_session, wp.access_token)
        return response(values)
    elif event['path'] == '/boesch/status':
        values = wp.status(current_session, wp.access_token)
        return response(values)
    elif event['path'].lower() == '/boesch/datapoint':
        datapoint_name = body.get('datapoint', '').upper()
        action = body.get('action', '').lower()
        if not datapoint_name:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Missing 'datapoint' parameter in request body"})
            }
        if action == 'get':
            try:
                value = wp.get_datapoint(current_session, wp.access_token, datapoint_name)
                unit = wp.config["setDatapoints"][datapoint_name]["unit"]
                return response([[f"sensors/eny/WP/TR/{datapoint_name}/{unit}", value]])
            except Exception as e:
                return {
                    "statusCode": 500,
                    "body": json.dumps({"error": f"Failed to get {datapoint_name} value: {str(e)}"})
                }
        elif action == 'set':
            if 'value' not in body:
                return {
                    "statusCode": 400,
                    "body": json.dumps({"error": "Missing 'value' parameter in request body"})
                }
            try:
                value = float(body['value'])
                wp.set_datapoint(current_session, wp.access_token, datapoint_name, value)
                unit = wp.config["setDatapoints"][datapoint_name]["unit"]
                return response([[f"sensors/eny/WP/TR/{datapoint_name}/{unit}", value]])
            except Exception as e:
                return {
                    "statusCode": 500,
                    "body": json.dumps({"error": f"Failed to set {datapoint_name} value: {str(e)}"})
                }
        else:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": f"Invalid action: {action}. Must be 'get' or 'set'."})
            }

    
