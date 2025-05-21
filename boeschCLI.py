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
import argparse

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

class BoeschWP:
    def __init__(self, home, jsonKeys):
        config_str = getConfig(home, jsonKeys)
        config = json.loads(config_str)
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
        if not csrf:
            print("Error: Failed to get CSRF token during login.")
            return None
        login_resp = self.submit_login_credentials(session, csrf, final_encoded_return_url)
        if not login_resp or not login_resp.url or "code=" not in login_resp.url:
             print("Error: Login submission failed or did not return a code.")
             return None
        access_token = self.exchange_code_for_tokens(session, login_resp.url, initial_state, verifier)
        return access_token
        
    def _validate_datapoint_config(self, datapoint_name):
        if "setDatapoints" not in self.config:
            raise ValueError("'setDatapoints' configuration not found in 'boesch' config.")
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
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json"
            }
        datapoint_id = datapoint_config["datapoint"]
        dpType = datapoint_config["dpType"]
        payload = {"DatapointValues":
                    [{"$type":dpType,
                        "Value": 0,
                        "DatapointConfigId":datapoint_id,
                        "DeviceId":self.config["device_id"],"Flags":0}
                    ]}
        response = requests.post(self.config["read_value_url"] + self.config["home_server_id"], 
                                    data=json.dumps(payload), headers=headers, verify=False)
        response.raise_for_status()
        data_points = response.json()['ResponseData']
        datapoint_value_item = next((item for item in data_points if item["DatapointConfigId"] == datapoint_id), None)
        if datapoint_value_item is None or 'Value' not in datapoint_value_item:
            raise ValueError(f"{datapoint_name} (ID: {datapoint_id}) not found in API response or 'Value' key is missing.")
        value = round(float(datapoint_value_item['Value']), 2)
        return value
    
    def set_datapoint(self, session, access_token, datapoint_name, value_to_set):
        datapoint_config = self._validate_datapoint_config(datapoint_name)
        values_cfg = datapoint_config["values"]
        if len(values_cfg) == 2 and isinstance(values_cfg[0], (int,float)) and isinstance(values_cfg[1], (int,float)) and values_cfg[0] < values_cfg[1]:
            min_value, max_value = values_cfg
            if not (min_value <= float(value_to_set) <= max_value):
                raise ValueError(f"{datapoint_name} value {value_to_set} must be between {min_value} and {max_value}")
        elif float(value_to_set) not in [float(v) for v in values_cfg]:
                raise ValueError(f"{datapoint_name} value {value_to_set} must be one of: {values_cfg}")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json"
            }
        datapoint_id = datapoint_config["datapoint"]
        dpType = datapoint_config["dpType"]
        
        raw_value = value_to_set
        if "Int32" in dpType:
            raw_value = int(value_to_set)
        elif "Single" in dpType or "Double" in dpType:
            raw_value = float(value_to_set)
        
        payload = {"DatapointValues":
                    [{"$type": dpType,
                        "Value": raw_value,
                        "DatapointConfigId": datapoint_id,
                        "DeviceId": self.config["device_id"], "Flags": 0}
                    ]}
        response = requests.post(self.config["write_value_url"] + self.config["home_server_id"], 
                                    data=json.dumps(payload), headers=headers, verify=False)
        response.raise_for_status()
        if response.json().get('StatusCode') == 1:
            raise ValueError(f"API error setting {datapoint_name} value: {response.json().get('StatusText', 'Unknown API error')}")
        return True
    
    def _read_datapoints_from_api(self, session, access_token, datapoints_config_key, datapoints_group_name):
        if datapoints_config_key not in self.config or not isinstance(self.config[datapoints_config_key], dict):
            print(f"Warning: '{datapoints_config_key}' is missing or not a dictionary in configuration. Skipping API call for {datapoints_group_name}.")
            return {}
        specific_datapoints = self.config[datapoints_config_key]
        if not specific_datapoints:
            print(f"Warning: '{datapoints_config_key}' is empty. No datapoints to read for {datapoints_group_name}.")
            return {}

        read_values_url = f'{self.config["read_value_url"]}{self.config["home_server_id"]}'
        datapoints_to_read = [
            {"DatapointConfigId": dp_id, "DeviceId": self.config["device_id"]}
            for dp_id in specific_datapoints.keys()
        ]
        
        if not datapoints_to_read:
            return {}
                
        read_payload = {"DatapointValues": datapoints_to_read}
        api_headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json"
        }
        api_response = session.post(read_values_url, json=read_payload, headers=api_headers, verify=False)
        api_response.raise_for_status()
        return api_response.json()

    def monitor(self, session, access_token):
        api_response_data = self._read_datapoints_from_api(session, access_token, "monitorDatapoints", "monitor")
        returned_datapoints = api_response_data.get('ResponseData', [])
        results = {}
        print("--- Monitored Datapoints ---")
        for dp_data in returned_datapoints:
            dp_id = dp_data.get('DatapointConfigId')
            raw_value = dp_data.get('Value')
            if dp_id and raw_value is not None:
                results[dp_id] = raw_value
                dp_detail_config = self.config["monitorDatapoints"].get(dp_id, {})
                desc = dp_detail_config.get('description', 'N/A')
                unit = dp_detail_config.get('unit', '')
                factor = float(dp_detail_config.get('factor', 1))
                actual_value = round(float(raw_value) * factor, 2)
                print(f"  {desc} ({dp_id}): {actual_value} {unit}")
                
                dp_mqtt_config = self.config["monitorDatapoints"].get(dp_id)
                if dp_mqtt_config and all(k in dp_mqtt_config for k in ['device', 'type', 'unit', 'factor']):
                    mqtt_device, mqtt_type, mqtt_unit = [
                        dp_mqtt_config['device'], 
                        dp_mqtt_config['type'], 
                        dp_mqtt_config['unit']
                    ]
                    topic = f"sensors/{mqtt_type}/WP/TR/{mqtt_device}/{mqtt_unit}"
                    publish_to_mqtt(self.mqtt_config, topic, actual_value)
        if not results:
            print("No data returned or processed for monitor.")
        return results

    def status(self, session, access_token):
        api_response_data = self._read_datapoints_from_api(session, access_token, "statusDatapoints", "status")
        returned_datapoints = api_response_data.get('ResponseData', [])
        results = {}
        print("--- Status Datapoints ---")
        for dp_data in returned_datapoints:
            dp_id = dp_data.get('DatapointConfigId')
            raw_value = dp_data.get('Value')
            if dp_id and raw_value is not None:
                results[dp_id] = raw_value
                dp_detail_config = self.config["statusDatapoints"].get(dp_id, {})
                desc = dp_detail_config.get('description', 'N/A')
                print(f"  {desc} ({dp_id}): {raw_value}")
        if not results:
            print("No data returned or processed for status.")
        return results
            
def main_cli():
    parser = argparse.ArgumentParser(description="Boesch Heatpump CLI Tool")
    parser.add_argument("home_id", help="Your Home ID (e.g., prg)")
    
    subparsers = parser.add_subparsers(dest="command", title="commands", required=True)
    
    monitor_parser = subparsers.add_parser("monitor", help="Fetch and display monitor datapoints.")
    
    status_parser = subparsers.add_parser("status", help="Fetch and display status datapoints.")
    
    dp_parser = subparsers.add_parser("datapoint", help="Get or set a specific datapoint.")
    dp_parser.add_argument("action", choices=["get", "set"], help="Action to perform on the datapoint.")
    dp_parser.add_argument("name", help="Name of the datapoint (e.g., PVHK, SBHK as defined in config).")
    dp_parser.add_argument("value", nargs='?', help="Value to set (only for 'set' action).")

    args = parser.parse_args()

    json_keys = ["boesch", "mqtt"]
    
    print(f"Initializing for Home ID: {args.home_id}...")
    try:
        wp = BoeschWP(args.home_id, json_keys)
    except Exception as e:
        print(f"Error initializing BoeschWP: {e}")
        print("Please ensure your domuxConfig Lambda is working and accessible, and the home_id is correct.")
        return

    current_session = requests.Session()
    print("Authenticating...")
    try:
        wp.access_token = wp.perform_pkce_login_and_get_token(current_session)
        if not wp.access_token:
            print("Authentication failed. Exiting.")
            return
        print("Authentication successful.")
    except Exception as e:
        print(f"An error occurred during authentication: {e}")
        return

    try:
        if args.command == "monitor":
            wp.monitor(current_session, wp.access_token)
        elif args.command == "status":
            wp.status(current_session, wp.access_token)
        elif args.command == "datapoint":
            datapoint_name_upper = args.name.upper()
            if args.action == "get":
                value = wp.get_datapoint(current_session, wp.access_token, datapoint_name_upper)
                unit = wp.config.get("setDatapoints", {}).get(datapoint_name_upper, {}).get("unit", "")
                print(f"Datapoint '{datapoint_name_upper}' value: {value} {unit}")
            elif args.action == "set":
                if args.value is None:
                    print("Error: Value is required for 'set' action.")
                    dp_parser.print_help()
                    return
                print(f"Attempting to set datapoint '{datapoint_name_upper}' to '{args.value}'...")
                success = wp.set_datapoint(current_session, wp.access_token, datapoint_name_upper, args.value)
                if success:
                    print(f"Successfully set datapoint '{datapoint_name_upper}' to '{args.value}'.")
    except ValueError as ve:
        print(f"Configuration or Value Error: {ve}")
    except requests.exceptions.HTTPError as he:
        print(f"HTTP Error: {he} - {he.response.text if he.response else 'No response content'}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main_cli()

    
