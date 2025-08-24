import requests
import hashlib
import base64
import secrets
import urllib.parse
import re
import json
import argparse
import boto3
from typing import Dict, Optional

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
        import paho.mqtt.client as mqtt
        mqtt_client = mqtt.Client()
        if mqtt_config.get('user') and mqtt_config.get('password'):
            mqtt_client.username_pw_set(mqtt_config['user'], mqtt_config['password'])
        mqtt_client.connect(mqtt_config['broker'], int(mqtt_config['port']), 60)
        mqtt_client.publish(topic, value)
        mqtt_client.disconnect()
    except Exception as e:
        print(f"Could not publish to MQTT: {e}")

class BoeschWP:
    def __init__(self, home, jsonKeys):
        config_str = getConfig(home, jsonKeys)
        config = json.loads(config_str)
        self.config = config['boesch']
        self.mqtt_config = config.get('mqtt', {})
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
        })
        self.access_token = None

    def login(self):
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(96)).decode('utf-8').rstrip('=')
        challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')
        state = secrets.token_hex(16)

        auth_params = {
            'client_id': self.config["client_id"],
            'redirect_uri': self.config["redirect_uri"],
            'response_type': 'code',
            'scope': self.config["scope"],
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }
        
        auth_url = f"{self.config['portal']}/openid/connect/authorize"
        response = self.session.get(auth_url, params=auth_params, allow_redirects=True)
        response.raise_for_status()

        match = re.search(r'name="__RequestVerificationToken".*?value="([^"]+)"', response.text)
        if not match:
            raise ValueError("Failed to extract form verification token")
        form_token = match.group(1)

        login_data = {
            'Login': self.config["user"],
            'Password': self.config["pass"],
            'login': '',
            '__RequestVerificationToken': form_token
        }

        return_url_match = re.search(r'action="([^"]+)"', response.text)
        if not return_url_match:
            raise ValueError("Could not find login post URL")
        
        login_post_url = f"{self.config['portal']}{return_url_match.group(1)}"
        
        response = self.session.post(
            login_post_url, data=login_data, 
            headers={'Content-Type': 'application/x-www-form-urlencoded', 'Origin': self.config['portal'], 'Referer': response.url},
            allow_redirects=False
        )

        auth_code = None
        while response.status_code in [302, 301]:
            location = response.headers.get('Location')
            if not location: break
            if 'code=' in location:
                parsed_url = urllib.parse.urlparse(location)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                auth_code = query_params.get('code', [None])[0]
                break
            
            next_url = urllib.parse.urljoin(self.config['portal'], location)
            response = self.session.get(next_url, allow_redirects=False)

        if not auth_code:
            raise ValueError("Failed to get authorization code")

        token_data = {
            'grant_type': 'authorization_code',
            'redirect_uri': self.config["redirect_uri"],
            'code': auth_code,
            'code_verifier': code_verifier,
            'client_id': self.config["client_id"]
        }
        token_url = f"{self.config['portal']}/openid/connect/token"
        token_response = self.session.post(token_url, data=token_data)
        token_response.raise_for_status()
        
        tokens = token_response.json()
        self.access_token = tokens['access_token']
        return self.access_token

    def _validate_datapoint_config(self, datapoint_name):
        datapoint_config = self.config.get("setDatapoints", {}).get(datapoint_name)
        if not datapoint_config:
            raise ValueError(f"{datapoint_name} datapoint configuration not found")
        return datapoint_config

    def get_datapoint(self, datapoint_name):
        datapoint_config = self._validate_datapoint_config(datapoint_name)
        payload = {"DatapointValues": [{
            "$type": datapoint_config["dpType"], "Value": 0,
            "DatapointConfigId": datapoint_config["datapoint"],
            "DeviceId": self.config["device_id"], "Flags": 0
        }]}
        response = self.session.post(
            f'{self.config["read_value_url"]}{self.config["home_server_id"]}',
            json=payload, headers={"Authorization": f"Bearer {self.access_token}"}
        )
        response.raise_for_status()
        data_points = response.json()['ResponseData']
        dp_item = next((item for item in data_points if item["DatapointConfigId"] == datapoint_config["datapoint"]), None)
        if dp_item is None or 'Value' not in dp_item:
            raise ValueError(f"{datapoint_name} not found in API response")
        return round(float(dp_item['Value']), 2)

    def set_datapoint(self, datapoint_name, value_to_set):
        datapoint_config = self._validate_datapoint_config(datapoint_name)
        raw_value = value_to_set
        if "Int32" in datapoint_config["dpType"]: raw_value = int(value_to_set)
        elif "Single" in datapoint_config["dpType"] or "Double" in datapoint_config["dpType"]: raw_value = float(value_to_set)
        
        payload = {"DatapointValues": [{
            "$type": datapoint_config["dpType"], "Value": raw_value,
            "DatapointConfigId": datapoint_config["datapoint"],
            "DeviceId": self.config["device_id"], "Flags": 0
        }]}
        response = self.session.post(
            f'{self.config["write_value_url"]}{self.config["home_server_id"]}',
            json=payload, headers={"Authorization": f"Bearer {self.access_token}"}
        )
        response.raise_for_status()
        if response.json().get('StatusCode') == 1:
            raise ValueError(f"API error: {response.json().get('StatusText', 'Unknown')}")
        return True

    def _read_datapoints_from_api(self, datapoints_key):
        datapoints_config = self.config.get(datapoints_key, {})
        if not datapoints_config: return {}
        
        datapoints_to_read = [
            {"DatapointConfigId": dp_id, "DeviceId": self.config["device_id"]}
            for dp_id in datapoints_config.keys()
        ]
        if not datapoints_to_read: return {}

        read_payload = {"DatapointValues": datapoints_to_read}
        response = self.session.post(
            f'{self.config["read_value_url"]}{self.config["home_server_id"]}',
            json=read_payload, headers={"Authorization": f"Bearer {self.access_token}"}
        )
        response.raise_for_status()
        return response.json()

    def monitor(self):
        api_response_data = self._read_datapoints_from_api("monitorDatapoints")
        returned_datapoints = api_response_data.get('ResponseData', [])
        print("--- Monitored Datapoints ---")
        for dp_data in returned_datapoints:
            dp_id = dp_data.get('DatapointConfigId')
            raw_value = dp_data.get('Value')
            if dp_id and raw_value is not None:
                dp_detail_config = self.config["monitorDatapoints"].get(dp_id, {})
                desc = dp_detail_config.get('description', 'N/A')
                unit = dp_detail_config.get('unit', '')
                factor = float(dp_detail_config.get('factor', 1))
                actual_value = round(float(raw_value) * factor, 2)
                print(f"  {desc} ({dp_id}): {actual_value} {unit}")
                
                if self.mqtt_config:
                    mqtt_cfg = dp_detail_config
                    if all(k in mqtt_cfg for k in ['device', 'type', 'unit']):
                        topic = f"sensors/{mqtt_cfg['type']}/WP/TR/{mqtt_cfg['device']}/{mqtt_cfg['unit']}"
                        publish_to_mqtt(self.mqtt_config, topic, actual_value)

    def status(self):
        api_response_data = self._read_datapoints_from_api("statusDatapoints")
        returned_datapoints = api_response_data.get('ResponseData', [])
        print("--- Status Datapoints ---")
        for dp_data in returned_datapoints:
            dp_id = dp_data.get('DatapointConfigId')
            raw_value = dp_data.get('Value')
            if dp_id and raw_value is not None:
                dp_detail_config = self.config["statusDatapoints"].get(dp_id, {})
                desc = dp_detail_config.get('description', 'N/A')
                print(f"  {desc} ({dp_id}): {raw_value}")

def main_cli():
    parser = argparse.ArgumentParser(description="Boesch Heatpump CLI Tool")
    parser.add_argument("home_id", help="Your Home ID (e.g., prg), used for config selection if applicable.")
    subparsers = parser.add_subparsers(dest="command", title="commands", required=True)
    
    subparsers.add_parser("monitor", help="Fetch and display monitor datapoints.")
    subparsers.add_parser("status", help="Fetch and display status datapoints.")
    
    dp_parser = subparsers.add_parser("datapoint", help="Get or set a specific datapoint.")
    dp_parser.add_argument("action", choices=["get", "set"], help="Action to perform on the datapoint.")
    dp_parser.add_argument("name", help="Name of the datapoint (e.g., PVHK, SBHK as defined in config).")
    dp_parser.add_argument("value", nargs='?', help="Value to set (only for 'set' action).")

    args = parser.parse_args()

    try:
        json_keys = ["boesch", "mqtt"]
        wp = BoeschWP(args.home_id, json_keys)
        print("Authenticating...")
        wp.login()
        print("Authentication successful.")

        if args.command == "monitor":
            wp.monitor()
        elif args.command == "status":
            wp.status()
        elif args.command == "datapoint":
            dp_name = args.name.upper()
            if args.action == "get":
                value = wp.get_datapoint(dp_name)
                unit = wp.config.get("setDatapoints", {}).get(dp_name, {}).get("unit", "")
                print(f"Datapoint '{dp_name}' value: {value} {unit}")
            elif args.action == "set":
                if args.value is None:
                    print("Error: Value is required for 'set' action.")
                    return
                print(f"Attempting to set '{dp_name}' to '{args.value}'...")
                if wp.set_datapoint(dp_name, args.value):
                    print(f"Successfully set '{dp_name}' to '{args.value}'.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main_cli()