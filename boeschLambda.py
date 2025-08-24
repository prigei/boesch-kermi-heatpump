import json
import re
import requests
import secrets
import base64
import hashlib
import urllib.parse
import boto3

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

def response(values=None):
    if values is None:
        values = {}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"status": "OK", "values": values})
    }

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
        resp = self.session.get(auth_url, params=auth_params, allow_redirects=True)
        resp.raise_for_status()

        match = re.search(r'name="__RequestVerificationToken".*?value="([^"]+)"', resp.text)
        if not match: raise ValueError("Failed to extract form verification token")
        form_token = match.group(1)

        login_data = {
            'Login': self.config["user"], 'Password': self.config["pass"],
            'login': '', '__RequestVerificationToken': form_token
        }

        match = re.search(r'action="([^"]+)"', resp.text)
        if not match: raise ValueError("Could not find login post URL")
        
        login_post_url = f"{self.config['portal']}{match.group(1)}"
        resp = self.session.post(login_post_url, data=login_data, allow_redirects=False)

        auth_code = None
        while resp.status_code in [302, 301]:
            location = resp.headers.get('Location')
            if not location: break
            if 'code=' in location:
                query_params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
                auth_code = query_params.get('code', [None])[0]
                break
            resp = self.session.get(urllib.parse.urljoin(self.config['portal'], location), allow_redirects=False)

        if not auth_code: raise ValueError("Failed to get authorization code")

        token_data = {
            'grant_type': 'authorization_code', 'redirect_uri': self.config["redirect_uri"],
            'code': auth_code, 'code_verifier': code_verifier, 'client_id': self.config["client_id"]
        }
        token_url = f"{self.config['portal']}/openid/connect/token"
        token_resp = self.session.post(token_url, data=token_data)
        token_resp.raise_for_status()
        
        tokens = token_resp.json()
        self.access_token = tokens['access_token']
        return self.access_token

    def _validate_datapoint_config(self, datapoint_name):
        datapoint_config = self.config.get("setDatapoints", {}).get(datapoint_name)
        if not datapoint_config: raise ValueError(f"{datapoint_name} datapoint configuration not found")
        return datapoint_config

    def get_datapoint(self, datapoint_name):
        cfg = self._validate_datapoint_config(datapoint_name)
        payload = {"DatapointValues": [{"$type": cfg["dpType"], "Value": 0, "DatapointConfigId": cfg["datapoint"],
                     "DeviceId": self.config["device_id"], "Flags": 0}]}
        resp = self.session.post(f'{self.config["read_value_url"]}{self.config["home_server_id"]}',
            json=payload, headers={"Authorization": f"Bearer {self.access_token}"})
        resp.raise_for_status()
        dp = next((i for i in resp.json()['ResponseData'] if i["DatapointConfigId"] == cfg["datapoint"]), None)
        if dp is None or 'Value' not in dp: raise ValueError(f"{datapoint_name} not found in API response")
        return round(float(dp['Value']), 2)

    def set_datapoint(self, datapoint_name, value):
        cfg = self._validate_datapoint_config(datapoint_name)
        raw_val = value
        if "Int32" in cfg["dpType"]: raw_val = int(value)
        elif "Single" in cfg["dpType"] or "Double" in cfg["dpType"]: raw_val = float(value)
        
        payload = {"DatapointValues": [{"$type": cfg["dpType"], "Value": raw_val, "DatapointConfigId": cfg["datapoint"],
                     "DeviceId": self.config["device_id"], "Flags": 0}]}
        resp = self.session.post(f'{self.config["write_value_url"]}{self.config["home_server_id"]}',
            json=payload, headers={"Authorization": f"Bearer {self.access_token}"})
        resp.raise_for_status()
        if resp.json().get('StatusCode') == 1: raise ValueError(f"API error: {resp.json().get('StatusText', 'Unknown')}")
        return True

    def _read_datapoints_from_api(self, datapoints_key):
        dp_config = self.config.get(datapoints_key, {})
        if not dp_config: return {}
        
        payload = {"DatapointValues": [{"DatapointConfigId": dp_id, "DeviceId": self.config["device_id"]} for dp_id in dp_config.keys()]}
        if not payload["DatapointValues"]: return {}

        resp = self.session.post(f'{self.config["read_value_url"]}{self.config["home_server_id"]}',
            json=payload, headers={"Authorization": f"Bearer {self.access_token}"})
        resp.raise_for_status()
        return resp.json()

    def monitor(self):
        api_data = self._read_datapoints_from_api("monitorDatapoints")
        results = {}
        for dp in api_data.get('ResponseData', []):
            dp_id, raw_val = dp.get('DatapointConfigId'), dp.get('Value')
            if dp_id and raw_val is not None:
                results[dp_id] = raw_val
                cfg = self.config["monitorDatapoints"].get(dp_id, {})
                actual_val = round(float(raw_val) * float(cfg.get('factor', 1)), 2)
                
                if self.mqtt_config and all(k in cfg for k in ['device', 'type', 'unit']):
                    topic = f"sensors/{cfg['type']}/WP/TR/{cfg['device']}/{cfg['unit']}"
                    publish_to_mqtt(self.mqtt_config, topic, actual_val)
        return results

    def status(self):
        api_data = self._read_datapoints_from_api("statusDatapoints")
        results = {}
        for dp in api_data.get('ResponseData', []):
            dp_id, raw_val = dp.get('DatapointConfigId'), dp.get('Value')
            if dp_id and raw_val is not None:
                results[dp_id] = raw_val
        return results

def main(event, context):
    try:
        path = event.get('path', '').lower()
        body = json.loads(event.get('body', '{}')) if isinstance(event.get('body'), str) else event.get('body', {})

        home = body.get('home')
        jsonKeys = body.get('jsonKeys', [])

        wp = BoeschWP(home, jsonKeys)
        wp.login()
        
        if path == '/boesch/monitor':
            return response(wp.monitor())
        elif path == '/boesch/status':
            return response(wp.status())
        elif path == '/boesch/datapoint':
            dp_name = body.get('datapoint', '').upper()
            action = body.get('action', '').lower()
            if not dp_name or not action:
                raise ValueError("Missing 'datapoint' or 'action'")

            if action == 'get':
                value = wp.get_datapoint(dp_name)
                unit = wp.config["setDatapoints"][dp_name]["unit"]
                return response({f"sensors/eny/WP/TR/{dp_name}/{unit}": value})
            elif action == 'set':
                value = body.get('value')
                if value is None: raise ValueError("Missing 'value'")
                wp.set_datapoint(dp_name, value)
                unit = wp.config["setDatapoints"][dp_name]["unit"]
                return response({f"sensors/eny/WP/TR/{dp_name}/{unit}": value})
            else:
                raise ValueError(f"Invalid action: {action}")
        else:
            raise ValueError(f"Invalid path: {event.get('path')}")

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}

    
