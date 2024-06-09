import json
import re
import requests
from bs4 import BeautifulSoup
import paho.mqtt.client as mqtt
import warnings
import argparse
from urllib.parse import urlparse
from urllib.parse import parse_qs

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class BoeschWP:
    def __init__(self):
        with open('haConfig.json', 'r') as file:
            haConfig = json.load(file)
        self.config = haConfig["boesch"]
        self.mqtt_config = haConfig["mqtt"]

    def publish_mqtt(self, topic, value):
        mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        mqtt_client.username_pw_set(self.mqtt_config['user'], self.mqtt_config['password'])
        mqtt_client.connect(self.mqtt_config['broker'], self.mqtt_config['port'], 60)
        mqtt_client.publish(topic, value)
        mqtt_client.disconnect()

    def get_session_cookie(self):
        culture_cookie = '.AspNetCore.Culture=c=de-DE|uic=de-DE'
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # get portal URL
        response = requests.get(self.config['portal_DE'], allow_redirects=False, verify=False)
        location = response.headers['location']
        parsed = urlparse(location)
        redirect_uri = parse_qs(parsed.query)['redirect_uri'][0]
        nonce_cookie = re.search(r".AspNetCore.OpenIdConnect.Nonce.[^;]*", response.headers['Set-Cookie']).group()
        correlation_cookie = re.search(r".AspNetCore.Correlation.[^;]*", response.headers['Set-Cookie']).group()
        headers['Cookie'] = f"{nonce_cookie};{correlation_cookie};.AspNetCore.Culture=c=de-DE|uic=de-DE"
        
        # authorize
        response = requests.get(location, allow_redirects=False, verify=False)
        location = response.headers['location']
        
        #login
        response = requests.get(location, allow_redirects=False, verify=False)
        cookie = response.headers['Set-Cookie']
        forgery_cookie = re.search(r".AspNetCore.Antiforgery.[^;]*", cookie).group()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        returnURL = soup.find('form', class_='login-form').get('action')
        token = soup.find(attrs={"name": "__RequestVerificationToken"}).attrs["value"]
        
        #openid
        headers['Cookie'] = f"{forgery_cookie};{culture_cookie};{nonce_cookie};{correlation_cookie}"
        payload = f"Login={self.config['user']}&Password={self.config['pass']}&__RequestVerificationToken={token}"
        response = requests.post(self.config['portal'] + returnURL, data=payload, headers=headers, allow_redirects=False, verify=False)
        location = response.headers['location']
        cookie = response.headers['Set-Cookie']
        openidauth_cookie = re.search(r".OpenIdAuth=[^;]*", response.headers['Set-Cookie']).group()

        #authorize
        headers['Cookie'] = f"{forgery_cookie};{culture_cookie};{nonce_cookie};{correlation_cookie};{openidauth_cookie}"
        response = requests.get(self.config['portal'] + location, headers=headers, allow_redirects=False, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        code, state, iss = [soup.find(attrs={"name": attr}).attrs["value"] for attr in ["code", "state", "iss"]]

        
        #signin-oidc
        payload = f"code={code}&state={state}&iss={iss}"
        response = requests.post(redirect_uri, data=payload, headers=headers, allow_redirects=False, verify=False)
        cookie = response.headers['Set-Cookie']
        core_cookie = re.search(r".AspNetCore.Cookies=.[^;]*", cookie).group()
        self.cookies_cookie = core_cookie
        
    def monitor(self):
        headers = {
            'Cookie': self.cookies_cookie,
            'Content-Type': 'application/json;charset=UTF-8'
        }
        payload = {
            "DatapointValues": [{"DatapointConfigId": key, "DeviceId": self.config["device_id"]} for key in self.config["monitorDatapoints"].keys()]
        }
        response = requests.post(self.config["read_value_url"] + self.config["home_server_id"], data=json.dumps(payload), headers=headers, verify=False)
        data_points = json.loads(response.text)['ResponseData']
        try:
            # hlhf1 entspricht verdichteraufnahme
            va = next((item for item in data_points if item["DatapointConfigId"] == "3576624b-1af4-4406-8e8b-12500acd4840" ), None)
            # hlhf2 ist ein korrekturfaktor, keine ahnung welcher
            hlhfaktor = next((item for item in data_points if item["DatapointConfigId"] == "7605e769-5bcf-4e37-97e4-e1cded35dc54" ), None)
            cop = next((item for item in data_points if item["DatapointConfigId"] == "34760a09-8f79-424f-a1b0-5f1a9339d864" ), None)
            heizleistung = (va['Value'] + hlhfaktor['Value']) * cop['Value']
            self.publish_mqtt('sensors/eny/WP/TR/HLH/kW', heizleistung*1000)
        except Exception as e:
            print("Heizung not running?")
            print("error: ", e)
       
        for data_point in data_points:
            config_id = data_point["DatapointConfigId"]
            if config_id == "7605e769-5bcf-4e37-97e4-e1cded35dc54":
                continue
            if config_id in self.config["monitorDatapoints"]: 
                datapoint_config = self.config["monitorDatapoints"][config_id]
                device, type_, unit, factor = [datapoint_config[key] for key in ['device', 'type', 'unit', 'factor']]
                value = round(float(data_point['Value'] * factor ),2)
                topic = f"sensors/{type_}/WP/TR/{device}/{unit}"
                try:
                    self.publish_mqtt(topic, value)
                except Exception as e:
                    print("error: ", e)

    def switch(self, datapoint, onOff):
        headers = {
            'Cookie': self.cookies_cookie,
            'Content-Type': 'application/json;charset=UTF-8'
        }
        dpType = ''
        if (isinstance(onOff, bool)):
            dpType = "BMS.Shared.DatapointCore.DatapointValue`1[[System.Boolean, mscorlib]], BMS.Shared"
        elif (isinstance(onOff, int)):
            dpType = "BMS.Shared.DatapointCore.DatapointValue`1[[System.Int32, mscorlib]], BMS.Shared"
        payload = {"DatapointValues":
                    [{"$type":dpType,
                        "Value": onOff,
                        "DatapointConfigId":datapoint,
                        "DeviceId":self.config["device_id"],"Flags":0}
                    ]}
        try:
            response = requests.post(self.config["write_value_url"] + self.config["home_server_id"], data=json.dumps(payload), headers=headers, verify=False)
            if (response.json()['StatusCode'] == 1):
                print("Error: ", response.json())
            
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def main():

    wp = BoeschWP()
    wp.get_session_cookie()

    parser = argparse.ArgumentParser(description="boeschWP Control Script")
    subparsers = parser.add_subparsers(dest='subcommand', required=True)

    switch_parser = subparsers.add_parser('switch', help="Switch device on or off")
    device_help = {device: f"Device: {device} ({info['description']})" for device, info in wp.config["switchDatapoints"].items()}

    device_choices = list(wp.config["switchDatapoints"].keys())
    switch_parser.add_argument('device', choices=device_choices, help=" | ".join(device_help.values()))
    switch_parser.add_argument('state', choices=['on', 'off'], help="State to switch the device to (on/off)")

    monitor_parser = subparsers.add_parser('monitor', help="Monitor data")

    # not used atm
    #setvalue_parser = subparsers.add_parser('setvalue', help="Set a specific value")
    #setvalue_parser.add_argument('device', choices=['test'], help="Device name (currently only supports test)")
    #setvalue_parser.add_argument('value', type=int, choices=range(0, 101), help="Value to set (from 0 to 100)")

    args = parser.parse_args()
    
    if args.subcommand == "switch":
        datapoint = wp.config["switchDatapoints"][args.device]["datapoint"]
        if args.state == "on":
            value = wp.config["switchDatapoints"][args.device]["values"][0]
        else:
            value = wp.config["switchDatapoints"][args.device]["values"][1]
        wp.switch(datapoint, value)
    elif args.subcommand == "monitor":
        wp.monitor()
    elif args.subcommand == "setvalue":
        if args.device == "test":
            wp.set_value(args.device, args.value)


if __name__ == "__main__":
    main()
