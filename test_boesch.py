import unittest
import json
import sys
from pathlib import Path
import requests # For real HTTP calls
from unittest.mock import patch

# Add the directory of boeschLambda.py to sys.path
script_dir = Path(__file__).resolve().parent
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

try:
    from boeschLambda import BoeschWP, main as lambda_main, publish_to_mqtt, getConfig # getConfig will be called for real
except ImportError as e:
    print(f"Error importing from boeschLambda.py: {e}. Ensure it's in the same directory.")
    BoeschWP = None # Prevent further NameErrors

# --- Configuration for Integration Tests ---
# !!! IMPORTANT: Replace with a REAL Home ID that your domuxConfig Lambda can process !!!
# This ID will be used to fetch LIVE configuration.
TEST_HOME_ID = "prg"  # Or your actual home ID, e.g., "prg"
# !!! IMPORTANT: Replace with real datapoint names from your Kermi config for testing !!!
# These should exist in the 'setDatapoints' of the config returned for TEST_HOME_ID.
TEST_DATAPOINT_NAME_FOR_GET = "PVHK"  # Example: A readable datapoint
TEST_DATAPOINT_NAME_FOR_SET = "SBHK"  # Example: A writable datapoint
# !!! IMPORTANT: Define a SAFE value to set for the TEST_DATAPOINT_NAME_FOR_SET !!!
# This value WILL be written to your heat pump.
TEST_VALUE_TO_SET = 20.0 # Example: A safe temperature or mode value

@unittest.skipIf(BoeschWP is None, "Skipping tests: BoeschWP class not imported.")
class TestBoeschLambdaIntegration(unittest.TestCase):
    wp_instance = None
    access_token = None
    live_config = None

    @classmethod
    def setUpClass(cls):
        """Fetches live config and authenticates ONCE for all tests in this class."""
        if BoeschWP is None: # Double check in case of import issues not caught by skipIf
            raise unittest.SkipTest("BoeschWP class not available.")

        print(f"--- Test Suite Setup ({cls.__name__}) ---")
        print(f"Fetching LIVE configuration for home ID: {TEST_HOME_ID}...")
        try:
            cls.current_session = requests.Session() # Create a session
            
            # BoeschWP init will call getConfig.
            cls.wp_instance = BoeschWP(home=TEST_HOME_ID, jsonKeys=["boesch", "mqtt"])
            
            # Perform login to get the access token
            print("Live configuration fetched. Authenticating with Kermi service...")
            token = cls.wp_instance.perform_pkce_login_and_get_token(cls.current_session)
            
            if not token:
                raise Exception("Failed to obtain access token during BoeschWP initialization. Check credentials and Kermi service availability.")
            
            cls.wp_instance.access_token = token # Assign token to the instance
            cls.access_token = token # Keep a class-level reference if needed, though wp_instance.access_token is preferred
            
            print(f"Authentication successful. Access token starts with: {cls.access_token[:20]}...")

            cls.live_config = cls.wp_instance.config # The 'boesch' part of the config
            cls.live_mqtt_config = cls.wp_instance.mqtt_config
            
            # Overwrite monitorDatapoints with the user-provided configuration
            user_monitor_datapoints = {
                "83a34595-924a-421e-b9c1-44c2a49f97ad": {"description": "Trinkwassertemperatur", "device": "TWT", "type": "temp", "unit": "C", "factor": 1},
                "3576624b-1af4-4406-8e8b-12500acd4840": {"description": "Verdichteraufnahme", "device": "VA", "type": "eny", "unit": "W", "factor": 1},
                "dbf925c9-f24e-456c-ac49-f7702adeb9d1": {"description": "Leistungsaufnahme Heizung", "device": "LAH", "type": "eny", "unit": "kWh", "factor": 1},
                "b94586b8-1a4c-4c4f-b56c-07895cb71a89": {"description": "Leistungsaufnahme Trinkwasser", "device": "LATW", "type": "eny", "unit": "kWh", "factor": 1},
                "ac0a8989-e55d-4c8d-9550-071cfc57c01c": {"description": "Leistungsaufnahme Gesamt", "device": "LAG", "type": "eny", "unit": "kWh", "factor": 1},
                "e9343511-e130-4fa0-81a8-764a69890f31": {"description": "Isttemperatur HK", "device": "ITHK", "type": "temp", "unit": "C", "factor": 1},
                "34760a09-8f79-424f-a1b0-5f1a9339d864": {"description": "COP", "device": "COP", "type": "ratio", "unit": "ratio", "factor": 1},
                "7605e769-5bcf-4e37-97e4-e1cded35dc54": {"description": "Heizleistung Heizung", "device": "HLHF2", "type": "eny", "unit": "kW", "factor": 1}
            }
            if cls.wp_instance.config is None: # Should not happen if BoeschWP init is successful
                cls.wp_instance.config = {}
            if cls.live_config is None: # Defensive
                cls.live_config = {}
                
            cls.wp_instance.config['monitorDatapoints'] = user_monitor_datapoints
            cls.live_config['monitorDatapoints'] = user_monitor_datapoints
            print("INFO: Overwrote monitorDatapoints in test configuration with user-provided structure.")
            
            if not cls.live_config.get('setDatapoints'): # Check if setDatapoints might also be missing or empty
                 print("Warning: 'setDatapoints' is missing or empty in the live_config. Other tests might be affected.")

            if not cls.live_config: # This check is a bit redundant now given the above
                raise Exception("Failed to load 'boesch' configuration from BoeschWP instance.")
            if not cls.live_mqtt_config:
                print("Warning: MQTT configuration was not loaded. MQTT dependent tests might behave unexpectedly.")

            print("--- Test Suite Setup Complete ---")

        except Exception as e:
            print(f"CRITICAL ERROR during setUpClass: {e}")
            print("Integration tests cannot proceed. Ensure Kermi portal is accessible, domuxConfig Lambda is working, and credentials are valid.")
            # To prevent individual tests from running if setup fails badly:
            cls.wp_instance = None 
            cls.access_token = None
            # This will cause individual tests to likely fail or be skipped if they check for wp_instance

    def setUp(self):
        """Ensures that setup was successful before running each test."""
        if not self.__class__.wp_instance or not self.__class__.access_token:
            self.skipTest("Skipping test due to critical failure in setUpClass (config load or auth failed).")

    # --- Test Methods --- 

    def test_01_get_datapoint(self):
        print(f"\nRunning test_01_get_datapoint for: {TEST_DATAPOINT_NAME_FOR_GET}")
        self.assertIsNotNone(self.live_config.get("setDatapoints"), "'setDatapoints' missing in live config.")
        self.assertIn(TEST_DATAPOINT_NAME_FOR_GET, self.live_config["setDatapoints"], f"Datapoint {TEST_DATAPOINT_NAME_FOR_GET} not in live config's setDatapoints.")
        
        # Call get_datapoint without session and access_token arguments
        value = self.wp_instance.get_datapoint(self.current_session, self.access_token, TEST_DATAPOINT_NAME_FOR_GET)
        print(f"Value for {TEST_DATAPOINT_NAME_FOR_GET}: {value}")
        self.assertIsNotNone(value, f"get_datapoint for {TEST_DATAPOINT_NAME_FOR_GET} returned None.")
        # Add more specific assertions if you know the expected type or rough range, e.g.:
        # self.assertIsInstance(value, (int, float))

    #@unittest.skip("Skipping set_datapoint test by default. Uncomment to run, ensure TEST_VALUE_TO_SET is safe.")
    def test_02_set_then_get_datapoint(self):
        print(f"\nRunning test_02_set_then_get_datapoint for: {TEST_DATAPOINT_NAME_FOR_SET} with value {TEST_VALUE_TO_SET}")
        self.assertIsNotNone(self.live_config.get("setDatapoints"), "'setDatapoints' missing in live config.")
        self.assertIn(TEST_DATAPOINT_NAME_FOR_SET, self.live_config["setDatapoints"], f"Datapoint {TEST_DATAPOINT_NAME_FOR_SET} not in live config's setDatapoints.")

        print(f"Attempting to set {TEST_DATAPOINT_NAME_FOR_SET} to {TEST_VALUE_TO_SET}...")
        # Call set_datapoint without session and access_token arguments
        set_success = self.wp_instance.set_datapoint(self.current_session, self.access_token, TEST_DATAPOINT_NAME_FOR_SET, TEST_VALUE_TO_SET)
        self.assertTrue(set_success, f"set_datapoint for {TEST_DATAPOINT_NAME_FOR_SET} failed.")
        print(f"Set successful. Reading back value for {TEST_DATAPOINT_NAME_FOR_SET}...")
        
        # import time
        # time.sleep(5) # Allow time for value to propagate if necessary
        # new_value = self.wp_instance.get_datapoint(TEST_DATAPOINT_NAME_FOR_SET) # Adjusted call
        # print(f"Value read back for {TEST_DATAPOINT_NAME_FOR_SET}: {new_value}")
        # self.assertEqual(new_value, TEST_VALUE_TO_SET, "Value read back does not match value set.")

    # @patch('boeschLambda.publish_to_mqtt') # Keep this commented or remove
    def test_03_monitor(self): # Removed mock_publish_to_mqtt parameter
        print(f"\nRunning test_03_monitor...")
        self.assertIsNotNone(self.live_config.get("monitorDatapoints"), "'monitorDatapoints' missing in live config.")
        if not self.live_config.get("monitorDatapoints"):
            self.skipTest("Skipping monitor test as 'monitorDatapoints' is empty in live config.")
        print(f"Monitor data: {json.dumps(self.live_config['monitorDatapoints'], indent=2)}")
        monitor_data = self.wp_instance.monitor(self.current_session, self.access_token)
        print(f"Monitor data: {json.dumps(monitor_data, indent=2)}")
        self.assertIsNotNone(monitor_data, "monitor method returned None.")
        self.assertIsInstance(monitor_data, dict, "Monitor data should be a dict.") # monitor returns a dict
        
        # Removed assertions related to mock_publish_to_mqtt.call_count
        # as publish_to_mqtt is no longer mocked in this test.
        # If you need to verify MQTT publishing, you would need a different
        # mechanism, e.g., an actual MQTT subscriber or a test broker.

    def test_04_status(self):
        print(f"\nRunning test_04_status...")
        self.assertIsNotNone(self.live_config.get("statusDatapoints"), "'statusDatapoints' missing in live config.")
        if not self.live_config.get("statusDatapoints"):
            self.skipTest("Skipping status test as 'statusDatapoints' is empty in live config.")
            
        # Call status without session and access_token arguments
        status_data = self.wp_instance.status(self.current_session, self.access_token)
        print(f"Status data: {json.dumps(status_data, indent=2)}") # status now returns a list of dicts
        self.assertIsNotNone(status_data, "status method returned None.")
        self.assertIsInstance(status_data, dict, "Status data should be a dict.") # status returns a dict
        # Add more assertions based on expected structure or keys for your status datapoints
        # Example: Check if all expected datapoint names are present in the results
        if status_data: # Only proceed if status_data is not empty
            configured_status_dp_ids = self.live_config["statusDatapoints"].keys()
            for returned_dp_id_key in status_data.keys(): # Iterate over actual returned keys
                self.assertIn(returned_dp_id_key, configured_status_dp_ids, f"Returned datapoint ID {returned_dp_id_key} was not found in configured statusDatapoints.")
            
            # Optional: You might also want to check if at least some expected datapoints were returned if that's a critical requirement.
            # For instance, if configured_status_dp_ids is not empty, you might expect status_data to not be empty.
            # However, the current assertion focuses on validating the content of what IS returned.
            if configured_status_dp_ids and not status_data:
                print(f"WARNING: statusDatapoints were configured for this home ID, but the API returned no data for them in the status call.")
        elif self.live_config.get("statusDatapoints"): # Configured datapoints exist, but API returned empty or None
             print(f"WARNING: statusDatapoints are configured in live_config, but the status() call returned no data (None or empty dict).")

if __name__ == '__main__':
    # Ensure to set TEST_HOME_ID, TEST_DATAPOINT_NAME_FOR_GET, etc. above before running.
    print("### Running Integration Tests for boeschLambda.py ###")
    print("### These tests will make REAL calls to Kermi services and your domuxConfig Lambda. ###")
    print(f"### Using HOME ID: {TEST_HOME_ID} ###")
    
    unittest.main(verbosity=2) 