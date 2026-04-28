#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests

# 1. Read the alert file that Wazuh generates (Passed as Argument 1)
with open(sys.argv[1]) as alert_file:
    alert_json = json.load(alert_file)

# 2. Grab your Shuffle Webhook URL from the configuration (Passed as Argument 3)
webhook_url = sys.argv[3]

# 3. Fire the JSON alert to Shuffle
headers = {'content-type': 'application/json'}
requests.post(webhook_url, json=alert_json, headers=headers)