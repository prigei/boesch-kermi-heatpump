# boesch / kermi
Bösch Mozart / kermi x-change Heatpump API workaround

As Bösch/Kermi do not provide an API (which frustrated me heavily) for their Heatpumps I created a workaround:

You scrape their website to get a .AspNetCore.Cookie to get and set values. To get this cookie you just need to walk through their openID login sequence on their web portal (https://portal.kermi.com). If you add this core cookie to your HTTP request headers you can easily read and write to any value.

The datapoints or uniqe ID's you get through inspecting the http requests when you login or read/write values on their portal.

The code is very straightforward and self explanatory but also very custom and not really reusable. But it should save time for anyone who wants to build something similar.

There are now two versions: boeschCLI.py and boeschLambda.py

I run the script from AWS Lambda. The config is also fetched from a Lambda function called domuxConfig which you would need to replace. The scripts also expect a home_id as it could be used for multiple setups.

On the command line you just call eg:
python boeschCLI.py your_home_id monitor
python boeschCLI.py your_home_id status
python boeschCLI.py your_home_id datapoint get PVHK
python boeschCLI.py your_home_id datapoint set SBHK 21.5
