# boesch / kermi
Bösch Mozart / kermi x-change Heatpump API workaround

As Bösch/Kermi do not provide an API (which frustrated me heavily) for their Heatpumps I created a workaround:

You scrape their website to get a .AspNetCore.Cookie to get and set values. To get this cookie you just need to walk through their openID login sequence on their web portal (https://portal.kermi.com). If you add this core cookie to your HTTP request headers you can easily read and write to any value.

The datapoints or uniqe ID's you get through inspecting the http requests when you login or read/write values on their portal.

The code is very straightforward and self explanatory but also very custom and not really reusable. But it should save time for anyone who wants to build something similar.
