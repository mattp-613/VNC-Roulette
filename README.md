# VNC-Roulette
This script is taken from https://github.com/davidomil/VNCMassscan except fixed up to not be a total piece of shit

Requirements:

Python will tell you what to install when you attempt to run the scripts. Please use a venv environment when running these. Install in the environment using pip both vncdotool and twisted. The other dependencies are either included or you will be notified after attempting to run the script. You will also need to install masscan. You can install it by compiling it from the github page here:

https://github.com/robertdavidgraham/masscan

Instructions:

Run the VNC Mass Scanner first to scan the entire internet for available VNC Ips. It'll add them to a .txt file. The script has no option to resume, and it shouldn't need an option as you can bang this out easily in an hour. Change the rate if necessary, it is preset to a gignatic value so it goes as fast as possible.

Next, run the screenshot tool. This will provide screenshots of vulnerable VNC servers with their IP included in the title of the image. It will read from the ips.txt file that the scanner provides.

usually adding "ulimit -n 50000" to the terminal running the script will resolve a bug in access limits
