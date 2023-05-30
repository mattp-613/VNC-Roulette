# VNC-Roulette
Notice:

Use the scripts included in this repository responsibly. Everything here is made for educational and/or research purposes.

Intro:

This script is taken from https://github.com/davidomil/VNCMassscan except fixed up to not be a total piece of shit. I didn't like the way they made it at all, though they did have the right idea and used the correct dependencies. Their approach was very weird and awkward, so I corrected it in my view of what it should be like. For example, multithreading here is solved by dividing the list of ips amongst all the threads and giving them their own chunk of ips to solve. In that script, each ip had its own thread, which would runtime error (duh???)

Requirements:

Python will tell you what to install when you attempt to run the scripts. Please use a venv environment when running these. Install in the environment using pip both vncdotool and twisted. The other dependencies are either included or you will be notified after attempting to run the script. You will also need to install masscan. You can install it by compiling it from the github page here:

https://github.com/robertdavidgraham/masscan

Instructions:

Note: Mass scanning or scanning unauthorized IP's for an open port is NOT allowed nor do I believe (not legal advice) is allowed unless permitted. Modify the scanner to scan addresses from a range that you are permitted to do so by, or do not use the scanner at all and manually add IP's to a text file.

Run the VNC Mass Scanner first to scan the entire internet for available VNC Ips. It'll add them to a .txt file. This script has no option to resume, and it shouldn't need an option as you can bang this out easily in ten hours. Change the rate if necessary, it is preset to a gignatic value so it goes as fast as possible.

Next, run the screenshot tool. This will provide screenshots of vulnerable VNC servers with their IP included in the title of the image. It will read from the ips.txt file that the scanner provides.

usually adding "ulimit -n 50000" to the terminal running the script will resolve a bug in access limits to the .txt files