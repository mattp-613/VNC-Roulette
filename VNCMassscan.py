import os
from subprocess import call
#from vncdotool import api
import os.path
import threading
from filelock import FileLock


def getIPs():
    masscanCommand = "masscan"
    #masscanParameter = '-p5900 0.0.0.0/0 --rate=100 --exclude 255.255.255.255 --output-format list --output-filename ips.txt'
    call([masscanCommand, '-p5900', '0.0.0.0/0', '--rate=1000000000', '--exclude', '255.255.255.255', '--output-format', 'list','--output-filename','ips.txt'])


def main():
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

    ipgetter = threading.Thread(target=getIPs,args=())
    ipgetter.start()





if __name__ == '__main__':
    main()
