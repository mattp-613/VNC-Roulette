import os
from subprocess import call
from vncapi import api
import os.path
import threading
from filelock import FileLock


def parseLine(line):

    parsedLine = line.split(" ")
    try:
        client = api.connect("{ip}:0".format(ip=parsedLine[3]))
        client.captureScreen('screenshot_IP_{ip}.png'.format(ip=parsedLine[3]))
        print('Got image from {ip}'.format(ip=parsedLine[3]))
        with FileLock("vulnerableIPs.txt"):
                with open('vulnerableIPs.txt', 'a') as file:
                    file.write(parsedLine[3])

    except:
        print('Cant get image from {ip}'.format(ip=parsedLine[3]))
        pass


def main():

    if os.path.isfile('ips.txt'):
        print('List of ips detected.')
        with open('ips.txt') as f:
            lines = f.readlines() # list containing lines of file
            for line in lines:
                print(line)
                thread = threading.Thread(target=parseLine,  kwargs={'line':line})
                thread.start()    


if __name__ == '__main__':
    main()
