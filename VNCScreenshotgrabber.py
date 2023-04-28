import os
from subprocess import call
from vncapi import api
import os.path
import threading
from filelock import FileLock

def parseLine(line):
    try: 
        client = api.connect('{ip}:0'.format(ip=parsedLine[3]),timeout=10)
        client.captureScreen('screenshot_IP_{ip}.png'.format(ip=parsedLine[3]))
        print('Got image from {ip}'.format(ip=parsedLine[3]))
        with FileLock("vulnerableIPs.txt"):
                with open('vulnerableIPs.txt', 'a') as file:
                    file.write(parsedLine[3])

    except:
        print('Cant get image from {ip}'.format(ip=parsedLine[3]))
        #TODO add ability to edit "open" to "close" so as to not re-read the line
        pass

def createThread(maxThreads, ips):
        currentIndex = 0
        ipThreadGap = len(ips) // maxThreads
        nextIndex = ipThreadGap
        #the index will be the thread number. the list will contain the ips it has to solve
        ips_to_solve = []
        for i in range(0, maxThreads):
            temp = []
            for x in range(currentIndex, nextIndex): #TODO: simplify with a range(0, ipThreadGap) and use current and next within the loop
                temp.append(ips[x])
            ips_to_solve.append(temp)
            currentIndex += ipThreadGap
            nextIndex += ipThreadGap 
        return ips_to_solve

def main():
    #TODO: limit amount of threads multithreading
    if os.path.isfile('ips.txt'):
        print('List of ips detected.')
        with open('ips.txt') as f:
            lines = f.readlines() # list containing lines of file
            ips = []
            for line in lines:
                parsedLine = line.split(" ")
                try:
                    ips.append(parsedLine[3])
                except:
                    print("The following line does not work. Skipping line:")
                    print(line)
                    print("")
            print("Done. Proceeding with screenshotting: ")

            #thread = threading.Thread(target=parseLine, kwargs={'line':line})
            #thread.start()
            maxThreads = 2000
            ips_to_multithread = createThread(maxThreads, ips)
            print(len(ips_to_multithread))


if __name__ == '__main__':
    #if os.geteuid() != 0:
        #exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
