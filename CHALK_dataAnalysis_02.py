import csv
import nmap
import re

filename = "finalresult.csv"
systemList = []
scanBoolean = True

class systemObj:
    SystemID = 0
    ipAddress = ""
    operatingSystem = ""
    openPorts = []
    numOpenPorts = 0
    openPortPercent = 0
    systemRanking = False
    serverCheck = False
    vulnerabilityPercent = 0.0
    numberVulnerabilities = 0
    vulnerabilities = []

    # Current OS and up to date = 0
    # Current OS but out of date = 1
    # Previous Version OS = 2
    # Previous version OS but out of date = 3
    # Continue to add 1 for each preceding OS version and if they are out of date.
    # Example - Win10 up to date = 0

def getIpAddress(rowString):
    ipAddress =""
    regex = '\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}'
    ipAddress = re.findall(regex, rowString)
    return str(ipAddress[0])

def calcSystemId():
    highestId = 0
    if not systemList:
        highestId = -1
    for system in systemList:
        x = system.SystemID
        if x > highestId:
            highestId = x
    return highestId + 1

def getPorts(rowString):
    regex = '[0-9]+[:][ ]'
    regex2 = '(name).+?(?=,)'
    ports = []
    port = []
    temp = rowString.split("}")
    portName = ''
    for e in temp:
        x = str(e)
        if re.search(regex, x):
            a = str(re.findall(regex, x))
            port.append(a.replace(": ", "").replace("'", "").replace("]", "").replace("[", ""))
            charCount = 0
            portName = ''
            for c in x:
                if c == ',':
                    charCount = charCount + 1
                if charCount == 4:
                    break
                if charCount == 3:
                        portName = portName + c
            port.append(portName.replace("'", "").replace("nam': ", "").replace(", ", ""))
            port.append(x.replace("tcp: {", "")[2:])
            ports.append(port)
            port = []
    return ports


def systemCheck(ipAddress):
    sys = False
    if len(systemList) > 0:
        for entry in systemList:
            if entry.ipAddress == ipAddress:
                sys = True
                print('System with Ip Address ' + ipAddress + ' already in the result list')
    return sys

def findPosition(ipAdd):
    position = 0
    for x in systemList:
        if int(x.ipAddress.replace(".", "")) - int(ipAdd) == 0:
            break
        else:
            position += 1
    return position

def analyseData():
    global filename
    global systemList
    flag = 0
    iteration = 0
    systemCount = 0
    nmapRow = True
    regex = '[0-9]+[:][ ]'
    ipAddress = ''
    ports = []
    rowCount = -1
    recordFlag = 0
    vulnerableList = []
    tempAddress = ''
    ipList = []

    if scanBoolean == True:
        lineCount=0 #Remove this and write code to run the scanning code.
    else:
        filename = input("Enter the name of the file to import, including file path:")
    while flag < 1:
        with open(filename, mode='r') as csvFile:
            print(iteration)
            if iteration == 0:
                for row in csvFile:
                    if re.search("VULNERABILITY SCAN RESULTS", row, re.IGNORECASE):
                        nmapRow = False
                    elif nmapRow and re.search(regex, row):
                        systemCount += 1
                        ipList.append(getIpAddress(row))
                iteration += 1
                nmapRow = True
            elif iteration > 0 and iteration < systemCount + 1:
                nmapRow = True
                for row in csvFile:
                    rowCount += 1
                    if re.search("VULNERABILITY SCAN RESULTS", row, re.IGNORECASE):
                        nmapRow = False
                    if nmapRow and re.search(regex, row):
                        ipAddress = str(ipList[iteration-1])
                        print(ipList)
                        print(ipAddress)
                        if not systemCheck(ipAddress):
                            tempSystem = systemObj()
                            tempSystem.ipAddress = ipAddress
                            tempSystem.SystemID = calcSystemId()
                            # tempSystem.operatingSystem = osDetect(ipAddress)
                            # if "server" in tempSystem.operatingSystem.lower():
                            # tempSystem.serverCheck = True
                            ports.append(getPorts(row))
                            tempSystem.openPorts = ports
                            tempSystem.numOpenPorts = len(ports)
                            # tempSystem.systemRanking = rankSystem(tempSystem)
                            nmapRow = False
                    if not nmapRow:
                        if str(row).__contains__("Target IP"):
                            tempAddress = getIpAddress(row)
                        elif str(row).__contains__("Start Time") and int(tempAddress.replace(".", "")) - int(ipAddress.replace(".", "")) == 0:
                            recordFlag = 1
                        elif str(row).__contains__("-----") or str(row).__contains__("items checked"):
                            continue
                        elif str(row).__contains__("host(s)"):
                            recordFlag = 0
                        elif str(row).__contains__("End Time") and int(tempAddress.replace(".", "")) - int(ipAddress.replace(".", "")) == 0:
                            tempSystem.vulnerabilities.append(vulnerableList)
                            vulnerableList = []
                            print('System with IP Address: ' + ipAddress + ' added to the results list.')
                            print(systemList)
                        elif recordFlag > 0 and int(tempAddress.replace(".", "")) - int(ipAddress.replace(".", "")) == 0:
                            vulnerableList.append(row[2:])
                iteration += 1
                systemList.append(tempSystem)
                tempSystem = None
            elif iteration == systemCount + 1:
                flag += 1

def osDetect(ipAddress):
    nm = nmap.PortScanner()
    scan_range = nm.scan(hosts=ipAddress, arguments="-O")
    x = nm['127.0.0.1']['osmatch']
    os=x[0]
    return os['name']

def checkSystems(flag) -> object:
    for system in systemList:
        if flag == 'p':
            print('System ID: ' + str(system.SystemID))
            print('IP Address: ' + system.ipAddress)
            print('Operating System: ' + system.operatingSystem)
            print('Number of Potential Vulnerabilities: ' + str(system.numberVulnerabilities))
            print('Open Ports: ' + str(system.openPorts))
            print('Vulnerabilities: ' + str(system.vulnerabilities))


def main():
    analyseData()
    checkSystems("p")
    #results = getPorts()
    #for entry in results:
    #    print(entry)
    print(len(systemList))
main()
