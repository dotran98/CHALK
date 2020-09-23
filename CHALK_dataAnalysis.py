import csv
import nmap
import re

filename = "results.csv"
systemList = []
scanBoolean = True

class systemObj:
    SystemID = 0
    ipAddress = ""
    operatingSystem = ""
    openPorts = []
    numOpenPorts = 0
    openPortPercent = 0
    systemRanking = 0
    serverCheck = False
    vulnerabilityPercent = 0.0
    numVulnerabilities = 0
    vulnerabilities = []

    # Current OS and up to date = 0
    # Current OS but out of date = 1
    # Previous Version OS = 2
    # Previous version OS but out of date = 3
    # Continue to add 1 for each preceding OS version and if they are out of date.
    # Example - Win10 up to date = 0

def getIpAddress(rowString):
    ipAddress =""
    regex = '\d{3}[.]\d{3}[.]\d{3}[.]\d{3}'
    ipAddress = re.findall(regex, rowString)
    return ipAddress[0]

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
    ports = []
    portNum = ""
    portDef = ""
    if re.search("open", rowString):
        for char in rowString:
            if char != "/":
                portNum = portNum + char
            else:
                break
        count = 0
        for char in rowString:
            if char != " " and count != 2:
                continue
            elif char == " ":
                count += 1
            else:
                portDef = portDef + char
        ports.append((portNum + ":" + portDef).strip("\n"))
    return ports

def systemCheck(ipAddress):
    sys = False
    if len(systemList) > 0:
        for entry in systemList:
            if entry.ipAddress == ipAddress:
                sys = True
                print('System with Ip Address ' + ipAddress + ' already in the result list')
    return sys

def analyseNmapData():
    global filename
    global systemList
    regex1 = 'Nmap scan report'
    regex2 = 'open'
    if scanBoolean == True:
        lineCount=0 #Remove this and write code to run the scanning code.
    else:
        filename = input("Enter the name of the file to import, including file path:")

    with open(filename, mode='r') as csvFile:
        tempSystem = None
        ipAddress = ''
        ports = []
        rowCount = -1
        skipRows = False
        csvReader = csv.reader(csvFile)
        for row in csvFile:
            rowCount += 1
            if re.search(regex1, row):
                ipAddress = getIpAddress(row)
                if not systemCheck(ipAddress):
                    tempSystem = systemObj()
                    tempSystem.ipAddress = ipAddress
                    tempSystem.SystemID = calcSystemId()
                    tempSystem.operatingSystem = osDetect(tempSystem)
                    #tempSystem.operatingSystem = osDetect(ipAddress)
                    #if "server" in tempSystem.operatingSystem.lower():
                        #tempSystem.serverCheck = True
                else:
                    skipRpws =True
            elif re.search(regex2, row) and not skipRows:
                ports.append(getPorts(row))
            elif row.isspace() and rowCount != 0:
                if skipRows:
                    skipRows = False
                else:
                    print('System with IP Address: ' + ipAddress + ' added to the results list.')
                    tempSystem.openPorts = ports
                    tempSystem.numOpenPorts = len(ports)
                    tempSystem.systemRanking = rankSystem(tempSystem)
                    systemList.append(tempSystem)
                    print(tempSystem.systemRanking)
                    ports = []
                    tempSystem = None
                    ipAddress = ''
            else:
                continue

def rankSystem(system):
    systemRanking = 0
    # Rank Based on OS and Service pack first.
    if system.operatingSystem == 'Windows 10' or system.operatingSystem =='Linux':
        systemRanking = 1
    if system.operatingSystem == 'Windows 8':
        systemRanking = 0.9
    if system.operatingSystem == 'Windows 7':
        systemRanking = 0.8
    if system.operatingSystem == 'Windows XP':
        systemRanking = 0.5
    if system.serverCheck and system.vulnerabilityPercent > 0.3:
        systemRanking = 0.5
    # For every vulnerability found:
    systemRanking = systemRanking - ((0.025*system.numVulnerabilities) + (0.01*system.numOpenPorts))

    return systemRanking

#def detectHostProgram():
    # Scan csv headings.
    # Based on a match score of over 60%, determine what program was used to create the data in the file.
    # Use multiple lists to compare heading names.

def osDetect(system):
    os = ''
    if system.SystemID == 0:
        os = 'Windows XP'
    if system.SystemID == 1:
        os = 'Windows 7'
    if system.SystemID == 2:
        os = 'Linux'
    return os

#def osDetect(ipAddress):
#    nm = nmap.PortScanner()
#    scan_range = nm.scan(hosts=ipAddress, arguments="-O")
#    x = nm['127.0.0.1']['osmatch']
#    os=x[0]
#    return os['name']

def checkSystems():
    for system in systemList:
        print('System ID: ' + str(system.SystemID))
        print('IP Address: ' + system.ipAddress)
        print('Operating System: ' + system.operatingSystem)
        print('Number of Potential Vulnerabilities: ' + str(system.numVulnerabilities))
        print('Open Ports: ' + str(system.openPorts))


def main():
    analyseNmapData()
    checkSystems()

main()