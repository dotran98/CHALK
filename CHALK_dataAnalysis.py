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
    shortPorts = []
    openPorts = []
    numOpenPorts = 0
    openPortPercent = 0
    systemRanking = 0
    vulnerabilityPercent = 0.0
    numberVulnerabilities = 0
    vulnerabilities = []

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

def shortList(lst):
    resList = []
    temp = lst[0]
    for x in temp:
        a = x[0]
        b = x[1]
        resList.append(str(a) + ":" + str(b).replace('name: ', ''))
    return resList

def analyseData():
    global filename
    global systemList
    regex = '[0-9]+[:][ ]'

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
        nmapRow = True
        recordFlag = 0
        vulnerableList = []
        tempAddress = ''
        for row in csvFile:
            rowCount += 1
            if re.search("VULNERABILITY SCAN RESULTS", row, re.IGNORECASE):
                nmapRow = False
            if nmapRow and re.search(regex, row):
                ipAddress = getIpAddress(row)
                if not systemCheck(ipAddress):
                    tempSystem = systemObj()
                    tempSystem.ipAddress = ipAddress
                    tempSystem.SystemID = calcSystemId()
                    #tempSystem.operatingSystem = osDetect(ipAddress)
                    #if "server" in tempSystem.operatingSystem.lower():
                        #tempSystem.serverCheck = True
                    ports.append(getPorts(row))
                    print('System with IP Address: ' + ipAddress + ' added to the results list.')
                    tempSystem.openPorts = ports
                    tempSystem.shortPorts = shortList(tempSystem.openPorts)
                    tempSystem.numOpenPorts = len(tempSystem.shortPorts)
                    systemList.append(tempSystem)
                    ports = []
                    tempSystem = None
                    ipAddress = ''
            if not nmapRow:
                if str(row).__contains__("Target IP"):
                    tempAddress = getIpAddress(row)
                    vulnerableList.clear()
                elif str(row).__contains__("Start Time"):
                    recordFlag = 1
                elif str(row).__contains__("-----") or str(row).__contains__("items checked"):
                    continue
                elif str(row).__contains__("host(s)"):
                    recordFlag = 0
                elif str(row).__contains__("End Time"):
                    posn = findPosition(tempAddress.replace(".", ""))
                    if systemList[posn].ipAddress == tempAddress:
                        # This section was added as concatenation was occuring with the vulnerablelist variable
                        # even though it was being appropriately cleared. I assume it has something to do with
                        # storing, retrieving and updating objects from a list and/or memory.
                        if len(systemList[posn].vulnerabilities) > 0:
                            temp = systemList[posn].vulnerabilities
                            temp.append(vulnerableList)
                            systemList[posn].vulnerabilities = temp
                            systemList[posn].numberVulnerabilities += len(vulnerableList) - 1
                        else:
                            systemList[posn].vulnerabilities = vulnerableList
                            systemList[posn].numberVulnerabilities += len(vulnerableList) - 1
                    vulnerableList = []
                elif recordFlag > 0:
                    vulnerableList.append(row[2:])
    for sys in systemList:
        sys.systemRanking = rankSystem(sys)

def rankSystem(sys):
    rank = 1
    rank -= (sys.numOpenPorts * 0.01)
    rank -= (sys.numberVulnerabilities * 0.05)
    return "%.2f" % rank

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
            print('Number of Ports Open: ' + str(system.numOpenPorts))
            print('Short Ports: ' + str(system.shortPorts))
            print('Open Ports: ' + str(system.openPorts))
            print('Vulnerabilities: ' + str(system.vulnerabilities))
            print('System Ranking: ' + str(system.systemRanking))


def main():
    analyseData()
    checkSystems("p")
    print(len(systemList))

main()
