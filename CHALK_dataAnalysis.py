import nmap
import re


class SystemObj:
    def __init__(self):
        self.systemObj = 0
        self.ip_address = ""
        self.operatingSystem = ""
        self.openPorts = []
        self.numOpenPorts = 0
        self.openPortPercent = 0
        self.systemRanking = False
        self.serverCheck = False
        self.vulnerabilityPercent = 0.0
        self.numberVulnerabilities = 0
        self.vulnerabilities = []

    # Current OS and up to date = 0
    # Current OS but out of date = 1
    # Previous Version OS = 2
    # Previous version OS but out of date = 3
    # Continue to add 1 for each preceding OS version and if they are out of date.
    # Example - Win10 up to date = 0


class Data_Analysis():
    def __init__(self):
        self.system_list = []

    def getIpAddress(self, rowString):
        regex = '\d{3}[.]\d{3}[.]\d{3}[.]\d{3}'
        ip_address = re.findall(regex, rowString)
        return ip_address[0]

    def calcSystemId(self):
        highestId = 0
        if not self.system_list:
            highestId = -1
        for system in self.system_list:
            x = system.SystemID
            if x > highestId:
                highestId = x
        return highestId + 1

    def getPorts(self, rowString):
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

    def is_existed(self, ip_address):
        sys = False
        if len(self.system_list) > 0:
            for entry in self.system_list:
                if entry.ip_address == ip_address:
                    sys = True
                    print('System with Ip Address ' + ip_address + ' already in the result list')
        return sys

    def live_analyse_data(self):
        print('Live')

    def offline_analyse_data(self, filename):
        regex1 = 'Nmap scan report'
        regex2 = 'open'
        """if self.is_scan:
            lineCount=0 #Remove this and write code to run the scanning code.
        else:
            filename = input("Enter the name of the file to import, including file path:")"""

        with open(filename, mode='r') as csvFile:
            tempSystem = None
            ip_address = ''
            ports = []
            rowCount = -1
            skipRows = False
            for row in csvFile:
                rowCount += 1
                if re.search(regex1, row):
                    ip_address = self.getIpAddress(row)
                    if not self.is_existed(ip_address):
                        tempSystem = SystemObj()
                        tempSystem.ip_address = ip_address
                        tempSystem.SystemID = self.calcSystemId()
                        #tempSystem.operatingSystem = osDetect(ipAddress)
                        #if "server" in tempSystem.operatingSystem.lower():
                            #tempSystem.serverCheck = True
                    else:
                        skipRows =True
                elif re.search(regex2, row) and not skipRows:
                    ports.append(self.getPorts(row))
                elif row.isspace() and rowCount != 0:
                    if skipRows:
                        skipRows = False
                    else:
                        print('System with IP Address: ' + ip_address + ' added to the results list.')
                        tempSystem.openPorts = ports
                        tempSystem.numOpenPorts = len(ports)
                        #tempSystem.systemRanking = rankSystem(tempSystem)
                        self.system_list.append(tempSystem)
                        ports = []
                        tempSystem = None
                        ip_address = ''
                else:
                    continue

    def osDetect(self, ip_address):
        nm = nmap.PortScanner()
        scan_range = nm.scan(hosts=ip_address, arguments="-O")
        x = nm['127.0.0.1']['osmatch']
        os=x[0]
        return os['name']

    def checkSystems(self):
        for system in self.system_list:
            print('System ID: ' + str(system.SystemID))
            print('IP Address: ' + system.ip_address)
            print('Operating System: ' + system.operatingSystem)
            print('Number of Potential Vulnerabilities: ' + str(system.numberVulnerabilities))
            print('Open Ports: ' + str(system.openPorts))


if __name__ == "__main__":
    t = Data_Analysis()
    t.offline_analyse_data('results.csv')
    t.checkSystems()