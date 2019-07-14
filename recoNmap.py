# -*- coding: utf-8 -*-
#!/usr/bin/python
import subprocess
import sys
import os
import datetime
import time
import argparse
from enum import Enum


class LogType(Enum):
    Scan = "Scan"
    Reconnaissance = "Reconnaissance"
    NmapScripts = "NmapScripts"
    SystemInterraction = "SystemInterraction"
    Error = "Error"

def GetCurrentDateAndTime():
    # return now.year + "-" + now.month + "-" + now.day + " " +
    now = datetime.datetime.now()
    return "["+str(now)+"]"

def WriteLog(TypeOfLog, description):
    # Format: [date and time] - Scan|Reconnaissance|VulnScanning|SystemInterraction|Error - Description
    f = open("recoNmap.log", "a+")
    f.write(GetCurrentDateAndTime() + " - " + str(TypeOfLog) + " - " + description + "\n")
    f.close()

def WriteHostLog(File, CWD, TypeOfLog, description):
    # Format: [date and time] - Scan|Reconnaissance|VulnScanning|SystemInterraction|Error - Description
    f = open(CWD + "/" + File, "a+")
    f.write(GetCurrentDateAndTime() + " - " + str(TypeOfLog) + " - " + description + "\n")
    f.close()

def WriteLogError(ErrorLogFile, Host, description, commandRaisingError, errorOutput, errorReturnCode):
    # Format: [date and time] - host - description of what was happening - command raising the error - error output - error return code
    f = open(ErrorLogFile, "a+")
    f.write(GetCurrentDateAndTime() + " - " + str(Host) + " - description: " + description + " - e.cmd= " + commandRaisingError + " - e.output= " + str(errorOutput) + " - e.returncode= " + str(errorReturnCode) + "\n")
    f.close()

def ParseFileWithOpenPorts(FileToParse, DestinationFile, CWD):
    WriteLog(LogType.SystemInterraction, "Parsing file %s to only keep open ports" % (FileToParse))
    # this command works but I'm not able to make it output in a file:
    # egrep -v "^#|Status: Up" 10.11.1.31-nmap-oG-raw.txt | cut -d' ' -f4- | sed -n -e 's/Ignored.*//p' | tr ',' '\n' | cut -d' ' -f2- > 10.11.1.31-open-ports.txt
    GrepCommand = "egrep -v \"^#|Status: Up\" %s | cut -d' ' -f4- | tr ',' '\\n' >> %s" %(FileToParse, DestinationFile)
    print "\n[*] Parsing the nmap file %s with the command %s" % (FileToParse, GrepCommand)
    try:
        subprocess.check_output(GrepCommand, cwd=CWD, shell=True)
    except subprocess.CalledProcessError as e:
        print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
        print "[-] Logging the error."
        WriteLog(LogType.Error, "Error happened during the following command: Parsing file %s to only keep open ports" % (FileToParse))
        WriteLogError(ReconLogErrorFileName, NmapTarget, ("Parsing file %s to only keep open ports" % (FileToParse)), e.cmd, e.output, e.returncode)

def WriteResultsFromNmapVulnScripts (NmapVulnScript, NmapVulnScriptCommand, CWD, GenReconVulnFilename, SpecificHostVulnFilename):
        GrepWithSedVulnExtract = " | sed -n '/|/p'"
        print "[*] Starting nmap script %s" % NmapVulnScript
        try:
            WriteLog(LogType.NmapScripts, "Starting Nmap script %s" % (NmapVulnScript))
            result = subprocess.check_output(NmapVulnScriptCommand + GrepWithSedVulnExtract, cwd=CWD, shell=True)
            print "[*] Nmap script finished\n	"
            WriteLog(LogType.NmapScripts, "Nmap script finished")
            if "VULNERABLE" in result:
                GeneralVulnFile = open(GenReconVulnFilename, "a+")
                GeneralVulnFile.write("from nmap script %s, running command %s\n" % (NmapVulnScript, NmapVulnScriptCommand))
                GeneralVulnFile.write(result + "\n\n")
                GeneralVulnFile.close()
                HostVulnFile = open(CurrentIP + "/" + SpecificHostVulnFilename, "a+")
                HostVulnFile.write("from nmap script %s, running command %s\n" % (NmapVulnScript, NmapVulnScriptCommand))
                HostVulnFile.write(result + "\n\n")
                HostVulnFile.close()
                print "[*] Results written to %s and %s\n" % (GenReconVulnFilename, (CWD + "/" + SpecificHostVulnFilename))
                WriteLog(LogType.NmapScripts, "Results written to %s and %s" % (GenReconVulnFilename, (CWD + "/" + SpecificHostVulnFilename)))
        except subprocess.CalledProcessError as e:
            print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
            print "[-] Logging the error."
            WriteLog(LogType.Error, "Starting Nmap script %s" % NmapVulnScript)
            WriteLogError("recoNmap-error.log", CWD, "Starting Nmap script %s" % NmapVulnScript, e.cmd, e.output, e.returncode)

parser = argparse.ArgumentParser()
parser.add_argument('IP', help='IP needed to perform the scan. By default it does consider it\'s a /24 network.')
parser.add_argument('true', help='Tell the script if you want to run it against one IP or doing the complete recon + scan sequence. True = perform complete sequence, False = perform single host sequence')
args = parser.parse_args()

#if len(sys.argv) != 2:
#    print "Usage: python recoNmap.py <IP> <IP-End> Ex: 10.11.1.5"
#    print "\nBy default it does consider it's a /24 network."
#    print "\n\n\tSome grep commands to parse Nmap output came from https://github.com/leonjza/awesome-nmap-grep. Big thanks to Leonjza!"
#    sys.exit(0)


# we split the IP for later usage
IPSplit = sys.argv[1].split(".")

# create the log file
ReconLogErrorFileName = "recoNmap-error.log"
f = open(ReconLogErrorFileName, "w+")
f.close()
WriteLog(LogType.SystemInterraction, "Created %s." % ReconLogErrorFileName)

# create the log file
ReconLogFileName = "recoNmap.log"
f = open(ReconLogFileName, "w+")
f.close()
WriteLog(LogType.SystemInterraction, "Created %s." % ReconLogFileName)

# create the file that will contain the list of vulnerabilities
ReconVulnFilename = "recoNmap_vulnerabilities_per_hosts.txt"
ReconVulnFile = open(ReconVulnFilename, "w+")
ReconVulnFile.close()
WriteLog(LogType.SystemInterraction, "Created %s." % ReconVulnFilename)

# create the file that will contain the list of users enumerated by SMB and SNMP Nmap scripts
ReconEnumUsersFilename = "recoNmap_enum_users_per_hosts.txt"
ReconEnumUsersFile = open(ReconEnumUsersFilename, "w+")
ReconEnumUsersFile.close()
WriteLog(LogType.SystemInterraction, "Created %s." % ReconEnumUsersFilename)

# create the file that will contain the list of domains enumerated by SMB Nmap scripts
ReconEnumDomainsFilename = "recoNmap_enum_domains_per_hosts.txt"
ReconEnumDomainsFile = open(ReconEnumDomainsFilename, "w+")
ReconEnumDomainsFile.close()
WriteLog(LogType.SystemInterraction, "Created %s." % ReconEnumDomainsFilename)

# create the file that will contain the list of shares enumerated by SMB and SNMP Nmap scripts
ReconEnumSharesFilename = "recoNmap_enum_shares_per_hosts.txt"
ReconEnumSharesFile = open(ReconEnumSharesFilename, "w+")
ReconEnumSharesFile.close()
WriteLog(LogType.SystemInterraction, "Created %s." % ReconEnumSharesFilename)

# create the file that will contain the list of shares enumerated by SMB and SNMP Nmap scripts
ReconEnumServicesFilename = "recoNmap_enum_services_per_hosts.txt"
ReconEnumServicesFile = open(ReconEnumServicesFilename, "w+")
ReconEnumSharesFile.close()
WriteLog(LogType.SystemInterraction, "Created %s." % ReconEnumServicesFilename)

# Define the suffix for host files
SUFFIX_HostAllPortsFileName = "-all-ports.txt"
SUFFIX_HostOpenPortsFileName = "-open-ports.txt"

### recon phase ###

if str.capitalize(args.true) == "True":
    NmapTarget = IPSplit[0] + "." + IPSplit[1] + "." + IPSplit[2] + ".1-254"
else:
    NmapTarget = args.IP

ReconFileName = "recon.txt"
NmapRecon = "nmap --privileged -nvv -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 %s -oG %s" % (NmapTarget, ReconFileName)
WriteLog(LogType.Reconnaissance, "Performing recon phase with the following nmap command: %s." % NmapRecon)
print "\n[*] Performing recon phase with the following nmap command: %s." % NmapRecon
try:
    subprocess.check_output(NmapRecon, shell=True)
    # subprocess.check_call(["nmap"] + ["-v"] + ["-sN"] + ["-F"] + ["-T5"] + [NmapTarget] + ["-oG"] + [ReconFileName])
except subprocess.CalledProcessError as e:
    print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
    print "[-] Logging the error."
    WriteLog(LogType.Error, "Performing recon phase with the following nmap command: %s." % NmapRecon)
    WriteLogError(ReconLogErrorFileName, NmapTarget, ("Performing recon phase with the following nmap command: %s." % NmapRecon), e.cmd, e.output, e.returncode)
    
# extracting the information from the nmap grepable format to obtain only the list of IPs that are up
ReconHostsUpFileName = "recon-hosts-up.txt"
ReconParseFileCommand = "cat %s | grep Up | uniq | cut -d' ' -f2 > %s" % (ReconFileName, ReconHostsUpFileName)
WriteLog(LogType.SystemInterraction, "Parsing the nmap file %s with the command %s" % (ReconFileName, ReconParseFileCommand))
print "\n[*] Parsing the nmap file %s with the command %s" % (ReconFileName, ReconParseFileCommand)
try:
    subprocess.check_output(ReconParseFileCommand, shell=True)
except subprocess.CalledProcessError as e:
    print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
    print "[-] Logging the error."
    WriteLog(LogType.Error, "Parsing the nmap file %s with the command %s" % (ReconFileName, ReconParseFileCommand))
    WriteLogError(ReconLogErrorFileName, NmapTarget, "Parsing the nmap file %s with the command %s" % (ReconFileName, ReconParseFileCommand), e.cmd, e.output, e.returncode)

### Scan phase ###

with open(ReconHostsUpFileName) as myfile:
    HostsUp = myfile.readlines()
    # remove whitespace characters like `\n` at the end of each line
    HostsUp = [host.strip('\n') for host in HostsUp]

# iterate through all the IPs we want to scan
for HostIP in HostsUp:
    CurrentIP = HostIP
    
    # create directory and move into this directory to add the different stuff
    # subprocess.check_call(["/bin/mkdir"] + [CurrentIP])
    os.mkdir(CurrentIP)
    WriteLog(LogType.SystemInterraction, "Moving the current working directory to %s." % CurrentIP)

    # create a specific log file that will contain details only related to the scans
    HostLogFileName = CurrentIP + ".log"
    try:
        subprocess.check_call(["/usr/bin/touch"] + [HostLogFileName], cwd=CurrentIP)
        WriteLog(LogType.SystemInterraction, "Created %s." % HostLogFileName)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.SystemInterraction, "Created %s host log file" % HostLogFileName)
    except subprocess.CalledProcessError as e:
        print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
        print "[-] Logging the error."
        WriteLog(LogType.Error, "Error while creating %s." % HostLogFileName)
        WriteLogError(ReconLogErrorFileName, NmapTarget, "Error while creating %s." % HostLogFileName, e.cmd, e.output, e.returncode)

    # create file that will contain all host port scan results
    HostAllPortsFileName = CurrentIP + SUFFIX_HostAllPortsFileName
    try:
        subprocess.check_call(["/usr/bin/touch"] + [HostAllPortsFileName], cwd=CurrentIP)
        WriteLog(LogType.SystemInterraction, "Created %s." % HostAllPortsFileName)
    except subprocess.CalledProcessError as e:
        print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
        print "[-] Logging the error."
        WriteLog(LogType.Error, "Error while creating %s." % HostAllPortsFileName)
        WriteLogError(ReconLogErrorFileName, NmapTarget, "Error while creating %s." % HostAllPortsFileName, e.cmd, e.output, e.returncode)
    
    # create file that will contain only host open port
    HostOpenPortsFileName = CurrentIP + SUFFIX_HostOpenPortsFileName
    try:
        subprocess.check_call(["/usr/bin/touch"] + [HostOpenPortsFileName], cwd=CurrentIP)
        WriteLog(LogType.SystemInterraction, "Created %s." % HostOpenPortsFileName)
    except subprocess.CalledProcessError as e:
        print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
        print "[-] Logging the error."
        WriteLog(LogType.Error, "Error while creating %s." % HostOpenPortsFileName)
        WriteLogError(ReconLogErrorFileName, NmapTarget, "Error while creating %s." % HostOpenPortsFileName, e.cmd, e.output, e.returncode)

    # add timer to see how much time it takes to scan the host
    Start_Time = time.time()

    # OS guessing
    OSFileName = CurrentIP + "-OS-Detection.txt"
    OSNmapScanCommand="nmap --privileged -nvv -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 -sS -sU -O --osscan-guess --max-os-tries 1 --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 " + CurrentIP + " | grep \"Device type:\" -A4 > "+ OSFileName
    WriteHostLog(HostLogFileName, CurrentIP, LogType.Scan, "Performing the OS discovery, nmap command: %s" % OSNmapScanCommand)
    print "\n[*] Sending nmap command for OS detection scan: " + OSNmapScanCommand
    WriteLog(LogType.Scan, "Sending nmap command for OS detection scan: %s" % (OSNmapScanCommand))
    try:
        subprocess.check_output(OSNmapScanCommand, cwd=CurrentIP, shell=True)
    except subprocess.CalledProcessError as e:
        print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
        print "[-] Logging the error."
        WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
        WriteLog(LogType.Error, "Sending nmap command for OS detection scan: %s" % (OSNmapScanCommand))
        WriteLogError(ReconLogErrorFileName, NmapTarget, "Sending nmap command for OS detection scan: %s" % (OSNmapScanCommand), e.cmd, e.output, e.returncode)

    # Full TCP, UDP port range including service detection
    NmapTCPUDPCommandFileName = CurrentIP + "-nmap-oG-raw.txt"
    NmapTCPUDPCommand = "nmap --privileged -nvv -PE -PS21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 -PU53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,5353,49152 -sS -sU -pT:1-65535,U:1-65535 --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 %s -oG %s" % (CurrentIP, NmapTCPUDPCommandFileName)
    WriteHostLog(HostLogFileName, CurrentIP, LogType.Scan, "Performing host TCP and UDP port scan, nmap command: %s" % NmapTCPUDPCommand)
    print "\n[*] Performing host TCP and UDP port scan, nmap command: %s" % NmapTCPUDPCommand
    WriteLog(LogType.Scan, "Performing host TCP and UDP port scan, nmap command: %s" % NmapTCPUDPCommand)
    try:
        subprocess.check_output(NmapTCPUDPCommand, cwd=CurrentIP, shell=True)
        ParseFileWithOpenPorts(NmapTCPUDPCommandFileName, HostAllPortsFileName, CurrentIP)
        ScanFile = open(CurrentIP + "/" + HostAllPortsFileName, "a+")
        ScanResults = ScanFile.readlines()
        ScanFile.close()
        ScanResults = [lala.strip('\n') for lala in ScanResults]

        TCP_Ports = ""
        UDP_Ports = ""
        TempLine = ""

        for line in ScanResults:
            if "/////" in line:
                TempLine = line.replace("/////", '/')

            if "///" in line:
                TempLine = line.replace("///", '/')

            if "//" in line:
                TempLine = line.replace('//', '/')    

            TempLine = TempLine.split("/")
        
            if "udp" in line:
                if len(UDP_Ports) == 0:
                    # replace get rid of the initial extra space before the port number
                    UDP_Ports = TempLine[0].replace(' ', '')
                else:
                    UDP_Ports = UDP_Ports + "," + TempLine[0].replace(' ', '')

            if "tcp" in line:
                if len(TCP_Ports) == 0:
                    # replace get rid of the initial extra space before the port number
                    TCP_Ports = TempLine[0].replace(' ', '')
                else:
                    TCP_Ports = TCP_Ports + "," + TempLine[0].replace(' ', '')

        print "\n[*] Found TCP ports %s and UDP ports %s" % (TCP_Ports, UDP_Ports)

        if (len(TCP_Ports) != 0) or (len(UDP_Ports) != 0):
            Nmap_sS_sU_Arg = "" 
            Nmap_pT_Arg = ""
            Nmap_pU_Arg = ""

            if len(TCP_Ports) != 0:
                Nmap_pT_Arg = "T:%s" % TCP_Ports
                Nmap_sS_sU_Arg = "-sS"

            if len(UDP_Ports) != 0:
                if len(TCP_Ports) != 0:
                    Nmap_pU_Arg = ",U:%s" % UDP_Ports
                    Nmap_sS_sU_Arg = Nmap_sS_sU_Arg + " -sU"
                else:
                    Nmap_pU_Arg = "U:%s" % UDP_Ports
                    Nmap_sS_sU_Arg = Nmap_sS_sU_Arg + " -sU"

            NmapServiceDetectionCommand = "nmap --privileged -nvv %s -p%s%s -sV --version-intensity 9 --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 3000ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 %s -oG %s" % (Nmap_sS_sU_Arg, Nmap_pT_Arg, Nmap_pU_Arg, CurrentIP, HostAllPortsFileName)

            WriteHostLog(HostLogFileName, CurrentIP, LogType.Scan, "Performing host TCP ports '%s' and UDP ports '%s' service detection, nmap command: %s" % (TCP_Ports, UDP_Ports, NmapServiceDetectionCommand))
            print "\n[*] Performing host TCP ports '%s' and UDP ports '%s' service detection, nmap command: %s" % (TCP_Ports, UDP_Ports, NmapServiceDetectionCommand)
            WriteLog(LogType.Scan, "Performing host TCP ports '%s' and UDP ports '%s' service detection, nmap command: %s" % (TCP_Ports, UDP_Ports, NmapServiceDetectionCommand))

            subprocess.check_output(NmapServiceDetectionCommand, cwd=CurrentIP, shell=True)
            
            WriteLog(LogType.SystemInterraction, "Parsing file %s to extract open ports to file %s" % (HostAllPortsFileName, HostOpenPortsFileName))
            WriteHostLog(HostLogFileName, CurrentIP, LogType.Scan, "Parsing file %s to extract open ports to file %s" % (HostAllPortsFileName, HostOpenPortsFileName))
            ParseFileWithOpenPorts(HostAllPortsFileName, HostOpenPortsFileName, CurrentIP)
    except subprocess.CalledProcessError as e:
        print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
        print "[-] Logging the error."
        WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
        WriteLog(LogType.Error, "Sending nmap command for OS detection scan: %s" % (OSNmapScanCommand))
        WriteLogError(ReconLogErrorFileName, NmapTarget, "Sending nmap command for OS detection scan: %s" % (OSNmapScanCommand), e.cmd, e.output, e.returncode)
        
    # ending scan timer!
    End_Time = time.time()
    WriteHostLog(HostLogFileName, CurrentIP, LogType.Scan, "Scan endend in %s seconds (or %s minutes)" % ( str((End_Time - Start_Time)), str((End_Time - Start_Time)/60.0)) )

    # export list of open ports to dedicated file

    #GrepCommand = "grep open %s >> %s" %(HostAllPortsFileName, HostOpenPortsFileName)
    #print "\n[*] Parsing file %s to extract open ports to file %s with the command: %s" % (HostAllPortsFileName, HostOpenPortsFileName, GrepCommand)
    #try:
    #    subprocess.Popen(GrepCommand, cwd=CurrentIP, shell=True)
    #except subprocess.CalledProcessError as e:
    #    print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
    #    print "[-] Logging the error."
    #    WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
    #    WriteLog(LogType.Error, "grep open %s >> %s" %(HostAllPortsFileName, HostOpenPortsFileName))
    #    WriteLogError(ReconLogErrorFileName, NmapTarget, "grep open %s >> %s" %(HostAllPortsFileName, HostOpenPortsFileName), e.cmd, e.output, e.returncode)

    ### Host vulnerability enumeration phase ###

    # Mac OS X AFP
    AFP_PATH_VULN_PATH = "afp-path-vuln"
    AFP_PATH_VULN_NMAP = "nmap -p548 --script=%s %s" % (AFP_PATH_VULN_PATH, CurrentIP)
    # FTP ProFTPD server, version between 1.3.2rc3 and 1.3.3b
    FTP_VULN_CVE_2010_4221_PATH = "ftp-vuln-cve2010-4221"
    FTP_VULN_CVE_2010_4221_NMAP = "nmap --script=%s -p21 %s" % (FTP_VULN_CVE_2010_4221_PATH, CurrentIP)
    # TCP port 80,8080,443 vulnerability checks
    HTTP_IIS_WEBDAV_VULN_PATH = "http-iis-webdav-vuln.nse"
    HTTP_IIS_WEBDAV_VULN_NMAP = "nmap --script=%s -p80,8080,443 %s" % (HTTP_IIS_WEBDAV_VULN_PATH, CurrentIP)
    # 
    HTTP_VULN_CVE_2006_3392_PATH = "http-vuln-cve2006-3392"
    HTTP_VULN_CVE_2006_3392_FILE_ARG = "\"/etc/shadow\""
    HTTP_VULN_CVE_2006_3392_NMAP1 = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2006_3392_PATH, CurrentIP)
    HTTP_VULN_CVE_2006_3392_NMAP2 = "nmap -p80,8080,443 --script=%s --script-args=%s.file=%s %s" % (HTTP_VULN_CVE_2006_3392_PATH, HTTP_VULN_CVE_2006_3392_PATH, HTTP_VULN_CVE_2006_3392_FILE_ARG, CurrentIP)
    #
    HTTP_VULN_CVE_2009_3960_PATH = "http-vuln-cve2009-3960"
    HTTP_VULN_CVE_2009_3960_ROOT_ARG = "\"/root/\""
    HTTP_VULN_CVE_2009_3960_NMAP = "nmap -p80,8080,443 --script=%s --script-args=%s.root=%s %s" % (HTTP_VULN_CVE_2009_3960_PATH, HTTP_VULN_CVE_2009_3960_PATH, HTTP_VULN_CVE_2009_3960_ROOT_ARG, CurrentIP)
    #
    HTTP_VULN_CVE_2010_0738_PATH = "http-vuln-cve2010-0738"
    HTTP_VULN_CVE_2010_0738_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2010_0738_PATH, CurrentIP)
    #
    HTTP_VULN_CVE_2010_2861_PATH = "http-vuln-cve2010-2861"
    HTTP_VULN_CVE_2010_2861_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2010_2861_PATH, CurrentIP)
    # Apache HTTP reverse proxy mode. Port 80
    HTTP_VULN_CVE_2011_3368_PATH = "http-vuln-cve2011-3368"
    HTTP_VULN_CVE_2011_3368_NMAP = "nmap --script=%s %s" % (HTTP_VULN_CVE_2011_3368_PATH, CurrentIP)
    # PHP cgi
    HTTP_VULN_CVE_2012_1823_PATH = "http-vuln-cve2012-1823"
    HTTP_VULN_CVE_2012_1823_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2012_1823_PATH, CurrentIP)

    # Vulnerabilities above this line do not have all the different usage listed. TODO: add the second nmap usage and perform the checks to launch it if the first does not report anything

    # Ruby on Rails. All Ruby on Rails versions before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 are vulnerable to object injection, remote command execution and denial of service attacks. The attackers don't need to be authenticated to exploit these vulnerabilities.
    HTTP_VULN_CVE_2013_0156_PATH = "http-vuln-cve2013-0156"
    HTTP_VULN_CVE_2013_0156_NMAP1 = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2013_0156_PATH, CurrentIP)
    HTTP_VULN_CVE_2013_0156_NMAP2_URI_ARG = "\"/test/\""
    HTTP_VULN_CVE_2013_0156_NMAP2 = "nmap -p80,8080,443 --script=%s --script-args uri=%s %s" % (HTTP_VULN_CVE_2013_0156_PATH, HTTP_VULN_CVE_2013_0156_NMAP2_URI_ARG, CurrentIP)
    # Allegro RomPager, port 80
    HTTP_VULN_CVE_2013_6786_PATH = "http-vuln-cve2013-6786"
    HTTP_VULN_CVE_2013_6786_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2013_6786_PATH, CurrentIP)
    # Zimbra, port 80 (patched in Zimbra 7.2.6)
    HTTP_VULN_CVE_2013_7091_PATH = "http-vuln-cve2013-7091"
    HTTP_VULN_CVE_2013_7091_NMAP1 = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2013_7091_PATH, CurrentIP)
    HTTP_VULN_CVE_2013_7091_NMAP2_ARG = "\"/ZimBra\""
    HTTP_VULN_CVE_2013_7091_NMAP2 = "nmap -p80,8080,443 --script=%s --script-args=%s=/ZimBra %s" %(HTTP_VULN_CVE_2013_7091_PATH, HTTP_VULN_CVE_2013_7091_NMAP2_ARG, CurrentIP)
    # Cisco ASA Applicances (privilege escalation) port 443 (Cisco Adaptive Security Appliance (ASA) Software 8.2 before 8.2(5.47), 8.4 before 8.4(7.5), 8.7 before 8.7(1.11), 9.0 before 9.0(3.10), and 9.1 before 9.1(3.4)
    HTTP_VULN_CVE_2014_2126_PATH = "http-vuln-cve2014-2126"
    HTTP_VULN_CVE_2014_2126_NMAP = "nmap -p443 --script=%s %s" % (HTTP_VULN_CVE_2014_2126_PATH, CurrentIP)
    # Cisco ASA Applicances (Cisco Adaptive Security Appliance (ASA) Software 8.x before 8.2(5.48), 8.3 before 8.3(2.40), 8.4 before 8.4(7.9), 8.6 before 8.6(1.13), 9.0 before 9.0(4.1), and 9.1 before 9.1(4.3)) (port 443)
    HTTP_VULN_CVE_2014_2127_PATH = "http-vuln-cve2014-2127"
    HTTP_VULN_CVE_2014_2127_NMAP = "nmap -p443 --script=%s %s" % (HTTP_VULN_CVE_2014_2127_PATH, CurrentIP)
    # Cisco Adaptive Security Appliance (ASA) Software 8.2 before 8.2(5.47, 8.3 before 8.3(2.40), 8.4 before 8.4(7.3), 8.6 before 8.6(1.13), 9.0 before 9.0(3.8), and 9.1 before 9.1(3.2) (port 443)
    HTTP_VULN_CVE_2014_2128_PATH = "http-vuln-cve2014-2128"
    HTTP_VULN_CVE_2014_2128_NMAP = "nmap -p443 --script=%s %s" % (HTTP_VULN_CVE_2014_2128_PATH, CurrentIP)
    # Wordpress CM Download Manager plugin. Versions <= 2.0.0 are known to be affected.
    HTTP_VULN_CVE_2014_8877_PATH = "http-vuln-cve2014-8877"
    HTTP_VULN_CVE_2014_8877_NMAP1 = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2014_8877_PATH, CurrentIP)
    HTTP_VULN_CVE_2014_8877_NMAP2_CMD_ARG = "\"whoami\""
    HTTP_VULN_CVE_2014_8877_NMAP2_URI_ARG = "\"/wordpress\""
    HTTP_VULN_CVE_2014_8877_NMAP2 = "nmap -p80,8080,443 --script=%s --script-args=%s.cmd=%s,%s.uri=%s %s" % (HTTP_VULN_CVE_2014_8877_PATH, HTTP_VULN_CVE_2014_8877_PATH, HTTP_VULN_CVE_2014_8877_NMAP2_CMD_ARG, HTTP_VULN_CVE_2014_8877_PATH, HTTP_VULN_CVE_2014_8877_NMAP2_URI_ARG, CurrentIP)
    # Drupal core < versions 7.32 (sql injection in login form) (port 80, check 800, 433 too?)
    HTTP_VULN_CVE_2014_3704_PATH = "http-vuln-cve2014-3704"
    HTTP_VULN_CVE_2014_3704_NMAP_CMD_ARG = "\"uname -a\"" 
    HTTP_VULN_CVE_2014_3704_NMAP_URI_ARG = "\"/drupal\""
    HTTP_VULN_CVE_2014_3704_NMAP = "nmap -p80,8080,443 --script=%s --script-args=%s.cmd=%s,%s.uri=%s %s" % (HTTP_VULN_CVE_2014_3704_PATH, HTTP_VULN_CVE_2014_3704_PATH, HTTP_VULN_CVE_2014_3704_NMAP_CMD_ARG, HTTP_VULN_CVE_2014_3704_PATH, HTTP_VULN_CVE_2014_3704_NMAP_URI_ARG, CurrentIP)
        # nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.uri="/drupal",http-vuln-cve2014-3704.cleanup=false <target>
    # Elasticsearch versions 1.3.0-1.3.7 and 1.4.0-1.4.2 have a vulnerability
    HTTP_VULN_CVE_2015_1427_PATH = "http-vuln-cve2015-1427"
    HTTP_VULN_CVE_2015_1427_NMAP_COMMAND_ARG = "'ls'"
    HTTP_VULN_CVE_2015_1427_NMAP = "nmap -p9200 --script=%s --script-args command=%s %s" % (HTTP_VULN_CVE_2015_1427_PATH, HTTP_VULN_CVE_2015_1427_NMAP_COMMAND_ARG, CurrentIP)
    # Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, sand Windows Server 2012 R2.
    HTTP_VULN_CVE_2015_1635_PATH = "http-vuln-cve2015-1635"
    HTTP_VULN_CVE_2015_1635_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2015_1635_PATH, CurrentIP)
	# nmap -sV --script vuln <target>
        # nmap -sV --script http-vuln-cve2015-1635 --script-args uri='/anotheruri/' <target>
    # Wordpress API. privilege escalation vulnerability in Wordpress 4.7.0 and 4.7.1
    HTTP_VULN_CVE_2017_1001000_PATH = "http-vuln-cve2017-1001000"
    HTTP_VULN_CVE_2017_1001000_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2017_1001000_PATH, CurrentIP)
	# nmap --script http-vuln-cve2017-1001000 --script-args http-vuln-cve2017-1001000="uri" <target>
    # Apache Struts Remote Code Execution Vulnerability Apache Struts 2.3.5 - Struts 2.3.31 and Apache Struts 2.5 - Struts 2.5.10
    HTTP_VULN_CVE_2017_5638_PATH = "http-vuln-cve2017-5638"
    HTTP_VULN_CVE_2017_5638_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2017_5638_PATH, CurrentIP)
    # Intel Active Management Technology INTEL-SA-00075 Authentication Bypass (port 623 or 664 or 16992 or 16993 tcp service amt-soap-http)
    HTTP_VULN_CVE_2017_5689_PATH = "http-vuln-cve2017-5689"
    HTTP_VULN_CVE_2017_5689_NMAP = "nmap -p623,664,16992,16993 --script=%s %s" % (HTTP_VULN_CVE_2017_5689_PATH, CurrentIP)
    # Joomla! 3.7.x before 3.7.1 (SQL Injection)
    HTTP_VULN_CVE_2017_8917_PATH = "http-vuln-cve2017-8917"
    HTTP_VULN_CVE_2017_8917_NMAP = "nmap -p80,8080,443 --script=%s %s" % (HTTP_VULN_CVE_2017_8917_PATH, CurrentIP)
        # nmap --script http-vuln-cve2017-8917 --script-args http-vuln-cve2017-8917.uri=joomla/ -p 80<target>
    # RomPager 4.07 Misfortune Cookie vulnerability
    HTTP_VULN_MISFORTUNE_COOKIE_PATH = "http-vuln-misfortune-cookie"
    HTTP_VULN_MISFORTUNE_COOKIE_NMAP = "nmap -p7547 --script=%s %s" % (HTTP_VULN_MISFORTUNE_COOKIE_PATH, CurrentIP)
    # WNR 1000 series (V1.0.2.60_60.0.86 (Latest) and V1.0.2.54_60.0.82NA) to retrieve administrator credentials with the router interface.
    HTTP_VULN_WNR1000_CREDS_PATH = "http-vuln-wnr1000-creds"
    HTTP_VULN_WNR1000_CREDS_NMAP = "nmap -p80,8080,443 --script=%s %s" %(HTTP_VULN_WNR1000_CREDS_PATH, CurrentIP)
    # bypass authentication in MySQL and MariaDB servers. versions up to 5.1.61, 5.2.11, 5.3.5, 5.5.22 are vulnerable but exploitation depends on whether memcmp() returns an arbitrary integer outside of -128..127 range
    MYSQL_VULN_CVE_2012_2122_PATH = "mysql-vuln-cve2012-2122"
    MYSQL_VULN_CVE_2012_2122_NMAP = "nmap -p3306 --script=%s %s" % (MYSQL_VULN_CVE_2012_2122_PATH, CurrentIP)
    	# nmap -sV --script mysql-vuln-cve2012-2122 <target>
    # Remote Desktop Protocol. This check is for 2 vulns (1 dos 1 rce). RCE: MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability (port 3389 service ms-wbt-server)
    RDP_VULN_MS12_020_PATH = "rdp-vuln-ms12-020"
    RDP_VULN_MS12_020_NMAP = "nmap -p3389 --script=%s %s" % (RDP_VULN_MS12_020_PATH, CurrentIP)
    # Java rmiregistry (allows class loading)
    RMI_VULN_CLASSLOADER_PATH = "rmi-vuln-classloader"
    RMI_VULN_CLASSLOADER_NMAP = "nmap -p1099 --script=%s %s" % (RMI_VULN_CLASSLOADER_PATH, CurrentIP)
    # Samba: heap overflow vulnerability CVE-2012-1182. Samba versions 3.6.3 and all versions previous to this (port 139, service netbios-ssn)
    SAMBA_VULN_CVE_2012_1182_PATH = "samba-vuln-cve-2012-1182"
    SAMBA_VULN_CVE_2012_1182_NMAP = "nmap -p139 --script=%s %s" % (SAMBA_VULN_CVE_2012_1182_PATH, CurrentIP)
    # Windows SMB
    SMB2_VULN_UPTIME_PATH = "smb2-vuln-uptime"
    SMB2_VULN_UPTIME_NMAP_SKIPOS_ARG = "true"
    SMB2_VULN_UPTIME_NMAP = "nmap -p445 --script=%s --script-args=%.skip-os=%s %s" % (SMB2_VULN_UPTIME_PATH, SMB2_VULN_UPTIME_PATH, SMB2_VULN_UPTIME_NMAP_SKIPOS_ARG, CurrentIP)
        # nmap -O --script smb2-vuln-uptime <target>
    # Samba from 3.5.0 to 4.4.13, and versions prior to 4.5.10 and 4.6.4 are affected by a vulnerability that allows remote code execution (port 445, service microsoft-ds)
    SMB_VULN_CVE_2017_7494_PATH = "smb-vuln-cve-2017-7494"
    SMB_VULN_CVE_2017_7494_NMAP = "nmap -p445 --script=%s --script-args=%s.check-version %s" % (SMB_VULN_CVE_2017_7494_PATH, SMB_VULN_CVE_2017_7494_PATH, CurrentIP)
        # nmap --script smb-vuln-cve-2017-7494 -p 445 <target>
    # windows SMB. The Print Spooler service in Microsoft Windows XP,Server 2003 SP2,Vista,Server 2008, and 7. (port 445 tcp, service microsoft-ds)
    SMB_VULN_MS10_061_PATH = "smb-vuln-ms10-061"
    SMB_VULN_MS10_061_NMAP = "nmap -p445 --script=%s %s" % (SMB_VULN_MS10_061_PATH, CurrentIP)
    # Microsoft SMBv1 (eternal blue). Tested on Windows XP, 2003, 7, 8, 8.1, 10, 2008, 2012 and 2016.
    SMB_VULN_MS17_010_PATH = "smb-vuln-ms17-010"
    SMB_VULN_MS17_010_NMAP = "nmap -p445 --script=%s %s" % (SMB_VULN_MS17_010_PATH, CurrentIP)
    # Exim prior to 4.69 for heap overflow and Exim prior to 4.72 for priv escal. The <code>smtp-vuln-cve2010-4344.exploit</code> script argument will make the script try to exploit the vulnerabilities. Check the script for more information on how to use the script for exploitation!!! (port 25, service smtp)
    SMTP_VULN_CVE_2010_4344_PATH = "smtp-vuln-cve2010-4344"
    SMTP_VULN_CVE_2010_4344_NMAP_ARG = "\"exploit.cmd='uname -a'\""
    SMTP_VULN_CVE_2010_4344_NMAP = "nmap -pT:25,465,587 --script=%s --script-args=%s %s" % (SMTP_VULN_CVE_2010_4344_PATH, SMTP_VULN_CVE_2010_4344_NMAP_ARG, CurrentIP)
        # nmap --script=smtp-vuln-cve2010-4344 --script-args="smtp-vuln-cve2010-4344.exploit" -pT:25,465,587 <host>
    ####### SMB ENUMERATION #######
    # Attempts to enumerate domains on a system, along with their policies. This generally requires credentials, except against Windows 2000.
    SMB_ENUM_DOMAINS_PATH = "smb-enum-domains"
    SMB_ENUM_DOMAINS_NMAP = "nmap -sU -sS -pU:137,T:139 --script=%s %s" % (SMB_ENUM_DOMAINS_PATH, CurrentIP)
        # nmap --script smb-enum-domains.nse -p445 <host>
    # Attempts to list shares After a list of shares is found, the script attempts to connect to each of them anonymously, which divides them into "anonymous", for shares that the NULL user can connect to, or "restricted", for shares that require a user account.
    SMB_ENUM_SHARES_PATH = "smb-enum-shares"
    SMB_ENUM_SHARES_NMAP = "nmap -sU -sS -pU:137,T:139 --script=%s %s" % (SMB_ENUM_SHARES_PATH, CurrentIP)
        # nmap --script smb-enum-shares.nse -p445 <host>
    # Attempts to enumerate the users on a remote Windows system, with as much information as possible, through two different techniques (both over MSRPC, which uses port 445 or 139; see <code>smb.lua</code>). The goal of this script is to discover all user accounts that exist on a remote system. 
    SMB_ENUM_USERS_PATH = "smb-enum-users"
    SMB_ENUM_USERS_NMAP = "nmap -sU -sS -pU:137,T:139 --script=%s %s" % (SMB_ENUM_USERS_PATH, CurrentIP)
        # nmap --script smb-enum-users.nse -p445 <host>
    ####### SNMP ENUMERATION #######
    # Attempts to enumerate Windows services through SNMP. (port 161, udp)
    SNMP_WIN32_SERVICES_PATH = "snmp-win32-services"
    SNMP_WIN32_SERVICES_NMAP = "nmap -sU -p161 --script=%s %s" % (SNMP_WIN32_SERVICES_PATH, CurrentIP)
    # Attempts to enumerate Windows Shares through SNMP.
    SNMP_WIN32_SHARES_PATH = "snmp-win32-shares"
    SNMP_WIN32_SHARES_NMAP = "nmap -sU -p161 --script=%s %s" % (SNMP_WIN32_SHARES_PATH, CurrentIP)
    # Attempts to enumerate installed software through SNMP.
    SNMP_WIN32_SOFTWARE_PATH = "snmp-win32-software"
    SNMP_WIN32_SOFTWARE_NMAP = "nmap -sU -p161 --script=%s %s" % (SNMP_WIN32_SOFTWARE_PATH, CurrentIP)
    # Attempts to enumerate Windows user accounts through SNMP
    SNMP_WIN32_USERS_PATH = "snmp-win32-users"
    SNMP_WIN32_USERS_NMAP = "nmap -sU -p161 --script=%s %s" % (SNMP_WIN32_USERS_PATH, CurrentIP)

    print "\n[*] Starting Nmap scritps for host %s" % CurrentIP
    WriteLog(LogType.NmapScripts, "Starting Nmap scritps for host %s" % CurrentIP)
    
    GeneralVulnFile = open(ReconVulnFilename, "a+")
    GeneralVulnFile.write("#############################")
    GeneralVulnFile.write("\n")
    GeneralVulnFile.write("###      " + CurrentIP + "      ###")
    GeneralVulnFile.write("\n")
    GeneralVulnFile.write("#############################\n\n")
    GeneralVulnFile.close()

    GeneralReconEnumDomainsFile = open(ReconEnumDomainsFilename, "a+")
    GeneralReconEnumDomainsFile.write("#############################")
    GeneralReconEnumDomainsFile.write("\n")
    GeneralReconEnumDomainsFile.write("###      " + CurrentIP + "      ###")
    GeneralReconEnumDomainsFile.write("\n")
    GeneralReconEnumDomainsFile.write("#############################\n\n")
    GeneralReconEnumDomainsFile.close()

    GeneralReconEnumSharesFile = open(ReconEnumSharesFilename, "a+")
    GeneralReconEnumSharesFile.write("#############################")
    GeneralReconEnumSharesFile.write("\n")
    GeneralReconEnumSharesFile.write("###      " + CurrentIP + "      ###")
    GeneralReconEnumSharesFile.write("\n")
    GeneralReconEnumSharesFile.write("#############################\n\n")
    GeneralReconEnumSharesFile.close()

    GeneralReconEnumUsersFile = open(ReconEnumUsersFilename, "a+")
    GeneralReconEnumUsersFile.write("#############################")
    GeneralReconEnumUsersFile.write("\n")
    GeneralReconEnumUsersFile.write("###      " + CurrentIP + "      ###")
    GeneralReconEnumUsersFile.write("\n")
    GeneralReconEnumUsersFile.write("#############################\n\n")
    GeneralReconEnumUsersFile.close()

    
    GeneralReconEnumServicesFile = open(ReconEnumServicesFilename, "a+")
    GeneralReconEnumServicesFile.write("#############################")
    GeneralReconEnumServicesFile.write("\n")
    GeneralReconEnumServicesFile.write("###      " + CurrentIP + "      ###")
    GeneralReconEnumServicesFile.write("\n")
    GeneralReconEnumServicesFile.write("#############################\n\n")
    GeneralReconEnumServicesFile.close()
    
    HostVulnFilename = CurrentIP + "-vuln-scan-results.txt"
    HostEnumFilename = CurrentIP + "-enum-scan-results.txt"
    
    subprocess.check_call(["/usr/bin/touch"] + [HostVulnFilename], cwd=CurrentIP)
    subprocess.check_call(["/usr/bin/touch"] + [HostEnumFilename], cwd=CurrentIP)
    
    GrepWithSedVulnExtract = " | sed -n '/|/p'"

    PathToHostAllPorts = open(CurrentIP + "/" + HostAllPortsFileName, "r")
    port_scan_results = PathToHostAllPorts.read()
    PathToHostAllPorts.close()

    if "548" in port_scan_results and "afp" in port_scan_results:
        print "\n[*] Port %s detected!" % "548"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "548")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected! Starting nmap script %s" % ("548", AFP_PATH_VULN_PATH))
        # Mac_OS_X_AFP_directory_traversal_vulnerability_CVE_2010_0533
        WriteResultsFromNmapVulnScripts(AFP_PATH_VULN_PATH, AFP_PATH_VULN_NMAP, CurrentIP,ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "21" in port_scan_results or "ftp" in port_scan_results:	
        print "\n[*] Port %s detected!" % "21 or ftp service"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "21 or ftp service")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected! Starting nmap script %s" % ("21 or ftp service", FTP_VULN_CVE_2010_4221_PATH))
        # FTP_VULN_CVE_2010_4221
        WriteResultsFromNmapVulnScripts(FTP_VULN_CVE_2010_4221_PATH, FTP_VULN_CVE_2010_4221_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "25" in port_scan_results or "465" in port_scan_results or "587" in port_scan_results or "smtp" in port_scan_results:
        print "\n[*] Port %s detected!" % "25, 465 or 587 or smtp service"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "25, 465 or 587 or smtp service")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected! Starting nmap script %s" % ("25, 465 or 587 or smtp service", SMTP_VULN_CVE_2010_4344_PATH))
        # SMTP_VULN_CVE_2010_4344
        WriteResultsFromNmapVulnScripts(SMTP_VULN_CVE_2010_4344_PATH, SMTP_VULN_CVE_2010_4344_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "80" in port_scan_results or "8080" in port_scan_results or "443" in port_scan_results:
        print "\n[*] Port %s detected!" % "80, 8080 or 443"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "80, 8080 or 443")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "80, 8080 or 443")
        # HTTP_IIS_WEBDAV_VULN
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_IIS_WEBDAV_VULN_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_IIS_WEBDAV_VULN_PATH, HTTP_IIS_WEBDAV_VULN_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2009_3960
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2009_3960_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2009_3960_PATH, HTTP_VULN_CVE_2009_3960_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2010_0738
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2010_0738_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2010_0738_PATH, HTTP_VULN_CVE_2010_0738_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2010_2861
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2010_2861_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2010_2861_PATH, HTTP_VULN_CVE_2010_2861_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2011_3368
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2011_3368_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2011_3368_PATH, HTTP_VULN_CVE_2011_3368_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2012_1823
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2012_1823_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2012_1823_PATH, HTTP_VULN_CVE_2012_1823_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2013_0156
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2013_0156_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2013_0156_PATH, HTTP_VULN_CVE_2013_0156_NMAP1, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s with other args: %s" % (HTTP_VULN_CVE_2013_0156_PATH, HTTP_VULN_CVE_2013_0156_NMAP2))
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2013_0156_PATH, HTTP_VULN_CVE_2013_0156_NMAP2, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2013_6786
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2013_6786_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2013_6786_PATH, HTTP_VULN_CVE_2013_6786_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2013_7091
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2013_7091_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2013_7091_PATH, HTTP_VULN_CVE_2013_7091_NMAP1, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s with other args: %s" % (HTTP_VULN_CVE_2013_7091_PATH, HTTP_VULN_CVE_2013_7091_NMAP2))
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2013_7091_PATH, HTTP_VULN_CVE_2013_7091_NMAP2, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2014_8877
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2014_8877_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2014_8877_PATH, HTTP_VULN_CVE_2014_8877_NMAP1, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s with other args: %s" % (HTTP_VULN_CVE_2014_8877_PATH, HTTP_VULN_CVE_2014_8877_NMAP2))
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2014_8877_PATH, HTTP_VULN_CVE_2014_8877_NMAP2, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2014_3704
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2014_3704_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2014_3704_PATH, HTTP_VULN_CVE_2014_3704_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2015_1635
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2015_1635_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2015_1635_PATH, HTTP_VULN_CVE_2015_1635_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2017_1001000
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2017_1001000_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2017_1001000_PATH, HTTP_VULN_CVE_2017_1001000_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2017_5638
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2017_5638_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2017_5638_PATH, HTTP_VULN_CVE_2017_5638_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2017_8917
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2017_8917_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2017_8917_PATH, HTTP_VULN_CVE_2017_8917_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_WNR1000_CREDS
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_WNR1000_CREDS_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_WNR1000_CREDS_PATH, HTTP_VULN_WNR1000_CREDS_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "80" in port_scan_results or "8080" in port_scan_results or "443" in port_scan_results or "webmin" in port_scan_results:
        print "\n[*] Port %s detected!" % "80, 8080 or 443 or service webmin"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "80, 8080 or 443 or service webmin")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "80, 8080 or 443 or service webmin")
        # HTTP_VULN_CVE_2006_3392
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2006_3392_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2006_3392_PATH, HTTP_VULN_CVE_2006_3392_NMAP1, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s with other args: %s" % (HTTP_VULN_CVE_2006_3392_PATH, HTTP_VULN_CVE_2006_3392_NMAP2))
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2006_3392_PATH, HTTP_VULN_CVE_2006_3392_NMAP2, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "137" in port_scan_results or "139" in port_scan_results:
        # SMB_ENUM_DOMAINS_PATH
        print "\n[*] Port %s detected! Starting Nmap script %s, %s and %s" % ("137 and 139", SMB_ENUM_DOMAINS_PATH, SMB_ENUM_SHARES_PATH, SMB_ENUM_USERS_PATH)
        try:
            WriteLog(LogType.NmapScripts, "Port %s detected!" % "137 and 139")
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "137 and 139")
            WriteLog(LogType.NmapScripts, "Starting Nmap script %s" % SMB_ENUM_DOMAINS_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Starting Nmap script %s" % SMB_ENUM_DOMAINS_PATH)
            result = subprocess.check_output(SMB_ENUM_DOMAINS_NMAP + GrepWithSedVulnExtract, cwd=CurrentIP, shell=True)
            print "\n[*] Nmap script %s finished" % (SMB_ENUM_DOMAINS_PATH)
            WriteLog(LogType.NmapScripts, "Nmap script %s finished" % SMB_ENUM_DOMAINS_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
            if "Builtin" in result:
                GeneralReconEnumDomainsFile = open(ReconEnumDomainsFilename, "a+")
                GeneralReconEnumDomainsFile.write("from nmap script %s\n" % SMB_ENUM_DOMAINS_PATH)
                GeneralReconEnumDomainsFile.write(result + "\n\n")
                GeneralReconEnumDomainsFile.close()
                HostEnumFile = open(CurrentIP + "/" + HostEnumFilename, "a+")
                HostEnumFile.write("from nmap script %s\n" % SMB_ENUM_DOMAINS_PATH)
                HostEnumFile.write(result + "\n\n")
                HostEnumFile.close()
                print "[*] Results written to %s and %s\n" % (ReconEnumDomainsFilename, (CurrentIP + "/" + HostEnumFilename))
                WriteLog(LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumDomainsFilename, (CurrentIP + "/" + HostEnumFilename)))
                WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumDomainsFilename, (CurrentIP + "/" + HostEnumFilename)))
        except subprocess.CalledProcessError as e:
            print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
            print "[-] Logging the error."
            WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
            WriteLog(LogType.Error, "Starting Nmap script %s" % SMB_ENUM_DOMAINS_PATH)
            WriteLogError(ReconLogErrorFileName, NmapTarget, "Starting Nmap script %s" % SMB_ENUM_DOMAINS_PATH)
        # SMB_ENUM_SHARES_PATH
        try:
            WriteLog(LogType.NmapScripts, "Starting Nmap script %s" % SMB_ENUM_SHARES_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Starting Nmap script %s" % SMB_ENUM_SHARES_PATH)
            result = subprocess.check_output(SMB_ENUM_SHARES_NMAP + GrepWithSedVulnExtract, cwd=CurrentIP, shell=True)
            print "\n[*] Nmap script %s finished" % (SMB_ENUM_SHARES_PATH)
            WriteLog(LogType.NmapScripts, "Nmap script %s finished" % SMB_ENUM_SHARES_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
            if "\\\\" in result:
                GeneralReconEnumSharesFile = open(ReconEnumSharesFilename, "a+")
                GeneralReconEnumSharesFile.write("from nmap script %s\n" % SMB_ENUM_SHARES_PATH)
                GeneralReconEnumSharesFile.write(result + "\n\n")
                GeneralReconEnumSharesFile.close()
                HostEnumFile = open(CurrentIP + "/" + HostEnumFilename, "a+")
                HostEnumFile.write("from nmap script %s\n" % SMB_ENUM_SHARES_PATH)
                HostEnumFile.write(result + "\n\n")
                HostEnumFile.close()
                print "[*] Results written to %s and %s\n" % (ReconEnumSharesFilename, (CurrentIP + "/" + HostEnumFilename))
                WriteLog(LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumSharesFilename, (CurrentIP + "/" + HostEnumFilename)))
                WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumSharesFilename, (CurrentIP + "/" + HostEnumFilename)))
        except subprocess.CalledProcessError as e:
            print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
            print "[-] Logging the error."
            WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
            WriteLog(LogType.Error, "Starting Nmap script %s" % SMB_ENUM_SHARES_PATH)
            WriteLogError(ReconLogErrorFileName, NmapTarget, "Starting Nmap script %s" % SMB_ENUM_SHARES_PATH)
        # SMB_ENUM_USERS_PATH
        try:
            WriteLog(LogType.NmapScripts, "Starting Nmap script %s" % SMB_ENUM_USERS_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Starting Nmap script %s" % SMB_ENUM_USERS_PATH)
            result = subprocess.check_output(SMB_ENUM_USERS_NMAP + GrepWithSedVulnExtract, cwd=CurrentIP, shell=True)
            print "\n[*] Nmap script %s finished" % (SMB_ENUM_USERS_PATH)
            WriteLog(LogType.NmapScripts, "Nmap script %s finished" % SMB_ENUM_USERS_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
            if "RID:" in result:
                GeneralReconEnumUsersFile = open(ReconEnumUsersFilename, "a+")
                GeneralReconEnumUsersFile.write("from nmap script %s\n" % SMB_ENUM_USERS_PATH)
                GeneralReconEnumUsersFile.write(result + "\n\n")
                GeneralReconEnumUsersFile.close()
                HostEnumFile = open(CurrentIP + "/" + HostEnumFilename, "a+")
                HostEnumFile.write("from nmap script %s\n" % SMB_ENUM_USERS_PATH)
                HostEnumFile.write(result+"\n\n")
                HostEnumFile.close()
                print "[*] Results written to %s and %s\n" % (ReconEnumUsersFilename, (CurrentIP + "/" + HostEnumFilename))
                WriteLog(LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumUsersFilename, (CurrentIP + "/" + HostEnumFilename)))
                WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumUsersFilename, (CurrentIP + "/" + HostEnumFilename)))
        except subprocess.CalledProcessError as e:
            print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
            print "[-] Logging the error."
            WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
            WriteLog(LogType.Error, "Starting Nmap script %s" % SMB_ENUM_USERS_PATH)
            WriteLogError(ReconLogErrorFileName, NmapTarget, "Starting Nmap script %s" % SMB_ENUM_USERS_PATH)

    if "161" in port_scan_results:
        # SNMP_WIN32_SERVICES
        print "\n[*] Port %s detected! Starting Nmap script %s, %s and %s" % ("161", SNMP_WIN32_SERVICES_PATH, SNMP_WIN32_SHARES_PATH, SNMP_WIN32_USERS_PATH)
        try:
            WriteLog(LogType.NmapScripts, "Port %s detected!" % "161")
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "161")
            WriteLog(LogType.NmapScripts, "Starting Nmap script %s" % SNMP_WIN32_SERVICES_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Starting Nmap script %s" % SNMP_WIN32_SERVICES_PATH)
            result = subprocess.check_output(SNMP_WIN32_SERVICES_NMAP + GrepWithSedVulnExtract, cwd=CurrentIP, shell=True)
            print "\n[*] Nmap script %s finished" % (SNMP_WIN32_SERVICES_PATH)
            WriteLog(LogType.NmapScripts, "Nmap script %s finished" % SNMP_WIN32_SERVICES_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
            if "snmp-win32-services:" in result:
                GeneralReconEnumServicesFile = open(ReconEnumServicesFilename, "a+")
                GeneralReconEnumServicesFile.write("from nmap script %s\n" % SNMP_WIN32_SERVICES_PATH)
                GeneralReconEnumServicesFile.write(result + "\n\n")
                GeneralReconEnumServicesFile.close()
                HostEnumFile = open(CurrentIP + "/" + HostEnumFilename, "a+")
                HostEnumFile.write("from nmap script %s\n" % SNMP_WIN32_SERVICES_PATH)
                HostEnumFile.write(result + "\n\n")
                HostEnumFile.close()
                print "[*] Results written to %s and %s\n" % (ReconEnumServicesFilename, (CurrentIP + "/" + HostEnumFilename))
                WriteLog(LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumServicesFilename, (CurrentIP + "/" + HostEnumFilename)))
                WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumServicesFilename, (CurrentIP + "/" + HostEnumFilename)))
        except subprocess.CalledProcessError as e:
            print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
            print "[-] Logging the error."
            WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
            WriteLog(LogType.Error, "Starting Nmap script %s" % SNMP_WIN32_SERVICES_PATH)
            WriteLogError(ReconLogErrorFileName, NmapTarget, "Starting Nmap script %s" % SNMP_WIN32_SERVICES_PATH)
        # SNMP_WIN32_USERS
        try:
            WriteLog(LogType.NmapScripts, "Starting Nmap script %s" % SNMP_WIN32_USERS_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Starting Nmap script %s" % SNMP_WIN32_USERS_PATH)
            result = subprocess.check_output(SNMP_WIN32_USERS_NMAP + GrepWithSedVulnExtract, cwd=CurrentIP, shell=True)
            print "\n[*] Nmap script %s finished" % (SNMP_WIN32_USERS_PATH)
            WriteLog(LogType.NmapScripts, "Nmap script %s finished" % SNMP_WIN32_USERS_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
            if "snmp-win32-users:" in result:
                GeneralReconEnumUsersFile = open(ReconEnumUsersFilename, "a+")
                GeneralReconEnumUsersFile.write("from nmap script %s\n" % SNMP_WIN32_USERS_PATH)
                GeneralReconEnumUsersFile.write(result + "\n\n")
                GeneralReconEnumUsersFile.close()
                HostEnumFile = open(CurrentIP + "/" + HostEnumFilename, "a+")
                HostEnumFile.write("from nmap script %s\n" % SNMP_WIN32_USERS_PATH)
                HostEnumFile.write(result + "\n\n")
                HostEnumFile.close()
                print "[*] Results written to %s and %s\n" % (ReconEnumUsersFilename, (CurrentIP + "/" + HostEnumFilename))
                WriteLog(LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumUsersFilename, (CurrentIP + "/" + HostEnumFilename)))
                WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumUsersFilename, (CurrentIP + "/" + HostEnumFilename)))
        except subprocess.CalledProcessError as e:
            print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
            print "[-] Logging the error."
            WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
            WriteLog(LogType.Error, "Starting Nmap script %s" % SNMP_WIN32_USERS_PATH)
            WriteLogError(ReconLogErrorFileName, NmapTarget, "Starting Nmap script %s" % SNMP_WIN32_USERS_PATH)
        # SNMP_WIN32_SHARES
        try:
            WriteLog(LogType.NmapScripts, "Starting Nmap script %s" % SNMP_WIN32_SHARES_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Starting Nmap script %s" % SNMP_WIN32_SHARES_PATH)
            result = subprocess.check_output(SNMP_WIN32_SHARES_NMAP + GrepWithSedVulnExtract, cwd=CurrentIP, shell=True)
            print "\n[*] Nmap script %s finished" % (SNMP_WIN32_SHARES_PATH)
            WriteLog(LogType.NmapScripts, "Nmap script %s finished" % SNMP_WIN32_SHARES_PATH)
            WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
            if "snmp-win32-shares:" in result:
                GeneralReconEnumSharesFile = open(ReconEnumSharesFilename, "a+")
                GeneralReconEnumSharesFile.write("from nmap script %s\n" % SNMP_WIN32_SHARES_PATH)
                GeneralReconEnumSharesFile.write(result + "\n\n")
                GeneralReconEnumSharesFile.close()
                HostEnumFile = open(CurrentIP + "/" + HostEnumFilename, "a+")
                HostEnumFile.write("from nmap script %s\n" % SNMP_WIN32_SHARES_PATH)
                HostEnumFile.write(result + "\n\n")
                HostEnumFile.close()
                print "[*] Results written to %s and %s\n" % (ReconEnumSharesFilename, (CurrentIP + "/" + HostEnumFilename))
                WriteLog(LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumSharesFilename, (CurrentIP + "/" + HostEnumFilename)))
                WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Results written to %s and %s" % (ReconEnumSharesFilename, (CurrentIP + "/" + HostEnumFilename)))
        except subprocess.CalledProcessError as e:
            print "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)
            print "[-] Logging the error."
            WriteHostLog(HostLogFileName, CurrentIP, LogType.Error, "Error running the previous command!")
            WriteLog(LogType.Error, "Starting Nmap script %s" % SNMP_WIN32_SHARES_PATH)
            WriteLogError(ReconLogErrorFileName, NmapTarget, "Starting Nmap script %s" % SNMP_WIN32_SHARES_PATH)
    
    if "443" in port_scan_results:
        print "\n[*] Port %s detected!" % "443"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "443")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "443")
        # HTTP_VULN_CVE_2014_2126
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2014_2126_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2014_2126_PATH, HTTP_VULN_CVE_2014_2126_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2014_2127
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2014_2127_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2014_2127_PATH, HTTP_VULN_CVE_2014_2127_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # HTTP_VULN_CVE_2014_2128
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2014_2128_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2014_2128_PATH, HTTP_VULN_CVE_2014_2128_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "9200" in port_scan_results:
        print "\n[*] Port %s detected!" % "9200"
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "9200")
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "9200")
        # HTTP_VULN_CVE_2015_1427
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2015_1427_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2015_1427_PATH, HTTP_VULN_CVE_2015_1427_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "623" in port_scan_results or "664" in port_scan_results or "16992" in port_scan_results or "16993" in port_scan_results:
        print "\n[*] Port %s detected!" % "623, 664, 16992 or 16993"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "623, 664, 16992 or 16993")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "623, 664, 16992 or 16993")
        # HTTP_VULN_CVE_2017_5689
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_CVE_2017_5689_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_CVE_2017_5689_PATH, HTTP_VULN_CVE_2017_5689_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "7547" in port_scan_results:
        print "\n[*] Port %s detected!" % ("7547")
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "7547")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "7547")
        # HTTP_VULN_MISFORTUNE_COOKIE
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % HTTP_VULN_MISFORTUNE_COOKIE_PATH)
        WriteResultsFromNmapVulnScripts(HTTP_VULN_MISFORTUNE_COOKIE_PATH, HTTP_VULN_MISFORTUNE_COOKIE_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "3306" in port_scan_results or "mysql" in port_scan_results:
        print "\n[*] Port %s detected!" % ("3306")
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "3306")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Port %s detected!" % "3306")
        # MYSQL_VULN_CVE_2012_2122
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % MYSQL_VULN_CVE_2012_2122_PATH)
        WriteResultsFromNmapVulnScripts(MYSQL_VULN_CVE_2012_2122_PATH, MYSQL_VULN_CVE_2012_2122_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "3389" in port_scan_results or "ms-wbt-server" in port_scan_results:
        print "\n[*] Port %s detected!" % "3389 or service ms-wbt-server"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "3389 or service ms-wbt-server")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "3389 or service ms-wbt-server")
        # RDP_VULN_MS12_020
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % RDP_VULN_MS12_020_PATH)
        WriteResultsFromNmapVulnScripts(RDP_VULN_MS12_020_PATH, RDP_VULN_MS12_020_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "1099" in port_scan_results:
        print "\n[*] Port %s detected!" % ("1099")
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "1099")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "1099")
        # RMI_VULN_CLASSLOADER
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % RMI_VULN_CLASSLOADER_PATH)
        WriteResultsFromNmapVulnScripts(RMI_VULN_CLASSLOADER_PATH, RMI_VULN_CLASSLOADER_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "139" in port_scan_results or "netbios-ssn" in port_scan_results:
        print "\n[*] Port %s detected!" % "139 or netbios-ssn"
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "139 or netbios-ssn")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "139 or netbios-ssn")
        # SAMBA_VULN_CVE_2012_1182
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % SAMBA_VULN_CVE_2012_1182_PATH)
        WriteResultsFromNmapVulnScripts(SAMBA_VULN_CVE_2012_1182_PATH, SAMBA_VULN_CVE_2012_1182_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")

    if "445" in port_scan_results or "microsoft-ds" in port_scan_results:
        print "\n[*] Port %s detected!" % ("445 or microsoft-ds")
        WriteLog(LogType.NmapScripts, "Port %s detected!" % "445 or microsoft-ds service")
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "445 or microsoft-ds service")
        # SMB_VULN_MS17_010_SCAN
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % SMB_VULN_MS17_010_PATH)
        WriteResultsFromNmapVulnScripts(SMB_VULN_MS17_010_PATH, SMB_VULN_MS17_010_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # SMB2_VULN_UPTIME_SCAN
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % SMB2_VULN_UPTIME_PATH)
        WriteResultsFromNmapVulnScripts(SMB2_VULN_UPTIME_PATH, SMB2_VULN_UPTIME_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)        
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # SMB_VULN_CVE_2017_7494_SCAN
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % SMB_VULN_CVE_2017_7494_PATH)
        WriteResultsFromNmapVulnScripts(SMB_VULN_CVE_2017_7494_PATH, SMB_VULN_CVE_2017_7494_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)        
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
        # SMB_VULN_MS10_061_SCAN
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Start Nmap script %s" % SMB_VULN_MS10_061_PATH)
        WriteResultsFromNmapVulnScripts(SMB_VULN_MS10_061_PATH, SMB_VULN_MS10_061_NMAP, CurrentIP, ReconVulnFilename, HostVulnFilename)
        WriteHostLog(HostLogFileName, CurrentIP, LogType.NmapScripts, "Script finished")
