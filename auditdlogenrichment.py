#!/usr/bin/python
__author__ = 'scott.harrison'

# This script is designed to watch the /var/log/audit/auditd.log and enrich the data with ausearch substituting real user names
# for UID and AUID and then put the resulting data into a file to be monitored by OSSEC or Splunk, or both.  My current setup
# is to enrich the data and then use OSSEC to monitor the enriched data with custom alerts to cut down the amount of data
# Splunk indexes from auditd.log.  It is similar to the auditd ausearch scripted input get_ausearch.sh however the output is sent 
# to a file rather than directly to splunk.  Application flow is as folllows:
# auditd.log --> auditdlogenrichment.py --> OSSEC Alerting --> Splunk Indexing/Alerting
# Suggested script run is every 60 seconds.

from subprocess import *
import os

# Temp file for processing Auditd data through ausearch.
LOGPROCESSINGFILE = 'auditdata.log'
# Where Auditd logs are stored
AUDITLOG = '/var/log/audit/audit.log'
# Tracking file to keep position of last enriched log in auditd.log.
TRACKFILE = 'tracker.log'
# Log that holds enriched data, and the log that OSSEC will monitor.
ENRICHEDLOG = 'enricheddata.log'
# Starting index in auditd.log, if you've never indexed Auditd in Splunk with OSSEC you should set this to 0. 
# Negative numbers are bottom up positive numbers are top down.
STARTINDEX = '-5000'


def main():

    if os.path.isfile(TRACKFILE):
        indexedline = openfile(TRACKFILE)
        if indexedline:
            enrichdata(int(indexedline[0]))
        else:
            enrichdata(STARTINDEX)
    else:
        writetracker(STARTINDEX)
        indexedline = openfile(TRACKFILE)
        if indexedline:
            enrichdata(int(indexedline[0]))
        else:
            enrichdata(STARTINDEX)


def enrichdata(indexedline):

    logs = openfile(AUDITLOG)
    lastlogwritten = countloglines(AUDITLOG)

    if lastlogwritten < int(indexedline):
        indexedline = STARTINDEX

    writetracker(lastlogwritten)

    for log in logs[int(indexedline):]:
        if log:
            writefile(log + '\n')

    enricheddata = Popen(['ausearch', '-i', '-if', LOGPROCESSINGFILE], stdout=PIPE).communicate()[0]
    writeenricheddata(enricheddata)

    if os.path.isfile(LOGPROCESSINGFILE):
        os.remove(LOGPROCESSINGFILE)


def countloglines(logfile):

    with open(logfile) as fname:
        for i, l in enumerate(fname):
            pass
    return i + 1


def openfile(logfile):

    with open(logfile) as f:
        data = f.read()
        logs = data.split('\n')
    return logs


def writefile(output):

    fout = file(LOGPROCESSINGFILE, "ab")
    fout.write(output)
    fout.close()


def writetracker(output):

    fout = file(TRACKFILE, "w")
    fout.write(str(output))
    fout.close()


def writeenricheddata(output):

    fout = file(ENRICHEDLOG, "w")
    fout.write(output)
    fout.close()

if __name__ == "__main__":
    main()
