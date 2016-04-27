from subprocess import *
import os
import logging
from logging.handlers import RotatingFileHandler

# This script is designed to watch the /var/log/audit/auditd.log and enrich the data with ausearch substituting real user names
# for UID and AUID and then put the resulting data into a file to be monitored by OSSEC or Splunk, or both.  My current setup
# is to enrich the data and then use OSSEC to monitor the enriched data with custom alerts to cut down the amount of data
# Splunk indexes from auditd.log.  It is similar to the auditd ausearch scripted input get_ausearch.sh however the output is sent 
# to a file rather than directly to splunk.  Application flow is as folllows:
# auditd.log --> auditdlogenrichment.py --> OSSEC Alerting --> Splunk Indexing/Alerting
# Suggested script run is every 30 seconds.

__author__ = 'scott.harrison'

full_path = os.path.realpath(__file__)
thispath, thisfile = os.path.split(full_path)

LOGPROCESSINGFILE = thispath + "/../local/var/auditdata.log"
AUDITLOG = '/var/log/audit/audit.log'
TRACKFILE = thispath + "/../local/var/tracker.log"
ENRICHEDLOG = thispath + "/../local/var/enricheddata.log"
STARTINDEX = '0'

""" LOGPROCESSINGFILE = "auditdata.log"
AUDITLOG = '/var/log/audit/audit.log'
TRACKFILE = "tracker.log"
ENRICHEDLOG = "enricheddata.log" """


def main():

    if os.path.isfile(AUDITLOG):
        if os.path.isfile(TRACKFILE):
            indexed_line = openfile(TRACKFILE)
            if indexed_line:
                enrichdata(indexed_line[0])
            else:
                enrichdata(STARTINDEX)
        else:
            writetracker(STARTINDEX)
            indexed_line = openfile(TRACKFILE)
            if indexed_line:
                enrichdata(STARTINDEX)
            else:
                enrichdata(STARTINDEX)


def enrichdata(indexedline):

    log_process = create_rotating_log(LOGPROCESSINGFILE, 2)
    log_enriched = create_rotating_log(ENRICHEDLOG, 4)

    logs = openfile(AUDITLOG)
    lastlogwritten = countloglines(AUDITLOG)

    if lastlogwritten < int(indexedline):
        rolled_log = AUDITLOG + ".1"
        if os.path.isfile(rolled_log):
            roll_logs = openfile(AUDITLOG + ".1")

            for roll_log in roll_logs[int(indexedline):]:
                log_process.info(roll_log)

        indexedline = STARTINDEX

    writetracker(lastlogwritten)

    for log in logs[int(indexedline):]:
        if log:
            log_process.info(log)

    try:
        enricheddata = Popen(['ausearch', '-i', '-if', LOGPROCESSINGFILE], stdout=PIPE).communicate()[0]

    except:

        p = os.popen('ausearch -i')
        enricheddata = p.read()

    log_enriched.info(enricheddata)


def create_rotating_log(path, count):
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(path, maxBytes=6e+6, backupCount=count)
    logger.addHandler(handler)
    return logger


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


def writetracker(output):

    fout = file(TRACKFILE, "w")
    fout.write(str(output))
    fout.close()


if __name__ == "__main__":
    main()
