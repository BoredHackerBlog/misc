import pefile
import time
import os
import requests
import feature_extractor

def lineparser(line):
    if line[0] is not "#":
        line_fields = line.split("\t")
        if "PE" in line_fields[7]:
            try:
                if pefile.PE("extract_files/"+line_fields[22],fast_load=True).is_exe(): #just another way to validate
                    print "EXE FILE DOWNLOADED FROM %s BY %s"%(line_fields[2],line_fields[3])
                    print requests.post('http://localhost:8080/ML',json=feature_extractor.get_features("extract_files/"+line_fields[22])).json()
            except:
                print "Unable to open the file"

while not os.path.exists("files.log"):
    time.sleep(1)

file = open("files.log")

#https://stackoverflow.com/a/3290359

while True:
    where = file.tell()
    line = file.readline()
    if not line:
        time.sleep(.1)
        file.seek(where)
    else:
        lineparser(line)
