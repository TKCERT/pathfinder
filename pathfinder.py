#!/usr/bin/python
import sys
import lxml.objectify
import pygraphviz
import untangle
import re
import os
import sys
import re
import json
import time
import getopt
import xml.etree.ElementTree as xml
import copy
from xml.etree.ElementTree import fromstring, ElementTree
import getopt

def processNmapFile(inputNmapXmlFile, outputDotPngFile, skipDestHost, destIpToNetwork):
  nmap_start = """<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE nmaprun>
  <nmaprun scanner="nmap" args="nmap">
  """
  nmap_end = "</nmaprun>"
  counter = 0
  topology = pygraphviz.AGraph()
  lastaddr=""
  # Read xml file and split into separate small xml nmap files (to process large nmap files)
  host = False    # Flag for being inside a host in the XML report
  nmap_host = ""  # String with nmap XML report for a host
  pattern_start = re.compile("^<host starttime", re.IGNORECASE) 
  pattern_stop = re.compile("^</host>", re.IGNORECASE)  
  pattern_down = re.compile("^<host><status state=\"down\"", re.IGNORECASE)  
  skip_nmap_host = False # Set when a host is identified in the XML file which is down

  with open (inputNmapXmlFile,'rt') as nmap_xml_report:    
    for line in nmap_xml_report:
        if skip_nmap_host:
            if pattern_stop.search(line) != None:  # If a match is found (=> end of host section)
                skip_nmap_host = False
            continue
        if pattern_down.search(line) != None: # If a match is found (=> host is down)
            skip_nmap_host = True
        if pattern_start.search(line) != None: # If a match is found  (=> start of host section)
            nmap_host=nmap_start
            nmap_host+=line
            host = True
        if pattern_start.search(line) == None and pattern_stop.search(line) == None: # If nothing matches (=> inside host)
            nmap_host+=line
        if pattern_stop.search(line) != None:  # If a match is found (=> end of host section)
            nmap_host+=line
            nmap_host+=nmap_end
            host = False
            counter = counter + 1
            print("[*] Processing document " + str(counter))
            nmap = untangle.parse(nmap_host)

            for run in nmap.nmaprun.host:
                #print(run.address["addr"])
                # check for traceroute info
                if not "trace" in dir(run) or not "hop" in dir(run.trace):
                    print("    No trace information for host")
                    continue
                hops = run.trace.hop

                # check if last hop equals to target host (else skip due to incomplete traceroute)
                if run.address["addr"] != hops[len(hops)-1]["ipaddr"]:
                    print("    Incomplete traceroute for host")
                    continue

                # Workaround: nmap only records identified hops - those that could not
                #             be identified are not present (e.g. *). But the ttl
                #             is stored with each identified hop (e.g. ttl="2"). Therefore, 
                #             empty hops are refilled and a counter is used for identification of
                #             missing hops.

                # insert unknown, but missing hops
                ttlCounter=1
                emptyHop = {
                        "ttl": 0,
                        "ipaddr": "unknown",
                }
                # list of dictionaries (hops -> hop)
                completeHops = [
                ]
                for hop in hops:
                    ttl = hop["ttl"]
                    # hop is not present
                    while str(ttl) != str(ttlCounter):
                        emptyHop["ttl"] = ttlCounter
                        completeHops.append(copy.deepcopy(emptyHop))
                        ttlCounter = ttlCounter + 1
                    if ttl == str(ttlCounter):
                        completeHops.append(hop)
                        ttlCounter = ttlCounter + 1

                # Only gather traceroutes for hosts with more than 1 hop 
                # Workaround due to nmap outputting one hop traceroute
                # although actually no trace was identified.
                if len(completeHops) > 1:
                    hops = completeHops
                    # Skip the last system in the traceroute as only the route
                    # is of interest not the destination system itself.
                    if skipDestHost:
                        hops = hops[:-1]
                    for hop in hops:
                        ip = str(hop["ttl"]) + "\n" + hop["ipaddr"]
                        # The hop can be a dictionary or an untangled.element
                        # due to the function that appends "unknown" hops
                        # * untangle.Element
                        # * dict
                        if (isinstance(hop,dict)) and hop.get("host") != None:
                            ip += "\n" + hop["host"]
                        # untangled.element
                        if (isinstance(hop,untangle.Element)) and hop.get_attribute("host") != None:
                            ip += "\n" + hop["host"]
                        ttl = hop["ttl"]
                        # first hop
                        if str(ttl) == str(1):
                            print("    " + str(" - ".join(ip.split("\n"))))
                            topology.add_edge("scanner",ip)
                            lastaddr = ip
                        # hop on the route
                        else:
                            # check if last hop and set to /24 network
                            if destIpToNetwork and str(ttl) == str(hops[-1]['ttl']):
                                octets = ip.split('.')
                                ip = str(octets[0]) + "." + str(octets[1]) + "." + str(octets[2]) + ".0/24"
                            print("    " + str(" - ".join(ip.split("\n"))))
                            topology.add_edge(lastaddr,ip)
                            lastaddr = ip
    
  #write our output:
  topology.write(outputDotPngFile + '.dot')
       #dot - filter for drawing directed graphs
       #neato - filter for drawing undirected graphs
       #twopi - filter for radial layouts of graphs
       #circo - filter for circular layout of graphs
       #fdp - filter for drawing undirected graphs
       #sfdp - filter for drawing large undirected graphs
  topology.layout(prog='dot') # use which layout from the list above^
  topology.draw(outputDotPngFile + '.png')

def usage():
    banner = """
             _   _      __ _           _                 
 _ __   __ _| |_| |__  / _(_)_ __   __| | ___ _ __   
| '_ \ / _` | __| '_ \| |_| | '_ \ / _` |/ _ \ '__| 
| |_) | (_| | |_| | | |  _| | | | | (_| |  __/ |     
| .__/ \__,_|\__|_| |_|_| |_|_| |_|\__,_|\___|_|    
|_|                                                      
      ------------------------------------->
                               _                                      _                                _     _             
 _ __  _ __ ___   __ _ _ __   | |_ _ __ __ _  ___ ___ _ __ ___  _   _| |_ ___     __ _ _ __ __ _ _ __ | |__ (_)_ __   __ _ 
| '_ \| '_ ` _ \ / _` | '_ \  | __| '__/ _` |/ __/ _ \ '__/ _ \| | | | __/ _ \   / _` | '__/ _` | '_ \| '_ \| | '_ \ / _` |
| | | | | | | | | (_| | |_) | | |_| | | (_| | (_|  __/ | | (_) | |_| | ||  __/  | (_| | | | (_| | |_) | | | | | | | | (_| |
|_| |_|_| |_| |_|\__,_| .__/   \__|_|  \__,_|\___\___|_|  \___/ \__,_|\__\___|   \__, |_|  \__,_| .__/|_| |_|_|_| |_|\__, |
                      |_|                                                        |___/          |_|                  |___/ 
"""
    description = """    Info: Generates a graph via graphviz of the traceroute information in nmap XML files (nmap --traceroute [...]).
"""
    commandLineParams = """

    --help		This help text
    --ifile		The Nmap XML file to parse for traceroute information
    --ofile		Filename for output files: Graphviz dot and png file
    --skipDestHost	(Optional) For better visibility in huge scans the destination host can be excluded 
                        from the graph resulting in only the route information.
    --destIpToNetwork	(Optional) For better visibility in huge scans the destination IP can be transformed
                        into a class C network (e.g. 192.168.1.2 -> 192.168.1.0/24).

 """
    print(banner)
    print(description)
    print("    " + sys.argv[0] + "-i <nmap_xml_input_file> -o <outputfile> [-s <True|False>] [-d <True|False>]")
    print(commandLineParams)

def main():
   try:
       opts, args = getopt.getopt(sys.argv[1:],"hi:o:sd",["help","ifile=","ofile=","skipDestHost=","destIpToNetwork="])
   except getopt.GetoptError:
       print(getopt.GetoptError)
       usage()
       sys.exit(2)
   # Default values
   inputNmapXmlFile = None
   outputDotPngFile = None
   skipDestHost = False
   destIpToNetwork = False
   for opt, arg in opts:
      if opt == '-h':
         usage()
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputNmapXmlFile = arg
      elif opt in ("-o", "--ofile"):
         outputDotPngFile = arg
      elif opt in ("-s", "--skipDestHost"):
         skipDestHost = arg
      elif opt in ("-d", "--destIpToNetwork"):
         destIpToNetwork = arg
      else:
          print("unhandled option")

   if inputNmapXmlFile != None and outputDotPngFile != None:
       processNmapFile(inputNmapXmlFile, outputDotPngFile, skipDestHost, destIpToNetwork)
   else:
       usage()

if __name__ == "__main__":
   main()






