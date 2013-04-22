# -*- coding: utf-8 -*-
'''
Created on 2013-03-05

@author: Patrick Mathieu 
@summary: Small tool to create Kismet statistic from netxml file. Number of network and encryption type.
@contact: @PathetiQ / patrick@hackfest.ca
@organization: Hackfest.ca

@version: 0.1
@license BSD

@requires: lxml (http://lxml.de/) 


@todo: add option to see only certain encryption type, infrastructure, etc.
@todo: better output
@todo: read multiple files
@todo: 

'''

from lxml import etree
from StringIO import StringIO
import argparse


def parseNetwork(search,search2,tree):
    #accumulators
    ap = []
    wep = 0
    wpa = 0
    unsec = 0
    nosec = 0
   
    for call in tree.xpath(search):
        
        ssid = call
        encryption = ssid.xpath(search2)
        
        #create # stats
        #for sec in encryption: #can iterate to get all wpa kind
        try:
            sec = encryption[0]
        except IndexError:
            sec = ""
        
        if sec == "WPA+TKIP":
            wpa = wpa + 1
        elif sec == "WPA+AES-CCM":
            wpa = wpa + 1
        elif sec == "WPA+PSK":
            wpa= wpa + 1
        
        elif sec == "None":
            unsec = unsec + 1
        
        elif sec == "WEP":
            wep = wep + 1
        else:
            nosec = nosec + 1
        
        ap.append(call.attrib)
        
    #create % stats
    total = len(ap)
    wpaP = round((float(wpa)/float(total))*100,2)
    unsecP = round((float(unsec)/float(total))*100,2) 
    wepP = round((float(wep)/float(total))*100,2) 
    nosecP = round((float(nosec)/float(total))*100,2)
    notSecure = wep+unsec
    notSecureP = wepP+unsecP
    
    return (total,wpa,wpaP,unsec,unsecP,wep,wepP,nosec,nosecP,notSecure,notSecureP)

def parseChannels(s1,s2,tree):
    global totalChannels
    channels = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0]
    
    for call in tree.xpath(s1):
        
        ch = call
        chan = ch.xpath(s2)
        
        try:
            #print channels[int(chan[0])]
            channels[int(chan[0])] = channels[int(chan[0])]+1
            totalChannels[int(chan[0])] = totalChannels[int(chan[0])]+1
        except IndexError:
            pass
        
    return channels
        

def printChannels(title,data):
    total = 0
    print "\n",title
    for i in range(0,len(data)):
        print "Channel #",i+1," :",data[i]
        total += data[i]
        
    print "Total",title,": ",total

def printResults(title,data):
    global totalWifi
    totalWifi += data[0]
    print title,": ",data[0]
    print "\tWPA 1-2 (TKIP/AES/PSK)\t: ",data[1]," | ",data[2],"%"
    print "\tOpen\t\t\t: ",data[3]," | ",data[4],"%"
    print "\tWEP\t\t\t: ", data[5]," | ",data[6],"%"
    print "\tNot secure\t\t: ", data[7]," | ",data[8],"%"
    print "\tOpen+Wep\t\t: ", data[9]," | ",data[10],"%"

def parseXML(xmlFile):
    f = open(xmlFile)
    xml = f.read()
    f.close()
 
    #lxml parsing tree
    tree = etree.parse(StringIO(xml))
    
    #INFRASTRUCTURE
    data = parseNetwork('//wireless-network[@type="infrastructure"]/SSID','.//encryption/text()',tree)
    dataC = parseChannels('//wireless-network[@type="infrastructure"]/channel','text()',tree)
    #print the stats
    printResults("Access Points",data)
    printChannels("Channels for Access Points",dataC)
    print "\n"
    
    #MOBILE
    data = parseNetwork('//wireless-network[@type="ad-hoc" or @type="fromds" or @type="probes" or @type="tods"]','.//SSID/encryption/text()',tree)
    dataC = parseChannels('//wireless-network[@type="ad-hoc" or @type="fromds" or @type="probes" or @type="tods"]/channel','text()',tree)
    #print the stats
    printResults("Ad-Hoc (cellulaire)",data)
    printChannels("Channels for Ad-Hoc (cellulaire)",dataC)
    print "\n"
    
    #CLIENTS
    data = parseNetwork('//wireless-client[@type="ad-hoc" or @type="fromds" or @type="probes" or @type="tods"]','.//SSID/encryption/text()',tree)
    dataC = parseChannels('//wireless-client[@type="ad-hoc" or @type="fromds" or @type="probes" or @type="tods"]/channel','text()',tree)
    print "\n"
    
    #print the stats
    printResults("Wifi-Clients",data)
    printChannels("Channels for Wifi-Clients",dataC)
    print "\n"
    
    #data = parseChannels('//wireless-network/channel/text()',tree)
    #print the stats
    #printChannels("All Channels",data)
    

if __name__ == "__main__":

    #Intro
    version = 0.1
    print "------------------------------------"
    print "Kismet Quick Stats | version",version
    print "by @PathetiQ (patrick @ hackfest.ca)"
    print "------------------------------------"
    
    #parse cmd line args
    parser = argparse.ArgumentParser()
    parser.add_argument('-file', required=True, help='Enter the netxml kismet file to analyse')

    args = parser.parse_args()    
    
    #args
    filename = args.file
    
    totalWifi = 0
    totalChannel = 0
    totalChannels = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0]

    #dew it
    parseXML(filename)
    
    print "Total numbers of wifi:",totalWifi
    printChannels("List of total numbers of channels:",totalChannels)
    quit()
    
    
    
    
    
    
    
    
    
    
