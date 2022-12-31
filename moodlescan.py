#!/usr/bin/python3
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import argparse
import os
import sys
import urllib
from urllib.request import Request, urlopen 
from urllib.error import URLError
import zipfile
import re
import random
import ssl


class httpProxy():
    url = ""
    user = ""
    password = ""
    auth = ""

#descarga un archivo al directorio y nombre indicado en dest
def fileDownload(url, dest, agent):
    try:
        req = Request(url)
        if len(agent) > 2:
            req.add_header('user-agent', agent)

        with urlopen(req) as response, open(dest, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
            return None	
    except URLError as e:
        return e

def getuseragent():
    lines = open('data/agents.txt').read().splitlines()
    return random.choice(lines)

def savelog(e, url):
    logfile = open("errors.moodlescan.log", "a")
    if (hasattr(e, "reason")):
        logfile.write(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + " - " + url + " - " + str(e.reason) + "\n")
    else:
        logfile.write(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + " - " + url + " - no reason\n" )
    logfile.close()

def getignoressl():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


#genera una conecion HTTP con o sin proxy, dependiendo de los parametros, adicionalmente, el proxy lo puede autenticar con NTLM o Basic
def httpConnection(url,  proxy, agent, ignore):
    
    if (proxy.auth == "ntlm"):
        #todo
        print("")
    else:
        auth_handler = urllib.request.HTTPBasicAuthHandler()
        auth_handler.add_password(realm='Proxy', uri=proxy.url, user=proxy.user, passwd=proxy.password)

    if (proxy.url):		
        opener = urllib.request.build_opener(auth_handler)
        urllib.install_opener(opener)

    req = Request(url)
    if len(agent) > 2:
        req.add_header('user-agent', agent)

    if (ignore):
        return urlopen(req,  context=ignore)
    else:
        return urlopen(req)

def banner():
    print ("""

 .S_SsS_S.     sSSs_sSSs      sSSs_sSSs     .S_sSSs    S.        sSSs    sSSs    sSSs   .S_SSSs     .S_sSSs    
.SS~S*S~SS.   d%%SP~YS%%b    d%%SP~YS%%b   .SS~YS%%b   SS.      d%%SP   d%%SP   d%%SP  .SS~SSSSS   .SS~YS%%b   
S%S `Y' S%S  d%S'     `S%b  d%S'     `S%b  S%S   `S%b  S%S     d%S'    d%S'    d%S'    S%S   SSSS  S%S   `S%b  
S%S     S%S  S%S       S%S  S%S       S%S  S%S    S%S  S%S     S%S     S%|     S%S     S%S    S%S  S%S    S%S  
S%S     S%S  S&S       S&S  S&S       S&S  S%S    S&S  S&S     S&S     S&S     S&S     S%S SSSS%S  S%S    S&S  
S&S     S&S  S&S       S&S  S&S       S&S  S&S    S&S  S&S     S&S_Ss  Y&Ss    S&S     S&S  SSS%S  S&S    S&S  
S&S     S&S  S&S       S&S  S&S       S&S  S&S    S&S  S&S     S&S~SP  `S&&S   S&S     S&S    S&S  S&S    S&S  
S&S     S&S  S&S       S&S  S&S       S&S  S&S    S&S  S&S     S&S       `S*S  S&S     S&S    S&S  S&S    S&S  
S*S     S*S  S*b       d*S  S*b       d*S  S*S    d*S  S*b     S*b        l*S  S*b     S*S    S&S  S*S    S*S  
S*S     S*S  S*S.     .S*S  S*S.     .S*S  S*S   .S*S  S*S.    S*S.      .S*P  S*S.    S*S    S*S  S*S    S*S  
S*S     S*S   SSSbs_sdSSS    SSSbs_sdSSS   S*S_sdSSS    SSSbs   SSSbs  sSS*S    SSSbs  S*S    S*S  S*S    S*S  
SSS     S*S    YSSP~YSSY      YSSP~YSSY    SSS~YSSY      YSSP    YSSP  YSS'      YSSP  SSS    S*S  S*S    SSS  
        SP                                                                                    SP   SP          
        Y                                                                                     Y    Y           
                                                                                                               
Version 0.8 - May/2021""")
    print ("""
By Victor Herrera - supported by www.incode.cl
    """)
    print ("." * 109)
    print ("""
Version 1.0 - November/2022
    """)
    print ("""
Modified By NgoVanThang_D18CQAT04-B
    """)
    print ("." * 109)
    print ("")

    if len(sys.argv) == 1:

        print ("""

        Options

        -u [URL] 	: URL with the target, the moodle to scan
        -a 		: Update the database of vulnerabilities to latest version
        -r 		: Enable HTTP requests with random user-agent

        Proxy configuration

        -p [URL]	: URL of proxy server (http)
        -b [user]	: User for authenticate to proxy server
        -c [password]	: Password for authenticate to proxt server
        -d [protocol]  : Protocol of authentication: basic or ntlm

        """)



def main():
    banner()
    agent = ""
    parser = argparse.ArgumentParser()
    ignore = False

    parser.add_argument('-u', '--url', dest="url", help="URL with the target, the moodle to scan")
    parser.add_argument('-k', action="store_true", dest="ignore", help="Ignore SSL Certificate")
    parser.add_argument('-r', action="store_true", dest="agent", help="Enable HTTP requests with random user-agent")
    parser.add_argument('-a', action="store_true",dest="act", help="Update the database of vulnerabilities to latest version")
    parser.add_argument('-p', '--proxy', dest="prox", help="URL of proxy server")
    parser.add_argument('-b', '--proxy-user', dest="proxu", help="User for authenticate to proxy server")
    parser.add_argument('-c', '--proxy-pass', dest="proxp", help="Password for authenticate to proxt server")
    parser.add_argument('-d', '--proxy-auth', dest="proxa", help="Protocol of authentication: basic or ntlm")
    

    options = parser.parse_args()
    if options.act:
        checkupdate()

    if options.agent:
        agent = getuseragent()

    if options.ignore:
        ignore = getignoressl()

    if options.url:
        proxy = httpProxy()

        #se revisa si es necesario crear instancia de proxy
        if (options.prox):	

            proxy.url = options.prox

            if (options.proxu):
                proxy.user = options.proxu

            if (options.proxp):
                proxy.password = options.proxp
            
            if (options.proxa):
                proxy.auth = options.proxa

        getheader(options.url, proxy, agent, ignore)
        v = getversion(options.url, proxy, agent, ignore)
        if v:
            getcve(v)
            
        print ("\nScan completed.\n")


def update():
    #TODO: catch HTTP errors (404, 503, timeout, etc)
    print ("A new version of database was found, updating...")
    urlup = "https://raw.githubusercontent.com/inc0d3/moodlescan/master/update/update.zip"
    r = fileDownload(urlup, "data.zip", "")
    if (r):
            print("Error to connect with database service : " + str(r.reason) )
            sys.exit()
            
    zip_ref = zipfile.ZipFile('data.zip', 'r')
    zip_ref.extractall('data')
    zip_ref.close()
    os.remove('data.zip')
    print ("\nThe database is now updated.\n")


def checkupdate():
    #TODO: catch HTTP errors (404, 503, timeout, etc)

    urlup = "https://raw.githubusercontent.com/inc0d3/moodlescan/master/update/update.dat"
    
    try:

        fo = open("update.dat", "r+")
        actual = int(fo.readline())
        fo.close()
        
        r = fileDownload(urlup, "update.dat", "")
        if (r):
            print("Error to connect with database service : " + str(r.reason) )
            sys.exit()
        
        fo = open("update.dat", "r+")
        ultima = int(fo.readline())
        fo.close()
        
        if ultima > actual:
            update()
        else:
            print("The moodlescan database is up to date (version: " + str(actual) + ").\n")
        
    except IOError as e:
        if e.errno == 2:
            print(e)
            urllib.urlretrieve (urlup, "update.dat")
            fo = open("update.dat", "r+")
            update()
        else:
            print (e)
    



def getheader(url, proxy, agent, ignore):
    print ("Getting server information " + url + " ...\n")
    
    try:
        cnn = httpConnection(url, proxy, agent, ignore)
        headers = ['server', 'x-powered-by', 'x-frame-options', 'x-xss-protection', 'last-modified']		
        for el in headers:
            if cnn.info().get(el):
                print (el.ljust(15) + "	: " + cnn.info().get(el))
    except URLError as e:
        print("Error: Can't connect with the target : " + str(e.reason) )
        savelog(e, url)
        sys.exit()
    except Exception as e:
        print ("\nError: Can't connect with the target. Check URL option.\n\nScan finished.\n")
        savelog(e, url)
        sys.exit()
    

def getversion(url, proxy, agent, ignore):
    print ("\nGetting moodle version...")

    s = [['/admin/environment.xml'], ['/composer.lock'], ['/lib/upgrade.txt'], ['/privacy/export_files/general.js'], ['/composer.json'], ['/question/upgrade.txt'], ['/admin/tool/lp/tests/behat/course_competencies.feature']]
    
    i = 0
    urllib.request.urlcleanup() #no cache

    #obtiene todos los hash md5 remotamente a partir de la lista "s", luego al elemento de la misma
    #lista le agrega su hash md5, quedando:
    #[['/admin/environment.xml', '5880153d43cdc31d2ff81f2984b82e83'], ['/admin/upgrade.txt', '87a1a291465a87ac9f67473898044941'].....
    for a in s:		
        #TODO: catch HTTP errors (404, 503, timeout, etc)
        try:
            cnn = httpConnection(url + a[0], proxy, agent, ignore)
            #cnn = urllib.request.urlopen()
            cnt = cnn.read()
            s[i].append(hashlib.md5(cnt).hexdigest())
            
        except URLError as e:
            #print("Error " + str(e.code) + " en: " + url + a[0])
            s[i].append(0)
                
        i = i + 1


    with open('data/version.txt', 'r') as fve:
            data = fve.read()
    
    
    #busca en el archivo version.txt la cantidad de ocurrencias de los hashs obtenidos y los agrega a "s"
    #[['/admin/environment.xml', '5880153d43cdc31d2ff81f2984b82e83', 16], ['/composer.lock', 'edb7c357a8798a545154180891215e09', 9]....
    #si existe alguno con una ocurrencia, esa es la versión, de lo contrario se almacena en "occ" el de menor ocurrencias
    f = 100
    version = 0
    occ = 100
    nada = 1
    
    for m in s:
        if m[1] != 0:
            l = re.findall(".*" + m[1] + ".*", data)
            encontrados = len(l)
            m.append(encontrados)
            if encontrados > 0:
                if encontrados == 1:
                    return printversion(l[0])
                
                if encontrados < occ:
                    occ = encontrados
                    archivo = m
                    nada = 0
    
    #se crea una lista con todas las versiones que tienen el hash encontrado con menor frecuencia en el paso anterior
    #luego se comienza a revisar cuál de esas versiones tiene la mayor cantidad de similitud con la lista inicial "s" (hashes del objetivo)
    if nada == 0:
        candidatos = re.findall(".*" + archivo[1] + ".*", data)
        
        for z in s:
            occ = 0
            for x in candidatos:		
                tmp = x.split(";")		
                if tmp[2] != z[0]:
                        c = re.findall(tmp[0] + ";" +  str(z[1]) + ".*", data)
                        if len(c) > 0:						
                            version = c[0]
                            occ = occ + 1
            
            if occ == 1:
                break
            
    else:
        version = 0

    return printversion(version)
    

    

def printversion(version):
    if version != 0:
        print ("\nVersion found via " + version.split(';')[2] + " : Moodle " +  version.split(';')[0])
        return version.split(';')[0].replace("v","")
        
    print ("\nVersion not found")
    return False
def santize(versions):
    versions=(re.split('v|\-',versions))
    for sub_ver in versions:
        if('.'in sub_ver):
            sub_ver = re.sub(r"\.0$", "", sub_ver)
            return sub_ver
#count Digit of numbers
def countDigit(n): 
    if n//10 == 0:
        return 1
    return 1 + countDigit(n // 10)
def isOlder(v1,v2):
    #return true nếu v1 is older than v2.
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    m = len(arr1)
    n = len(arr2)	
    # converts to integer from string
    try:
        arr1 = [int(i) for i in arr1]
        arr2 = [int(i) for i in arr2]
    except:
        return False
    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimiters)
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m>n:
        for i in range(n, m):
            arr1.append(0)

    for i in range(len(arr1)):
        #số chữ số nhỏ hơn thì x10 rồi sô sánh
        # if(countDigit(arr1[i])>countDigit(arr2[i])): 
        #     if(arr1[i]<arr2[i]*10):
        #         return True
        #     else: return False
        # elif (countDigit(arr1[i])<countDigit(arr2[i])):
        #     if(arr1[i]*10<arr2[i]):
        #         return True
        #     else: return False
        if arr1[i]<arr2[i]:
            return True
        elif arr1[i]>arr2[i]:
            return False
    return False
def isNewer(v1,v2):
    #return true if v1 is newer than v2.
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    m = len(arr1)
    n = len(arr2)	
    # converts to integer from string
    try:
        arr1 = [int(i) for i in arr1]
        arr2 = [int(i) for i in arr2]
    except:
        return False
    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimiters)
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m>n:
        for i in range(n, m):
            arr1.append(0)

    for i in range(len(arr1)):
        # if(countDigit(arr1[i])>countDigit(arr2[i])): 
        #     if(arr1[i]>arr2[i]*10):
        #         return True
        #     else: return False
        # elif (countDigit(arr1[i])<countDigit(arr2[i])):
        #     if(arr1[i]*10>arr2[i]):
        #         return True
        #     else: return False
        if arr1[i]>arr2[i]:
            return True
        elif arr1[i]<arr2[i]:
            return False
    return False
def equalver(v1,v2):
    #return true if v1 is the same v2.
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    m = len(arr1)
    n = len(arr2)	
    # converts to integer from string
    try:
        arr1 = [int(i) for i in arr1]
        arr2 = [int(i) for i in arr2]
    except:
        return False
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m<n:
        for i in range(m, n):
            arr1.append(0)
    for i in range(len(arr1)):
        if arr1[i]>arr2[i]:
            return False
        elif arr2[i]>arr1[i]:
            return False
    return True
def Oldest(list):
    Oldest=list[0]
    for li in list:
        if(isOlder(li,Oldest)):
            Oldest=li
    return Oldest
def printcve(cve):
    if('CVE identifier:' in cve and cve['CVE identifier:'] is not None and 'Tracker issue:' in cve and cve['Tracker issue:'] is not None):
        print(cve['CVE identifier:']+' | ' +'Moodle issue: '+cve['Tracker issue:'])

def getcve(version):
    print("\nSearching vulnerabilities...\n")
    f = open('data/cve.json','r')
    listserious=[]
    listminor=[]
    jsond = json.load(f)
    f.close()
    vercheck=santize(version) #làm sạch version dạng x.y.z
    for data in jsond:
        if('CVE identifier:' in data and data['CVE identifier:'] is not None and 'Versions affected:' in data and data['Versions affected:'] is not None and 'Severity/Risk:' in data and data['Severity/Risk:'] is not None):
            stringcheck=data['Versions affected:']
            if(vercheck in stringcheck):
                if( 'Serious' in data['Severity/Risk:']):
                    listserious.append(data)
                if( 'Minor' in data['Severity/Risk:']):
                    listminor.append(data)
                #nvul+=1
                #printcve(data)
                continue
            templist=[]
            affecteds=(re.split('and|\,',stringcheck)) #['4.0 to 4.0.4', ' 3.11 to 3.11.10', ' 3.9 to 3.9.17', ' ', ' earlier unsupported versions']
            for subs in affecteds:
                if('to' in subs):
                    lissub=re.split('to',subs)
                    #check(vercheck,lissub) # kiểm tra v trong lissub, gói thông tin và return luôn
                    if(equalver(vercheck,lissub[0])or equalver(vercheck,lissub[1])):
                        if( 'Serious' in data['Severity/Risk:']):
                            listserious.append(data)
                        if( 'Minor' in data['Severity/Risk:']):
                            listminor.append(data)
                        # nvul+=1
                        # printcve(data)
                        break
                    elif(isNewer(vercheck,lissub[0]) and isOlder(vercheck,lissub[1])):
                        if( 'Serious' in data['Severity/Risk:']):
                            listserious.append(data)
                        if( 'Minor' in data['Severity/Risk:']):
                            listminor.append(data)
                        # nvul+=1
                        # printcve(data)
                        break
                    for sub in lissub:
                        templist.append(sub)
                #print(templist)
                if('earlier' in subs):
                    if(isOlder(vercheck,Oldest(templist))):
                        if( 'Serious' in data['Severity/Risk:']):
                            listserious.append(data)
                        if( 'Minor' in data['Severity/Risk:']):
                            listminor.append(data)
                        # nvul+=1
                        # printcve(data)
                        break
    ser=len(listserious)
    minor=len(listminor)
    total=ser+minor
    print("\nYour Moodle version is related to " + str(total)+" CVE")
    print(str(ser)+ " CVE with Serious Risk")
    print(str(minor)+ " CVE with Minor Risk")
    print("Check information for security your Moodle version: ")
    print(109*'.')
    print("SERIOUS: \n")
    for cve in listserious:
        printcve(cve)
    print(109*'.')
    print("Minor: \n")
    for cve in listminor:
        printcve(cve)

if __name__ == "__main__":
    main()








