# masscan 端口扫描，进行http服务探测后,用nmap进行服务识别

import argparse
import json
import os
import re
import threading
import requests
import warnings
warnings.filterwarnings("ignore")
threadLock = threading.Lock()

otherports = []
httpPorts = []

def findhttp(ip,port):
    try:
        url = f'http://{ip}:'+ port
        resp=requests.get(url=url,timeout=3)
        resp.encoding = resp.apparent_encoding  #猜测响应编码
        service = 'http'
    except Exception as e:
        try:
            # threadLock.acquire()
            # print(e)
            # threadLock.release()
            url = f'https://{ip}:' + port
            resp=requests.get(url=url,timeout=3,verify=False)
            resp.encoding = resp.apparent_encoding
            service = 'https'
        except:
            threadLock.acquire()
            print(port,'有待nmap测试')
            otherports.append(port)
            threadLock.release()
            return
    try:
        server = resp.headers["server"]
    except :
        server = "未知"
    title = re.findall("<title>(.*?)</title>",resp.text,re.S)

    threadLock.acquire()

    if title == None or len(title) == 0 :
        t = ''
    else:
        t = title[0]
    # httpPorts.append(port+"/tcp"+'  '+"open"+" "+service+"\t"+server+'\t'+t)
    httpPorts.append([str(port)+'/tcp','open',service,server,t])
    threadLock.release()


def getnmap(ip):
    with open(f'nmap-{ip}.txt') as f:
        result = f.read()

    tmp1 = re.findall("VERSION(.*?)[s/S]ervice ",result,re.S)
    c = tmp1[0].split('\n')
    d = c[1:len(c)-1]

    if len(d) >= 3 and d[-2] == '':
        d = d[:-2]

    return d


# http 服务加上nmap格式化输出
def fmprint(d):

    plen = 0
    serlen = 0
    f = []

    for i in d:
        e = re.split(r'[ ]+',i) + ['']
        f.append(e)

    for f1 in f:
        if len(f1[0]) > plen:
            plen = len(f1[0])
        if len(f1[2]) > serlen:
            serlen = len(f1[2])


    print(f"PORT{' '*(plen-4)} STATE SERVICE{' '*(serlen-7)} VERSION")

    # 打印nmap扫描服务
    for r1 in d:
        print(r1)

    # 格式化打印http服务
    if len(httpPorts) != 0:


        for r1 in httpPorts:
            print(f"{r1[0]+' '*(plen-len(r1[0]))} {r1[1]}  {r1[2]+' '*(serlen-len(r1[2]))} {' '.join(r1[3:])}")


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument('ip', type=str, help='IP 地址')
    parse.add_argument('--rate', type=str,default='100', help='发包速率')
    parse.add_argument('-p', type=str,default='1-65535', help='扫描端口')
    args = parse.parse_args()


    ip = args.ip

    # ip = '183.230.169.240'

    masscan = f'./masscan {ip} -p{args.p} -oJ mascan-{ip}.json --rate={args.rate}'
    print(masscan)
    os.system(masscan)
    with open(f'mascan-{ip}.json') as f:
        a = f.read()

    try:
        j = json.loads(a)
    except:
        print(f"{ip} 未发现开放端口")
        return

    ports = []
    for i in j :
        port = i["ports"][0]["port"]
        ports.append(str(port))



    print("正在进行http服务探测")
    th = [threading.Thread(target=findhttp, args=(ip,ports[i],)) for i in range(len(ports)) ]

    for t in th:
        t.start()

    for t in th:
        t.join()

    print()


    # 判断是否全是http服务端口，若全是就不进行nmap扫描
    if len(otherports) == 0 :
        print(f'已完成对ip（{ip}）端口扫描,扫描端口：{args.p}\n')
        for r1 in httpPorts:
            print('  '.join(r1))

    else:
        otherport = ','.join(otherports)
        # print(otherports,otherport)

        print('正在使用nmap进行服务探测')
        nmap = f'nmap -sV -p {otherport} -v -Pn {ip} -oN nmap-{ip}.txt'
        print(nmap)
        os.system(nmap)

        print()
        print(f'已完成对ip（{ip}）端口扫描,扫描端口：{args.p}\n')
        fmprint(getnmap(ip))  #格式化打印输出



if __name__ == "__main__":
    main()