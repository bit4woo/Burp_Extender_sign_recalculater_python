#!/usr/bin/env python
#coding=utf-8
#referer https://github.com/stayliv3/burpsuite-changeU


from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse #这个接口包含了每个请求和响应的细节。在Brupsuite中的每个请求或者响应都是IHttpRequestResponse实例
from burp import IExtensionHelpers #这个接口是新加的。提供了编写扩展中常用的一些通用函数，比如编解码、构造请求等。这样就不需要重负造轮子了。
from burp import IRequestInfo
from burp import IParameter

import collections
import sys
import os


reload(sys)
sys.setdefaultencoding('utf-8')
sys.path.append(os.getcwd())
import Sign_Calculater

# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API

print 'sign calculater(python edition)-- by bit4'


class BurpExtender(IBurpExtender, IHttpListener):

    # define registerExtenderCallbacks: From IBurpExtender Interface 
    def registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks
        # obtain an extension helpers object (Burp Extensibility Feature)
        # http://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
        self._helpers = callbacks.getHelpers()
        # set our extension name that will display in Extender Tab
        self._callbacks.setExtensionName("Sign Recalculator")
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
    # define processHttpMessage: From IHttpListener Interface 
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # determine what tool we would like to pass though our extension:
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32 or toolFlag == 4: #if tool is Proxy Tab or repeater # 通过修改这里来指定该插件对哪些脚本生效 64-repeater 16-scanner
            # determine if request or response:
                if messageIsRequest:#only handle requsets

                    analyzedRequest = self._helpers.analyzeRequest(messageInfo)
                    requestMethod = analyzedRequest.getMethod()
                    request = str(messageInfo.getRequest())
                    headers = analyzedRequest.getHeaders()
                    #print headers
                    if "create_and_buy" in headers[0]:
                    #if 1 == 1:
                        #print "xxxx"
                        Para = analyzedRequest.getParameters() #这个方法无论是get还是post，都能获取到全部的参数，包括cookie。
                        #print "Para: %s" %Para  #获取到的是在缓存buf中的位置信息 就像这样burp.buf@c6bf923
                        full_para_dict = collections.OrderedDict() #有序字典
                        for item in Para: #取参数，放入字典当中
                            #print item
                            if (item.getType() == 0 and requestMethod == "GET") or (item.getType() == 1 and requestMethod == "POST"):
                                #print item.getName()
                                #print item.getValue() #经验证，获取参数只是单纯获取字符串，不会进行编码的转义。
                                full_para_dict[item.getName()] = item.getValue()
                        print "full_para_dict %s" %full_para_dict #打印出的顺序和插入顺序恰好相反

                        new = Sign_Calculater.Sign_calculater()
                        new_sign = new.sort(full_para_dict)
                        print new_sign

                        #更新参数
                        if requestMethod == "GET":
                            new_para = self._helpers.buildParameter('sign', new_sign, IParameter.PARAM_URL)
                        elif requestMethod == "POST":
                            new_para = self._helpers.buildParameter('sign', new_sign, IParameter.PARAM_BODY)
                        #IParameter.PARAM_BODY这个参数则表明是Body中的请求参数，如果是URl中的则是PARAM_URL，还有PARAM_COOKIE
                        #print "new_para:%s" %new_para

                        new_Request = self._helpers.updateParameter(messageInfo.getRequest(), new_para)
                        messageInfo.setRequest(new_Request)
                        # print "new_Request: %s" %new_Request