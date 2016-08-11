#!/usr/bin/python
#coding:utf-8
#不要出现非英文文字和符合，burp会异常，切记！！！注释除外

import hashlib
import urllib
import urlparse
import collections
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


class Sign_calculater():
    def __init__(self):
        # del para that not need
        self.exclude_para_list = ['sign','sign_type','access_token','_'] #指定需要排除的参数名
        # how to sort
        self.need_sort = True
        self.sort_by_key = True
        self.reverse_or_not = False
        # secret key
        self.secret_key_str = "ojxdpHu7dhdljaUw1ubf"#"ojxdpHu7dhdljaUw1ubf"
        #self.secret_key_str = "520f51f92694446c95a2124c1deb416a"  # ks=*Photos$@w7c  注意包含连接符
        self.connector = ":"
        self.add_to_end = True

    def sort(self, para_dict): #这里传入的para_dict是 collections中的有序字典。
        # 排除不需要的参数
        para_dict_copy = para_dict.copy()
        for item in para_dict_copy.iteritems():
            if item[0] in self.exclude_para_list:
                del(para_dict[item[0]])
        #print u"待签名参数列表： %s\n\r" %para_dict #这个语句导致了burp调用异常，不能出现u和中午，以后尽量使用英文
        print "Para list that need to sign:\n %s\n\r" %para_dict #在burp的输出中，输出顺序和实际顺序恰好相反

        # 排序
        if self.need_sort is True:
            if self.sort_by_key is True and self.reverse_or_not is False:
                sorted_para_dic = sorted(para_dict.items(), key=lambda d:d[0], reverse=False)
            if self.sort_by_key is True and self.reverse_or_not is True:
                sorted_para_dic = sorted(para_dict.items(), key=lambda d:d[0], reverse=True)
            if self.sort_by_key is False and self.reverse_or_not is False:
                sorted_para_dic = sorted(para_dict.items(), key=lambda d:d[1], reverse=False)
            if self.sort_by_key is False and self.reverse_or_not is True:
                sorted_para_dic = sorted(para_dict.items(), key=lambda d:d[1], reverse=True)
        else:
            sorted_para_dic = para_dict
        print "sorted para list that need to sign:\n %s\n\r" %sorted_para_dic

        # 重新拼接
        list_str = []
        for item in sorted_para_dic:
            #print item #item是元组对象
            c_item = '='.join(item) # join的参数应该是list的，原来元组也可以，不过，本来他们就是类似的。
            list_str.append(c_item)
        sorted_str = "&".join(list_str)
        sorted_str = urllib.unquote(sorted_str)#url编码的解码,是否需要解密也要看具体算法


        if self.add_to_end is True:
            sorted_str = sorted_str+self.connector+self.secret_key_str
            sorted_str = urllib.unquote(sorted_str)#url编码的解码,是否需要解密也要看具体算法
        print "sorted string:\n\r%s\n\r" %sorted_str

        # 加密计算
        m = hashlib.md5()
        m.update(sorted_str)
        return m.hexdigest()


if __name__ == "__main__":
    while True:
        p_sort = Sign_calculater()
        r_input = raw_input("please input:")
        # url_str = urllib.unquote(r_input)
        if "?" in r_input:
            url_para = urlparse.urlparse(r_input).query
        else:
            url_para = r_input
        lists = url_para.split('&')
        print lists
        para_dic = collections.OrderedDict()
        for item in lists:
            print item
            if '=' not in item or item == '':
                print "No \'=\' in %s or it's null" %item
            else:
                para_dic[item.split('=')[0]] = item.split('=')[1]
        print "para_dic %s" %para_dic
        print p_sort.sort(para_dic)
