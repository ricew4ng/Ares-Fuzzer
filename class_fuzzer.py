#coding:utf8

import requests
from my_utils import *  # Fuzzer类依赖于my_utils的方法 


class Fuzzer():
	def __init__(self, url, vector_path='data/sql_string.data', headers={}):
		self.url = url
		self.vector_path = vector_path
		self.headers = headers
		# 载入初始权重
		self.weight_length = self.pre_weight_length(url)
		
	def fuzz(self):
		# base_url 是基准url，query_list是查询字符串用 & 切割后的数组
		self.base_url, self.query_list = analyze_url(self.url)
		# 载入攻击向量
		self.vectors = load_vector(self.vector_path) 
		
		print("[*] PREPRARED")
		
		for i, kv in enumerate(self.query_list):
			key = kv.split("=")[0]
			query_string1 = "&".join(self.query_list[:i])+"&"
			query_string2 = "&"+"&".join(self.query_list[i+1:]) if i+1 != len(self.query_list) else ""
			for vector in self.vectors:
				vector = "=".join([key,vector])
				query_string = query_string1 + vector + query_string2
				final_url = self.base_url+'?'+query_string
				
				req = requests.get(final_url,headers=self.headers)
				self.check_response(req)
		
	def check_response(self, req, threshold=100):
		'''
		维护一个全局数字，每次响应加权平均，超过阈值则显示为 发现漏洞
		'''
		content_length = len(req.text)  # 粗略估计返回的页面大小
		
		if abs(content_length-self.weight_length) <= 100:
			self.weight_length = (content_length+self.weight_length) // 2
		else:
			print( "[!] Payload => {0}".format(req.url) )
		
		
	def pre_weight_length(self, url):
		'''
		先取得正常响应下的返回长度，以此来计算加权的值
		输入：string => url
		'''
		req = requests.get(url,headers=self.headers)
		return len(req.text)
		
	def set_url(self, url):
		'''
		设置类的URL属性
		'''
		self.url = url
	def set_headers(self, headers):
		'''
		设置类的HEADERS属性
		'''
		self.headers = headers
	def set_cookie(self, cookie):
		'''
		设置类的HEADERS属性
		'''
		self.headers["Cookie"] = cookie