#coding:utf8


import requests
import time
from my_utils import *  # Fuzzer类依赖于my_utils的方法 


class Fuzzer():
	def __init__(self, url, headers={} ):
		self.url = url
		self.headers = headers
		self.count = 0 # 设置发现的漏洞数
		
	def start_fuzz(self):
		'''
		TODO: 对输入url做GET型的，各种漏洞检测
		'''
		print("[*] start fuzzing...")
		
		self.fuzz_sql() # 测试sql注入
				
	def fuzz_sql( self, method='g', threshold=100, postdata={} ):
		'''
		TODO: SQL 注入检测，数字型，字符型，报错，盲注
		'''
		# base_url 是基准url，query_list是查询字符串用 & 切割后的数组
		base_url, query_list = analyze_url(self.url)
		
		sql_fuzz_vectors = load_vector('data/sql_fuzz.data') # 载入攻击向量
		time_based_vectors = load_vector('data/sql_fuzz_time_based.data')
		
		sleep_time = 10  # 设置时间盲注检测时间
		
		for m in method:
			if m == 'g': # GET型注入测试
				weight_length = self.pre_weight_length(self.url)  # 载入初始权重
				q_len = len(query_list)
				for i in range(q_len):
					query_string1 = "&".join(query_list[:i])+"&" if i != 0 else ""
					query_string2 = "&"+"&".join(query_list[i+1:]) if i+1 != q_len else ""
					for vector in sql_fuzz_vectors:
						query_string = "{0}{1}{2}{3}".format( query_string1, query_list[i], vector, query_string2 )
						final_url = "{0}?{1}".format(base_url, query_string)
						
						req = requests.get( final_url, headers=self.headers )
						# 测试是否存在注入
						r = self.check_sql_fuzz( req, weight_length, threshold ) 
						if r: print( "[*] Payload => {0}".format( req.url ) )
					if not self.count:
						for vector in time_based_vectors:
							query_string = "{0}{1}{2}{3}".format( query_string1, query_list[i], vector.replace("*index*", str(sleep_time) ), query_string2 )
							final_url = "{0}?{1}".format(base_url, query_string)
							try:
								req = requests.get( final_url, headers=self.headers, timeout=sleep_time-5 )
							except Exception as e:
								print("[*] Payload => {0}".format(final_url) )
			elif m == 'p':  # POST型注入
				weight_length = self.pre_weight_length(self.url, method='p', postdata=postdata)  # 载入初始权重
				
				for k,v in postdata.items():
					for vector in sql_fuzz_vectors:
						temp = v
						vector = vector.replace("%23","#")
						postdata[k]+=vector
						req = requests.post( self.url, headers=self.headers, data=postdata )
						# 测试是否存在注入
						r = self.check_sql_fuzz( req, weight_length, threshold ) 
						if r: print("[*] Payload => {0} | URL => {1}".format( form_postdata(postdata),self.url ) )
						postdata[k] = temp
					if not self.count:
						for vector in time_based_vectors:
							vector = vector.replace("%23","#").replace("*sleep_time*",str(sleep_time).replace("%20"," ") ).replace("*index*",str(3000000) )
							temp = v
							try:
								postdata[k]+=vector
								req = requests.post( self.url, headers=self.headers, data=postdata, timeout=sleep_time-5 )
							except Exception as e:
								print("[*] Payload => {0} | URL => {1}".format( form_postdata(postdata),self.url ) )
							finally:
								postdata[k] = temp
								
				test_key = ['User-Agent','Cookie','Referer']
				for k in test_key:
					for vector in sql_fuzz_vectors:
						vector = vector.replace("%23","#")
						if k in self.headers:
							temp = self.headers[k]
						else:
							self.headers[k] = ""
							temp = ""
						self.headers[k]+=vector
						
						req = requests.post( self.url, headers=self.headers, data=postdata )
						# 测试是否存在注入
						r = self.check_sql_fuzz( req, weight_length, threshold ) 
						if r: print("[*] Payload => {0} | URL => {1}".format( form_dict(self.headers), self.url ) )
						self.headers[k] = temp
						
					if not self.count:
						for vector in time_based_vectors:
							vector = vector.replace("%23","#").replace("*sleep_time*",str(sleep_time).replace("%20"," ") ).replace("*index*",str(30000000))
							if k in self.headers:
								temp = self.headers[k]
							else:
								self.headers[k] = ""
								temp = ""
							self.headers[k]+=vector
							try:
								req = requests.post( self.url, headers=self.headers, data=postdata, timeout=sleep_time-5 )
							except Exception as e:
								print("[*] Payload => {0} | URL => {1}".format( form_dict(self.headers),self.url ) )
							finally:
								self.headers[k] = temp
			
		
	def fuzz_headers( self, method='p', postdata={}, vectors=[],threshold=100  ):
		'''
		TODO: HEADERS型注入，包括USER-AGENT，REFERER，COOKIE
		'''
		test_key = ['User-Agent','Cookie','Referer']
		
		if method == 'p':
			weight_length = self.pre_weight_length(self.url, method='p', postdata=postdata)  # 载入初始权重
			for k in test_key:
				for vector in vectors[0]:
					vector = vector.replace("%23","#")
					if k in self.headers:
						temp = self.headers[k]
					else:
						self.headers[k] = ""
						temp = ""
					self.headers[k]+=vector
					req = requests.post( self.url, headers=self.headers, data=postdata )
					# 测试是否存在注入
					r = self.check_sql_fuzz( req, weight_length, threshold ) 
					if r: print("[*] Payload => {0} | URL => {1}".format( form_dict(self.headers), self.url ) )
					self.headers[k] = temp
					
				if not self.count:
					for vector in vectors[1]:
						vector = vector.replace("%23","#").replace("*index*",str(sleep_time).replace("%20"," ") )
						if k in self.headers:
							temp = self.headers[k]
						else:
							self.headers[k] = ""
							temp = ""
						try:
							self.headers[k]+=vector
							req = requests.post( self.url, headers=self.headers, data=postdata, timeout=sleep_time-5 )
						except Exception as e:
							print("[*] Payload => {0} | URL => {1}".format( form_dict(self.headers),self.url ) )
						finally:
							self.headers[k] = temp
		
	def check_sql_fuzz(self, req, weight_length, threshold=100 ):
		'''
		维护一个全局数字，每次响应加权平均，超过阈值则显示为 发现漏洞
		'''
		content_length = len( req.text )  # 粗略估计返回的页面大小
		
		if abs( content_length - weight_length ) <= threshold:
			weight_length = ( content_length + weight_length ) // 2
			r = False
		else:
			self.count+=1
			r = True
		return r
		
	def pre_weight_length(self, url, method='g', postdata={} ):
		'''
		先取得正常响应下的返回长度，以此来计算加权的值
		输入：string => url
		'''
		
		if method == 'g':
			req = requests.get( url, headers=self.headers )
		elif method == 'p':
			req = requests.post( url, headers=self.headers, data=postdata )
		return len( req.text )
		
		
	#  set方法
	
	def set_url(self, url):
		'''
		设置类的URL属性 string
		'''
		self.url = url
	def set_headers(self, headers):
		'''
		设置类的HEADERS属性 dict
		'''
		self.headers = headers
	def set_cookie(self, cookie):
		'''
		设置类的HEADERS属性 string
		'''
		self.headers["Cookie"] = cookie
	def set_threshold(self, threshold):
		'''
		设置类的THRESHOLD属性 (阈值) int
		'''
		self.threshold = threshold