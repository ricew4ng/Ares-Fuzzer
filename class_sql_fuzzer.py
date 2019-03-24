#coding:utf8

import requests
from my_utils import *

class SqlFuzzer():
	def __init__(self, url):
		self.url = url
	
	def fuzz( self, method='g', headers={}, threshold=100, postdata=None ):
		'''
		TODO: SQL 注入检测，数字型，字符型，报错，盲注
		'''
		normal_vectors = load_vector('data/sql_fuzz.data') # 载入攻击向量
		timebased_vectors = load_vector('data/sql_fuzz_timebased.data')
		
		for m in method:
			if m == 'g': # GET型注入测试
				self.sql_fuzz_get(normal_vectors,timebased_vectors,headers=headers,threshold=threshold)
			elif m == 'p':  # POST型注入
				self.sql_fuzz_post(normal_vectors,timebased_vectors,headers=headers,postdata=postdata,threshold=threshold )
			elif m == 'h':  # HEADERS类型的注入
				self.sql_fuzz_headers(normal_vectors,timebased_vectors,headers=headers,postdata=postdata,threshold=threshold)
	
	def sql_fuzz_get(self,normal_vectors=[],timebased_vectors=[],headers={},threshold=100):
		'''
		GET类型sql注入fuzz
		'''
		weight_length = self.send_request(url=self.url,headers=headers).text.__len__()  # 载入初始权重
				
		payloads1 = self.gen_url_payload(self.url, vectors=normal_vectors)
		payloads2 = self.gen_url_payload(self.url, vectors=timebased_vectors, timebased=True)
		
		for payload in payloads1: # 检测GET型有回显注入
			req = self.send_request( payload, headers=headers )
			weight_length = self.vuln_detect( req, weight_length, threshold )
			
		for payload in payloads2: # 检测GET型无回显注入（盲注）
			req = self.send_request( payload, headers=headers, timeout=5 )
			self.vuln_detect( req, timebased=True )
	
	def sql_fuzz_post(self, normal_vectors=[], timebased_vectors=[], postdata=None, headers=None, threshold=100):
		'''
		POST型sql注入fuzz
		'''
		weight_length = self.send_request(url=self.url,headers=headers,method='p',postdata=postdata).text.__len__()  # 载入初始权重
		
		payloads1 = self.gen_dict_payload(vectors=normal_vectors)
		payloads2 = self.gen_dict_payload(vectors=timebased_vectors)
				
		for k,v in postdata.items():
			for payload in payloads1:
				postdata[k]+=payload
				
				req = self.send_request( self.url, method='p', headers=headers, postdata=postdata )
				weight_length = self.vuln_detect( req, weight_length, threshold,dict=postdata )
				
				postdata[k] = v
			for payload in payloads2:
				postdata[k]+=payload
				
				req = self.send_request( self.url, method='p', headers=headers, postdata=postdata, timeout=5 )
				self.vuln_detect( req, timebased=True,dict=postdata )
				
				postdata[k] = v
				
	def sql_fuzz_headers(self, normal_vectors=None, timebased_vectors=None, postdata=None, headers=None, threshold=100):
		'''
		HEADERS型sql注入fuzz
		'''
		
		payloads1 = self.gen_dict_payload(vectors=normal_vectors)
		payloads2 = self.gen_dict_payload(vectors=timebased_vectors)
		
		if postdata == None: # GET 类型提交
			method = 'g'
		else:  # POST类型提交
			method = 'p'
			
		weight_length = self.send_request(url=self.url,headers=headers,method=method,postdata=postdata).text.__len__()  # 载入初始权重
		
		keys = ["User-Agent","Referer","Cookie"]
				
		for key in keys:
			if key not in headers.keys():
				headers[key] = ""
				
		for k,v in headers.items():
			for payload in payloads1:
				headers[k]+=payload
				
				req = self.send_request( self.url, method=method, headers=headers, postdata=postdata )
				weight_length = self.vuln_detect( req, weight_length, threshold,dict=headers )
				
				headers[k] = v
			for payload in payloads2:
				headers[k]+=payload
				
				req = self.send_request( self.url, method=method, headers=headers, postdata=postdata, timeout=5 )
				self.vuln_detect( req, timebased=True,dict=headers )
				
				headers[k] = v
	
	def vuln_detect(self, req, weight_length=0, threshold=100, timebased=False,dict=None):
		'''
		根据send_request方法的结果检测漏洞
		'''
		if not timebased:
			content_length = req.text.__len__()
			# 每次响应取加权平均，超过阈值threshold则为 发现漏洞
			if abs( content_length - weight_length ) <= threshold:				
				weight_length = ( content_length+weight_length ) // 2
			else:
				if dict == None:
					print( "[*] Payload => {0}".format( req.url ) )
				else:
					print( "[*] Payload => {0}".format( dict2string(dict) )  )
			return weight_length
		else:
			if req[0] == True:
				s = "[*] Payload => " + req[1] + " | "
				for i in range( 2, req.__len__() ):
					s = s + dict2string(req[i]) + " | "
				print(s)
			return 0
	
	def gen_dict_payload(self, vectors, var_sleep_time="10", var_index="3000000"):
		'''
		生成dict类型SQL注入的payload
		'''
		if not len(vectors):
			print("[!] error: passing vectors failed")
			return []
		payloads = [x.replace("*sleep_time*",var_sleep_time).replace("*index*",var_index).replace("%23","#").replace("%20"," ") for x in vectors]
		
		return payloads
		
		
	def gen_url_payload(self, url, vectors, timebased=False, var_sleep_time="10", var_index="3000000"):
		'''
		生成GET类型SQL注入的payload(url)
		'''
		ret = []
		if not len(vectors):
			print("[!] error: passing vectors failed")
			return ret
		
		if timebased:  # 处理时间盲注的payload
			vectors = [x.replace("*sleep_time*", var_sleep_time).replace("*index*",var_index ) for x in vectors]
		
		# base_url 是基准url，query_list是查询字符串用 & 切割后的数组
		base_url, query_list = analyze_url(url)
		
		q_len = query_list.__len__()
		
		for i in range( q_len ):
			query_string1 = "&".join(query_list[:i])+"&" if i != 0 else ""
			query_string2 = "&"+"&".join(query_list[i+1:]) if i+1 != q_len else ""
			for vector in vectors: 
				query_string = "{0}{1}{2}{3}".format( query_string1, query_list[i], vector, query_string2 )
				url = "{0}?{1}".format(base_url, query_string)
				ret.append(url)
		
		return ret
	
	def send_request(self, url, method='g', headers={}, postdata={}, timeout=0):
		'''
		处理requests请求
		:string url
		:string method => 'g' GET类型， 'p' POST类型
		:int timeout
		:rtype requests req | list [True]=>存在盲注 [False]=>不存在
		'''
		if not timeout: # 基于时间的盲注请求
			if method == 'g':
				req = requests.get( url, headers=headers )
			elif method == 'p':
				req = requests.post( url, headers=headers, data=postdata )
			return req
		else:
			if method == 'g':
				try:
					req = requests.get( url, headers=headers, timeout=timeout )
				except:
					return  [ True, url, headers ] 
			elif method == 'p':
				try:
					req = requests.post( url, headers=headers, data=postdata, timeout=timeout )
				except:
					return [ True, url, headers, postdata ]
			return [ False, ]