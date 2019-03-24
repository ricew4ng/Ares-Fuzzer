#coding:utf8


import requests
import time
from my_utils import *  # Fuzzer类依赖于my_utils的方法 


class Fuzzer():
	def __init__(self, url ):
		self.url = url
		
	def start_fuzz(self):
		'''
		TODO: 对输入url做GET型的，各种漏洞检测
		'''
		print("[*] start fuzzing...")