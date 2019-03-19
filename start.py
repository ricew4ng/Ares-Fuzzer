#coding:utf8

from class_fuzzer import Fuzzer

if __name__ == '__main__':
	url = 'http://localhost:89/sqli_labs/Less-18/'
	
	postdata = {
		'uname'	:	'Dumb',
		'passwd'	:	'Dumb',
	}
	
	headers = {
		'User-Agent'	:	"aaa",
		"Cookie"			:	"bbb",
		"Referer"		:	"ccc"
	}
	
	Fuzzer(url=url,headers=headers).fuzz_sql(method='p',postdata=postdata,threshold=20)
	