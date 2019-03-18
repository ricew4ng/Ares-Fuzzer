#coding:utf8

from class_fuzzer import Fuzzer

if __name__ == '__main__':
	url = 'http://localhost:89/sqli_labs/Less-16/'
	
	postdata = {
		'uname'	:	'1',
		'passwd'	:	'2',
		'submit'	:	'Submit'
	}
	
	Fuzzer(url=url,headers={}).fuzz_sql(method='p',postdata=postdata,threshold=20)
	