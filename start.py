#coding:utf8

# from class_fuzzer import Fuzzer
from class_sql_fuzzer import SqlFuzzer

if __name__ == '__main__':
	url = 'http://localhost:89/sqli_labs/Less-18/?id=1'
	
	postdata = {
		'uname'	:	"Dumb",
		'passwd'	:	'Dumb',
	}
	
	headers = {
		'User-Agent'	:	"aaa",
		"Cookie"			:	"uname=123",
		"Referer"		:	"ccc"
	}
	
	SqlFuzzer(url).fuzz(method='h',headers=headers,postdata=postdata,threshold=50)
	