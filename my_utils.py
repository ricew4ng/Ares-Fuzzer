#coding:utf8

'''
各种工具函数
'''

def load_vector(target_file):
	'''
	TODO: 从文件中载入指定攻击向量
	输入：string => target_file
	输出：list  => string list[x]
	'''
	vectors = []
	with open( target_file, 'r', encoding="utf8" ) as file:
		for line in file:	
			vectors.append( line.replace("\n","") )
	return vectors

def analyze_url(url):
	'''
	TODO: 将url解析成 base_url(无查询字符串,问号)，list(查询字符串中的键=值)
	输入: string => url
	输出: string => base_url; list => query_list | [ "key=value",... ]
	'''
	tmp = url.split("#")[0].split("?")
	base_url = tmp[0]
	
	if len(tmp) ==  2: # 正常情况下，比如有查询字符串
		query_list = tmp[1].split("&") # 获取查询字符串中的键值对
		# query_list = [ s.split("=") for s in query_string ]
	elif len(tmp) == 1: # 没有查询字符串的情况下
		query_list = []
	else:
		exit(0)
	return base_url, query_list
	
	
def form_dict(target_dict):
	'''
	TODO: 将字典类型的data/headers值转换成常规字符串类型
	输入: dict => {"key":"value","key2":"value2",...}
	输出: string => "key=value&key2=value2&..."
	'''
	r = []
	for kv in target_dict.items():
		r.append( "=".join(kv) )
	
	return "&".join(r)