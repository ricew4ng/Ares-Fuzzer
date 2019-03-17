#coding:utf8

from class_fuzzer import Fuzzer

if __name__ == '__main__':
	Fuzzer(
	url='http://localhost:89/dvwa/vulnerabilities/sqli/?Submit=Submit&id=1',
	headers={
		"Cookie"	:	"security=low; Idea-f3d5ea42=0412e530-e09a-49d5-b3a7-6f2a5574d661; ECS[visit_times]=4; Phpstorm-cdc2401e=d6fefbb2-7a00-45d4-ae49-d771d69dce72; UM_distinctid=1660587f81d46f-061d9a2ec59df38-4c312878-144000-1660587f8211b2; CNZZDATA1263804910=441307823-1537689259-null%7C1537707039; bdshare_firstime=1537795245207; goods[cart]=180930181554100529; Hm_lvt_f6f37dc3416ca514857b78d0b158037e=1543741761,1543845471,1545125243; PHPSESSID=h97tpuh0hdq0fsv62qf8i1udb2"
		}
	).fuzz()