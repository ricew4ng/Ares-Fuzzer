import requests

url = 'http://localhost:89/sqli_labs/Less-2/?id=1'

postdata = "uname=1&passwd=2&submit=Submit"

req = requests.post(url=url,data=postdata)

with open("test.html","w") as file:
	file.write(req.text)