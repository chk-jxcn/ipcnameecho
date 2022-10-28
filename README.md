# ipcnameecho

A tool to access domain or private IP of customer with our certificate, then https could apply.
For example, there is a server at 192.168.1.1, but how could I access it from Teams web APP?

My answer is use the domain/IP map and wildcard-cert.
deploy a wildcard-cert, *.alias.example.com, and use the domain/IP map to access it.

Step:
1. convert private IP to domain, 192.168.1.1 -> ip-192-168-1-1.alias.example.com
2. access https://ip-192-168-1-1.alias.example.com

Or if customer got a public domain xxx.com
1. convert domain to our domain xxx.com -> cname-xxx-dcom.alias.example.com
2. access https://cname-xxx-dcom.alias.example.com

## Setup

insert it after template
```
ipcnameecho:github.com/chk-jxcn/ipcnameecho
```

config
```
   ipcnameecho {
       alias.example.com
   }
```

request
```
ip-192-168-1-1.alias.example.com  -> A 192.168.1.1
cname-google-dcom.alias.example.com -> CNAME google.com (-d replace with ., -- replace with -)
```

limit
1. Not support AAAA or any other type of query
2. Not support private domain, which resolve in local network.
