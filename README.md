# **CHMLFRP_UI**
### 基于v2 api开发的chmlfrp ui版本的客户端
下载地址: 蓝奏云：https://wwvn.lanzoul.com/b00pzv3oyj 密码:ff50

下载解压运行即可(仅支持win10以上版本)，如有bug请提出谢谢!


## **以下为chmlfrp的api文档**
### ChmlFrp-v3控制面板链接：http://preview.panel.chmlfrp.cn

开源链接：https://github.com/TechCat-Team/ChmlFrp-Panel-v3

更多TechCat开源代码请前往：https://github.com/orgs/TechCat-Team

## api文档链接
这是群友northwind的api文档https://docs.northwind.top/#/

这是官方api v2文档https://apifox.com/apidoc/shared-24b31bd1-e48b-44ab-a486-81cf5f964422/

以下我以官方api文档真实测试出的数据
## 登录
请求方式GET

请求链接http://cf-v2.uapis.cn/login

请求参数：

| username | 账号/用户名/QQ号
| ------- | ------- |
| password |    密码     |



python示例代码：

```
import requests
url = "http://cf-v2.uapis.cn/login?username=*****&password=*******"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
{
    "msg": "登录成功",
    "code": 200,
    "data": {
        "id": ***,
        "username": "boring_student",
        "password": null,
        "userimg": "https://q.qlogo.cn/g?b=qq&nk=**********&s=100",
        "qq": "**********",
        "email": "**********@qq.com",
        "usertoken": "********************",
        "usergroup": "超级会员",
        "bandwidth": 50,
        "tunnel": 16,
        "realname": "已实名",
        "login_attempts": 0,
        "integral": 15168,
        "term": "9999-09-09",
        "scgm": null,
        "regtime": "2023-08-26",
        "t_token": null,
        "realname_count": 0,
        "total_download": 150640674,
        "total_upload": 3224701,
        "tunnelCount": 2,
        "totalCurConns": 0
    },
    "state": "success"
}
```



注意："password": null不管什么参数都不会返回密码永远null

请求失败返回：

一、
```{
    "msg": "用户不存在",
    "code": 401,
    "state": "fail"
}
```
二、
```{
    "msg": "密码错误",
    "code": 401,
    "state": "fail"
}
```
三、

```
{
    "msg": "密码不符合要求，长度在6到48个字符之间，并且至少包含字母、数字和符号中的两种。",
    "code": 400,
    "state": "fail"
}
```


## 发送邮箱验证码
请求方式POST

请求链接http://cf-v2.uapis.cn/sendmailcode

请求参数：

| type | "register"为注册类型验证码, "retoken"为重置令牌验证码 |
| ------- | ------- |
| mail |    邮箱地址



python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/sendmailcode?type=retoken&mail=John@qq.com"
payload={}
headers = {}
response = requests.request("POST", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
{
    "msg": "发送成功",
    "code": 200,
    "state": "success"
}
```

请求失败返回：

```{
    "msg": "邮箱格式错误",
    "code": 400,
    "state": "fail"
}
```
## 注册
请求方式GET

请求链接http://cf-v2.uapis.cnregister

请求参数：

| username | 用户名 |
| ------- | ------- |
| password | 密码 |
| mail | 邮箱 |
| qq |  qq号  |
| code | 验证码 |

python示例代码：

```
import requests

url = "http://cf-v2.uapis.cnregister?username=John&password=123456&mail=John@qq.com&qq=123&code=666666"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
{
    "msg": "注册成功",
    "code": 200,
    "state": "success"
}
```

请求失败返回：

```
{
    "msg": "验证码错误",
    "code": 400,
    "state": "fail"
}
```
## 用户信息
请求方式GET

请求链接http://cf-v2.uapis.cn/userinfo

请求参数：

| token | 用户token |
| ------- | ------- |


python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/userinfo?token"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
{
    "msg": "请求成功",
    "code": 200,
    "data": {
        "id": ***
        "username": "boring student",
        "password": null,
        "userimg": "https://q.qlogo.cn/g?b=qq&nk=QQ号&s=100",
        "qq": "QQ号",
        "email": "QQ邮箱",
        "usertoken": "用户token",
        "usergroup": "超级会员",
        "bandwidth": 50,
        "tunnel": 16,
        "realname": "已实名",
        "login_attempts": 0,
        "integral": 15168,
        "term": "9999-09-09",
        "scgm": null,
        "regtime": "2023-08-26",
        "t_token": null,
        "realname_count": 0,
        "total_download": 150640674,
        "total_upload": 3224701,
        "tunnelCount": 2,
        "totalCurConns": 0
    },
    "state": "success"
}
```

请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 重置令牌（即用户token）
请求方式GET

请求链接http://cf-v2.uapis.cn/retoken

请求参数：

| token | 用户token |
| ------- | ------- |
| code | 邮箱验证码 |



python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/retoken?token=token1&code=666666"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
{
    "msg": "重置成功",
    "code": 200,
    "state": "success"
}
```

请求失败返回：

```
{
    "msg": "string",
    "code": 0,
    "state": "string"
}
```

## 用户签到（如果没GeeTest服务器就别想了）
请求方式POST

请求链接http://cf-v2.uapis.cn/qiandao

请求参数：

| token | 用户token |
| ------- | ------- |
| code | 邮箱验证码 |
| lot_number | GeeTest人机验证参数 |
| captcha_output | GeeTest人机验证参数 |
| pass_token | GeeTest人机验证参数 |
| gen_time | GeeTest人机验证参数 |

python示例代码：

```
import requests
import json

url = "http://cf-v2.uapis.cn/qiandao"

payload = json.dumps({
   "token": "string",
   "lot_number": "string",
   "captcha_output": "string",
   "pass_token": "string",
   "gen_time": "string"
})
headers = {
   'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
```



请求成功返回：

```
{
    "msg": "签到成功, 获得9积分",
    "code": 200,
    "state": "success"
}
```

```
{
    "msg": "请勿重复签到",
    "code": 400,
    "state": "fail"
}
```
请求失败返回：

```
{
    "msg": "string",
    "code": 0,
    "state": "string"
}
```

## 重置密码
请求方式GET

请求链接http://cf-v2.uapis.cn/reset_password

请求参数：

| original_password | 原来的密码 |
| ------- | ------- |
| new_password | 新的密码 |
| token | 用户Token |




python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/reset_password?original_password=password&new_password=new_password&token=ChmlFrpTokenPreview"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
我懒得重置密码了
{
    "code": 0,
    "state": "string",
    "msg": "string"
}
```

请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 修改用户名
请求方式GET

请求链接http://cf-v2.uapis.cnupdate_username

请求参数：

| token | 用户Token |
| ------- | ------- |
| new_username | 新用户名 |




python示例代码：

```
import requests

url = "http://cf-v2.uapis.cnupdate_username?token=ChmlFrpToken&new_username=chaoji"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
好像挂了emm...
```


请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```
## 修改QQ
请求方式GET

请求链接http://cf-v2.uapis.cn/update_qq

请求参数：

| token | 用户Token |
| ------- | ------- |
| new_qq | 新的qq |




python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/update_qq?token=ChmlFrpToken&new_qq=242247494"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
我懒，以后再补
{
    "code": 0,
    "state": "string",
    "msg": "string"
}
```


请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 重置头像
请求方式GET

请求链接http://cf-v2.uapis.cn/update_userimg

请求参数：

| token | 用户Token |
| ------- | ------- |
| new_userimg | 头像图片链接 |




python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/update_userimg?token=ChmlFrpToken&new_userimg=https://www.chmlfrp.cn/favicon.ico"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
{
    "msg": "用户头像更新成功",
    "code": 200,
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "新头像不能与当前头像相同",
    "code": 400,
    "state": "fail"
}
```

```
{
    "msg": "无效的链接",
    "code": 400,
    "state": "error"
}
```

## 隧道列表
请求方式GET

请求链接http://cf-v2.uapis.cn/tunnel

请求参数：

| token | 用户Token |
| ------- | ------- |





python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/tunnel?token=wasf21479haHWON"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
#这里按照官方要求vip节点ip不外传以***代替
{
    "msg": "获取隧道数据成功",
    "code": 200,
    "data": [
        {
            "id": 76427,
            "name": "3I40Au4X",
            "localip": "127.0.0.1",
            "type": "tcp",
            "nport": 5244,
            "dorp": "65500",
            "node": "中国香港CN2-4",
            "state": "false",
            "userid": 227,
            "encryption": "true",
            "compression": "true",
            "ap": "",
            "uptime": null,
            "client_version": "尚未启动",
            "today_traffic_in": 0,
            "today_traffic_out": 0,
            "cur_conns": 0,
            "nodestate": "offline",
            "ip": "**********"
        },
        {
            "id": 81329,
            "name": "230vZqUp",
            "localip": "127.0.0.1",
            "type": "tcp",
            "nport": 222,
            "dorp": "56078",
            "node": "日本东京直连-2",
            "state": "true",
            "userid": 227,
            "encryption": "false",
            "compression": "false",
            "ap": "",
            "uptime": "2024-12-21T01:38:19.000+00:00",
            "client_version": "尚未启动",
            "today_traffic_in": 0,
            "today_traffic_out": 0,
            "cur_conns": 0,
            "nodestate": "online",
            "ip": "*******"
        }
    ],
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 创建隧道
请求方式post

请求链接http://cf-v2.uapis.cn/create_tunnel

请求参数：


```
token 用户Token 必需
tunnelname 隧道名 必需
node 节点名 必需
localip 本地IP 可选，不传递则默认为127.0.0.1
porttype 端口类型 必需 仅允许tcp、udp、http、https，可为大写，也可大小写混用
localport 本地端口 必需
remoteport 外网端口 可选 如果porttype参数为tcp、udp，则这个字段为必须，同时禁止传递banddomain
banddomain 绑定域名 可选 如果porttype参数为http、https，则这个字段为必须，同时禁止传递remoteport
encryption 数据加密 必需 传递true或false，可为string和boolean
compression 数据压缩 必需 传递true或false，可为string和boolean
extraparams 额外参数 可选 不传递则默认为空
```

python示例代码：

```
import requests
import json

url = "http://cf-v2.uapis.cn/create_tunnel"

payload = json.dumps({
   "token": "labore ut dolore",
   "tunnelname": "志场度达到",
   "node": "anim in",
   "localip": "100.5.204.64",
   "porttype": "sint cillum Duis non reprehenderit",
   "localport": 70,
   "remoteport": 93,
   "banddomain": "u.japoen@qq.com",
   "encryption": True,
   "compression": True,
   "extraparams": "culpa commodo"
})
headers = {
   'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
```



请求成功返回：

```
{
    "msg": "隧道创建成功",
    "code": 200,
    "data": {
        "id": null,
        "name": "12424",
        "localip": "127.0.0.1",
        "type": "tcp",
        "nport": 51,
        "dorp": "36981",
        "node": "日本东京直连-2",
        "state": "false",
        "userid": 227,
        "encryption": "false",
        "compression": "false",
        "ap": "",
        "uptime": null,
        "client_version": "尚未启动",
        "today_traffic_in": 0,
        "today_traffic_out": 0,
        "cur_conns": 0,
        "nodestate": null,
        "ip": null
    },
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 删除隧道
请求方式post

请求链接http://cf-v2.uapis.cn/deletetunnel

请求参数：



| token | 用户token |
| ------- | ------- |
| tunnelid | 隧道id |


python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/deletetunnel?token=iwoa123WODshaod&tunnelid=17"
payload={}
headers = {}
response = requests.request("POST", url, headers=headers, data=payload)
print(response.text)
```



请求成功返回：

```
chaoji到现在还没修好都好几个月了(
可以去使用v1的api但是v1api可能在以后失效
```


请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 修改隧道
请求方式post

请求链接http://cf-v2.uapis.cn/update_tunnel

请求参数：



```

tunnelid  隧道ID 必需
token 用户Token 必需
tunnelname 隧道名 必需
node 节点名 必需
localip 本地IP 可选，不传递则默认为127.0.0.1
porttype 端口类型 必需 仅允许tcp、udp、http、https，可为大写，也可大小写混用
localport 本地端口 必需
remoteport 外网端口 可选 如果porttype参数为tcp、udp，则这个字段为必须，同时禁止传递banddomain
banddomain 绑定域名 可选 如果porttype参数为http、https，则这个字段为必须，同时禁止传递remoteport
encryption 数据加密 可选 传递true或false，可为string和boolean。不传递则默认为false
compression 数据压缩 可选 传递true或false，可为string和boolean。不传递则默认为false
extraparams 额外参数 可选 不传递则默认为空

```


python示例代码：

```
import requests
import json

url = "http://cf-v2.uapis.cn/update_tunnel"

payload = json.dumps({
   "tunnelid": 0,
   "token": "string",
   "tunnelname": "string",
   "node": "string",
   "localip": "string",
   "porttype": "string",
   "localport": 0,
   "remoteport": 0,
   "banddomain": "string",
   "encryption": True,
   "compression": True,
   "extraparams": "string"
})
headers = {
   'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
```



请求成功返回：

```
{
    "msg": "隧道更新成功",
    "code": 200,
    "data": {
        "id": 76427,
        "name": "string",
        "localip": "127.0.0.1",
        "type": "tcp",
        "nport": 214,
        "dorp": "54342",
        "node": "中国香港CN2-4",
        "state": "false",
        "userid": 227,
        "encryption": "true",
        "compression": "true",
        "ap": "",
        "uptime": null,
        "client_version": "尚未启动",
        "today_traffic_in": 0,
        "today_traffic_out": 0,
        "cur_conns": 0,
        "nodestate": null,
        "ip": null
    },
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 获取配置文件
请求方式GET

请求链接http://cf-v2.uapis.cn/tunnel_config

请求参数：


| token | 用户Token |
| ------- | ------- |
| node  | 节点名称 |
| tunnel_names  |要获取的隧道名，可为空，为空则输出此节点所有隧道配置文件。隧道名对应的隧道必须和节点名相同。如果要返回多个，则以","分割。|




python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/tunnel_config?token=ChmlFrpToken&node=月球CN2&tunnel_names=Tunnel1,Tunnel2"

payload={}
headers = {}

response = requests.request("GET", url, headers=headers, data=payload)

print(response.text)
```



请求成功返回：

```
{
    "msg": "配置文件获取成功",
    "code": 200,
    "data": "[common]\nserver_addr = ***.***.***.***\nserver_port = 7000\ntls_enable = false\nuser = *****************************\ntoken = ChmlFrpToken\n\n[*******]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 132\nremote_port = 49736\n\n",
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "无效的Token",
    "code": 401,
    "state": "fail"
}
```

## 节点列表
请求方式GET

请求链接http://cf-v2.uapis.cn/node

请求参数：

无




python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/node"

payload={}
headers = {}

response = requests.request("GET", url, headers=headers, data=payload)

print(response.text)
```



请求成功返回：

```
{
    "msg": "获取成功",
    "code": 200,
    "data": [
        {
            "id": 2,
            "name": "四川德阳电信",
            "area": "中国四川德阳",
            "nodegroup": "vip",
            "china": "yes",
            "web": "yes",
            "udp": "true",
            "fangyu": "true",
            "notes": "超大带宽，啥都能干"
        },
        {
            "id": 4,
            "name": "湖北十堰",
            "area": "中国湖北十堰",
            "nodegroup": "vip",
            "china": "yes",
            "web": "yes",
            "udp": "true",
            "fangyu": "true",
            "notes": "超大带宽，啥都能干"
        },
        {
            "id": 6,
            "name": "日本东京直连-2",
            "area": "日本东京",
            "nodegroup": "vip",
            "china": "no",
            "web": "yes",
            "udp": "true",
            "fangyu": "true",
            "notes": "超高带宽，干啥都行"
        },
        {
            "id": 11,
            "name": "江苏宿迁",
            "area": "江苏宿迁",
            "nodegroup": "user",
            "china": "yes",
            "web": "no",
            "udp": "true",
            "fangyu": "true",
            "notes": "推荐游戏,web,ssh等服务"
        },
        {
            "id": 16,
            "name": "湖南娄底",
            "area": "中国湖南娄底",
            "nodegroup": "user",
            "china": "yes",
            "web": "yes",
            "udp": "true",
            "fangyu": "true",
            "notes": "推荐游戏,web,ssh等服务"
        },
        {
            "id": 19,
            "name": "河北秦皇岛联通",
            "area": "河北秦皇岛",
            "nodegroup": "user",
            "china": "yes",
            "web": "no",
            "udp": "true",
            "fangyu": "true",
            "notes": "推荐大带宽类服务"
        },
        {
            "id": 30,
            "name": "美国洛杉矶-2",
            "area": "美国洛杉矶",
            "nodegroup": "vip",
            "china": "no",
            "web": "yes",
            "udp": "true",
            "fangyu": "true",
            "notes": "大带宽AS9929线路，晚高峰不卡顿"
        },
        {
            "id": 31,
            "name": "呼和浩特电信",
            "area": "中国内蒙古呼和浩特",
            "nodegroup": "user",
            "china": "yes",
            "web": "no",
            "udp": "true",
            "fangyu": "true",
            "notes": "大带宽内蒙古，稳定性未知"
        }
    ],
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "无法连接至服务器",
    "code": 404,
    "state": "fail"
}
```


## 节点详情
请求方式GET

请求链接http://cf-v2.uapis.cn/nodeinfo

请求参数：


| token | 用户Token |
| ------- | ------- |
| node  | 节点名 |





python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/nodeinfo?token&node"

payload={}
headers = {}

response = requests.request("GET", url, headers=headers, data=payload)

print(response.text)
```



请求成功返回：

```
{
    "msg": "获取成功",
    "code": 200,
    "data": {
        "udp": "true",
        "total_traffic_in": 0,
        "notes": "推荐游戏,web,ssh等服务",
        "cpu_info": "Intel(R) Xeon(R) Gold 6146 CPU @ 3.20GHz",
        "fangyu": "true",
        "rport": "10000-65535",
        "storage_total": 160801107968,
        "nodegroup": "user",
        "apitoken": "ChmlFrpToken|11",
        "web": "no",
        "ipv6": null,
        "toowhite": false,
        "uptime_seconds": 1286486,
        "id": 11,
        "state": "online",
        "bandwidth_usage_percent": 0,
        "memory_total": 16779546624,
        "nodetoken": "ChmlFrpToken",
        "load15": 0.03,
        "area": "江苏宿迁",
        "realIp": "***.***.***.**",
        "ip": "sq.frp.one",
        "num_cores": 8,
        "coordinates": "118.295113,33.946709",
        "load5": 0.02,
        "version": "ChmlFrp-0.51.2_240715",
        "load1": 0,
        "china": "yes",
        "port": 7000,
        "total_traffic_out": 0,
        "name": "江苏宿迁",
        "adminPort": 8233,
        "storage_used": 17889017856
    },
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "错误的token",
    "code": 401,
    "state": "fail"
}
```

## 节点状态
请求方式GET

请求链接http://cf-v2.uapis.cn/nodeinfo

请求参数：


无



python示例代码：

```
import requests

url = "http://cf-v2.uapis.cn/node_stats"

payload={}
headers = {}

response = requests.request("GET", url, headers=headers, data=payload)

print(response.text)
```



请求成功返回：

```
{
    "msg": "节点统计数据获取成功",
    "code": 200,
    "data": [
        {
            "total_traffic_in": 550093529,
            "total_traffic_out": 14367772669,
            "cur_counts": 54,
            "node_name": "四川德阳电信",
            "id": 2,
            "state": "online",
            "bandwidth_usage_percent": 12,
            "cpu_usage": 11.913401,
            "nodegroup": "vip",
            "client_counts": 93,
            "tunnel_counts": 190
        },
        {
            "total_traffic_in": 42756780,
            "total_traffic_out": 627716268,
            "cur_counts": 0,
            "node_name": "日本东京直连",
            "id": 3,
            "state": "offline",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 0,
            "nodegroup": "user",
            "client_counts": 0,
            "tunnel_counts": 0
        },
        {
            "total_traffic_in": 4889547522,
            "total_traffic_out": 23194219684,
            "cur_counts": 78,
            "node_name": "湖北十堰",
            "id": 4,
            "state": "online",
            "bandwidth_usage_percent": 1,
            "cpu_usage": 7.002964,
            "nodegroup": "vip",
            "client_counts": 81,
            "tunnel_counts": 206
        },
        {
            "total_traffic_in": 370133148,
            "total_traffic_out": 1806032050,
            "cur_counts": 14,
            "node_name": "日本东京直连-2",
            "id": 6,
            "state": "online",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 15.734785,
            "nodegroup": "vip",
            "client_counts": 52,
            "tunnel_counts": 166
        },
        {
            "total_traffic_in": 29645901,
            "total_traffic_out": 185976760,
            "cur_counts": 0,
            "node_name": "英国伦敦",
            "id": 8,
            "state": "offline",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 0,
            "nodegroup": "user",
            "client_counts": 0,
            "tunnel_counts": 0
        },
        {
            "total_traffic_in": 0,
            "total_traffic_out": 0,
            "cur_counts": 0,
            "node_name": "江苏宿迁",
            "id": 11,
            "state": "online",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 0.669085,
            "nodegroup": "user",
            "client_counts": 0,
            "tunnel_counts": 0
        },
        {
            "total_traffic_in": 102720193,
            "total_traffic_out": 3505114345,
            "cur_counts": 0,
            "node_name": "中国台湾",
            "id": 12,
            "state": "offline",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 0,
            "nodegroup": "user",
            "client_counts": 0,
            "tunnel_counts": 0
        },
        {
            "total_traffic_in": 3117717383,
            "total_traffic_out": 19172556232,
            "cur_counts": 133,
            "node_name": "湖南娄底",
            "id": 16,
            "state": "online",
            "bandwidth_usage_percent": 47,
            "cpu_usage": 6.482438,
            "nodegroup": "user",
            "client_counts": 422,
            "tunnel_counts": 590
        },
        {
            "total_traffic_in": 3065984513,
            "total_traffic_out": 26479783790,
            "cur_counts": 147,
            "node_name": "河北秦皇岛联通",
            "id": 19,
            "state": "online",
            "bandwidth_usage_percent": 19,
            "cpu_usage": 3.518275,
            "nodegroup": "user",
            "client_counts": 163,
            "tunnel_counts": 216
        },
        {
            "total_traffic_in": 7510489,
            "total_traffic_out": 12531460,
            "cur_counts": 0,
            "node_name": "中国香港CN2-4",
            "id": 24,
            "state": "offline",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 0,
            "nodegroup": "vip",
            "client_counts": 0,
            "tunnel_counts": 0
        },
        {
            "total_traffic_in": 6500049,
            "total_traffic_out": 136115575,
            "cur_counts": 0,
            "node_name": "浙江宁波",
            "id": 27,
            "state": "offline",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 0,
            "nodegroup": "vip",
            "client_counts": 0,
            "tunnel_counts": 0
        },
        {
            "total_traffic_in": 1108281131,
            "total_traffic_out": 1046310738,
            "cur_counts": 0,
            "node_name": "美国洛杉矶-1",
            "id": 29,
            "state": "offline",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 0,
            "nodegroup": "user",
            "client_counts": 0,
            "tunnel_counts": 0
        },
        {
            "total_traffic_in": 864098232,
            "total_traffic_out": 7786697517,
            "cur_counts": 71,
            "node_name": "美国洛杉矶-2",
            "id": 30,
            "state": "online",
            "bandwidth_usage_percent": 0,
            "cpu_usage": 1.931229,
            "nodegroup": "vip",
            "client_counts": 37,
            "tunnel_counts": 87
        },
        {
            "total_traffic_in": 275058994,
            "total_traffic_out": 765604230,
            "cur_counts": 7,
            "node_name": "呼和浩特电信",
            "id": 31,
            "state": "online",
            "bandwidth_usage_percent": 1,
            "cpu_usage": 2.929857,
            "nodegroup": "user",
            "client_counts": 10,
            "tunnel_counts": 11
        }
    ],
    "state": "success"
}
```


请求失败返回：

```
{
    "msg": "无法连接至服务器",
    "code": 404,
    "state": "fail"
}
```










