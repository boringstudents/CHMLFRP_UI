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


