# **CHMLFRP_UI**
## 基于v2 api开发的chmlfrp ui版本的客户端
下载地址: 蓝奏云：https://wwvn.lanzoul.com/b00pzv3oyj 密码:ff50

gitc：https://gitcode.com/2403_86951163/CHMLFRP_UI

github：https://github.com/boringstudents/CHMLFRP_UI

下载解压运行即可(仅支持win10以上版本)，如有bug请提出谢谢!


# **以下为chmlfrp的api文档**
## ChmlFrp-v3控制面板链接：
http://preview.panel.chmlfrp.cn
开源链接：https://github.com/TechCat-Team/ChmlFrp-Panel-v3
更多TechCat开源代码请前往：https://github.com/orgs/TechCat-Team

## api文档链接
这是群友northwind的api文档https://docs.northwind.top/#/
这是官方api v2文档https://apifox.com/apidoc/shared-24b31bd1-e48b-44ab-a486-81cf5f964422/

以下我以官方api文档真实测试出的数据
## 登录
请求方式get
请求链接http://cf-v2.uapis.cn/login
请求参数：username，password
python示例代码：
import requests
url = "http://cf-v2.uapis.cn/login?username=*****&password=*******"
payload={}
headers = {}
response = requests.request("GET", url, headers=headers, data=payload)
print(response.text)

请求成功返回：
{
    "msg": "登录成功",
    "code": 200,
    "data": {
        "id": ***,
        "username": "boring_student",
        "password": null,
        "userimg": "https://q.qlogo.cn/g?b=qq&nk=1972403603&s=100",
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

注意："password": null不管什么参数都不会返回密码永远null

请求失败返回：
一、{
    "msg": "用户不存在",
    "code": 401,
    "state": "fail"
}
二、{
    "msg": "密码错误",
    "code": 401,
    "state": "fail"
}
三、{
    "msg": "密码不符合要求，长度在6到48个字符之间，并且至少包含字母、数字和符号中的两种。",
    "code": 400,
    "state": "fail"
}
四、
## 
