# **CUL-CHMLFRP启动器**
### 基于PyQt6开发的chmlfrp的第三方启动器图形化客户端

CUL原名CHMLFRP_UI

CUL顾名思义为CHMLFRP-UI-Launcher

下载地址: 蓝奏云：[https://cul.lanzoul.com/b00pzv3oyj](https://cul.lanzoul.com/b00pzv3oyj) 密码:ff50

下载解压运行即可(仅支持win10以上版本)，如有bug请提出谢谢!

肯定没bug，有的话找吃了

# **flag**

| 序号 | 内容 |
| ------- | ------- |
| 1 | 将ip工具和ping工具合并为“百宝箱”并加入dns防污染和ddns |
| 2 | 加入模版管理模块 |
| 3 | 远程github DNS防污染 |
| 5 | 可能的更新检测 |
| 5 | 可能的web管理端 |

**模版管理模块**

| 序号 | 内容 |
| ------- | ------- |
| 1 | 隧道添加模版
| 2 | 隧道编辑
| 3 | 隧道启动备用节点模版
| 4 | 隧道启动备用节点+自动解析切换模版
| 5 | 节点备用模版
| 6 | 域名添加模版

---

## 相关链接
[https://cpl.chmlfrp.com](https://cpl.chmlfrp.com)  #千依🅥的cpl

[https://xcl.chmlfrp.com](https://xcl.chmlfrp.com)  #枫相的xcl2

[https://cul.chmlfrp.com](https://cul.chmlfrp.com)  #我的a

[https://github.com/TechCat-Team/ChmlFrp-Frp](https://github.com/TechCat-Team/ChmlFrp-Frp)  #chmlfrp官方魔改的frpc

---

## **以下为chmlfrp的api文档**
### ChmlFrp-v3控制面板链接：[http://v3.chmlfrp.com](http://v3.chmlfrp.com)

开源链接：[https://github.com/TechCat-Team/ChmlFrp-Panel-v3](https://github.com/TechCat-Team/ChmlFrp-Panel-v3)

更多TechCat开源代码请前往：[https://github.com/orgs/TechCat-Team](https://github.com/orgs/TechCat-Team)

---

## api文档链接
这是群友的api文档[https://docs.apiv1.chmlfrp.com](https://docs.apiv1.chmlfrp.com)

这是官方api v2文档[https://docs.apiv2.chmlfrp.com](https://docs.apiv2.chmlfrp.com)

## chmlfrp官方bug链接
[http://bug.chmlfrp.com](http://bug.chmlfrp.com)

---
dns防污染（测试代码）
```
import dns.resolver
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# 定义DNS服务器列表
dns_servers = [
    "1.1.1.1",  # Cloudflare DNS
    "1.0.0.1",  # Cloudflare DNS
    "8.8.8.8",  # Google Public DNS
    "8.8.4.4",  # Google Public DNS
    "9.9.9.9",  # Quad9 DNS
    "149.112.112.112",  # Quad9 DNS
    "94.140.14.14",  # AdGuard DNS
    "94.140.15.15",  # AdGuard DNS
    "77.88.8.8",  # Yandex DNS
    "77.88.8.1",  # Yandex DNS
    "223.5.5.5",  # 阿里 DNS
    "223.6.6.6",  # 阿里 DNS
    "119.29.29.29",  # 腾讯DNS
    "183.254.116.116",  # 腾讯DNS
    "180.76.76.76",  # 百度DNS
    "114.114.114.114",  # 114DNS
    "210.2.4.8",  # CNNIC
    "117.50.10.10",  # OneDNS
    "52.80.52.52",  # OneDNS
    "218.30.118.6",  # 360 安全DNS
    "123.125.81.6",  # 360 安全DNS
    "140.207.198.6",  # 360 安全DNS
    "101.226.4.6",  # 360 安全DNS
    "210.2.4.8",  # 中国互联网中心dns
    "218.30.118.6",  # dns派
]

# 定义需要更新的域名列表
domains = [
    "github.com",
    "api.github.com",
    "githubstatus.com",
    "gist.github.com",
    "vscode-auth.github.com",
]

# 定义DNS查询函数
def query_dns(domain, dns_server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    resolver.timeout = 1
    resolver.lifetime = 1

    try:
        answers = resolver.resolve(domain, "A")
        return [ip.address for ip in answers]
    except Exception as e:
        return []

# 定义IP连通性测试函数（使用TCP连接测试）
def test_tcp_connectivity(ip, port=443, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except socket.error as e:
        return False

# 更新hosts文件
def update_hosts_file(domain, ips):
    hosts_path = "/etc/hosts" if sys.platform != "win32" else "C:\\Windows\\System32\\drivers\\etc\\hosts"
    try:
        with open(hosts_path, "r+", encoding="utf-8") as hosts_file:
            lines = hosts_file.readlines()
            hosts_file.seek(0)
            hosts_file.truncate()

            # 移除旧的域名记录
            new_lines = []
            for line in lines:
                if domain not in line:
                    new_lines.append(line)
            
            # 添加新的IP记录
            for ip in ips:
                new_lines.append(f"{ip} {domain}\n")
            
            hosts_file.writelines(new_lines)
    except Exception as e:
        print(f"更新 hosts 文件失败：{e}")

def process_domain(domain):
    all_ips = set()
    
    # 获取所有IP地址
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(query_dns, domain, server) for server in dns_servers]
        for future in futures:
            ips = future.result()
            all_ips.update(ips)
    
    # 测试每个IP的连通性
    sorted_ips = sorted(all_ips)
    working_ips = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_tcp_connectivity, ip) for ip in sorted_ips]
        for ip, future in zip(sorted_ips, futures):
            result = future.result()
            if result:
                working_ips.append(ip)
    
    # 更新 hosts 文件
    update_hosts_file(domain, working_ips)


def start():
    for domain in domains:
        process_domain(domain)

if __name__ == "__main__":
    ci = 0
    while True:
        ci += 1
        start()
        print(f"次数: {ci}")
        print("----------------------")
        time.sleep(50)


```

## 开源致谢

本项目使用了以下第三方开源库，特此声明致谢：

### 核心依赖
| 库名称 | 协议 | 项目链接 | 备注 |
|--------|------|----------|------|
| **[PyQt6](https://www.riverbankcomputing.com/software/pyqt/)** | [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) | `Riverbank Computing` | GUI 框架<br>UI库 |
| **[psutil](https://github.com/giampaolo/psutil)** | [BSD-3-Clause](https://opensource.org/licenses/BSD-3-Clause) | `Giampaolo Rodola` | 系统监控工具 |
| **[requests](https://requests.readthedocs.io/)** | [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) | `Python Software Foundation` | HTTP 请求库 |
| **[mcstatus](https://github.com/py-mine/mcstatus)** | [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) | `py-mine` | Minecraft 服务器状态查询 |
| **[pyperclip](https://github.com/asweigart/pyperclip)** | [BSD-3-Clause](https://opensource.org/licenses/BSD-3-Clause) | `Al Sweigart` | 剪贴板操作库 |

### Windows 扩展
| 库名称 | 协议 | 项目链接 |
|--------|------|----------|
| **[pywin32](https://github.com/mhammond/pywin32)** | [Python Software Foundation License](https://docs.python.org/3/license.html) | `Mark Hammond` | 
| **[win32security](https://pypi.org/project/pywin32/)** | (同上) | (同上) |

---
