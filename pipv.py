# 升级 pip
# python.exe -m pip install --upgrade pip

# 安装包
# pip install win32process

# 查看包
# pip show Nuitka

# 卸载包
# pip uninstall logging

# 镜像源
# 清华大学 https://pypi.tuna.tsinghua.edu.cn/simple/
# 阿里云 http://mirrors.aliyun.com/pypi/simple/
# 中国科技大学 https://pypi.mirrors.ustc.edu.cn/simple/
# 中国科学技术大学 http://pypi.mirrors.ustc.edu.cn/simple/

# import win32security
# import win32api
# import win32con
# import win32process
#
#
# def elevate_privileges():
#     try:
#         current_process = win32api.GetCurrentProcess()
#         token = win32security.OpenProcessToken(current_process, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
#
#         privilege_id = win32security.LookupPrivilegeValue(None, win32con.SE_DEBUG_NAME)
#
#         new_privileges = [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
#         win32security.AdjustTokenPrivileges(token, False, new_privileges)
#
#         return True
#     except Exception as e:
#         print(f"提升权限时出错: {e}")
#         return False
#
#
# # 使用示例
# if __name__ == "__main__":
#     if elevate_privileges():
#         print("成功提升权限")
#         # 在这里添加需要管理员权限的代码
#     else:
#         print("提升权限失败")
