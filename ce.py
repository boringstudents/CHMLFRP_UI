url = f"http://cf-v2.uapis.cn/userinfo"
headers = get_headers()
params = {
    "token": token
}
response = requests.get(url, params=params, headers=headers)
data = response.json()