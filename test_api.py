import requests
#
# url = "http://127.0.0.1:5000"
#
# body = {
#     "email": "test@test.com",
#     "password": "123456"
# }
#
# response = requests.post(url + "/register", json=body)
#
# print(response.status_code)
# print(response.text)

response = requests.get()
print(response.text)
