import requests

status = requests.get('http://localhost:8000/status/5')
print(status.text)
