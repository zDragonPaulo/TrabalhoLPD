#python
import os
status = "ligado"
ip_target = input('Insert the IP:\n')
response = os.popen('ping -c 1 ' + ip_target )

for line in response.readlines():
    if '100' in line:
        status = "desligado"
    print(line)
print(status)

