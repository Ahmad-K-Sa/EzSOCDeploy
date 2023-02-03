import os
import sys

system = False
if len(sys.argv) > 1:
    if sys.argv[1] == "server":
        system  = True

if os.name == "posix" and system:
    os.system("sudo /elk/elk_stack_server.sh")

elif os.name == "posix" and not system:
    os.system("sudo /elk/elk_stack_client.sh")

elif os.name == "nt":
    os.system('powereshell -c & "./Windows Hardning rules.ps1"')

else:
    print("os cannot be detected")