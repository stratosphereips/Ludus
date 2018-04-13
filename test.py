import subprocess
print(subprocess.Popen("ps | grep haas_proxy", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate())