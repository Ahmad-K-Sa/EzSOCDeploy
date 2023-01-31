# Download OSSEC package
Invoke-WebRequest -Uri "https://updates.atomicorp.com/channels/atomic/windows/ossec-agent-win32-3.7.0-24343.exe" -OutFile "ossec-hids-2.9.3.exe"

# Install OSSEC
Start-Process -FilePath "ossec-hids-2.9.3.exe" -ArgumentList '/S' -Wait

# Start the OSSEC service
Start-Service "ossecsvc"

# Define the OSSEC server IP
$osserver = "192.168.206.128"

# Write the OSSEC server IP to the client.conf file
Set-Content -Path "C:\Program Files (x86)\ossec-agent\client.conf" -Value "`n<client>`n<server>$osserver</server>`n<config-profile>IPS-HID-EDR-Firewall</config-profile>`n</client>"

# Restart the OSSEC service
Restart-Service "ossecsvc"
