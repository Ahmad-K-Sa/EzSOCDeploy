:: Enable Windows Defender Network Protection
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled


:: Enable Firewall Logging
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable


:: Enable Defender exploit system-wide protection
:: The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
:: powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG

powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError

powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart


powershell.exe Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile ProcessMitigation.xml
powershell.exe Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml
del ProcessMitigation.xml

:: Enforce the Administrator role for adding printer drivers. This is a frequent exploit attack vector. 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
:: Enforces the Administrator role for removing and formatting removable NTFS drives
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD /t REG_DWORD /d 0 /f
:: Forces Installer to NOT use elevated privileges during installs by default, which prevents escalation of privileges vulnerabilities and attacks
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
:: Disable storing password in memory in cleartext
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
:: Set the IGMPLevel key only if you don't need local or network printers on a LAN. To reset, set to 2. 
:: It is a valuable setting for stand-alone machines which mostly use cloud services and do not need to work with other machines in a LAN.
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
:: the next setting could impact RDP connections to desktops from other domain users and machines. Enable it in environments where you don't use RDP to internal user machines or you don't allow users to share folders on their machines. 
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f
:: THIS BREAKS RDP (outgoing to other domain machines) & SHARES
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
:: 5 in the next setting could impact share access. Comment it / edit registry if you see any impact. 
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f
:: https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
:: https://en.hackndo.com/pass-the-hash/
:: Affects Windows Remoting (WinRM) deployments
:: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
:: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f

:: Prevent guest logons to SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

:: Enforce NTLMv2 and LM authentication
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
::
:: Prevent unencrypted passwords being sent to third-party SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

:: Prevent (remote) DLL Hijacking
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f

:: Enable Windows Firewall and configure some advanced options
:: Block Win32/64 binaries (LOLBins) from making net connections when they shouldn't
:: ---------------------
netsh Advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh Advfirewall set allprofiles state on
::
:: Disable TCP timestamps
netsh int tcp set global timestamps=disabled
::
:: Enable Firewall Logging
:: ---------------------
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable

::Disable AutoRun
:: ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f


:: Biometrics
:: Enable anti-spoofing for facial recognition
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
:: Disable other camera use while screen is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
:: Prevent Windows app voice activation while locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
:: Prevent Windows app voice activation entirely (be mindful of those with accesibility needs)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
