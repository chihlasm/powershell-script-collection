##Download the installer files from our blob

New-Item -Path 'C:\compuvision\installers\apps' -ItemType Directory

## wget "https://cvsnerdio.blob.core.windows.net/cvsapps/cloudlens.exe?sp=r&st=2022-06-22T18:34:44Z&se=2030-08-17T02:34:44Z&spr=https&sv=2021-06-08&sr=b&sig=oH%2BfyAhzdZs3JtR1tOtgFuQ8Vdog2dHdD66RrFVh1a4%3D" -O "C:\CompuVision\Installers\Apps\cloudlens.exe"

wget "https://cvsnerdio.blob.core.windows.net/cvsapps/KcsSetup.exe?sp=r&st=2022-06-22T18:35:24Z&se=2030-03-07T03:35:24Z&spr=https&sv=2021-06-08&sr=b&sig=spbTC5bWo8nCYOsW8ypI5IDK98N5QEe5y7JNYjjvRKY%3D" -O "C:\CompuVision\Installers\Apps\KcsSetup.exe"

wget "https://cvsnerdio.blob.core.windows.net/cvsapps/CSInstall.exe?sp=r&st=2024-06-21T15:08:20Z&se=2029-03-02T00:08:20Z&spr=https&sv=2022-11-02&sr=b&sig=Vx3uqUZFyapR%2FyIeni%2FtrJC0o6BKPFYMe%2FP7L3fSUdw%3D" -O "C:\CompuVision\Installers\Apps\CSInstall.exe"


##Install CVS Tools

C:\CompuVision\Installers\Apps\CSInstall.exe /install /quiet /norestart CID=E4AB44F3794848A2AEBD069F365FE0FD-0D VDI=1

C:\CompuVision\Installers\Apps\KcsSetup.exe /s /g=hci-ventures.avd

## C:\CompuVision\Installers\Apps\cloudlens.exe /install /quiet Server="ixia.compuvision.biz" Project_Key="#PKEY#" SSL_Verify="no" Auto_Update="yes" -Wait

Start-Sleep -Seconds 120

## Add-Content C:\ProgramData\CloudLens\Config\agent.yml "custom:"
## Start-Sleep -Seconds 5
## Add-Content C:\ProgramData\CloudLens\Config\agent.yml '  role: azure'
## Start-Sleep -Seconds 5
## restart-service -name CloudLens



