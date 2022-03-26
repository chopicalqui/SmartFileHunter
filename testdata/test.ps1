$pass=ConvertTo-SecureString "s3cur1ty" -AsPlainText -Force
$cred=New-Object System.Management.Automation.PSCredential("red\mquimby", $pass)
Invoke-Command -ComputerName sql01.red.local -ScriptBlock { hostname; whoami } -Credential $cred
