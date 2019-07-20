####
### Extracting pfSense Certificates (without private key)
####
# Redefine the $cfg string variable to point to a valid unencrypted pfSense Configuration XML file
# The script will return the CA, Server, User and Duplicated Serial Number Certificates
#
# Tested on PowerShell 5 and avobe
# Created by Alvaro Sedano Galindo. al_sedano@hotmail.com

Function Get-CN {
    Param([Parameter(Mandatory=$true)][string]$name)
    if($name -match "CN=([^,]*)") {
        $Matches[1] }
    else {$name}
}

Function Add-Lista {
    Param([Parameter(Mandatory=$true)][ref]$lista `
         ,[Parameter(Mandatory=$true)][ref]$obj `
         ,[Parameter(Mandatory=$true)][bool]$fromCA)

    [string]$oidCLI = '1.3.6.1.5.5.7.3.2'
    [string]$oidSRV = '1.3.6.1.5.5.7.3.1'
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$ccc = $null
    foreach($c in $obj.Value) {
        $ccc = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String($c.crt))
        $ccc.FriendlyName = "[$($c.refid)] $($c.descr.'#cdata-section')"
        $lista.Value += $ccc | Select *, @{N='IsCA';E={$fromCA}} `
                                  , @{N='IsServer';E={-not $fromCA -and $_.EnhancedKeyUsageList.ObjectId -contains $oidSRV}} `
                                  , @{N='IsClient';E={-not $fromCA -and $_.EnhancedKeyUsageList.ObjectId -contains $oidCLI}} `
                                  , @{N='sIssuer';E={Get-CN($_.Issuer)}}, @{N='sSubject';E={Get-CN($_.Subject)}}
    }
}

#
# BODY
#

#Read XML pfSense config file
[string]$cfg = "$env:USERPROFILE\Downloads\config-pfSense01.private.xml"
[xml]$aaa = Get-Content $cfg -Encoding Default

#Add CA Certificates to $listaC (WITHOUT private keys)
[array]$listaC = @()
Add-Lista -lista ([ref]$listaC) -obj ([ref]$aaa.pfsense.ca) -fromCA $true

#Add user/server certificates to $listaC (WITHOUT private keys)
Add-Lista -lista ([ref]$listaC) -obj ([ref]$aaa.pfsense.cert) -fromCA $false
#Note: User Certificates created with old pfSense versions can set the EnhancedKeyUsageList property to <empty>

Remove-Variable aaa

#List of CA Certificates
Write-Output "`nCA Certificates"
$listaC | Where-Object {$_.isCA} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject | Sort-Object -Property sIssuer, SerialNumber | ft

#List of Server Certificates
Write-Output "`nServer Certificates"
$listaC | Where-Object {$_.isServer} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject | Sort-Object -Property sIssuer, SerialNumber | ft

#List of User Certificates (not CA and not Server)
Write-Output "`nUser Certificates"
$listaC | Where-Object {-not ($_.isCA -or $_.isServer)} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject | Sort-Object -Property sIssuer, SerialNumber | ft

#List of Dupicated SerialNumbers (per CA)
Write-Output "`nDuplicated Serial Numbers (per CA)"
$listaC | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject | Group-Object -Property sIssuer, SerialNumber | Where-Object {$_.Count -gt 1} | Select -ExpandProperty Group | ft