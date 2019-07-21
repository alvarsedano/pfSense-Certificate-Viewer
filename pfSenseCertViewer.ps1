####
### Extracting pfSense Certificates (without private key)
####
# Redefine the $cfg string variable to point to a valid unecripted pfSense Configuration XML file
# The script will return the CA certificates, Server certificates, User certificated (used or not used) and duplicate Serial Number Certificates
#
# Tested on PowerShell 5 and avobe
# Created by Alvaro Sedano Galindo. al_sedano@hotmail.com
#

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
    [array]$revs = $listaR | Select -ExpandProperty refid -Unique
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$ccc = $null
    foreach($c in $obj.Value) {
        $ccc = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String($c.crt))
        $ccc.FriendlyName = $c.descr.'#cdata-section'
        $objTmp = $ccc | Select *, @{N='IsCA';E={$fromCA}} `
                                  , @{N='IsServer';E={-not $fromCA -and $_.EnhancedKeyUsageList.ObjectId -contains $oidSRV}} `
                                  , @{N='IsClient';E={-not $fromCA -and $_.EnhancedKeyUsageList.ObjectId -contains $oidCLI}} `
                                  , @{N='sIssuer';E={Get-CN($_.Issuer)}}, @{N='sSubject';E={Get-CN($_.Subject)}} `
                                  , @{N='refid'; E={$c.refid}} `
                                  , @{N='isRevoked'; E={-not $fromCA -and $c.refid -in $revs}} `
                                  , @{N='revokedOn'; Expression={$null}} `

        if ($objTmp.isRevoked) {
            [string[]]$strRev = @()
            foreach($d in $listaR) {
                if ($d.refid -eq $c.refid) {
                    $strRev += [string]($d.listRev)
                }
            }
            $objTmp.revokedOn = $strRev
        }
        $lista.Value += $objTmp
    }
}


#
# BODY
#

#Read XML pfSense config file
[string]$cfg = "$env:USERPROFILE\Downloads\config-pfSense01.private.xml"
[xml]$aaa = Get-Content $cfg -Encoding Default

#Get the CRL revocation list
[DateTime]$time0 = '1970-01-01'
[array]$listaR = @()
foreach($r in $aaa.pfsense.crl) {
    $listaR += $r.cert | Select @{N='listRev';E={$r.descr.'#cdata-section'}}, caref, refid, reason, @{N='revDate';E={$time0.AddSeconds($_.revoke_time)}}
}

#Add CA Certificates to $listaC (WITHOUT private keys)
[array]$listaC = @()
Add-Lista -lista ([ref]$listaC) -obj ([ref]$aaa.pfsense.ca) -fromCA $true

#Add user/server certificates to $listaC (WITHOUT private keys)
Add-Lista -lista ([ref]$listaC) -obj ([ref]$aaa.pfsense.cert) -fromCA $false
#Note: User Certificates created with old pfSense versions can set the EnhancedKeyUsageList property to <empty>

Remove-Variable aaa, r

#List of CA Certificates
Write-Output "`nCA Certificates"
$listaC | Where-Object {$_.isCA} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject | Sort-Object -Property sIssuer, SerialNumber | ft

#List of Server Certificates
Write-Output "`nServer Certificates"
$listaC | Where-Object {$_.isServer} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | Sort-Object -Property sIssuer, SerialNumber | ft

#List of User Certificates (not CA and not Server)
Write-Output "`nUser Certificates"
$listaC | Where-Object {-not ($_.isCA -or $_.isServer)} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | Sort-Object -Property sIssuer, SerialNumber | ft

#List of Dupicated SerialNumbers (per CA)
Write-Output "`nDuplicated Serial Numbers (per CA)"
$listaC | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | Group-Object -Property sIssuer, SerialNumber | Where-Object {$_.Count -gt 1} | Select -ExpandProperty Group | ft
