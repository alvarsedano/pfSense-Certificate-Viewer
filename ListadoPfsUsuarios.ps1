####
### Extracting pfSense Certificates (without private key)
####
# Redefine the $cfg string variable to point to a valid non encrypted pfSense XML configuration backup file.
# You can also pass the command line FilePath parameter as path to the input XML cfg file.
# [array]$listaC = .\ListadoPfsUsuarios <path_to_uncipher_pfsense_xml_config_file.xml>
#
# The csv export file <"$($env:userprofile)\Downloads\usuariospfsense.csv"> bill by created/rewrited
# every time you exececute the script
# 
# Also, you will obtain the $listaC variable, an object plain of data about the certificates and related users.
# You can filter $listaC as you want after the first excecution.

# This script will return the CA certificates, Server certificates, User certificates (used or not used) and
# duplicated Serial Number Certificates.
#
# Tested on PowerShell 5
# Created by Alvaro Sedano Galindo. al_sedano@hotmail.com
#

#[CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false,
                        Position=0,
                        ValueFromPipeline=$true,
                        ValueFromPipelineByPropertyName=$true)]
        [Alias("File")]
        [string]$FilePath)

Add-Type -AssemblyName System.Web


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
        $objTmp = $ccc | Select *, @{N='IsCA';       E={ $fromCA }} `
                                  , @{N='IsServer';  E={ -not $fromCA -and $_.EnhancedKeyUsageList.ObjectId -contains $oidSRV }} `
                                  , @{N='IsClient';  E={ -not $fromCA -and $_.EnhancedKeyUsageList.ObjectId -contains $oidCLI }} `
                                  , @{N='sIssuer';   E={ Get-CN($_.Issuer)}}, @{N='sSubject';E={Get-CN($_.Subject) }} `
                                  , @{N='refid';     E={ $c.refid}} `
                                  , @{N='isRevoked'; E={ -not $fromCA -and $c.refid -in $revs}} `
                                  , @{N='revokedOn'; E={ [string[]]$null }} `
                                  , @{N='revDate';   E={ [string[]]$null }} `
                                  , @{N='revDateDT'; E={ [datetime]$null }} `
                                  , @{N='Udisabled'; E={ [string]$null }} `
                                  , @{N='Uexpires';  E={ [string]$null }} `
                                  , @{N='UExpiresDT';E={ [datetime]$null }} `
                                  , @{N='Usuario' ;  E={ [string]$null }} `
                                  , @{N='UGrupos' ;  E={ [string[]]$null }}


        # Revocation Lists
        if ($objTmp.isRevoked) {
            [string[]]$strRev = @()
            foreach($d in $listaR) {
                if ($d.refid -eq $c.refid) {
                    $strRev += [string]($d.listRev)
                    #$objTmp.revDate =  # No guarda array. El último revocado reescribe el anterior
                    if ($d.revDate -ne $null) {
                        $objTmp.revDateDT = [datetime]::SpecifyKind($d.revDate,'UTC').ToLocalTime()
                        #$objTmp.revDateDT = $d.revDate.ToLocalTime()
                        $objTmp.revDate = $objTmp.revDateDT.ToString('yyyy/MM/dd HH:mm:ss')
                    }
                }
            }
            $objTmp.revokedOn = $strRev
        }

        # Load User Properties
        $ndx = $listaU.name.Indexof($objTmp.sSubject)
        if ($ndx -gt -1) {
            $objTmp.Usuario = [System.Web.HttpUtility]::HtmlDecode(($listaU[$ndx]).descr.'#cdata-section')
            $objTmp.Udisabled = ($listaU[$ndx]).disabled
            [string[]]$strGrp = @()
            foreach ($grp in $listaG) {
                if ($grp.member -contains ($listaU[$ndx]).uid ) {
                    $strGrp += [string]($grp.name)
                }
            }
            $objTmp.UGrupos = $strGrp
            $objTmp.Uexpires = [string](($listaU[$ndx]).expires)
            if ($objTmp.Uexpires -ne $null -and $objTmp.Uexpires -ne '') {
                $objTmp.UexpiresDT = [datetime]::ParseExact($objTmp.Uexpires, 'MM/dd/yyyy', $null)
                $objTmp.Uexpires = $objTmp.UexpiresDT.ToString('yyyy/MM/dd')
            }
        }
        $lista.Value += $objTmp
    }
}


Function Usuarios {
    [array]$usr = $fxml.pfsense.system.user
    foreach($a in $usr) {
        if ([bool]($a.PSobject.Properties.name -match 'disabled')) {
        $a.disabled ='Disabled'
        }
    }
    $usr
}


#
# BODY
#

# Check if param 0 is assigned
if ($FilePath -eq $null -or $FilePath -eq '') {
    [string]$cfg = "$($env:UserProfile)\Downloads\mydefault_config_file.xml"
}
else {
    # Use the FilePath console input parameter
    [string]$cfg = $FilePath
}

if (-not (Test-Path -Path $cfg)) {
    Write-Host "File '$cfg' not found. Process stopped." -BackgroundColor DarkRed
    Exit 1
}

#Read XML pfSense config file
[xml]$fxml = Get-Content $cfg -Encoding Default

#Get the CRL revocation list
[DateTime]$time0 = '1970-01-01'
[array]$listaR = @()
foreach($r in $fxml.pfsense.crl) {
    $listaR += $r.cert | Select @{N='listRev';E={$r.descr.'#cdata-section'}}, caref, refid, reason, @{N='revDate';E={$time0.AddSeconds($_.revoke_time)}}
}

#UserList
[array]$listaU = $fxml.pfsense.system.user
foreach($a in $listaU) {
    if ([bool]($a.PSobject.Properties.name -match 'disabled')) {
        $a.disabled ='Disabled'
    }
}

#GroupList
[array]$listaG = $fxml.pfsense.system.group | Where-Object { $_.name -ne 'all' } | Select-Object name, member


#Add CA Certificates to $listaC (WITHOUT private keys)
[array]$listaC = @()
Add-Lista -lista ([ref]$listaC) -obj ([ref]$fxml.pfsense.ca) -fromCA $true

#Add user/server certificates to $listaC (WITHOUT private keys)
Add-Lista -lista ([ref]$listaC) -obj ([ref]$fxml.pfsense.cert) -fromCA $false
#Note: User Certificates created with old pfSense versions can set the EnhancedKeyUsageList property to <empty>

Remove-Variable fxml, r, listaR, listaU, listaG

###
### Ruta de archivo CSV destino (delimitado por punto y coma)
### (Se abre automáticamente desde Excel Español sin importar)
###
[string]$rutaExportacion = "$($env:userprofile)\Downloads\usuariospfsense.csv"

#List of CA Certificates
#Write-Output "`nCA Certificates"
#$listaC | Where-Object {$_.isCA} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject | Sort-Object -Property sIssuer, SerialNumber | ft

#List of Server Certificates
#Write-Output "`nServer Certificates"
#$listaC | Where-Object {$_.isServer} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | Sort-Object -Property sIssuer, SerialNumber | ft

#List of User Certificates (not CA and not Server)
#Write-Output "`nUser Certificates"
#$listaC | Where-Object {-not ($_.isCA -or $_.isServer)} | Select FriendlyName, revokedOn, Udisabled, Uexpires | `
#          Sort-Object -Property sIssuer, SerialNumber | ft > $($rutaExportacion)

#Export to CSV
$listaC | Where-Object {-not ($_.isCA -or $_.isServer)} | `
          Select FriendlyName, @{N='revokedOn'; E={[string]($_.revokedOn)}}, revDate, Udisabled, Uexpires, @{N='UGrupos'; E={[string]($_.UGrupos)}}, sSubject, NotBefore, NotAfter, Usuario | `
          Sort-Object -Property FriendlyName, Usuario | Export-Csv -Path $rutaExportacion -NoTypeInformation -Delimiter ';' -Encoding 'UTF8'


#List of Dupicated SerialNumbers (per CA)
#Write-Output "`nDuplicated Serial Numbers (per CA)"
#$listaC | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | Group-Object -Property sIssuer, SerialNumber | `
#          Where-Object {$_.Count -gt 1} | Select -ExpandProperty Group | ft

$listaC