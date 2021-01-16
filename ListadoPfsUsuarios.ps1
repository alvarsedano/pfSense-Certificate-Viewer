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
         ,[Parameter(Mandatory=$true)][bool]$fromCA `
         ,[Parameter(Mandatory=$false)][bool]$isOpnsense=$false)

    [string]$oidCLI = '1.3.6.1.5.5.7.3.2'
    [string]$oidSRV = '1.3.6.1.5.5.7.3.1'
    [array]$revs = $listaR | Select -ExpandProperty refid -Unique

    [System.Security.Cryptography.X509Certificates.X509Certificate2]$ccc = $null
    foreach($c in $obj.Value) {
        $ccc = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String($c.crt))
        $ccc.FriendlyName = [System.Web.HttpUtility]::HtmlDecode($c.descr.'#cdata-section')
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
            if ($isOpnsense -eq $true) {
                $objTmp.Usuario = $listaU[$ndx].descr
            }
            else {
                $objTmp.Usuario = [System.Web.HttpUtility]::HtmlDecode(($listaU[$ndx]).descr.'#cdata-section')
            }
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

Function Get-BeginEndWO {
    Param([Parameter(Mandatory=$true, Position=0)][string]$path)

    #OPNsense saves information on how to decrypt it in the xml encrypted file.
    #pfSense does'nt.

    #Check if "^Version: OPNsense" exists in the line 2
    [string[]]$text = Get-Content $path -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($text[1] -match '^Version: OPNsense') {
        [int]$start = 5
    }
    else {
        [int]$start = 1
    }

    #Remove 1st and last lines
    $text[$start..($text.Count-2)]
}

Function Decrypt {
    Param([Parameter(Mandatory=$true,Position=0)][string]$fileIn
         ,[Parameter(Mandatory=$true,Position=1)][string]$fileOut
         ,[Parameter(Mandatory=$false,Position=2)][string]$pass)

    # If $openSSL is not '', we will look for the openSSL.exe available with openVPN install.
    # You can define a value for $openSSL if you have a valid openssl executable path.
    [string]$openSSL = ''
    if ($openSSL -eq '') {
        #Look for openvpn installation
        [string]$rutaREG = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN"
        if (-not (Test-Path($rutaREG))) {
            Write-Host 'No openvpn installation found. openssl.exe is part of the openVPN installation. ' + `
                       'If you have another openssl.exe available path, you can redefine the $openSSL variable (line# 140).' -BackgroundColor DarkRed
            Exit 3
        }
        $openSSL = ((Get-ItemProperty -Path $rutaREG).exe_path).Replace("openvpn.exe", "openssl.exe")
    }

    if ($pass -eq '') {
        [System.Security.SecureString]$pwd = Read-Host "Password XML File:" -AsSecureString
        $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
    }

    & "$($openSSL)" enc -d -aes-256-cbc -in "$($fileIn)" -out "$($fileOut)" -salt -md md5 -k ''$($pass)''
}

Function Get-ConfigFile {
    Param([Parameter(Mandatory=$true,Position=0)][string]$filePath `
         ,[Parameter(Mandatory=$true,Position=1)][ref]$xml)

    if (-not (Test-Path -Path $filePath)) {
        Write-Host "File '$cfg' not found. Process stopped." -BackgroundColor DarkRed
        Exit 1
    }

    [bool]$encrypted = $false
    try {
        $xml.Value = Get-Content $filePath -Encoding UTF8
    }
    catch {
        $encrypted = $true
    }

    if ($encrypted -eq $true) {
        #Encrypted xml file
        [string[]]$cifrado = Get-BeginEndWO -path $filePath
        $f1Cin  = New-TemporaryFile
        $f1Cou  = New-TemporaryFile
        try {
            [IO.File]::WriteAllBytes($f1Cin.FullName, [System.Convert]::FromBase64String($cifrado))
            Decrypt -fileIn $f1Cin.FullName -fileOut $f1Cou.FullName

            # Check if file exists
            if (-not (Test-Path $f1Cou.FullName) -or (Get-Item $f1Cou.FullName).Length -eq 0) {
                Write-Host "Unable to decrypt file. Process stoped." -BackgroundColor DarkRed
                Exit 4
            }
            
            # File exists
            $xml.Value = Get-Content $f1Cou.FullName -Encoding UTF8
        }
        catch {
            Write-Host "Error decrypting xml file: Bad password. Process stoped." -BackgroundColor DarkRed
            Exit 5
        }
        finally {
            Remove-Item $f1Cin.FullName -Force
            Remove-Item $f1Cou.FullName -Force
        }
    }
}

Function Usuarios {
    [array]$usr = $product.system.user
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

# Look for assigned param 0
if ($FilePath -eq $null -or $FilePath -eq '') {
    [string]$cfg = "$($env:UserProfile)\Downloads\mydefault_config_file.xml"
}
else {
    # Use the FilePath console input parameter
    [string]$cfg = $FilePath
}

#Read XML pfSense config file (UTF8 Encoding)
[xml]$fxml = $null
Get-ConfigFile -filePath $cfg -xml ([ref]$fxml)

#Check for pfSense/OPNsense products
if ($fxml.ChildNodes.Count -eq 2) {
    [System.Xml.XmlElement]$product = $fxml.ChildNodes[1]
    if ($product.Name -notin ('pfsense','opnsense')) {
        Write-Host 'The xml file does not contains a pfSense or OPNsense backup. Process stoped.' -BackgroundColor DarkRed
        Exit 6
    }
}
Remove-Variable fxml -ErrorAction SilentlyContinue


#Get the CRL revocation list
[DateTime]$time0 = '1970-01-01'
[array]$listaR = @()
foreach($r in $product.crl) {
    $listaR += $r.cert | Select @{N='listRev';E={$r.descr.'#cdata-section'}}, caref, refid, reason, @{N='revDate';E={$time0.AddSeconds($_.revoke_time)}}
}

#UserList
[array]$listaU = $product.system.user
foreach($a in $listaU) {
    if ([bool]($a.PSobject.Properties.name -match 'disabled')) {
        $a.disabled ='Disabled'
    }
}

#GroupList
[array]$listaG = $product.system.group | Where-Object { $_.name -ne 'all' } | Select-Object name, member


#Add CA Certificates to $listaC (WITHOUT private keys)
[array]$listaC = @()
Add-Lista -lista ([ref]$listaC) -obj ([ref]$product.ca) -fromCA $true

#Add user/server certificates to $listaC (WITHOUT private keys)
Add-Lista -lista ([ref]$listaC) -obj ([ref]$product.cert) -fromCA $false -isOpnSense $($product.Name -eq 'opnsense')
#Note: User Certificates created with old pfSense versions can set the EnhancedKeyUsageList property to <empty>

Remove-Variable product, r, listaR, listaU, listaG -ErrorAction SilentlyContinue

###
### Ruta de archivo CSV destino (delimitado por punto y coma)
### (Se abre automáticamente desde Excel Español sin proceso de importación)
###
[string]$rutaExportacion = "$($env:userprofile)\Downloads\usuariospfsense.csv"
[char]$csvDelimiter = ';'

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
          Sort-Object -Property FriendlyName, Usuario | Export-Csv -Path $rutaExportacion -NoTypeInformation -Delimiter $csvDelimiter -Encoding 'UTF8' -ErrorAction SilentlyContinue


#List of Dupicated SerialNumbers (per CA)
#Write-Output "`nDuplicated Serial Numbers (per CA)"
#$listaC | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | Group-Object -Property sIssuer, SerialNumber | `
#          Where-Object {$_.Count -gt 1} | Select -ExpandProperty Group | ft

$listaC
