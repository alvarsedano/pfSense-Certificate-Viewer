

Duplicated Serial Numbers (per CA)

sIssuer|SerialNumber|FriendlyName|DnsNameList|sSubject|revokedOn
-------|------------|------------|-----------|--------|---------
internal-ca|2F|hsanchez|{hsanchez}|hsanchez|
internal-ca|2F|city1|{city1}|city1|{revocados}
internal-ca|30|audit03|{audit03}|audit03|{revocados}
internal-ca|30|uaIntro|{uaIntro}|uaIntro|
internal-ca|31|city04|{city04}|city04|
internal-ca|31|uaDevice(2)|{uaDevice}|uaDevice|
internal-ca|32|fperez|{fperez}|fperez|
internal-ca|32|uaExit(2)|{uaExit}|uaExit|

This is the last part of the result returned by the script: It shows duplicated SerialNumbers 2F, 30, 31 and 32
To avoid issues when some of this certs is revoked, you must revoked all them, and recreate new certs forevery user involved.

As example: The execution result shows that the "city1" and "audit03" certs are revoked in the "revocados" CRL.
But due to the duplicity of SerialNumbers, the openVPN tunnel that uses "revocados" as CRL also will consider revoked
the certs "hsanchez" and "uaIntro".

every item of $listaC has these attributes:
```powershell
$listaC[56]
```
Property|Value
--------|-----
EnhancedKeyUsageList|{Client Authentication (1.3.6.1.5.5.7.3.2)}
DnsNameList|{uaDedicated01}
SendAsTrustedIssuer|False
Archived|False
Extensions|{System.Security.Cryptography.Oid, System.Security.Cryptography.Oid, System.Security.Cryptography.Oid, System.Security.Cryptography.Oid...}
FriendlyName|uaDedicated01(02)
IssuerName|System.Security.Cryptography.X509Certificates.X500DistinguishedName
NotAfter|12/07/2020 14:10:54
NotBefore|13/07/2018 14:10:54
HasPrivateKey|False <-- NOT IMPORTED BY THIS POWERSHELL SCRIPT
PrivateKey| 
PublicKey|System.Security.Cryptography.X509Certificates.PublicKey
RawData|{18, ...}
SerialNumber|3F
SubjectName|System.Security.Cryptography.X509Certificates.X500DistinguishedName
SignatureAlgorithm|System.Security.Cryptography.Oid
Thumbprint|4AD2BBE653414EE1A10E01FB3D26F62D003B52C7
Version|3
Handle|2788955271140
Issuer|CN=internal-ca, E=mail@mycompany.com, O=MYCOMP, L=myCity, S=myCity, C=ES
Subject|CN=uaDedicated01, E=mail@mycompany.com, O=MYCOMP, L=myCity, S=myCity, C=ES
IsCA|False
IsServer|False
IsClient|True
sIssuer|internal-ca
sSubject|uaDedicated01
refid|5b85b04689ad1
isRevoked|True
revokedOn|{revocados, revCAcert}

---
You can show certs that will expire in the next 90 days
```powershell
$listaC | Where-Object {$_.NotAfter -le (Get-Date).AddDays(90)} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | ft
```
---
Or the list of revoked Certs
```powershell
$listaC | Where-Object {$_.revokedOn -ne $null} | Select sIssuer, SerialNumber, FriendlyName, DnsNameList, sSubject, revokedOn | ft
```
And everything you want :)
