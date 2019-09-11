## pfSense-Certificate-Viewer
Powershell script: pfSense Certificate Viewer

Sometimes it happens in pfSense that certificates are created with
duplicated SerialNumbers (in the same CAroot). If any of these certificates
are revoked, and it's in use by openVPN, we will be surprised of having more
revoked certs than the desired. This tool finds those duplicated SerialNumbers
into a non encrypted xml pfSense config backup.

2019/07/21: New feature: Now it also shows the CRL(s) in which the cert appears.
Last change 2019/09/11: New feature: Encrypted XML config files supported. To decrypt the xml files is mandatory a path to openssl.exe. By default this script looks for the openvpn bin folder.

Thanks to [pippin](https://forum.netgate.com/user/pippin) for show me the links to the pfSense docummented issue:

https://redmine.pfsense.org/issues/3694

https://forum.netgate.com/topic/69978/generated-certificates-with-non-unique-serial-numbers/2
