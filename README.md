Powershell script: pfSense Certificate Viewer

Sometimes it happens in pfSense that certificates are created with
duplicated SerialNumbers (for the same CAroot). If any of these certificates
are revoked, and it's in use for openVPN, we will be surprised of having more
revoked certs than the resired. This tool finds those duplicated SerialNumbe into a non encrypted xml pfSense config backup.

Last change 2017/07/21: New feature: Now it also shows the CRL(s) in which the cert appears.

Thank to pippin (https://forum.netgate.com/user/pippin) for show me the links to the pfSense docummented issue:

https://redmine.pfsense.org/issues/3694

https://forum.netgate.com/topic/69978/generated-certificates-with-non-unique-serial-numbers/2
