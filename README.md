Powershell script: pfSense Certificate Viewer

Sometimes it happens in pfSense that certificates are created with
duplicated SerialNumbers (for the same CAroot). If any of these certificates
are revoked, and it's in use for openVPN, we will be surprised of having more
revoked certs of the resired. This tool finds those duplicated SerialNumbe into a non encrypted xml pfSense config backup.

Last change 2017/07/21: New feature: Now it also shows the CRL(s) in which the cert appears.
