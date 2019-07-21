Powershell script: pfSense Certificate Viewer

Sometimes it happens in pfSense that certificates are created with
duplicated SerialNumbers (for the same CAroot). If any of these certificates
are revoked, and it's in use for openVPN, we will be surprised of having more
revoked certs of the resired. This tools finds those duplicated SerialNumber.

Last change 2017/07/21: New feature: Now it also shows the CRL(s) in which the cert appears.

ES
Visor de certificados de pfSense: a veces pasa (no debería) en pfSense
que se crean certificados con SerialNumber duplicado (en la misma CAroot).
Si se revoca alguno de estos certificados con SN duplicado, y están en uso en openVPN,
nos llevaremos la sorpresa de haber revocado más de lo deseado. Esta herramienta encuentra
esas duplicidades de SN.

ültimo cambio 2017/07/21: Nueva funcionalidad: Ahora muestra en qué CRL(s) está referenciado el certificado.
