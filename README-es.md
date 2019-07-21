Script Powershell. Visor de certificados de pfSense

A veces pasa (no debería) en pfSense que se crean certificados con SerialNumber
duplicado (en la misma CAroot).
Si se revoca alguno de estos certificados con SN duplicado, y están en uso en openVPN,
nos llevaremos la sorpresa de haber revocado más de lo deseado. Esta herramienta encuentra
esas duplicidades de SN.

ültimo cambio 2017/07/21: Nueva funcionalidad: Ahora muestra en qué CRL(s) está referenciado el certificado.
