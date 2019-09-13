## Visor de certificados pfSense/OPNsense
Script Powershell. Visor de certificados de pfSense/OPNsense

A veces pasa (no debería) en pfSense que se crean certificados con SerialNumber
duplicado (en la misma CAroot).
Si se revoca alguno de estos certificados con SN duplicado, y están en uso en openVPN,
nos llevaremos la sorpresa de haber revocado más de lo deseado. Esta herramienta encuentra
esas duplicidades de SN usando como entrada un backup XML de configuración de pfSense no cifrado.

También mostrará los certificados de CA, servidor y usuario.

2017/07/21: Nueva funcionalidad: Ahora muestra en qué CRL(s) está referenciado el certificado.

2019/09/11: Nueva funcionalidad: Se pueden descifrar archivos de configuración XML. Para hacerlo hay que disponer de openssl.exe. Por defecto el script lo buscará en la carpeta de instalación de openVPN. Se puede definir la ruta a openssl.exe si fuera necesario.

2019/09/13: También admite archivos de backup OPNsense (cifrados y no cifrados)

Último cambio 2019/09/13: Se utiliza la cabecera de descifrado de backups de OPNsense para llamar a openssl. En la versión anterior se asumía siempre aes-256-cbc/md5 (asumidos todavía para pfSense, por no contener cabecera de descifrado).
