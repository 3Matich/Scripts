# Scripts
La idea de este repositorio es publicar todos los scripts que realice o modifique detallando la finalidad de cada uno en este archivo *README.md*.

## Preparativos
Dejo algunas librerias que son necesarias para el funcionamiento del script

### Libreria de virus total
Es necesario la libreria que conecta con virus total, se la puede descargar e instalar con el siguiente comando:
> pip install virustotal-api

También hay que tener en cuenta que se debe agregar la key de virus total, con tener una cuenta gratuita en virus total ya podes obtener la key, no es necesario ser premium para poder usarlo.
Esto hay que reemplazarlo en la linea 6:
> API_KEY = "Api_Key"

Reemplazar "Api_Key" por tu key.

## ScanHash
El script ScanHash.py toma un archivo .txt o .csv y busca los hashes que tenga ese archivo en Virus Total, generando un nuevo archivo .csv con los detalles de la busqueda incluyendo si este hash es detectado por fortiguard y mcafee.
Se puede utilizar la función -h para mas detalles sobre el script
