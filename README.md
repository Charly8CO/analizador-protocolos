===============================================================================
GUÍA DE EJECUCIÓN DE LA APLICACIÓN (MAVEN WRAPPER)
===============================================================================

Este proyecto utiliza Maven Wrapper (mvnw). Esto significa que NO es necesario 
tener instalado Apache Maven de forma global en el sistema operativo para poder 
compilar, construir o ejecutar la aplicación. Todo lo necesario está incrustado 
en la estructura de carpetas.

-------------------------------------------------------------------------------
1. REQUISITOS PREVIOS
-------------------------------------------------------------------------------
- Tener instalado el Java Development Kit (JDK) versión 17 o superior.
- La variable de entorno 'JAVA_HOME' debe estar correctamente configurada en el 
  sistema, apuntando a la ruta raíz de dicha instalación del JDK.

-------------------------------------------------------------------------------
2. COMANDOS DE EJECUCIÓN
-------------------------------------------------------------------------------
Abra una terminal o consola de comandos directamente en la carpeta raíz del 
proyecto (donde se encuentra este archivo y el 'pom.xml') y ejecute:

En WINDOWS (PowerShell):
    .\mvnw javafx:run

En WINDOWS (Símbolo del sistema / CMD):
    mvnw javafx:run

En LINUX / MACOS:
    1. Otorgar permisos de ejecución al script (solo la primera vez):
       chmod +x mvnw
    2. Ejecutar la aplicación:
       ./mvnw javafx:run

===============================================================================