# 🛡️ Analizador de Protocolos Criptográficos

> **Trabajo de Fin de Grado (TFG) - Ingeniería Informática**
> Herramienta de software de escritorio orientada al análisis sintáctico y la detección automática de vulnerabilidades en protocolos criptográficos (desafío-respuesta, frescura de mensajes, suplantación de identidad, etc.).

Este proyecto aplica un diseño basado en el patrón arquitectónico **Modelo-Vista-Controlador (MVC)**, garantizando un almacenamiento persistente local seguro y ofreciendo una interfaz visual moderna e interactiva para la auditoría de seguridad.

---

## 🚀 Características Principales

* **Análisis Léxico y Sintáctico:** Compilación e interpretación de especificaciones de protocolos de red a partir de archivos de texto plano.
* **Motor de Análisis Avanzado:** Módulos de evaluación independientes para verificar la seguridad del intercambio de mensajes frente a ataques clásicos distribuidos.
* **Persistencia Altamente Segura:** Base de datos relacional local embebida (**SQLite**) con integridad referencial estricta mediante claves foráneas activas y borrado en cascada automatizado (`ON DELETE CASCADE`).
* **Criptografía de Contraseñas:** Protección absoluta de las credenciales de usuario mediante la función hash criptográfica unidireccional **BCrypt**, incorporando un *salt* aleatorio automático por registro para mitigar ataques de fuerza bruta.
* **Navegación Fluida e Interactiva:** Control centralizado del ciclo de vida de las ventanas y enrutamiento dinámico mediante JavaFX, complementado con hojas de estilo CSS para una experiencia de usuario (UX) pulida.
* **Generación de Auditorías:** Capacidad para importar/exportar el historial de protocolos y generar informes técnicos detallados en formato PDF.

---

## ⚙️ Stack Tecnológico

| Componente | Tecnología Utilizada |
| :--- | :--- |
| **Lenguaje Base** | Java 25 (Java SE) |
| **Diseño de Interfaz** | JavaFX 21.0.1 (FXML + CSS desacoplado) |
| **Motor de Base de Datos** | SQLite 3.45.1.0 (SQLite JDBC Driver) |
| **Seguridad** | JBCrypt 0.4 (Algoritmo adaptativo BCrypt) |
| **Construcción** | Maven Automated Wrapper Core |

---

## 🛠️ Arquitectura del Software

El código fuente está compartimentado de forma modular en capas independientes, cumpliendo estrictamente con los principios de **alta cohesión y bajo acoplamiento**:

* 📦 `com.tfg.analizador`: Punto de entrada de la aplicación. Gestiona el ciclo de vida, el despliegue de la BBDD y el entorno gráfico.
* 📦 `.../logica` *(Capa de Negocio)*: Contiene el núcleo analítico (frescura, suplantación, desafíos), el compilador léxico y los gestores que centralizan la validación de sesiones y operaciones de seguridad.
* 📦 `.../modelo` *(Capa de Entidades)*: Modelos de datos del dominio (Usuario, Protocolo, Vulnerabilidad, Agente, Mensaje, Nonces).
* 📦 `.../persistencia` *(Capa de Datos Física)*: Administrador de conexión global (patrón Singleton) mediante JDBC, autoconstrucción de tablas y lógica de almacenamiento en disco/exportación a PDF.
* 📦 `.../presentacion` *(Capa UI)*: Controladores FXML que gestionan los eventos visuales y la validación de entrada antes de delegar en la capa lógica.
* 📦 `.../util` *(Auxiliares)*: Enrutador central que orquesta los intercambios de escenas en JavaFX.

---

## 📊 Modelo de Datos

La base de datos se autoconstruye secuencialmente siguiendo un esquema relacional blindado:

### 1. Tabla `USUARIO`
Registra las cuentas con restricción de unicidad estricta para evitar duplicidades.

| Columna | Tipo | Restricciones |
| :--- | :--- | :--- |
| `id_usuario` | INTEGER | Primary Key, Autoincrement |
| `nombre_usuario` | TEXT | UNIQUE, Not Null |
| `hash_contra` | TEXT | Not Null |

### 2. Tabla `PROTOCOLO`
Almacena el historial de especificaciones cargadas por cada usuario.

| Columna | Tipo | Restricciones |
| :--- | :--- | :--- |
| `id_protocolo` | INTEGER | Primary Key, Autoincrement |
| `id_usuario` | INTEGER | Foreign Key -> `USUARIO` (ON DELETE CASCADE) |
| `nombre_protocolo`| TEXT | Not Null |
| `fecha_analisis` | TEXT | Nullable |
| `es_seguro` | INTEGER | Nullable |
| `Path` | TEXT | Not Null |

### 3. Tabla `VULNERABILIDAD`
Registra detalladamente cada fallo de seguridad detectado.

| Columna | Tipo | Restricciones |
| :--- | :--- | :--- |
| `id_vulnerabilidad`| INTEGER | Primary Key, Autoincrement |
| `id_protocolo` | INTEGER | Foreign Key -> `PROTOCOLO` (ON DELETE CASCADE) |
| `nombre` | TEXT | Not Null |
| `tipo` | TEXT | Not Null |
| `linea` | INTEGER | Not Null |
| `descripcion` | TEXT | Nullable |

---

## 🎨 Documentación Técnica y Diseño Visual

Toda la documentación arquitectónica complementaria se encuentra organizada en la raíz del repositorio:

* 📂 **`docs/mockups/`**: Capturas de pantalla y diseño UI planificado en Scene Builder.
* 📂 **`docs/diagramas/`**: Diagramas UML de clases, flujos lógicos y esquema conceptual relacional.

---

## 💻 Guía de Ejecución (Maven Wrapper)

El proyecto integra **Maven Wrapper (`mvnw`)**. No es necesario tener instalado Apache Maven globalmente para compilar o lanzar la aplicación; el motor binario está preconfigurado en el repositorio.

### Requisitos Previos

1. **Java Development Kit (JDK):** Versión **25** o superior.
2. **Variable de Entorno:** `JAVA_HOME` debe apuntar a la ruta absoluta de la instalación del JDK.

### Comandos de Despliegue

Abre una terminal en el directorio raíz del proyecto y ejecuta el comando correspondiente a tu sistema operativo:

#### 🔹 Windows (PowerShell)
```
.\mvnw javafx:run
```

### 🔹 Windows (CMD)
```
mvnw javafx:run
```

### 🔹 Linux / macOS
La primera vez, otorga permisos de ejecución al script:
```
chmod +x mvnw
```

Lanza la aplicación de escritorio:
```
./mvnw javafx:run
```

##🎓 Autoría y Créditos
Autor: Carlos Corbacho Ordóñez

Tutor: Francisco Jose Jaime Rodríguez

Institución: Universidad de Málaga

Titulación: Grado en Ingeniería Informática

Mención: Sistemas de Información

Terminado en Junio 2026
