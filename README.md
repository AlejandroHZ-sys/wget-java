# WgetJava

Reimplementación de una herramienta tipo **wget** desarrollada completamente en **Java**, enfocada en comprender a bajo nivel el funcionamiento de **HTTP**, **HTTPS**, descarga recursiva de recursos web y manejo de concurrencia.

Este proyecto no utiliza librerías externas para HTTP: todas las peticiones, respuestas, encabezados, redirecciones y descargas se manejan directamente mediante **sockets**.

---

## Características principales

- Descarga de recursos vía **HTTP y HTTPS**
- Soporte para **descarga recursiva** de sitios web
- Manejo de:
  - Redirecciones (301, 302, 308)
  - `Content-Length`
  - `Transfer-Encoding: chunked`
  - Compresión `gzip`
- Extracción y descarga automática de:
  - HTML
  - CSS
  - JavaScript
  - Imágenes
  - Fuentes
- Reescritura de enlaces para **navegación local offline**
- Descarga concurrente mediante **pool de hilos**
- Control de:
  - Profundidad máxima
  - Número de intentos
  - Número de hilos
- Generación automática de un **índice HTML** para navegar el sitio descargado

---

## Ejecución

Compilar:

```bash
javac WgetJava.java
````

Ejecutar:

```bash
java WgetJava [opciones] URL
```

Ejemplo:

```bash
java WgetJava -r -t 10 --tries 3 --max-depth 5 https://example.com
```

---

## Opciones disponibles

* `-r`
  Activa el modo recursivo

* `-t <num>`
  Tamaño del pool de hilos de descarga

* `--tries <num>`
  Número máximo de intentos por recurso

* `--max-depth <num>`
  Profundidad máxima de recursión

---

## Salida

Los recursos descargados se almacenan en el directorio:

```
downloads/
```

Al finalizar, se genera automáticamente:

```
downloads/site_index.html
```

Este archivo permite navegar localmente por todas las páginas descargadas.

---

## Aspectos técnicos destacados

* Implementación manual del protocolo **HTTP/1.1**
* Manejo directo de **sockets TCP y SSL**
* Decodificación de respuestas `chunked`
* Descompresión de contenido `gzip`
* Normalización y validación de rutas
* Extracción de enlaces mediante expresiones regulares
* Control de concurrencia con:

  * `ExecutorService`
  * `Semaphore`
  * `ConcurrentHashMap`

---

## Propósito del proyecto

Este proyecto fue desarrollado con fines **académicos y formativos**, con el objetivo de comprender en profundidad:

* El funcionamiento real de HTTP/HTTPS
* La comunicación cliente-servidor a bajo nivel
* La descarga y reconstrucción de sitios web
* La programación concurrente en Java

No pretende reemplazar a herramientas como `wget` o `curl`, sino demostrar dominio técnico del stack de red.

---

## Autor

Alejandro HZ

```



Buen movimiento separar este proyecto 👌
```
