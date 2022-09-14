<div id="top"></div>

Traducciones:

- Chino: / 中文: <a href=./README_CN.md>README_CN</a>

<br />
<div align="center">
  <a href="https://github.com/SitinCloud/Owlyshield">
    <img src="./Misc/logo_transparent.png" alt="Logo" width="150" height="150">
  </a>

<h2 align="center">Owlyshield</h2>
  <p align="center">
	  Un antivirus con IA escrito en Rust
  </p>
  <p align="center">
	<img src="https://github.com/SitinCloud/Owlyshield/actions/workflows/rust-build.yml/badge.svg">
	<img src="https://img.shields.io/github/license/SitinCloud/Owlyshield">
  </p>

  <p align="center">
    :test_tube: <a href="https://github.com/SitinCloud/malwares-ml">Accesar a los datos de entrenamiento</a>
    ·
    :book: <a href="http://doc.owlyshield.com">Lee los documentos técnicos</a>
    ·
    :speech_balloon: <a href="https://github.com/SitinCloud/Owlyshield/issues">Solicita una Característica</a>
  </p>
</div>

<p align="center">
	<img src="./gif_demo_owlyshield.gif" alt="Gif Demo Owlyshield" style="align:center; width: 75%">
</p>

## :owl: The owl's hoot: troubles-hoot!

Owlyshield es un antivirus open-source Impulsado por IA (Inteligencia Artificial) escrito en [Rust](https://rust-lang.org). Los análisis estaticos realizados por AV son solo capaces de detectar amenazas conocidas, explicando porque los hackers se adaptan tan rapidamente y surgen más ataques Ransom. Proveemos análisis embebido conductual por IA que es capaz de detectar y eliminar Ransomwares durante los primeros momentos de su ejecución.

Hemos puesto mucho esfuerzo en hacer la aplicación rápida, usando multi-hilos para la ejecución y algoritmos de machine learning como random forest, que son rápidos de ejecutar.

## :vulcan_salute: Filosofía Open-source

Nosotros en [SitinCloud 🇫🇷](https://www.sitincloud.com) creemos fuertemente que los productos de ciberseguridad deben ser siempre open-source:

1. En adición al código fuente, proveemos una wiki completa y documentación de código,
2. Los productos Open-source pueden ser considerados soluciones soberanas ya que no hay riesgo de que ninguna agencia externa introduzca características escondidas (backdoor) or de vigilancia masiva que los usuarios no esten enterados,
3. Proveemos entrypints en el código para poder interactuar con herramientas de terceros facilmente (Específicamente SIEM y EDRs).

## :arrow_forward: Instalación en 2 minutos

Regularmente liberamos instaladores (en la sección de GitHub *Releases*). La versión gratuita (community edition) es totalmente operacional y va a proteger eficientemente tu sistema contra Ransomwares. Ya no vas a tener que iniciar Windows en modo de pruebas ya que proveemos el driver firmado en la versión community.

Por favor consulta la *Wiki* para las instrucctiones de instalación o si prefieres construirlo tu mismo.
Sugerencias bienvenidas (Ver *Contributing*).

Ve a la sección de open issues para lista de características propuestas (y problemas conocidos).
<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :money_mouth_face: Negocio

### :arrow_upper_right: Edición Gratuita vs Pro

La edición Pro (edición comercial) añade las siguientes características:

* Una webapp que recopila todos los datos de incidentes para ayudar al equipo de TI a entender el alvance del ataque dentro de la red de la compañia y actuar acorde (o clasificarlo como falso positivo),
* Interactua con tus herramientas de registros (proveemos una API),
* Programa tareas para actualizar automaticamente la aplicación.

Con la versión gratuita haremos mejor para encontrar una sulución a cualquier problema que puedas encontrar.

Los problemas que nuestros suscriptores de la versión comercial o revendedores con valor añadido van a tener prioridad.

### :moneybag: Modelo de negocio

Although commercial products or services can be directly purchased from us (feel free
to [contact us](mailto:opensource@sitincloud.com) directly for any quotation that could suit your need), we think that
our products should be distributed to end customer in an indirect way.

Please [contact us](mailto:opensource@sitincloud.com):

* If you want to become a distribution partner or use our products as an MSSP: we are opened to such kind of
  partnerships,
* If you want to integrate Owlyshield as part of your own EDR / XDR system: we will be pleased to issue the best
  proposal for appropriate level of professional services to do so,
* If you need to protect your critical enterprise servers against crafted attacks or progressive wipers: we can
  introduce you with our brand new novelty detection engine based on encoders AI tools (Owlyshield Enterprise Edition),
* For any question or a presentation of our products.

<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :nerd_face: Technical

### :gear: How does it work?

1. A minifilter (a file system filter driver) intercepts I/O request packets (IRPs) to collect metadata about what
   happens on the disks (*DriverMsg* in the sources),
2. *Owlyshield-predict* uses the previously created *DriverMsgs* to compute features submitted to a RNN (a special type
   of neural network wich works on sequences). Behavioural as well as static analysis are performed.
3. If the RNN predicts a malware, *owlyshield-predict* asks the minifilter to kill the malicious processes and send a
   very detailed report about what happened to your SIEM tools (and/or a local file).

<img src="./Misc/Architecture2.png" alt="Architecture" style="align:center">

### :robot: How was the model trained?

The model was trained with malwares from the real world collected from very diverse places on the internet (dark web, by
sharing with researchers, analysis of thousands of downloads with virustotal).

We ran them on Windows VMs with Owlyshield working in a specific mode (`--features record`) to save the IRPs. *
Owlyshield-predict* with `--features replay` was then used to write the learning dataset (a csv file).

The [Malwares-ML](https://github.com/SitinCloud/malwares-ml) repository is the place where we share some of our learning
datasets.
<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :mechanical_arm: Contribuciones

Ayudamos a nuestros contribuidores dandoles acceso gratuito a la versión Pro de Owlyshield.

If you discover any undetected ransomware please do open an issue with the tag "undetected". It will help us improve the AI engine and understand what new trick has been implemented in order not to be detected.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also
simply open an *Issue* with the tag "enhancement".
Don't forget to give the project a :star:! Thanks again!

1. Bifurca el proyecto (Fork)
2. Crea la rama de tu característica (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push la branch (`git push origin feature/AmazingFeature`)
5. Abre una Pull Request

<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :book: Licencia

Distribuido bajo la licencia EUPL v1.2. Ve al archivo `LICENSE.txt` para más información.

<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :love_letter: Contacto

Damien LESCOS - [@DamienLescos](https://twitter.com/DamienLescos)
- [opensource@sitincloud.com](mailto:opensource@sitincloud.com)

Enlace del proyecto: [https://github.com/SitinCloud/Owlyshield/](https://github.com/SitinCloud/Owlyshield/)

Enlace de la compañia: [SitinCloud](https://www.sitincloud.com)

<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :pray: Agradecimientos

* [RansomWatch](https://github.com/RafWu/RansomWatch)
* [Behavioural machine activity for benign and malicious Win7 64-bit executables](https://research.cardiff.ac.uk/converis/portal/detail/Dataset/50524986?auxfun=&lang=en_GB)

<p align="right">(<a href="#top">Volver al inicio</a>)</p>
