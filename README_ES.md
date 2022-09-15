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

Los productos comerciales o servicios pueden ser comprados directamente con nosotros (sientete libre de [contactarnos](mailto:opensource@sitincloud.com) directamente por cualquier cotización que se ajuste a tus necesidades), pensamos que nuestros productos pueden ser distribuidos al usuario final en una forma indirecta.

Por favor [contactanos](mailto:opensource@sitincloud.com):

* Si te quieres convertir en un socio de distribución o usar nuestros productos como un MSSP: estamos abiertos a ese tipo de alianzas,
* Si quieres integrar Ownlyshield como parte de tu sistema EDR / XDR: estaremos encantados de proveerte la mejor propuesta de nuestros servicios profesionales,
* Si necesitas proteger tus servidores criticos empresariales contra ataques dirigidos o limpiadores progresivos (progressive wipers) :podemos mostrarte nuestras nuevas herramientas de IA con nuevos motores de detección basados en Owlyshield Enterprise Edition,
* Para cualquier pregunta o presentación de nuestros productos.

<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :nerd_face: Detalles técnicos

### :gear: ¿Cómo funciona?

1. Un minifiltro (un driver de filtro de archivos de sistema) intercepta peticiones y paquetes entrantes y salientes (IRPs) para recopilar metadatos acerca de lo que está pasando en los discos (*DriverMsg* en la fuente),
2. *Owlyshield-predict* usa el previamente creado *DriverMsgs* para computar características enviadas a una RNN (un tipo especial de red neuronal que trabaja en secuencias). Analisis de comportamiento y estáticos son realizados.
3. Si la red neuronal RNN predice un malware, *owlyshield-predict* le pide al minifiltro matar al proceso malicioso y enviar un reporte detallado de lo que paso a tus herramientas SIEM (y/o a un archivo local).

<img src="./Misc/Architecture2.png" alt="Architecture" style="align:center">

### :robot: ¿Cómo fue el modelo entrenado?

El modelo fue entrenado con malwares reales recopilados de internet (dark web, compartidos por investigadores con miles de analisis de virustotal).

Nosotros ejecutamos en Windows maquinas virtuales (VMs) en un modo específico (`--features record`) para registrar las IRPs. *Owlyshield-predict* con el modo `--features replay` fue despues usado para escribir el conjunto de datos de aprendizaje (un archivo csv).

El repositorio [Malwares-ML](https://github.com/SitinCloud/malwares-ml) es el lugar donde compartimos algunos de nuestros datos de entrenamiento.
<p align="right">(<a href="#top">Volver al inicio</a>)</p>

## :mechanical_arm: Contribuciones

Ayudamos a nuestros contribuidores dandoles acceso gratuito a la versión Pro de Owlyshield.

Si descubres algún ransomware que no ha sido detectado por favor abre un issue con la etiqueta de "undetected". Eso nos ayuda a mejorar el motor de IA y para entender la nueva implementación para que no sea detectado.

Si tienes alguna sugerencia para hacer este proyecto mejor, por favor bifurca el repo y crea una pull request. Puedes también un *Issue* con la etiqueta "enhancement". No olvides dar al proyecto una :star:! Gracias!

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
