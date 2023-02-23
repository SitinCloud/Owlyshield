<div id="top"></div>

Traductions:

- Chinois: / 中文: <a href=./README_CN.md>README_CN</a>
- Espagnol: <a href=./README_ES.md>README_ES</a>

<br />
<div align="center">
  <a href="https://github.com/SitinCloud/Owlyshield">
    <img src="./Misc/logo_transparent.png" alt="Logo" width="150" height="150">
  </a>

<h2 align="center">Owlyshield</h2>
  <p align="center">
	  Un antivirus écrit en Rust basé sur un moteur d'IA
  </p>
  <p align="center">
	<img src="https://github.com/SitinCloud/Owlyshield/actions/workflows/rust-build.yml/badge.svg">
	<img src="https://img.shields.io/github/license/SitinCloud/Owlyshield">
  </p>

  <p align="center">
    :test_tube: <a href="https://github.com/SitinCloud/malwares-ml">Access training data</a>
    ·
    :book: <a href="http://doc.owlyshield.com">Read the technical doc</a>
    ·
    :speech_balloon: <a href="https://github.com/SitinCloud/Owlyshield/issues">Request Feature</a>
  </p>
</div>

<p align="center">
	<img src="./gif_demo_owlyshield.gif" alt="Gif Demo Owlyshield" style="align:center; width: 75%">
</p>

## :owl: Quand les virus pullulent le hibou hulule !

Owlyshield est un moteur d'antivirus open source écrit en [Rust](https://rust-lang.org) et basé sur de l'intelligence
artificielle.
L'analyse statique, telle qu'effectuée par les antivirus classiques, ne peut détecter que des menaces déjà connues, ce
qui explique pourquoi les attaquants s'adaptent si rapidement
et pourquoi les attaques par demandes de rançons se multiplient autant.
Nous fournissons une IA d'analyse comportementale embarquée capable de détecter et de tuer les ransomwares dès le début
de leur exécution.

Nous nous sommes efforcés de réaliser une application rapide,
par l'utilisation du multithreading et d'algorithmes de machine learning comme les random forests qui sont rapides à
calculer.

## :vulcan_salute: La philosophie open source

A [SitinCloud 🇫🇷](https://www.sitincloud.com) nous sommes convaincus que les produits de cyber sécurité devraient être
open source :

1. En plus du code source nous fournissons un wiki complet et la documentation du code,
2. Les produits open source peuvent être considérés comme des solutions souveraines car il n'y a pas de risque qu'une
   agence étrangère y introduise de backdoor cachée
   ni de fonction de surveillance de masse dont les utilisateurs pourraient ne pas avoir connaissance,
3. Nous fournissons des points d'entrée spécifiques dans le code de sorte à faciliter l'interfaçage avec des solutions
   tierces (spécialement des SIEM et des EDR).

## :arrow_forward: Installation en 2 minutes

Nous publions régulièrement des installateurs (dans la section GitHub *Releases*). L'édition gratuite (édition
communautaire) est entièrement fonctionnelle et
protège efficacement votre système contre les ransomwares. Il n'est plus nécessaire de démarrer Windows en mode
test-signing car nous fournissons désormais le driver signé
dans l'édition communautaire.

Merci de consulter le *Wiki* pour les instructions d'utilisation ou si vous préférez construire le système vous-même.
Les suggestions sont les bienvenues (consulter la section *Contributing*)

Merci de consulter les questions en cours pour accéder à la liste complète des fonctionnalités proposées et des
problèmes connus.

<p align="right">(<a href="#top">back to top</a>)</p>

## :money_mouth_face: Business

### :arrow_upper_right: Editions gratuites vs éditions professionnelles

L'édition professionnelle (édition commerciale) ajouté les fonctionnalités suivantes :

* Une application web qui collecte toutes les données des incidents afin d'aider le service informatique à comprendre l'
  étendue des attaques
  effectuées dans les réseaux de l'entreprise et à agir en conséquence (ou à classer la menace en tant que faux
  positif),
* Des interfaces avec vos outils de gestion des logs (nous fournissons même une API),
* Des tâches planifiées pour la mise à jour automatique de l'application.

Dans le cadre de l'utilisation de la version gratuite nous nouos efforcerons de trouver une solution pour chaque *Issue*
que vous pourriez soulever dans GitHub.

Les problèmes soulevés par les personnes utilisatrices de la version commerciale ou par les distributeurs seront bien
sûr traitées en priorité.

### :moneybag: Business model

Bien que vous puissiez nous acheter directement les versions commerciales et les prestations associées, n'hésitez pas
à [nous contacter](mailto:opensource@sitincloud.com) directement
pour tout devis dont vous auriez besoin, nous pensons que nos produits devraient faire l'objet d'une distribution
indirecte via des revendeurs.

Merci de [nous contacter](mailto:opensource@sitincloud.com):

* Si vous souhaitez devenir partenaire distributeur ou si vous souhaitez utiliser nos produits dans le cadre d'une
  gestion de service managés de votre parc client (MSSP).
  Nous sommes tout à fait ouverts à ce type de partenariat.
* Si vous souhaitez intégrer Owlyshield en tant que module de votre propre système EDR ou XDR :
  Nous nous ferons un plaisir de vous adresser notre meilleure offre pour un service adapté à votre besoin.
* Si vous souhaitez protéger les serveurs critiques de votre entreprise contre des attaques spécialement écrites pour
  eux (comme des wipers progressifs)
  alors nous pouvons vous présenter notre nouveau moteur de détection des comportements nouveaux basé sur des outils
  d'IA de type auto-encodeurs (Owlyshield édition entreprise)
* Pour toute question ou présentation de nos solutions.

<p align="right">(<a href="#top">back to top</a>)</p>

## :nerd_face: Aspects techniques

### :gear: Comment ça marche ?

1. Un minifilter (un driver du système de fichier) intercepte les requêtes d'E/S disques (IRPs) pour collecter des meta
   data sur ce
   qui se passe sur les disques (*DriverMsg* dans les sources),
2. *Owlyshield-predict* utilise les *DriverMsgs* précemment créés pour calculer des caractéristiques soumises à un
   réseau de neurones adapté au travail sur des séquences.
   Le système effectue une analyse comportementale mais aussi une analyse statique.
3. Si le réseau de neuronnes prédit un malware, *owlyshield-predict* demande au minifilter de tuer les processus
   malicieux et envoie
   un rapport très détaillé sur ce qui s'est passé à votre SIEM (et/ou un fichier local).

<img src="./Misc/Architecture2.png" alt="Architecture" style="align:center">

### :robot: Comment le modèle a-t-il été entraîné ?

Le modèle a été entraîné avec des malwares du monde réel collectés dans divers endroits de l'internet
(partage avec des chercheurs, dark web, analyse de milliers de téléchargements avec virustotal)

Nous les avons exécutés sur des machines virtuelles Windows avec Owlyshield fonctionnant dans un mode spécifique de
collecte (`--features record`) pour enregistrer les IRPs.
Puis *Owlyshield-predict* avec `--features replay` a été utilisé pour écrire les datasets d'apprentissage (un fichier
csv).

Le dépôt [Malwares-ML](https://github.com/SitinCloud/malwares-ml) est l'endroit où nous partageons certains de ces
datasets.

<p align="right">(<a href="#top">back to top</a>)</p>

## :mechanical_arm: Participer

Les participants au projet bénéficient s'ils le souhaitent d'un droit d'utilisation gratuit de la version
professionnelle.

Si vous découvrez un ransomware non détecté merci d'ouvrir une issue avec le tag "undetected".
Celà nous aidera à améliorer le moteur d'IA et à comprendre quelle astuce les attaquants ont mise en œuvre pour échapper
à la détection.

Si vous avez une suggestion pour améliorer le système, n'hésitez pas à "forker" le dépôt et à créer une "pull request".
Vous pouvez aussi simplement ouvrir une *issue* avec le tag "enhancement".
N'oubliez pas s'il vous plaît de donner une :star: au projet ! Merci encore !

1. Forker le projet
2. Créez votre branche fonctionnelle (`git checkout -b feature/AmazingFeature`)
3. Committez vos modifications (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>

## :book: Licence

Distribué sous la licence EUPL v1.2. Cf. `LICENSE.txt` pour plus d'information.

<p align="right">(<a href="#top">back to top</a>)</p>

## :love_letter: Contact

Damien LESCOS - [@DamienLescos](https://twitter.com/DamienLescos)

- [opensource@sitincloud.com](mailto:opensource@sitincloud.com)

Lien du projet : [https://github.com/SitinCloud/Owlyshield/](https://github.com/SitinCloud/Owlyshield/)
Lien de la société : [SitinCloud](https://www.sitincloud.com)

<p align="right">(<a href="#top">back to top</a>)</p>

## :pray: Remerciements

* [RansomWatch](https://github.com/RafWu/RansomWatch)
* [Behavioural machine activity for benign and malicious Win7 64-bit executables](https://research.cardiff.ac.uk/converis/portal/detail/Dataset/50524986?auxfun=&lang=en_GB)

<p align="right">(<a href="#top">back to top</a>)</p>
