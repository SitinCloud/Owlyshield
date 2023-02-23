<div id="top"></div>

Translations (obsolete):

- Chinese: / 中文: <a href=./translations/README_CN.md>README_CN</a>
- Español: <a href=./translations/README_ES.md>README_ES</a>
- Français: <a href=./translations/README_FR.md>README_FR</a>
  <br />

<div align="center">
  <a href="https://github.com/SitinCloud/Owlyshield">
    <img src="./resources/logo_transparent.png" alt="Logo" width="150" height="150">
  </a>

<h2 align="center">Owlyshield</h2>
  <p align="center">
	  An AI antivirus written in Rust
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

## :fast_forward: TL;DR

Owlyshield is an open-source EDR (Endpoint Detection and Response) solution for Linux and Windows servers. It analyzes how processes use files to detect intrusions through vulnerability exploitation, with a particular focus on detecting C2 (Command and Control) beacons like Cobalt Strike. The project is developed by [SitinCloud](https://www.sitincloud.com), a French company.

The main idea behind Owlyshield is to learn the normal behavior of applications (essentially trees of processes) and use this knowledge to identify weak signals of an attack through the use of novelty detection.

## :question: An EDR Framework...

Owlyshield's extensibility is a key feature that sets it apart from other EDR solutions.  As a framework you can add new algorithms for malware detection, UEBA (User and Entity Behavior Analytics), and novelty detection. You can also use Owlyshield to record and replay file activities for training machine learning models, as we do with our autoencoder feature.

Owlyshield provides powerful and efficient endpoint detection and response capabilities for Linux, Windows, and IoT devices. Its unique focus on file activities makes it highly effective at detecting fileless malware and C2 beacons that may go unnoticed by other EDR solutions.

<p align="right">(<a href="#top">back to top</a>)</p>

## :ballot_box_with_check: ...that's comes with pre-built features

Although Owlyshield is a framework designed to be customized and extended, it also comes with pre-built, powerful features that are immediately usable :

- [x] Advanced novelty detection with autoencoders (commercial version),
- [x] Ransomware protection in real-time on Windows using XGBoost,
- [ ] Novelty detection with embedded training on both Linux (+IoT) and Windows,
- [ ] Auto-configuration of SELinux to automatically protect exposed applications.


<p align="center">
	<img src="./resources/pca_3d.gif" alt="Gif Demo Owlyshield" style="align:center; width: 75%">
</p>

<p align="right">(<a href="#top">back to top</a>)</p>

## :see_no_evil: Real-Life Examples

Owlyshield provides a powerful solution for detecting and responding to threats in real-time. Here are three real-life examples of how Owlyshield protected our customers:

- An attacker exploited a critical CVE in an ESXi server to deploy a payload. Owlyshield detected weak signals of the attack on the ESXi server by analyzing the file activities and identifying unusual behavior in the ESXi process family, indicating the presence of a malicious process.
- A web application built with JHipster had a hidden URL that could be used to dump the JVM memory, but the infrastructure team was not aware of this vulnerability. Owlyshield was able to detect it was exploited by analyzing the file system for unusual activity related to creating the dump file,
- A large and expensive ERP system was accessed by teams of consultants from different countries. One of them, with admin rights, began to slowly corrupt specific files in the ERP system. The attacker used this tactic to make the corruption look like a series of bugs or glitches rather than a deliberate attack. 

<p align="right">(<a href="#top">back to top</a>)</p>

## :arrow_forward: 2 minutes install

Installation instructions for Owlyshield can be found in the Releases section of the project's GitHub repository. For usage instructions, please refer to the project's Wiki or see the Contributing section if you prefer to build Owlyshield yourself.

<p align="right">(<a href="#top">back to top</a>)</p>

## :money_mouth_face: Business

### :arrow_upper_right: Free vs Pro editions

The Pro Edition (commercial edition) includes the following features:

- Integration with Wazuh,
- Nice local interfaces for end users,
- Scheduled tasks to automatically update the application.

Within the scope of free version usage, we will do our best to help you find a solution for any issues you may
encounter. However, we prioritize support for subscribers to our commercial version and valued added resellers.

### :moneybag: Business model

While our products and services can be purchased directly from us (feel free
to [contact us](mailto:opensource@sitincloud.com) for a quotation that meets your needs), we believe that it is best for
our products to be distributed to end customers indirectly.

Please [contact us](mailto:opensource@sitincloud.com) if you:

- Want to become a distribution partner or use our products as an MSSP – we are open to such partnerships.
- Want to integrate Owlyshield as part of your own EDR/XDR system – we will be happy to provide the best proposal for
  the appropriate level of professional services to do so.
- Need to protect your critical enterprise servers against crafted attacks or progressive wipers – we can introduce you
  to our brand-new novelty detection engine based on encoders AI tools (Owlyshield Enterprise Edition).
- Have any questions or would like a presentation of our products.

<p align="right">(<a href="#top">back to top</a>)</p>

## :mechanical_arm: Contributing

We offer free access to the Owlyshield Pro Edition to our contributors.

If you discover an undetected ransomware, please open an issue with the tag "undetected" to help us improve the AI
engine and understand the new techniques used to avoid detection.

If you have suggestions on how to improve Owlyshield, you can fork the repository and create
a [pull request](https://github.com/SitinCloud/Owlyshield/compare) or simply open
an [issue](https://github.com/SitinCloud/Owlyshield/issues/new) with the tag "enhancement".

Don't forget to give the project a :star:! Thank you for your contributions.

To contribute:

1. Fork the project.
2. Create a feature branch: `git checkout -b feature/AmazingFeature`.
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`.
4. Push to the branch: `git push origin feature/AmazingFeature`.
5. Open a pull request.

<p align="right">(<a href="#top">back to top</a>)</p>

## :book: License

Distributed under the EUPL v1.2 license. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>

## :love_letter: Contact

Damien LESCOS - [@DamienLescos](https://twitter.com/DamienLescos)

- [opensource@sitincloud.com](mailto:opensource@sitincloud.com)

Project Link: [https://github.com/SitinCloud/Owlyshield/](https://github.com/SitinCloud/Owlyshield/)

Company Link: [SitinCloud](https://www.sitincloud.com)

<p align="right">(<a href="#top">back to top</a>)</p>

## :pray: Acknowledgments

* [RansomWatch](https://github.com/RafWu/RansomWatch)
* [Behavioural machine activity for benign and malicious Win7 64-bit executables](https://research.cardiff.ac.uk/converis/portal/detail/Dataset/50524986?auxfun=&lang=en_GB)

<p align="right">(<a href="#top">back to top</a>)</p>
