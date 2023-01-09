<div id="top"></div>

Translations:

- Chinese: / 中文: <a href=./README_CN.md>README_CN</a>
- Español: <a href=./README_ES.md>README_ES</a>
- Français: <a href=./README_FR.md>README_FR</a>
  <br />

<div align="center">
  <a href="https://github.com/SitinCloud/Owlyshield">
    <img src="./Misc/logo_transparent.png" alt="Logo" width="150" height="150">
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

<p align="center">
	<img src="./pca_3d.gif" alt="Gif Demo Owlyshield" style="align:center; width: 75%">
</p>

## :owl: The owl's hoot: troubles-hoot!

Owlyshield is an open-source, AI-driven antivirus engine written in [Rust](https://rust-lang.org). Traditional antivirus
software, which uses static analysis, can only detect known threats. This is why ransom attacks have been on the rise,
as hackers can easily adapt and avoid detection. Owlyshield addresses this issue by using behavioural analysis to detect
and terminate ransomwares in their early stages of execution.

To ensure that the application runs efficiently, we have implemented multithreading and machine learning algorithms such
as random forests, which are known for their speed of computation. We have also put a significant amount of effort into
optimizing the performance of Owlyshield.

## :vulcan_salute: Open-source philosophy

At [SitinCloud 🇫🇷](https://www.sitincloud.com), we are firm believers that cybersecurity products should always be
open-source:

1. In addition to the source code, we provide comprehensive documentation in the form of a
   complete [wiki](https://github.com/SitinCloud/Owlyshield/wiki) and code documentation.
2. Open-source products can be considered as sovereign solutions, as there is no risk of any foreign agency introducing
   hidden backdoors or mass surveillance features that users may not be aware of.
3. We have included specific entry points in the code to facilitate easy integration with third-party tools, such as
   SIEM and EDRs.

## :arrow_forward: 2 minutes install

We release installers regularly in the [Releases](https://github.com/SitinCloud/Owlyshield/releases) section on GitHub.
The Free Edition (community edition) is fully functional and will effectively protect your system against ransomwares.
You no longer need to start Windows in test-signing mode, as the signed driver is now included in the community version.

For usage instructions, refer to the [Wiki](https://github.com/SitinCloud/Owlyshield/wiki) or
see [Contributing](#-mechanicalarm--contributing) if you prefer to build Owlyshield yourself. Suggestions and feature
requests are welcome – see the [open issues](https://github.com/SitinCloud/Owlyshield/issues) for a full list of
proposed features and known issues.
<p align="right">(<a href="#top">back to top</a>)</p>

## :money_mouth_face: Business

### :arrow_upper_right: Free vs Pro editions

The Pro Edition (commercial edition) includes the following features:

- A web app that gathers all incident data to help IT staff understand the scope of an attack within a company's
  networks and take appropriate action (or classify it as a false positive).
- Interfaces with log management tools (we even provide an API).
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

## :nerd_face: Technical

### :gear: How does it work?

1. A minifilter (a file system filter driver) intercepts I/O request packets (IRPs) to collect metadata about disk
   activity (*DriverMsg* in the sources).
2. *Owlyshield-predict* uses the previously created *DriverMsgs* to compute features submitted to an RNN (a special type
   of neural network that works with sequences). Both behavioural and static analysis are performed.
3. If the RNN predicts a malware, owlyshield-predict asks the minifilter to kill the malicious processes and send a
   detailed report about the incident to your SIEM tools (or to a local file).

<img src="./Misc/Architecture2.png" alt="Architecture" style="align:center">

### :robot: How was the model trained?

The model was trained on real-world malware samples collected from various sources on the internet (dark web, shared
with researchers, and analysis of thousands of downloads using VirusTotal).

We ran the malware samples on Windows VMs with Owlyshield in record mode (`--features record`) to save the IRPs.
Owlyshield-predict with `--features replay` was then used to create the learning dataset (a CSV file).

The [Malwares-ML](https://github.com/SitinCloud/malwares-ml) repository is the place where we share some of our learning
datasets.
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
