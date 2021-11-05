# Owlyshield

<img src="https://www.sitincloud.com/wp-content/uploads/2019/05/gif_demo_owlyshield.gif" alt="Gif Demo Owlyshield">

[![Owlyshield](https://www.sitincloud.com/wp-content/uploads/2019/05/cropped-favicon_owlyshield-1.png)](https://www.sitincloud.com)
[![Discord](https://img.shields.io/badge/discord-join-blue.svg)](https://forms.gle/Cn6pynGmY2zuaPsz6) [![Email](https://img.shields.io/badge/email-join-blue.svg)](mailto:register@sitincloud.com) (mailto:register@sitincloud.com)


We at SitinCloud strongly believe that cybersecurity products should always be open-source:

1. Critical decisions about your company cybersecurity strategy cannot be based only on marketing propaganda
2. Interface the software with third-party tools, or even customize it, should be easy, or at least possible
3. Check the software does not add a new vulnerability to your organisation is critical. This cannot be done with closed sources products whose vulnerabilities are only known from attackers (see [our blog](https://www.sitincloud.com/2021/09/10/fortinet-leak/) for a real life example involving fortinet)

Owlyshield is an open-source AI-driven behaviour based antivirus engine written in Rust. 
As of now, the model was **specifically trained to detect and kill ransomwares** but we think this technology can be used in a more general way to detect other malwares categories.


## Why still another product against ransomwares ?

Cybersecurity is a game where attacking players have a significant advantage over their victims:
* Sophisticated weaponry is available for free or at very little cost
* Crypto-currencies have made collecting ransom and laundering it easy and risk-free
* SMEs and even mid-caps use a plethora of third-party softwares over which they have no knowledge or control


What we see everyday:

* Critical sofwares, used daily to manage company core activities like ERPs, full of security holes waiting to be exploited, and editors shirking their resposabilities (*"we have no bounty program, hide it behind a VPN"*)
* Critical state organisations and large corporations be victims of unsubtle attacks (for example, Sopra-Steria and three public hospitals were severy hit by the Ryuk Ransomware in France this year)
* IT services relying entirely on closed proprietary security products they don't know anything about (*"We lost our data with a ransomware last year. But now we bought *XYZ* and feel protected"*). This is not a sound defense strategy


## Community vs commercial versions

Both versions share the same source code. The commercial version adds the following features:

* Driver signing of the minifilter, allowing it to be intalled without having to start Windows in test-signing mode
* A webapp gathering all incidents data to help IT staff to understand the scope of the attack within the company networks and act accordingly (or classify it as a false positive)
* Interfaces with your log management tools (we even provide an API)
* Scheduled tasks to auto-update the whole application


# How it works - Overview

Processes creation defines a family tree where nodes have a unique parent. All processes are children of the Windows  *System* process (pid = 4). This allows us to define subfamilies identified by a group id (which obviously has nothing to do with the Linux one):

![Processes family tree](https://www.sitincloud.com/wp-content/uploads/2019/05/gid_trees.jpg)

Owlyshield collects and analyse meta-data on inputs and outputs (I/O) using a RNN to monitor and kill suspect processes.

![Components](https://www.sitincloud.com/wp-content/uploads/2019/05/Architecture.jpg)


As of now, this model has been trained exclusively on ransomwares (our training exemples set cardinality exceeds 110,000 ransomwares).


# Components

Owlyshield consists of the following components:
* Runtime components:
  * Owlyshield Predict - the prediction unit (user space) collects data from the minifilter to make prediction about running processes. This is a Windows service that depends on the minifilter
  * Installer - to make the installation easier (creation of the two predict and minifilter services and their registry keys)
  * RustWinToast - a basic exe to toast notifications
* Driver components:
  * Owlyshield Minifilter - the driver (user space), intercepts i/o operations and processes creations that will be used by *Owlyshield Predict*. The minifilter is also responsible for killing suspect processes families
* Deep Learning:
  * Keras script used to train the model and create the tflite file used by *Owlyshield Predict*
	
We plan to make the following components available to the community in the next future:
* The malwares to cybersecurity researchers through a new online platform we are working on, including the 100,000 ransomwares we used to train our model


# Build Instructions

## Prerequisites

You need to install first: 
1. Rust from [rust-lang.org](https://rust-lang.org) (pay attention to take the *Visual Studio ABI* version if you get it from choco)
2. VS Studio 2017/2019 with C++ tools (some dependencies like winlog need link.exe)
3. Windows Driver Kit (WDK)
4. (Optional) [InnoSetup](https://jrsoftware.org/isdl.php), used to build the installer


## Owlyshield Predict

To build the service, run ```cargo build --release --features service```
<br/>
To build it as a console app (for debug purposes), run ```cargo build``` 

**Make sure to manually copy moonlitefire-tflite/lib/tensorflow_lite_c.dll in target/debug and target/release, near to your generated .exe file.** 


## RustWinToast

To build it, run ```cargo build --release```


## Owlyshield Minifilter

1. Open *OwlyshieldMinifilter/OwlyshieldMinifilter.sln* in VS
2. Make sure the configuration manager is set to x64
3. Build the solution. This builds the driver

Please note the minifilter functional scope may not be changed often and that the released .sys file may let you skip this step.

## Installer

1. Open *owlyshield-ransom-community.iss* in InnoSetup
2. Compile the installer. This builds *owlyshield-ransom-community.exe* (or run it from InnoSetup).

Important: 
* The *Owlyshield Predict* executable is retrieved from */target/release*
* The *rust_win_toast* executable is retrieved from */target/release*
* The *Owlyshield Minifiter* sys, cat and inf files are retrieved from */x64/Debug/FsFilter* because the release build needs a signing certificate, which is not always easy to set up


## Librairies used

Rust crates used as dependencies by *Owlyshield Predict*: 
- windows
- wchar
- widestring
- sysinfo
- registry
- strum
- strum_macros
- byteorder
- chrono
- num
- num-derive
- num-traits
- serde_json
- serde
- log
- winlog
- windows-service
- winrt-notification
- moonfire-tflite (we had to make some changes in it)


# Community

* Join to Discord [![Discord](https://img.shields.io/badge/discord-join-blue.svg)](https://forms.gle/Cn6pynGmY2zuaPsz6) 


# Authors

* Damien LESCOS
* Allande OYHENART
* Pierre ROGER


# Copyright

The minifilter and Gid idea are heavily based on https://github.com/RafWu/RansomWatch by @RafWu, under the MIT licence.


# License

Licensed under EUPL v1.2. See LICENCE.txt.
