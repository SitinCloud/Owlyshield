# Owlyshield

[![Owlyshield](https://www.sitincloud.com/wp-content/uploads/2019/05/cropped-favicon_owlyshield-1.png)](https://www.sitincloud.com)
contact@sitincloud.com


我们坚定地相信，网络安全的相关产品应当是开源的open-source
1. 关于贵公司网络安全战略的关键决策，不能仅基于各类营销宣传。
2. 运用第三方工具，甚至在客户端创建应用程序界面，这个过程应该简易化，至少可以实现。
3. 安装的时候，检查网络安全相关软件没有给您的公司添加新的漏洞是至关重要的事情。使用仅攻击者知道漏洞的闭源产品是无法做到这一点的。(请看涉及 fortinet 的现实生活示例)

Owlyshield 是一个开源的 AI 驱动的基于分析病毒行为的反病毒引擎，用 Rust 编写。
截至目前，该模型**经过专门训练以检测和杀死勒索软件**，但我们认为该技术可以用于检测其他恶意软件类别。


## 为什么还有另一种产品可以抵御勒索软件的侵害？

网络安全是一种攻击者比受害者更具有显著优势的游戏 : 
* 先进的武器可免费或以极低的成本获得
* 加密货币使收集赎金和洗钱变得容易且无风险
* 众多的小型企业甚至中型企业使用大量的第三方软件，但是他们对这些软件一无所知并且根本无法控制。


我们每天都可以看到 :
* 许多关键软件，例如每天用于管理各类公司核心活动的ERP软件，它们充满着等待被利用的安全漏洞，以及各类逃避责任的编辑（*“我们没有赏金计划，只能将这些软件隐藏在 VPN 后面”*）
* 许多关键的国家组织和大公司成为不为人知的攻击的受害者（例如，今年法国的 Sopra-Steria 和三家公立医院受到了 Ryuk Ransomware 的严重打击）
* IT 服务业完全依赖于他们一无所知的封闭式专有安全产品（*“我们去年因勒索软件而丢失了数据库。但现在我们购买了 *XYZ* 并感到受到保护”*）。这并不是一个合理的防御策略。


## 社区版VS商业版

两个版本共享相同的源代码。商业版增加了以下功能 :
* 微过滤器的驱动程序签名，允许在无需测试Windows签名模式的情况下下启动安装它。
* 这是一个收集所有事件数据的网络应用程序，以帮助 IT 人员了解公司网络内的攻击范围并采取相应行动（或将其归类为误报）
* 与您的日志管理工具的接口（我们提供 API）
* 自动更新整个应用程序的计划任务


# 工作原理 - 概述

流程创建定义了一个家谱，其中节点具有唯一的父节点。所有进程都是 Windows *System* 进程 (pid = 4) 的子进程。这允许我们定义由组 ID 标识的子家族（这显然与 Linux 无关）：

![家谱流程](https://www.sitincloud.com/wp-content/uploads/2019/05/gid_trees.jpg)

Owlyshield 使用 RNN 收集和分析有关输入和输出 (I/O) 的元数据，以监视和终止可疑进程。

![组件](https://www.sitincloud.com/wp-content/uploads/2019/05/Architecture.jpg)

截至目前，该模型已专门针对勒索软件进行了系统的训练（我们的训练示例集基数超过 110,000 个勒索软件）。


# 组成部分

Owlyshield 由以下组件组成：
* 运行时组件：
	* Owlyshield Predict - 预测单元（用户空间）从微过滤器收集数据以对正在运行的进程进行预测。这是一个依赖于微过滤器的 Windows 服务
	* 安装程序 - 使安装更容易（创建两个 predict 和 minifilter 服务及其注册表项）
	* RustWinToast - Toast 通知的基本 exe
* 驱动组件：
	* Owlyshield Minifilter - 驱动程序（用户空间），拦截 I/O 操作并处理将由 *Owlyshield Predict* 使用的创建。微过滤器还负责杀死可疑进程家族
* 深度学习：
	* 用于训练模型和创建 *Owlyshield Predict* 使用的 tflite 文件的 Keras 脚本
	
我们计划在未来向社区提供以下组件：
* 通过我们正在开发的新在线平台向网络安全研究人员发送恶意软件，包括我们用来训练模型的 100,000 个勒索软件


# 构建说明
## 先决条件

您需要先安装：
1. Rust 来自 [rust-lang.org](https://rust-lang.org)（如果从 choco 获得，请注意采用 *Visual Studio ABI* 版本）
2. VS Studio 2017/2019 带C++工具（一些依赖比如winlog需要link.exe）
3. Windows 驱动程序套件 (WDK)
4.（可选）[InnoSetup](https://jrsoftware.org/isdl.php)，用于构建安装程序


## Owlyshield 预测

要构建服务，请运行 ```cargo build --release --features service```
<br/>
要将其构建为控制台应用程序（用于调试目的），请运行 ```cargo build```
**确保在生成的 .exe 文件附近手动复制目标/调试和目标/发布中的 Moonlitefire-tflite/lib/tensorflow_lite_c.dll。**


## RustWinToast

要构建它，请运行 ```cargo build --release```

## Owlyshield 微型过滤器

1.在VS中打开*OwlyshieldMinifilter/OwlyshieldMinifilter.sln*
2.确保配置管理器设置为x64
3. 构建解决方案。这将构建驱动程序

请注意，微过滤器的功能范围可能不会经常更改，并且发布的 .sys 文件可能会让您跳过此步骤。

##安装程序
1. 在 InnoSetup 中打开 *owlyshield-ransom-community.iss*
2. 编译安装程序。这将构建 *owlyshield-ransom-community.exe*（或从 InnoSetup 运行它）。

重要内容：
* *Owlyshield Predict* 可执行文件从 */target/release* 中检索
* *rust_win_toast* 可执行文件从 */target/release* 检索
* *Owlyshield Minifiter* sys、cat 和 inf 文件是从 */x64/Debug/FsFilter* 检索的，发布版本需要签名证书并不总是容易设置的。

## 使用的资料
*Owlyshield Predict* 用作依赖项的 Rust 板条箱：
 
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
- moonfire-tflite (我们必须对其进行一些更改）


# 作者
* 达米安·莱斯科斯
* 阿兰德·奥伊赫纳特
* 皮埃尔·罗杰


# 版权

微过滤器和 Gid 的想法很大程度上基于
https://github.com/RafWu/RansomWatch by @RafWu，在 MIT 许可下。

# 许可证
根据 EUPL v1.2 获得许可。请参阅许可证.txt。