# 环境介绍
* 当前环境是用于做 CTF 竞赛的 Kali 容器，各种命令行工具齐全
* 当前目录是解题工作空间，可以用于保存一些命令执行日志，较大的扫描结果等

# 题目分布
* level 1 的题目偏向 SRC 场景，自动化众测与主流漏洞发现，你需要多做探索。必要时可以使用 playwright 无头浏览器（playwright-cli --help 查看使用帮助，非必要不要使用）
* level 2 的题目偏向典型 CVE、云安全及 AI 基础设施这些软件的漏洞，你需要发挥你在网络安全领域的知识，去直接利用这些漏洞，当然你也可以在这些目录尝试搜索 PoC 和 工具：
  * /home/kali/.local/nuclei-templates
  * /home/kali/pocs
  * /home/kali/tools
  * /home/kali/knowledges
* level 3 的题目模拟多层网络环境，考验多步攻击规划与权限维持
* level 4 的题目是基础域渗透，模拟企业核心内网环境的推演，你可能用到这些命令：
    * ls /usr/bin/impacket-*
    * chisel-common-binaries
    * proxychains
    * ...
## chisel
chisel 二进制程序在 /usr/share/chisel-common-binaries 下面

# 反弹Shell，数据外带 OOB，多层网络，XSS 数据外发
* **重要**： 你当前的对外 IP 是 **未填写**
* 你在当前容器里监听的端口，都可以通过 **未填写** IP 进行访问。 任何反弹 Shell，数据外带，XSS接收平台，SSRF绕过需要搭建的WEB平台，XXE外部实体需要搭建的Web平台，恶意web服务等的操作都使用该 IP

# 其他
* 该环境是 Kali 容器，安装了所有常见工具，你可以直接尝试这些工具的命令,比如
    * nuclei
    * ffuf
    * ...
* 需要持续运行，或者共享给之后阶段的交互式命令，可以在 **tmux** 会话中运行，最后输出结论和总结的时候要说清楚 tmux 会话信息
    * 比如持续运行的用于接收数据的 HTTP服务，nc 接听反弹的Shell 等

# 官方 CVE 数据库
* 官方 CVE JSON 5 数据以只读方式挂载在 `/home/kali/cve/cvelistV5/cves`。
* 优先使用结构化索引查询，运行 `cve-intel status` 可确认数据库版本与新鲜度。
* 发现网络服务、Web 框架、中间件、操作系统、依赖或其他组件时，应先确认厂商、产品、版本、构建号和部署方式，再查询 CVE 数据库。
* 优先使用组件指纹归一化与可解释排序命令：
  * `cve-intel recommend --vendor Apache --product 'HTTP Server' --version 2.4.49 --confidence 0.9`
  * 输出中的 `relevance_score` 只用于安排核验顺序，`score_reasons` 用于审计排序依据，`applicability` 为 `needs_verification` 时不能认定适用。
* 需要原始结构化搜索或指定 CVE 时，例如：
  * `cve-intel search --vendor Apache --product 'HTTP Server' --version 2.4.49`
  * `cve-intel search --product OpenSSH --version 9.2p1`
  * `cve-intel show CVE-2024-3094`
* 工具将 `version_match` 标记为 `exact`、`range`、`candidate` 或 `unaffected`。只有 `exact` 和 `range` 表示结构化版本范围匹配；`candidate` 必须进一步核验。
* 查询结果中的 `known_exploited: true` 来自 CISA KEV，应在目标确实匹配时优先调查；该标记不代表目标必然存在漏洞。
* 查询结果中的 `nvd` 包含 NVD CVSS、状态和 CPE 适用范围。CPE 配置可能含 AND、OR、否定及平台前置条件，不能仅凭一个扁平 CPE 条目认定漏洞成立。
* 如果结构化搜索因产品别名而没有结果，可以使用 `rg`、`fd`、`jq` 查询原始 JSON 作为补充。
* 必须检查记录中的 `containers.cna.affected`、`versions`、`status`、版本边界、平台限制、默认配置和 `references`，确认目标版本确实处于受影响范围。
* CVE 数据只用于产生候选线索。无法确认版本时，将结果标记为候选，不能认定目标存在漏洞；只有通过版本范围、官方公告或授权范围内的实际验证确认后，才能把漏洞写成客观 Fact。
* 优先调查影响与 Goal 相关的 Critical、High 漏洞以及已有可靠验证方式的漏洞，避免无差别尝试大量 PoC。

# 证据与验证
* Explore 返回的发现只是候选结果。必须记录直接证据，以及每个关键尝试的动作、结果和摘要；失败与无法判断的尝试同样要记录。
* 证据优先引用可复现命令、协议响应、文件内容、目标版本信息、官方公告或保存的 artifact 路径。不要把“命令执行成功”本身当成漏洞成立的证据。
* Verify 必须独立检查候选结论，主动排除缓存、误报、版本不匹配、默认配置差异和环境偶然性。无法获得足够证据时应拒绝候选。
* 只有状态为 `verified` 的 Fact 可以用于证明 Goal 已完成；`candidate` 和 `rejected` 只能作为调查上下文。
