# sing-box 远程规则

现有原生 sing-box JSON 是客户端的规则来源。客户端不下载 Surge 文本，也不需要把规则复制进主配置。

- `Reject.json`、`USproxyRules.json`、`MyDirectRules.json`：保持既有 URL。
- `USproxyRules-domain.json`、`MyDirectRules-domain.json`：从上述原生 JSON 导出的纯域名子集，仅用于 DNS 选择，避免把目的 IP 条件误当成 DNS 返回地址筛选。
- `USproxyRules-app.json`、`MyDirectRules-app.json`：用户原始 sing-box 配置中的桌面进程和 Android 包名，独立维护；不是从 Surge 补写的分类规则。
- `LAN.json`：局域网规则；`SYSTEM.json`：与 Surge 内置 SYSTEM 对应的系统服务规则。两者不混用。

`USproxyRules.json` 原先的 `ip_asn` 不被官方 sing-box 接受，现转换为 RIPE 当前公告前缀，保留显式 IP 和两个 /8。RIPE 前缀与 Surge ASN 数据库并非精确同源；获取失败时同步任务失败，不发布缺失 ASN 的规则。

既有 `Sync from Surge` 工作流保留原同步机制，只在发布前调用 `.github/scripts/prepare_native_rules.py`，防止旧转换再次写回不支持的字段。该脚本只处理当前配置用到的原生 JSON，未重写上游 Surge 转换器，也不修改 Surge 仓库。其它分类规则没有加入客户端配置，本次也未修改。

行为契约：规则内容与出口由用户决定；脚本只修复格式、导出等价子集、分离 LAN/SYSTEM。主配置、节点密码、证书、Tailscale 登录状态不得提交到本仓库。

验证：Python 标准库单元测试与 sing-box 1.14.0-rc.5 配置/规则集检查。主配置接管系统网络的运行测试不属于这些静态检查。
