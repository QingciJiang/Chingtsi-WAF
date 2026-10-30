# Third-Party Notices

Chingtsi WAF 源码本身以 Apache License 2.0 发布。下列第三方组件仅以二进制或构建工具形式参与打包与运行，其版权归各自作者所有。

## 运行期依赖

### FlatLaf 3.5.4

- 用途：Swing 现代外观（图形控制台）
- 文件：`lib/flatlaf.jar`
- 许可：Apache License 2.0
- 版权：Copyright (C) 2019-2024 FormDev Software GmbH
- 项目主页：https://github.com/JFormDesigner/FlatLaf

## 可选数据

### ip2region (v1 数据库)

- 用途：离线 IP 属地定位，`data/ip2region.db`
- 许可：Apache License 2.0
- 版权：Copyright (c) 2015-2024 lionsoul2014 及各贡献者
- 项目主页：https://github.com/lionsoul2014/ip2region
- 说明：数据库文件不随源码仓库分发，运行时按需下载（见 `data/README.md`）。

## 打包工具（不随源码分发）

| 组件 | 版本 | 许可 | 用途 |
| --- | --- | --- | --- |
| Inno Setup | 6.7.3 | Inno Setup License（允许免费分发安装包） | 生成 Windows 安装程序 |
| WinSW | 3.x | MIT | 将 Java 进程注册为 Windows 服务 |
| OpenJDK (jlink) | 17+ | GPLv2 + Classpath Exception | 裁剪运行时 |

## 设计参考（未复制源码）

- ModSecurity `SecRule` 语法与变量命名：https://github.com/owasp-modsecurity/ModSecurity
- OWASP Core Rule Set 异常评分思路：https://github.com/coreruleset/coreruleset

规则文本为独立编写，仅沿用公开的语法形式与分类经验。
