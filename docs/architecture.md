# 架构说明

## 进程模型

Chingtsi WAF 是独立进程，作为站点前置的反向代理存在，**不修改 IIS 配置、不注册 HTTP 模块**：

```
客户端 ──▶ WAF 监听端口 ──▶ 检测链 ──▶ HttpClient ──▶ IIS 127.0.0.1:<站点端口>
                                   └─▶ 403 拦截页（命中规则时短路）
```

- 入口：`WafMain` 解析 `-Dwaf.home`（默认工作目录）、加载 `conf/waf.properties`、初始化日志与地理库，然后交给 `ListenerManager`。
- 监听：`com.sun.net.httpserver.HttpServer`，每个前置端口一个实例，共用线程池（`worker.threads`）。
- 转发：`java.net.http.HttpClient`（HTTP/1.1），保留原方法、路径、查询串与主体，补齐 `X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host`。

## 请求生命周期

1. **取真实 IP**：`trust.cloudflare.ip=true` 时优先 `CF-Connecting-IP`，其次 `X-Forwarded-For` 首段，最后 socket 地址。
2. **名单判定**：白名单命中直接放行（跳过全部检测）；黑名单命中直接 403。
3. **限流**：`RateLimiter` 以 IP 为键维护滑动窗口，超限封禁 `rate.ban.seconds`。
4. **规则评估**：`RuleEngine` 逐条取值、匹配，命中则累加 `score`；累计值达到 `threshold.inbound` 立即判定拦截。
5. **转发或拦截**：放行时转发到上游并回写响应（隐藏 `Server` 头）；拦截时返回 `BlockPage`。
6. **审计**：`AccessLog` 以 JSON Lines 落盘，同时通过 `WafEventLog` 供控制台读取。

规则评估对 URL 路径、查询串、参数与主体同时保留**原始值**和**一次解码值**，因此 `%27%20or%201%3D1` 这类编码绕过仍会命中。

## IIS 自动防护

| 类 | 职责 |
| --- | --- |
| `iis.IisConfigReader` | 解析 `applicationHost.config`：站点名、状态、绑定的 HTTP 端口与主机名 |
| `iis.IisSite` / `iis.IisBinding` | 站点与绑定的值对象 |
| `iis.IisSnapshot` | 一次解析的完整快照（站点列表 + 采集时间） |
| `iis.IisFrontPorts` | 端口规划：显式映射优先，否则最小站点端口沿用 `listen.port`，其余 `+8000`，冲突 `+1000` |
| `iis.IisMonitor` | 后台定时刷新（`iis.refresh.seconds`），与上一份快照比对后通知 `ListenerManager` 增删监听 |

要点：

- 前置端口永不等于 IIS 站点端口，避免端口冲突；
- 快照差分只增删变化的端口，不会全量重启监听；
- 解析失败（无 IIS、权限不足、文件被锁）时保留当前监听，并回落固定 `listen.port`。

## 控制台

- `DashboardMain` 构建四页界面，每 2 秒轮询一次状态与日志增量；
- `ui.WafEventLog` 解析 `logs/waf.log`（JSON Lines）为事件对象，支持按关键字/属地过滤与 CSV 导出；
- `ui.UiKit` 统一外观、图标（多尺寸 PNG 取最接近档位绘制）与地理库格式化；
- 未引入 FlatLaf 时自动回退系统外观，保证只带 JDK 也能启动。

## 打包

`installer/build-installer.bat` 负责：

1. 调用根目录 `build.bat` 生成 `dist\chingtsi-waf.jar`（版本取 `VERSION` 文件）；
2. `jlink` 生成裁剪运行时（`java.base`, `java.logging`, `java.net.http`, `jdk.httpserver`, `java.desktop`）；
3. 组装 `dist\stage`（运行时 / jar / 配置 / 规则 / 图标 / WinSW 服务包装器）；
4. 调用 `ISCC` 编译安装程序。

注意：`jlink` 不接受含非 ASCII 字符的输出路径（例如中文用户名目录），因此脚本先在 `%TEMP%\chingtsi-waf-runtime` 生成运行时，再复制进 `dist\stage\runtime`。

安装脚本把服务注册放在 `CurStepChanged(ssPostInstall)`，带 1.5 秒退避重试 3 次——`WinSW install` 在首次执行时可能直接返回非 0，放在 `[Run]` 段会导致服务未注册。

## 已知取舍

- 只用 JDK 标准库，不引入 Netty/Spring，规则引擎因此保持"够用即可"；
- 配置解析为自研实现（`WafConfig`），因为 `java.util.Properties` 会吞掉 Windows 路径里的反斜杠；
- 控制台直接读日志文件而非内置数据库，便于运维接管与多工具复用。
