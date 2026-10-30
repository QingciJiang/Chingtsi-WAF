# 规则参考

规则文件放在 `rules/`，按文件名顺序加载（`010-` → `900-`）。每行一条 `SecRule`，`#` 开头为注释。规则目录每 5 秒比对一次指纹，改动后自动热加载。

## 语法

```
SecRule <变量[|变量...]> "<操作符> <参数>" "id:<编号>,score:<分值>,msg:'<说明>',action:<block|pass>"
```

示例：

```
SecRule ARGS|REQUEST_URI|REQUEST_BODY "@rx (?:\bunion\b[\s/**/]+\bselect\b)" "id:2001,score:5,msg:'SQL 注入：union select',action:block"
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 规则唯一编号，建议按文件段位分段（1000 协议 / 2000 SQLi / 3000 XSS / 4000 RCE-LFI / 5000 敏感路径 / 9000 自定义） |
| `score` | 否 | 命中加分，缺省取 `score.default` |
| `msg` | 否 | 日志与事件列表中的说明文本 |
| `action` | 否 | `block`（默认，返回 403）或 `pass`（仅记分不拦截） |

## 可用变量

| 变量 | 取值 |
| --- | --- |
| `REQUEST_URI` | 路径 + 查询串 |
| `REQUEST_FILENAME` / `REQUEST_PATH` | 仅路径 |
| `QUERY_STRING` | 仅查询串 |
| `REQUEST_BODY` | 请求体文本（上限由 `max.body.bytes` 控制） |
| `REQUEST_METHOD` | 方法 |
| `REQUEST_LINE` | `METHOD URI PROTOCOL` |
| `REMOTE_ADDR` | 客户端真实 IP |
| `ARGS` / `REQUEST_ARGS` | 所有参数名与值 |
| `ARGS_NAMES` | 仅参数名 |
| `REQUEST_COOKIES` / `REQUEST_COOKIES_NAMES` | Cookie 头 |
| `REQUEST_HEADERS` | 所有头（名与值） |
| `REQUEST_HEADERS:<Name>` | 指定头，如 `REQUEST_HEADERS:User-Agent`、`REQUEST_HEADERS:Host` |

多个变量用 `|` 组合，任一命中即算本条命中。除 `REQUEST_METHOD`、`REMOTE_ADDR` 等原值字段外，路径、查询串、参数、主体都会同时提供**原始值**与**一次 URL 解码值**。

## 操作符

| 操作符 | 含义 | 示例 |
| --- | --- | --- |
| `@rx` | 正则（Java 语法） | `"@rx (?:\bunion\b[\s/**/]+\bselect\b)"` |
| `@pm` | 多关键词（空格分隔，任一命中） | `"@pm sqlmap nikto nmap"` |
| `@contains` | 子串包含 | `"@contains ../"` |
| `@streq` | 全等 | `"@streq HEAD"` |
| `@eq` / `@gt` / `@ge` | 数值比较 | `"@gt 10485760"` |
| `@beginsWith` / `@endsWith` | 前后缀 | `"@endsWith .php"` |

参数中如需单/双引号，请写 `\x27` / `\x22`，避免与规则行引号冲突。

## 编写建议

1. **按类别分文件**，编号连续，便于定位；
2. 高危特征给 `score:5`，可疑特征给 `score:3~4`，配合阈值避免单条规则造成误杀；
3. 会误伤正常业务的规则先用 `action:pass` 观察日志，确认后再改 `block`；
4. 正则尽量锚定边界（`\b`、`^`、`$`），不要写 `.*select.*` 这类宽泛匹配；
5. 自定义规则放 `900-custom.conf`，升级安装不会覆盖 `rules` 目录。

## 验证

```bash
# 白名单默认包含 127.0.0.1：本机自测请换源地址，否则检测被跳过
curl.exe --interface 127.0.0.2 "http://127.0.0.1:8091/?id=1%20union%20select%201,2,3"
# 期望：403 + 拦截页，logs/waf.log 出现对应规则 id
```

> 直接用 `curl 127.0.0.1` 测试得到"未拦截"是白名单造成的假象，不代表规则失效。
