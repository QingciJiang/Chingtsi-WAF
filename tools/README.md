# tools/

打包所需的第三方可执行文件不进入 Git 仓库（`.gitignore` 已忽略），请按需放到本目录。

| 文件 | 用途 | 获取方式 |
| --- | --- | --- |
| `WinSW-x64.exe` | 把 Java 进程注册为 Windows 服务 | https://github.com/winsw/winsw/releases （下载 `WinSW-x64.exe`，v3.x） |
| `ISCC.exe` | 编译 Inno Setup 脚本（一般已安装在系统路径） | https://jrsoftware.org/isdl.php （Inno Setup 6.7+） |

## 放置位置

```
tools\WinSW-x64.exe
```

`installer\build-installer.bat` 会依次查找：`tools\WinSW-x64.exe` → `%ProgramFiles%\WinSW\WinSW-x64.exe` → `PATH` 中的 `WinSW-x64.exe`。
`ISCC.exe` 同理：`%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe` → `PATH`。

## 许可

- WinSW：MIT
- Inno Setup：Inno Setup License（允许自由分发由其生成的安装包）

两者仅用于生成安装包，不会被复制进源码许可范围，详见根目录 `THIRD-PARTY-NOTICES.md`。

## 只想要 jar

不需要安装包时完全可以跳过本目录，直接 `build.bat` 产出 `dist\chingtsi-waf.jar`。
