# 离线 IP 地理库

`IpLocator` 读取本目录下的 `ip2region.db`，用于解析访问者 IP 属地（省/市）。

## 为什么不入库

该文件约 8.3 MB 的二进制索引，版本更新频繁，不适合放进 Git 历史。`.gitignore` 已忽略 `data/*.db`。

## 获取方式

需要 **ip2region v1 格式**（16 字节头部 + 小端序索引）：

```bat
curl -L -o data\ip2region.db ^
  https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region.db
```

或从 https://github.com/lionsoul2014/ip2region 的 `data` 目录下载后放入本目录。

## 缺失时的行为

- 控制台「属地」列固定显示 `-`，其余功能不受影响；
- 「防护配置」页的地理库状态会显示「未加载」；
- 内网 / 环回地址仍会显示 `内网`、`本机`，不需要查库。

## 打包安装包时

`installer\build-installer.bat` 会把本目录的 `ip2region.db` 一并打进安装包（安装到 `<安装目录>\data`）。库里没有该文件时安装包照常生成，只是不带属地数据。

## 校验

打开控制台「防护配置」页，地理库状态会显示库文件路径与索引条数，例如：

```
C:\Program Files\Chingtsi WAF\data\ip2region.db（索引 1181104 条）
```

也可以用系统属性指定其他位置：`-Dwaf.geodb=D:\geo\ip2region.db`。
