/*
 * Chingtsi WAF - 配置加载
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 运行时配置。所有项均可通过 conf/waf.properties 覆盖，缺省值即可直接运行。
 */
public record WafConfig(
        String listenHost,
        int listenPort,
        int workerThreads,
        String upstreamBase,
        long upstreamTimeoutMs,
        String serverName,
        long maxBodyBytes,
        int defaultScore,
        int inboundThreshold,
        int outboundThreshold,
        Path ruleDir,
        Path whitelistFile,
        Path blacklistFile,
        Path logFile,
        boolean logJson,
        int logFlushEvery,
        int rateWindowSeconds,
        int rateLimit,
        int banSeconds,
        String blockPageTitle,
        boolean trustCfConnectingIp,
        String allowMethods,
        boolean iisAuto,
        String iisConfigFile,
        String iisFrontMap,
        int iisRefreshSeconds
) {

    /** IIS 配置文件覆盖路径（空表示用系统默认位置）。 */
    public java.util.Optional<Path> iisConfigPath() {
        if (iisConfigFile == null || iisConfigFile.isBlank()) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(Path.of(iisConfigFile.trim()));
    }

    public static WafConfig load(Path file) {
        Map<String, String> p;
        if (Files.isRegularFile(file)) {
            try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                p = parse(r);
            } catch (IOException e) {
                throw new UncheckedIOException("读取配置失败: " + file, e);
            }
        } else {
            p = new LinkedHashMap<>();
            System.out.println("[WARN ] 配置文件不存在，全部使用内置默认值: " + file);
        }

        Path confDir = file.toAbsolutePath().getParent();
        Path root = confDir;
        if (confDir != null && confDir.getFileName() != null
                && "conf".equalsIgnoreCase(confDir.getFileName().toString())) {
            root = confDir.getParent();
        }
        if (root == null) {
            root = Path.of(".").toAbsolutePath();
        }

        String rootPath = root.toString();
        String rp = rootPath + java.io.File.separator;

        return new WafConfig(
                str(p, "listen.host", "0.0.0.0"),
                num(p, "listen.port", 8080),
                num(p, "worker.threads", 128),
                str(p, "upstream.base", "http://127.0.0.1:80"),
                lng(p, "upstream.timeout.ms", 30_000L),
                str(p, "server.name", "Chingtsi-WAF"),
                lng(p, "max.body.bytes", 10L * 1024 * 1024),
                num(p, "score.default", 5),
                num(p, "threshold.inbound", 5),
                num(p, "threshold.outbound", 4),
                path(root, p, "rule.dir", "rules"),
                path(root, p, "ip.whitelist", "conf/ip-whitelist.txt"),
                path(root, p, "ip.blacklist", "conf/ip-blacklist.txt"),
                path(root, p, "log.file", "logs/waf.log"),
                bool(p, "log.json", true),
                num(p, "log.flush.every", 1),
                num(p, "rate.window.seconds", 60),
                num(p, "rate.limit", 600),
                num(p, "rate.ban.seconds", 300),
                str(p, "block.page.title", "Chingtsi WAF · 访问被拦截"),
                bool(p, "trust.cloudflare.ip", true),
                str(p, "allow.methods", "GET,POST,HEAD,OPTIONS,PUT,DELETE,PATCH"),
                bool(p, "iis.auto", true),
                str(p, "iis.config.file", ""),
                str(p, "iis.front.map", ""),
                num(p, "iis.refresh.seconds", 20)
        );
    }

    /**
     * 逐行解析 key = value。不使用 java.util.Properties，避免 Windows 路径中的
     * 反斜杠被当作转义符吃掉，用户可直接写 C:\path\to\file。
     */
    private static Map<String, String> parse(Reader reader) throws IOException {
        Map<String, String> map = new LinkedHashMap<>();
        BufferedReader br = new BufferedReader(reader);
        String line;
        while ((line = br.readLine()) != null) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#") || t.startsWith("!") || t.startsWith(";")) {
                continue;
            }
            int eq = t.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            map.put(t.substring(0, eq).trim(), t.substring(eq + 1).trim());
        }
        return map;
    }

    private static Path path(Path root, Map<String, String> p, String key, String def) {
        String v = str(p, key, def);
        Path candidate = Path.of(v);
        return candidate.isAbsolute() ? candidate : root.resolve(v).normalize();
    }

    private static String str(Map<String, String> p, String key, String def) {
        String v = p.get(key);
        if (v == null) {
            return def;
        }
        v = v.trim();
        return v.isEmpty() ? def : v;
    }

    private static int num(Map<String, String> p, String key, int def) {
        try {
            return Integer.parseInt(str(p, key, String.valueOf(def)));
        } catch (NumberFormatException e) {
            System.out.println("[WARN ] 配置项 " + key + " 非整数，使用默认值 " + def);
            return def;
        }
    }

    private static long lng(Map<String, String> p, String key, long def) {
        try {
            return Long.parseLong(str(p, key, String.valueOf(def)));
        } catch (NumberFormatException e) {
            System.out.println("[WARN ] 配置项 " + key + " 非整数，使用默认值 " + def);
            return def;
        }
    }

    private static boolean bool(Map<String, String> p, String key, boolean def) {
        String v = str(p, key, String.valueOf(def));
        return "true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v);
    }
}
