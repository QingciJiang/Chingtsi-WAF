/*
 * Chingtsi WAF - 反向代理型 Web 应用防火墙
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 *
 * 设计参考：ModSecurity v3 引擎架构 + OWASP CRS 异常评分模型（Apache-2.0）
 * 本项目为独立实现，未复制上述项目的源代码。
 */
package com.chingtsi.waf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

/**
 * 程序入口。
 * <p>启动顺序：加载配置 → 加载规则 → 加载 IP 名单 → 启限流器 → 启 HTTP 服务。</p>
 */
public final class WafMain {

    public static final String PRODUCT = "Chingtsi WAF";
    public static final String VENDOR = "Chingtsi Studio";
    public static final String VERSION = resolveVersion();
    public static final String COPYRIGHT = "Copyright (c) 2026 Chingtsi Studio";

    /** 优先取 jar 清单里的 Implementation-Version，源码直跑时回退内置版本。 */
    private static String resolveVersion() {
        try {
            String v = WafMain.class.getPackage().getImplementationVersion();
            if (v != null && !v.isBlank()) {
                return v.trim();
            }
        } catch (Throwable ignored) {
            // 非 jar 运行（IDE / 未打包）时忽略
        }
        return "1.0.0.0";
    }

    private WafMain() {
    }

    public static void main(String[] args) throws Exception {
        // 允许透传原始 Host 首部，IIS 按主机名区分站点时必需
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        banner();

        Path projectRoot = Path.of(System.getProperty("waf.home", ".")).toAbsolutePath().normalize();
        Path confFile = projectRoot.resolve("conf").resolve("waf.properties");
        if (args.length > 0) {
            confFile = Path.of(args[0]).toAbsolutePath().normalize();
        }

        WafConfig cfg = WafConfig.load(confFile);
        System.out.println("[CONF ] " + confFile);
        System.out.println("[CONF ] 监听 " + cfg.listenHost() + ":" + cfg.listenPort()
                + "  上游 " + cfg.upstreamBase() + "  工作线程 " + cfg.workerThreads());

        AccessLog accessLog = new AccessLog(cfg.logFile(), cfg.logJson(), cfg.logFlushEvery());

        AtomicReference<RuleEngine> engineRef = new AtomicReference<>(
                RuleEngine.load(cfg.ruleDir(), cfg.defaultScore(),
                        cfg.inboundThreshold(), cfg.outboundThreshold()));
        System.out.println("[RULE ] 已加载规则 " + engineRef.get().size() + " 条，来源目录 " + cfg.ruleDir());
        startRuleWatcher(cfg, engineRef);

        IpSet whitelist = IpSet.load(cfg.whitelistFile());
        IpSet blacklist = IpSet.load(cfg.blacklistFile());
        System.out.println("[IP   ] 白名单 " + whitelist.size() + " 条 / 黑名单 " + blacklist.size() + " 条");

        RateLimiter limiter = new RateLimiter(cfg.rateWindowSeconds(), cfg.rateLimit(), cfg.banSeconds());
        System.out.println("[RATE ] 窗口 " + cfg.rateWindowSeconds() + "s 上限 " + cfg.rateLimit()
                + " 次，超限封禁 " + cfg.banSeconds() + "s");

        ExecutorService pool = Executors.newFixedThreadPool(cfg.workerThreads(), r -> {
            Thread t = new Thread(r, "waf-worker");
            t.setDaemon(true);
            return t;
        });

        // 自动检查 IIS 配置：为每个 IIS 站点端口建立防护监听（前置端口 → 127.0.0.1:站点端口）
        ListenerManager listeners = new ListenerManager(cfg, pool,
                cfg.iisConfigPath().orElse(null),
                sitePort -> new ProxyHandler(cfg, engineRef, whitelist, blacklist, limiter, accessLog,
                        sitePort > 0 ? "http://127.0.0.1:" + sitePort : null));
        listeners.reconcile();
        System.out.println("[IIS  ] " + listeners.describe());
        startIisWatcher(cfg, listeners);

        System.out.println("[READY ] 防护已启用  入站阈值=" + cfg.inboundThreshold()
                + "  出站阈值=" + cfg.outboundThreshold() + "  单请求体上限=" + cfg.maxBodyBytes() + "B");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("[STOP ] 正在停止 " + PRODUCT + " ...");
            listeners.stopAll();
            pool.shutdownNow();
            accessLog.close();
            System.out.println("[STOP ] 已安全停止");
        }, "waf-shutdown"));

        Thread.currentThread().join();
    }

    /** IIS 站点变更轮询：新增站点/改端口后自动增减监听器。 */
    private static void startIisWatcher(WafConfig cfg, ListenerManager listeners) {
        if (!cfg.iisAuto()) {
            return;
        }
        int period = Math.max(10, cfg.iisRefreshSeconds());
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(period * 1000L);
                } catch (InterruptedException e) {
                    return;
                }
                try {
                    listeners.reconcile();
                } catch (RuntimeException e) {
                    System.out.println("[WARN ] IIS 站点核对失败：" + e.getMessage());
                }
            }
        }, "waf-iis-reconcile");
        t.setDaemon(true);
        t.start();
    }

    /**
     * 规则热加载：每 5 秒比对规则目录的时间戳指纹，发现变化即重建引擎并原子替换。
     * 重建失败时保留旧引擎，避免规则写错导致防护失效。
     */
    private static void startRuleWatcher(WafConfig cfg, AtomicReference<RuleEngine> engineRef) {
        Thread t = new Thread(() -> {
            long last = ruleStamp(cfg.ruleDir());
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(5000L);
                } catch (InterruptedException e) {
                    return;
                }
                long now = ruleStamp(cfg.ruleDir());
                if (now == last || now == 0L) {
                    continue;
                }
                try {
                    RuleEngine fresh = RuleEngine.load(cfg.ruleDir(), cfg.defaultScore(),
                            cfg.inboundThreshold(), cfg.outboundThreshold());
                    engineRef.set(fresh);
                    last = now;
                    System.out.println("[RULE ] 规则已变更，热加载完成，当前 " + fresh.size() + " 条");
                } catch (RuntimeException e) {
                    last = now;
                    System.out.println("[WARN ] 规则热加载失败，继续使用旧规则：" + e.getMessage());
                }
            }
        }, "waf-rule-watch");
        t.setDaemon(true);
        t.start();
    }

    /** 规则目录指纹：文件名 + 大小 + 修改时间的汇总哈希。 */
    private static long ruleStamp(Path dir) {
        if (dir == null || !Files.isDirectory(dir)) {
            return 0L;
        }
        long sum = 0L;
        try (Stream<Path> s = Files.walk(dir, 1)) {
            for (Path p : (Iterable<Path>) s.filter(Files::isRegularFile)::iterator) {
                try {
                    sum += p.getFileName().toString().hashCode()
                            + Files.size(p)
                            + Files.getLastModifiedTime(p).toMillis();
                } catch (IOException ignored) {
                    // 文件被并发替换，跳过即可
                }
            }
        } catch (IOException e) {
            return 0L;
        }
        return sum;
    }

    private static void banner() {
        String[] lines = {
                "",
                "  ______ __  __ ___   __  ______ ______ ____",
                " / ____// / / //   | / / /_  __//_  __//  _/",
                "/ /    / /_/ // /| |/ /   / /    / /   / /  ",
                "/ /___ / __  // / |  /   / /    / /  _/ /   ",
                "\\____//_/ /_//_/  |_/   /_/    /_/  /___/   ",
                "",
                "  " + PRODUCT + " v" + VERSION + "  ·  反向代理型 Web 应用防火墙",
                "  " + COPYRIGHT,
                "  参考 ModSecurity + OWASP CRS 设计，独立实现",
                ""
        };
        for (String l : lines) {
            System.out.println(l);
        }
    }
}
