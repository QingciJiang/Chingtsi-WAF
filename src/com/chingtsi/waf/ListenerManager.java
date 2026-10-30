/*
 * Chingtsi WAF - 监听器管理
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import com.chingtsi.waf.iis.IisFrontPorts;
import com.chingtsi.waf.iis.IisMonitor;
import com.chingtsi.waf.iis.IisSnapshot;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

/**
 * 依据 IIS 站点端口动态维护防护监听器。
 * <p>每个 IIS 站点端口对应一个 WAF 前置监听端口，转发到 {@code 127.0.0.1:<站点端口>}；
 * IIS 站点变更（新增/删除/改端口）后，下一次核对会自动增删监听器。
 * 未检测到 IIS 或显式关闭自动模式时，退回配置里的单一监听端口 + 固定上游。</p>
 */
public final class ListenerManager {

    /** 为指定站点端口创建请求处理器；sitePort = 0 表示使用配置里的 upstream.base。 */
    public interface HandlerFactory {
        HttpHandler create(int sitePort);
    }

    private record Entry(int sitePort, HttpServer server) {
    }

    private final WafConfig cfg;
    private final ExecutorService pool;
    private final HandlerFactory factory;
    private final Path iisConfigFile;

    /** 前置端口 → 监听器。 */
    private final Map<Integer, Entry> running = new LinkedHashMap<>();
    /** 当前生效的 IIS 端口 → 前置端口。 */
    private final Map<Integer, Integer> plan = new LinkedHashMap<>();
    private HttpServer fallback;
    private int fallbackPort;
    private String lastNote = "";

    public ListenerManager(WafConfig cfg, ExecutorService pool, Path iisConfigFile, HandlerFactory factory) {
        this.cfg = cfg;
        this.pool = pool;
        this.iisConfigFile = iisConfigFile;
        this.factory = factory;
    }

    public synchronized Map<Integer, Integer> plan() {
        return new LinkedHashMap<>(plan);
    }

    public synchronized String lastNote() {
        return lastNote;
    }

    /**
     * 核对一次：读取 IIS 快照 → 计算端口映射 → 增删监听器。
     */
    public synchronized void reconcile() {
        IisSnapshot snap = IisMonitor.start(iisConfigFile, cfg.iisRefreshSeconds());
        List<Integer> sitePorts = snap.httpPorts();
        Map<Integer, Integer> target = cfg.iisAuto()
                ? IisFrontPorts.plan(sitePorts, cfg.listenPort(), cfg.iisFrontMap())
                : Map.of();

        // target: 站点端口 -> 前置端口；running: 前置端口 -> (站点端口, server)。
        // 核对时必须反查，否则每个刷新周期都会判定"端口已变更"而全量重建，
        // 造成监听器每 20 秒抖动、短暂拒连。
        Map<Integer, Integer> frontToSite = new java.util.HashMap<>();
        target.forEach((sitePort, front) -> frontToSite.put(front, sitePort));

        running.entrySet().removeIf(e -> {
            Integer sitePort = frontToSite.get(e.getKey());
            if (sitePort == null || sitePort.intValue() != e.getValue().sitePort()) {
                e.getValue().server().stop(2);
                System.out.println("[IIS  ] 已停止监听 :" + e.getKey() + "（站点端口已变更或站点被移除）");
                return true;
            }
            return false;
        });

        for (Map.Entry<Integer, Integer> e : target.entrySet()) {
            int front = e.getValue();
            int sitePort = e.getKey();
            if (running.containsKey(front)) {
                continue;
            }
            try {
                HttpServer server = HttpServer.create(
                        new InetSocketAddress(cfg.listenHost(), front), 256);
                server.createContext("/", factory.create(sitePort));
                server.setExecutor(pool);
                server.start();
                running.put(front, new Entry(sitePort, server));
                System.out.println("[IIS  ] 防护监听 :" + front + " → 127.0.0.1:" + sitePort);
            } catch (BindException be) {
                lastNote = "前置端口 " + front + " 已被占用，站点端口 " + sitePort + " 未受防护";
                System.out.println("[WARN ] " + lastNote);
            } catch (IOException ioe) {
                lastNote = "前置端口 " + front + " 启动失败：" + ioe.getMessage();
                System.out.println("[WARN ] " + lastNote);
            }
        }

        plan.clear();
        plan.putAll(target);

        if (target.isEmpty()) {
            stopFallbackIfAny();
            startFallback();
        } else {
            stopFallbackIfAny();
        }
    }

    /** 关闭全部监听器（进程退出时调用）。 */
    public synchronized void stopAll() {
        for (Entry e : new ArrayList<>(running.values())) {
            e.server().stop(2);
        }
        running.clear();
        stopFallbackIfAny();
    }

    /** 供启动日志使用的一句话描述。 */
    public synchronized String describe() {
        if (plan.isEmpty()) {
            return "固定监听 " + cfg.listenHost() + ":" + fallbackPort() + " → " + cfg.upstreamBase();
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Integer, Integer> e : plan.entrySet()) {
            if (sb.length() > 0) {
                sb.append("，");
            }
            sb.append(e.getValue()).append(" → IIS ").append(e.getKey());
        }
        return sb.toString();
    }

    private int fallbackPort() {
        return fallbackPort > 0 ? fallbackPort : cfg.listenPort();
    }

    private void startFallback() {
        if (fallback != null) {
            return;
        }
        try {
            HttpServer server = HttpServer.create(
                    new InetSocketAddress(cfg.listenHost(), cfg.listenPort()), 512);
            server.createContext("/", factory.create(0));
            server.setExecutor(pool);
            server.start();
            fallback = server;
            fallbackPort = cfg.listenPort();
            System.out.println("[IIS  ] 未检测到可保护的 IIS 站点，回退固定监听 :" + cfg.listenPort());
        } catch (IOException e) {
            lastNote = "监听 " + cfg.listenPort() + " 失败：" + e.getMessage();
            System.out.println("[WARN ] " + lastNote);
        }
    }

    private void stopFallbackIfAny() {
        if (fallback != null) {
            fallback.stop(2);
            fallback = null;
        }
    }
}
