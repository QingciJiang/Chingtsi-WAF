/*
 * Chingtsi WAF - IIS 配置监视器
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.iis;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 后台定期刷新 IIS 站点快照，供 WAF 引擎（按端口建监听器）和控制台（状态栏展示）共用。
 * <p>控制台是独立进程，只需调用 {@link #peek(Path)} 取当前快照，不会启动额外线程。</p>
 */
public final class IisMonitor {

    private static final AtomicReference<IisSnapshot> CURRENT = new AtomicReference<>();
    private static volatile Thread worker;
    private static volatile Path source;

    private IisMonitor() {
    }

    /**
     * 取当前快照；如果还没有数据则同步读取一次（不启动刷新线程）。
     */
    public static IisSnapshot peek(Path override) {
        IisSnapshot s = CURRENT.get();
        if (s != null) {
            return s;
        }
        IisSnapshot fresh = IisConfigReader.read(override);
        CURRENT.compareAndSet(null, fresh);
        return CURRENT.get();
    }

    /**
     * 立即读取一次并启动后台刷新线程（幂等，重复调用只会更新源路径）。
     *
     * @param override 配置里 iis.config.file 指定的文件，可为 null
     * @param seconds  刷新间隔（秒），最小 5
     */
    public static IisSnapshot start(Path override, int seconds) {
        source = override;
        IisSnapshot first = IisConfigReader.read(override);
        CURRENT.set(first);
        int period = Math.max(5, seconds);
        synchronized (IisMonitor.class) {
            if (worker != null && worker.isAlive()) {
                return first;
            }
            Thread t = new Thread(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(period * 1000L);
                    } catch (InterruptedException e) {
                        return;
                    }
                    try {
                        IisSnapshot next = IisConfigReader.read(source);
                        CURRENT.set(next);
                    } catch (RuntimeException ignored) {
                        // 读取失败则保留上一份快照
                    }
                }
            }, "waf-iis-watch");
            t.setDaemon(true);
            t.start();
            worker = t;
        }
        return first;
    }

    /** 强制立即重新读取一次（控制台手动刷新用）。 */
    public static IisSnapshot refresh(Path override) {
        IisSnapshot next = IisConfigReader.read(override);
        CURRENT.set(next);
        return next;
    }
}
