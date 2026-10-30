/*
 * Chingtsi WAF - 限流与 CC 防护
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 基于滑动窗口的单 IP 频率控制，超限后临时封禁。
 * <p>用于抵御 CC 攻击与爬虫洪泛，不替代规则引擎。</p>
 */
public final class RateLimiter {

    public enum Decision { ALLOW, RATE_LIMITED, BANNED }

    private final int windowSeconds;
    private final int limit;
    private final int banSeconds;

    private final Map<String, Deque<Long>> windows = new ConcurrentHashMap<>();
    private final Map<String, Long> bans = new ConcurrentHashMap<>();
    private final AtomicLong lastSweep = new AtomicLong(System.currentTimeMillis());

    public RateLimiter(int windowSeconds, int limit, int banSeconds) {
        this.windowSeconds = Math.max(1, windowSeconds);
        this.limit = Math.max(1, limit);
        this.banSeconds = Math.max(1, banSeconds);
    }

    public Decision check(String ip) {
        long now = System.currentTimeMillis();

        Long bannedUntil = bans.get(ip);
        if (bannedUntil != null) {
            if (bannedUntil > now) {
                return Decision.BANNED;
            }
            bans.remove(ip);
        }

        long windowStart = now - windowSeconds * 1000L;
        Deque<Long> q = windows.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (q) {
            while (!q.isEmpty() && q.peekFirst() < windowStart) {
                q.pollFirst();
            }
            if (q.size() >= limit) {
                ban(ip);
                return Decision.RATE_LIMITED;
            }
            q.addLast(now);
        }

        sweep(now);
        return Decision.ALLOW;
    }

    public void ban(String ip) {
        bans.put(ip, System.currentTimeMillis() + banSeconds * 1000L);
    }

    public boolean isBanned(String ip) {
        Long until = bans.get(ip);
        if (until == null) {
            return false;
        }
        if (until <= System.currentTimeMillis()) {
            bans.remove(ip);
            return false;
        }
        return true;
    }

    public int banCount() {
        return bans.size();
    }

    /**
     * 每 30 秒清理一次过期的窗口，防止内存增长。
     */
    private void sweep(long now) {
        long last = lastSweep.get();
        if (now - last < 30_000L) {
            return;
        }
        if (!lastSweep.compareAndSet(last, now)) {
            return;
        }
        long windowStart = now - windowSeconds * 1000L;
        windows.entrySet().removeIf(e -> {
            Deque<Long> q = e.getValue();
            synchronized (q) {
                if (q.isEmpty() || q.peekLast() < windowStart) {
                    return true;
                }
                while (!q.isEmpty() && q.peekFirst() < windowStart) {
                    q.pollFirst();
                }
                return q.isEmpty();
            }
        });
        bans.entrySet().removeIf(e -> e.getValue() <= now);
    }
}
