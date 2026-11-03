/*
 * Chingtsi WAF - 控制台日志读取与 IP 聚合
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.ui;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 增量读取 logs/waf.log（JSON Lines），维护最近事件列表与按 IP 的访问统计。
 * <p>只读文件，不向 WAF 写入任何内容，因此对防护链路零影响。</p>
 */
final class WafEventLog {

    private static final int MAX_EVENTS = 5000;
    private static final long TAIL_BYTES = 8L * 1024 * 1024;
    private static final long MAX_READ = 16L * 1024 * 1024;

    private final Path file;
    private long offset;
    private boolean primed;
    private long skipped;

    private final List<WafEvent> events = new ArrayList<>();
    private final Map<String, IpAgg> aggs = new LinkedHashMap<>();
    private long total;
    private long blocked;

    private String lastError = "";

    WafEventLog(Path file) {
        this.file = file;
    }

    Path file() {
        return file;
    }

    long total() {
        return total;
    }

    long blocked() {
        return blocked;
    }

    long skipped() {
        return skipped;
    }

    String lastError() {
        return lastError;
    }

    List<WafEvent> events() {
        return events;
    }

    Collection<IpAgg> aggs() {
        return aggs.values();
    }

    IpAgg agg(String ip) {
        return aggs.get(ip);
    }

    void resetAll() {
        offset = 0;
        primed = false;
        skipped = 0;
        events.clear();
        aggs.clear();
        total = 0;
        blocked = 0;
        lastError = "";
    }

    /** 读取新增日志行，返回新增事件条数。 */
    synchronized int poll() {
        if (file == null || !Files.isRegularFile(file)) {
            return 0;
        }
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            long size = raf.length();
            if (size < offset) {
                // 日志被清空或轮转
                resetAll();
            }
            if (!primed) {
                if (size > TAIL_BYTES) {
                    raf.seek(size - TAIL_BYTES);
                    offset = size - TAIL_BYTES;
                } else {
                    raf.seek(0);
                    offset = 0;
                }
                primed = true;
            }
            if (size <= offset) {
                return 0;
            }
            long avail = Math.min(size - offset, MAX_READ);
            raf.seek(offset);
            byte[] buf = new byte[(int) avail];
            raf.readFully(buf);
            int lastNl = -1;
            for (int i = buf.length - 1; i >= 0; i--) {
                if (buf[i] == '\n') {
                    lastNl = i;
                    break;
                }
            }
            if (lastNl < 0) {
                return 0;
            }
            String text = new String(buf, 0, lastNl + 1, StandardCharsets.UTF_8);
            offset += lastNl + 1;
            lastError = "";
            int added = 0;
            for (String raw : text.split("\n")) {
                String line = raw.strip();
                if (line.isEmpty()) {
                    continue;
                }
                if (line.charAt(0) != '{') {
                    // 首次从文件中间定位时可能落在半行，跳过
                    skipped++;
                    continue;
                }
                WafEvent ev = WafEvent.parse(line);
                if (ev == null) {
                    skipped++;
                    continue;
                }
                events.add(ev);
                added++;
                total++;
                if (ev.blocked()) {
                    blocked++;
                }
                aggs.computeIfAbsent(ev.ip, IpAgg::new).add(ev);
            }
            if (events.size() > MAX_EVENTS) {
                events.subList(0, events.size() - MAX_EVENTS).clear();
            }
            return added;
        } catch (IOException e) {
            lastError = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return 0;
        }
    }

    /** 单个访问来源的汇总。 */
    static final class IpAgg {

        final String ip;
        int requests;
        int blocks;
        int maxScore;
        String firstTs = "";
        String lastTs = "";
        String lastStatus = "";
        String lastUa = "";
        String lastPath = "";
        final Set<String> rules = new LinkedHashSet<>();

        IpAgg(String ip) {
            this.ip = ip;
        }

        void add(WafEvent e) {
            requests++;
            if (e.blocked()) {
                blocks++;
            }
            if (e.score > maxScore) {
                maxScore = e.score;
            }
            if (firstTs.isEmpty()) {
                firstTs = e.ts;
            }
            lastTs = e.ts;
            lastStatus = e.status;
            lastPath = e.pathText();
            if (!e.ua.isEmpty()) {
                lastUa = e.ua;
            }
            if (!e.rules.isEmpty()) {
                for (String part : e.rules.split("\\|")) {
                    int c = part.indexOf(':');
                    if (c > 0) {
                        rules.add(part.substring(0, c));
                    }
                }
            }
        }

        boolean abnormal() {
            return blocks > 0 || maxScore > 0;
        }

        String lastTimeText() {
            WafEvent tmp = WafEvent.parse("{\"ts\":\"" + lastTs + "\",\"ip\":\"" + ip + "\"}");
            return tmp == null ? lastTs : tmp.timeText;
        }
    }
}
