/*
 * Chingtsi WAF - 访问与安全日志
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 * 线程安全的日志写入器。默认输出 JSON Lines，便于被 Filebeat / Loki 采集。
 */
public final class AccessLog implements AutoCloseable {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

    private final Path file;
    private final boolean json;
    private final BufferedWriter writer;
    private final int flushEvery;
    private volatile boolean closed;
    private long written;

    public AccessLog(Path file, boolean json) {
        this(file, json, 1);
    }

    /**
     * @param flushEvery 每写多少条强制刷盘；小于等于 1 表示每条立即 flush。
     *                   取值大于 1 时仍会启动一个 1 秒的兜底后台刷盘线程，
     *                   保证低流量场景下日志也不会长时间停留在缓冲区。
     */
    public AccessLog(Path file, boolean json, int flushEvery) {
        this.file = file;
        this.json = json;
        this.flushEvery = flushEvery <= 0 ? 1 : flushEvery;
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            this.writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("无法打开日志文件: " + file, e);
        }
        if (this.flushEvery > 1) {
            Thread t = new Thread(this::flushLoop, "waf-log-flusher");
            t.setDaemon(true);
            t.start();
        }
    }

    private void flushLoop() {
        while (!closed) {
            try {
                Thread.sleep(1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            flush();
        }
    }

    /**
     * 记录一次请求判定结果。
     *
     * @param ctx      请求上下文
     * @param status   WAF 判定（PASS / BLOCK / RATE_LIMIT / BAN / UPSTREAM_ERROR 等）
     * @param httpCode 返回给客户端的状态码
     * @param score    异常分
     * @param elapsed  处理耗时（毫秒）
     * @param extra    附加说明
     */
    public synchronized void record(RequestContext ctx, String status, int httpCode,
                                    int score, long elapsed, String extra) {
        String ts = OffsetDateTime.now().format(TS);
        StringBuilder findings = new StringBuilder();
        List<RequestContext.Finding> list = ctx.findings();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) {
                findings.append('|');
            }
            findings.append(list.get(i).ruleId()).append(':').append(list.get(i).message());
        }

        String line;
        if (json) {
            line = "{"
                    + "\"ts\":\"" + ts + "\""
                    + ",\"ip\":\"" + esc(ctx.clientIp()) + "\""
                    + ",\"remoteAddr\":\"" + esc(ctx.remoteAddr()) + "\""
                    + ",\"cfIp\":\"" + esc(ctx.cfConnectingIp()) + "\""
                    + ",\"method\":\"" + esc(ctx.method()) + "\""
                    + ",\"uri\":\"" + esc(ctx.rawPath()) + "\""
                    + ",\"query\":\"" + esc(ctx.rawQuery()) + "\""
                    + ",\"ua\":\"" + esc(nullToEmpty(ctx.header("user-agent"))) + "\""
                    + ",\"status\":\"" + esc(status) + "\""
                    + ",\"code\":" + httpCode
                    + ",\"score\":" + score
                    + ",\"elapsed\":" + elapsed
                    + ",\"bodySize\":" + ctx.bodySize()
                    + ",\"args\":\"" + esc(ctx.argsSummary()) + "\""
                    + ",\"rules\":\"" + esc(findings.toString()) + "\""
                    + ",\"note\":\"" + esc(nullToEmpty(extra)) + "\""
                    + "}";
        } else {
            line = ts + " " + ctx.clientIp() + " (remote=" + ctx.remoteAddr()
                    + (ctx.cfConnectingIp().isEmpty() ? "" : " cf=" + ctx.cfConnectingIp()) + ") \""
                    + ctx.method() + " " + ctx.rawPath()
                    + (ctx.rawQuery().isEmpty() ? "" : "?" + ctx.rawQuery()) + "\" "
                    + httpCode + " score=" + score + " " + elapsed + "ms " + status
                    + (findings.length() > 0 ? " [" + findings + "]" : "")
                    + (extra == null || extra.isEmpty() ? "" : " (" + extra + ")");
        }

        try {
            writer.write(line);
            writer.newLine();
            written++;
            if (flushEvery <= 1 || written % flushEvery == 0 || !"PASS".equals(status)) {
                writer.flush();
            }
        } catch (IOException e) {
            System.out.println("[WARN ] 日志写入失败: " + e.getMessage());
        }
    }

    public void flush() {
        try {
            writer.flush();
        } catch (IOException ignored) {
            // 关闭阶段忽略
        }
    }

    public Path file() {
        return file;
    }

    @Override
    public synchronized void close() {
        closed = true;
        try {
            writer.flush();
            writer.close();
        } catch (IOException ignored) {
            // 关闭阶段忽略
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String esc(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
