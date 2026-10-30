/*
 * Chingtsi WAF - 控制台事件模型
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.ui;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 一条防护事件，对应 logs/waf.log 中的一行 JSON。
 * 控制台只读日志，不做任何拦截判定，判定结果全部来自 WAF 内核。
 */
final class WafEvent {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final DateTimeFormatter DATE_TIME = DateTimeFormatter.ofPattern("MM-dd HH:mm:ss");

    final String ts;
    final String timeText;
    final String ip;
    final String method;
    final String uri;
    final String query;
    final String ua;
    final String status;
    final int code;
    final int score;
    final long elapsed;
    final String rules;
    final String note;

    private WafEvent(String ts, String ip, String method, String uri, String query, String ua,
                     String status, int code, int score, long elapsed, String rules, String note) {
        this.ts = ts;
        this.timeText = formatTime(ts);
        this.ip = ip;
        this.method = method;
        this.uri = uri;
        this.query = query;
        this.ua = ua;
        this.status = status;
        this.code = code;
        this.score = score;
        this.elapsed = elapsed;
        this.rules = rules;
        this.note = note;
    }

    static WafEvent parse(String line) {
        var m = Json.parseObject(line);
        if (m.isEmpty() || m.get("ip") == null) {
            return null;
        }
        return new WafEvent(
                nz(m.get("ts")),
                nz(m.get("ip")),
                nz(m.get("method")),
                nz(m.get("uri")),
                nz(m.get("query")),
                nz(m.get("ua")),
                nz(m.get("status")).isEmpty() ? "PASS" : nz(m.get("status")),
                (int) num(m.get("code")),
                (int) num(m.get("score")),
                num(m.get("elapsed")),
                nz(m.get("rules")),
                nz(m.get("note")));
    }

    /** 是否被 WAF 拦截（判定非 PASS 即为异常事件）。 */
    boolean blocked() {
        return !"PASS".equals(status);
    }

    /** 判定等级：BLOCK=攻击拦截，RATE=限流封禁，BAD=非法请求，ERR=上游异常，PASS=放行。 */
    String level() {
        return switch (status) {
            case "PASS" -> "通行";
            case "BLOCK", "BLACKLIST" -> "拦截";
            case "BANNED", "RATE_LIMIT" -> "限流";
            case "BAD_URI" -> "非法";
            case "UPSTREAM_TIMEOUT", "UPSTREAM_UNREACHABLE" -> "上游异常";
            default -> status;
        };
    }

    String pathText() {
        return query == null || query.isEmpty() ? uri : uri + "?" + query;
    }

    /** 命中规则摘要：规则号列表，过长截断。 */
    String ruleSummary() {
        if (rules == null || rules.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String part : rules.split("\\|")) {
            int c = part.indexOf(':');
            String id = c > 0 ? part.substring(0, c) : part;
            if (id.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(id);
            if (sb.length() > 40) {
                sb.append("…");
                break;
            }
        }
        return sb.toString();
    }

    private static String formatTime(String ts) {
        if (ts == null || ts.length() < 19) {
            return nz(ts);
        }
        try {
            OffsetDateTime t = OffsetDateTime.parse(ts);
            if (t.getYear() == java.time.LocalDate.now().getYear()
                    && t.getDayOfYear() == java.time.LocalDate.now().getDayOfYear()) {
                return t.format(TIME);
            }
            return t.format(DATE_TIME);
        } catch (RuntimeException e) {
            return ts.length() >= 19 ? ts.substring(11, 19) : ts;
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static long num(String s) {
        if (s == null || s.isEmpty()) {
            return 0L;
        }
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }
}
