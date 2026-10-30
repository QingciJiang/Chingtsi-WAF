/*
 * Chingtsi WAF - 规则引擎
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 *
 * 采用 OWASP CRS 的异常评分（Anomaly Scoring）模型：
 * 单条规则只加分，累计分值达到阈值后整体拦截，减少误报造成的硬阻断。
 */
package com.chingtsi.waf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

/**
 * 规则集合与检测入口。
 */
public final class RuleEngine {

    private final List<Rule> rules;
    private final int inboundThreshold;

    private RuleEngine(List<Rule> rules, int inboundThreshold) {
        this.rules = rules;
        this.inboundThreshold = inboundThreshold;
    }

    /** 检测结果。 */
    public record Verdict(boolean blocked, int score, List<RequestContext.Finding> findings) {
    }

    public static RuleEngine load(Path ruleDir, int defaultScore, int inboundThreshold, int outboundThreshold) {
        List<Rule> list = new ArrayList<>();
        if (ruleDir != null && Files.isDirectory(ruleDir)) {
            List<Path> files;
            try (Stream<Path> s = Files.walk(ruleDir, 2)) {
                files = s.filter(Files::isRegularFile)
                        .filter(f -> {
                            String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
                            return n.endsWith(".conf") || n.endsWith(".rules");
                        })
                        .sorted(Comparator.comparing(Path::toString))
                        .toList();
            } catch (IOException e) {
                files = List.of();
                System.out.println("[WARN ] 规则目录读取失败: " + e.getMessage());
            }
            for (Path f : files) {
                int before = list.size();
                try {
                    for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                        Rule r = Rule.parse(line, defaultScore);
                        if (r != null) {
                            list.add(r);
                        }
                    }
                } catch (IOException e) {
                    System.out.println("[WARN ] 规则文件读取失败: " + f + " -> " + e.getMessage());
                    continue;
                }
                System.out.println("[RULE ] " + f.getFileName() + "  载入 " + (list.size() - before) + " 条");
            }
        } else {
            System.out.println("[WARN ] 规则目录不存在，将以空规则集运行: " + ruleDir);
        }
        return new RuleEngine(List.copyOf(list), inboundThreshold);
    }

    public int size() {
        return rules.size();
    }

    /**
     * 对请求做入站检测。
     */
    public Verdict inspect(RequestContext ctx) {
        for (Rule rule : rules) {
            if (hits(rule, ctx)) {
                int add = rule.action() == Rule.Action.LOG_ONLY ? 0 : rule.score();
                ctx.addFinding(new RequestContext.Finding(rule.id(), rule.message(), add));
                if (rule.action() == Rule.Action.BLOCK && ctx.score() >= inboundThreshold) {
                    return new Verdict(true, ctx.score(), List.copyOf(ctx.findings()));
                }
            }
        }
        return new Verdict(false, ctx.score(), List.copyOf(ctx.findings()));
    }

    private boolean hits(Rule rule, RequestContext ctx) {
        for (String var : rule.variables()) {
            for (String value : resolve(ctx, var.trim())) {
                if (rule.matches(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 变量解析，对齐 ModSecurity 常用集合。
     * 同时提供原始值与一次 URL 解码值，防止 %27%20 之类的编码绕过。
     */
    private List<String> resolve(RequestContext ctx, String var) {
        String upper = var.toUpperCase(Locale.ROOT);
        switch (upper) {
            case "REQUEST_URI" -> {
                String uri = ctx.rawPath() + (ctx.rawQuery().isEmpty() ? "" : "?" + ctx.rawQuery());
                return variants(uri);
            }
            case "REQUEST_FILENAME", "REQUEST_PATH" -> {
                return variants(ctx.rawPath());
            }
            case "QUERY_STRING" -> {
                return variants(ctx.rawQuery());
            }
            case "REQUEST_BODY" -> {
                return variants(ctx.bodyText());
            }
            case "REQUEST_METHOD" -> {
                return List.of(ctx.method());
            }
            case "REQUEST_LINE" -> {
                String uri = ctx.rawPath() + (ctx.rawQuery().isEmpty() ? "" : "?" + ctx.rawQuery());
                return List.of(ctx.method() + " " + uri + " " + ctx.protocol());
            }
            case "REMOTE_ADDR" -> {
                return List.of(ctx.clientIp());
            }
            case "ARGS", "REQUEST_ARGS" -> {
                List<String> out = new ArrayList<>();
                for (Map.Entry<String, String> e : ctx.arguments().entrySet()) {
                    out.addAll(variants(e.getKey()));
                    out.addAll(variants(e.getValue()));
                }
                return out;
            }
            case "ARGS_NAMES" -> {
                List<String> out = new ArrayList<>();
                for (String k : ctx.arguments().keySet()) {
                    out.addAll(variants(k));
                }
                return out;
            }
            case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES" -> {
                return variants(ctx.cookieHeader());
            }
            case "REQUEST_HEADERS" -> {
                List<String> out = new ArrayList<>();
                for (Map.Entry<String, List<String>> e : ctx.headers().entrySet()) {
                    out.add(e.getKey());
                    out.addAll(e.getValue());
                }
                return out;
            }
            case "REQUEST_HEADERS:USER-AGENT", "REQUEST_HEADERS:USER_AGENT" -> {
                // 缺失时返回空串而非空集合，使 ^$ 规则能命中"无 UA"的脚本化请求
                String ua = ctx.header("user-agent");
                return List.of(ua == null ? "" : ua);
            }
            case "REQUEST_HEADERS:HOST" -> {
                String h = ctx.header("host");
                return h == null ? List.of() : List.of(h);
            }
            case "REQUEST_HEADERS:REFERER", "REQUEST_HEADERS:REFERRER" -> {
                String h = ctx.header("referer");
                return h == null ? List.of() : List.of(h);
            }
            case "REQUEST_HEADERS:CONTENT-TYPE" -> {
                String h = ctx.header("content-type");
                return h == null ? List.of() : List.of(h);
            }
            default -> {
                if (upper.startsWith("REQUEST_HEADERS:")) {
                    String name = var.substring("REQUEST_HEADERS:".length()).trim().toLowerCase(Locale.ROOT);
                    String v = ctx.header(name);
                    return v == null ? List.of() : List.of(v);
                }
                return List.of();
            }
        }
    }

    private static List<String> variants(String raw) {
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>(3);
        out.add(raw);
        String once = urlDecode(raw);
        if (!once.equals(raw)) {
            out.add(once);
        }
        String twice = urlDecode(once);
        if (!twice.equals(once) && !twice.equals(raw)) {
            out.add(twice);
        }
        return out;
    }

    private static String urlDecode(String s) {
        if (s.indexOf('%') < 0 && s.indexOf('+') < 0) {
            return s;
        }
        try {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
}
