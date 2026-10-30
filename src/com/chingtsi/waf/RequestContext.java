/*
 * Chingtsi WAF - 请求上下文
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 一次请求的安全检查上下文。变量命名对齐 ModSecurity 的 transaction 变量。
 */
public final class RequestContext {

    private final String clientIp;
    private final String remoteAddr;
    private final String method;
    private final String rawPath;
    private final String rawQuery;
    private final String protocol;
    private final Map<String, List<String>> headers;
    private final byte[] body;
    private final String bodyText;

    private final List<Finding> findings = new ArrayList<>();
    private int score;

    public record Finding(String ruleId, String message, int score) {
    }

    public RequestContext(String clientIp, String method, String rawPath, String rawQuery,
                          String protocol, Map<String, List<String>> headers, byte[] body) {
        this(clientIp, "", method, rawPath, rawQuery, protocol, headers, body);
    }

    /**
     * @param clientIp   经 CF / XFF 还原后的客户端 IP
     * @param remoteAddr TCP 对端地址（隧道场景通常为 127.0.0.1，用于链路取证）
     */
    public RequestContext(String clientIp, String remoteAddr, String method, String rawPath, String rawQuery,
                          String protocol, Map<String, List<String>> headers, byte[] body) {
        this.clientIp = clientIp;
        this.remoteAddr = remoteAddr == null ? "" : remoteAddr;
        this.method = method;
        this.rawPath = rawPath == null ? "/" : rawPath;
        this.rawQuery = rawQuery == null ? "" : rawQuery;
        this.protocol = protocol;
        this.headers = headers;
        this.body = body == null ? new byte[0] : body;
        this.bodyText = decodeBody();
    }

    private String decodeBody() {
        if (body.length == 0) {
            return "";
        }
        String ct = header("content-type");
        String cs = "UTF-8";
        if (ct != null) {
            int i = ct.toLowerCase(Locale.ROOT).indexOf("charset=");
            if (i >= 0) {
                cs = ct.substring(i + 8).split("[;,]")[0].trim();
            }
        }
        try {
            return new String(body, cs);
        } catch (Exception e) {
            return new String(body, StandardCharsets.ISO_8859_1);
        }
    }

    /**
     * 解析全部"参数面"：查询串 + 表单体。键统一转小写。
     */
    public Map<String, String> arguments() {
        Map<String, String> map = new LinkedHashMap<>();
        parseForm(rawQuery, map);
        String ct = header("content-type");
        if (ct != null && ct.toLowerCase(Locale.ROOT).contains("application/x-www-form-urlencoded")) {
            parseForm(bodyText, map);
        }
        return map;
    }

    private static void parseForm(String s, Map<String, String> out) {
        if (s == null || s.isEmpty()) {
            return;
        }
        for (String pair : s.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            out.putIfAbsent(decode(k).toLowerCase(Locale.ROOT), decode(v));
        }
    }

    private static String decode(String s) {
        try {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    public String cookieHeader() {
        String c = header("cookie");
        return c == null ? "" : c;
    }

    public String header(String name) {
        List<String> v = headers.get(name.toLowerCase(Locale.ROOT));
        if (v == null || v.isEmpty()) {
            return null;
        }
        return String.join(",", v);
    }

    public String headerValue(String name) {
        return header(name);
    }

    public void addFinding(Finding f) {
        findings.add(f);
        score += f.score();
    }

    public List<Finding> findings() {
        return findings;
    }

    public int score() {
        return score;
    }

    /**
     * 供日志输出：所有参数值拼接，便于攻击回溯。
     */
    public String argsSummary() {
        Map<String, String> a = arguments();
        if (a.isEmpty()) {
            return "";
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        StringBuilder sb = new StringBuilder();
        a.forEach((k, v) -> {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(k).append('=').append(v.length() > 128 ? v.substring(0, 128) + "..." : v);
        });
        buf.writeBytes(sb.toString().getBytes(StandardCharsets.UTF_8));
        return sb.toString();
    }

    public String clientIp() { return clientIp; }
    public String remoteAddr() { return remoteAddr; }

    /** 原始 CF-Connecting-IP 首部（未做任何还原），便于核对链路。 */
    public String cfConnectingIp() {
        String v = header("cf-connecting-ip");
        return v == null ? "" : v.trim();
    }

    public String method() { return method; }
    public String rawPath() { return rawPath; }
    public String rawQuery() { return rawQuery; }
    public String protocol() { return protocol; }
    public String bodyText() { return bodyText; }
    public int bodySize() { return body.length; }
    public byte[] body() { return body; }
    public Map<String, List<String>> headers() { return headers; }
}
