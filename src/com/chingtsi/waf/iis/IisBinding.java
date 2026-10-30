/*
 * Chingtsi WAF - IIS 站点绑定
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.iis;

import java.util.Locale;

/**
 * IIS 站点的一条协议绑定，对应 applicationHost.config 中的
 * {@code <binding protocol="http" bindingInformation="*:80:www.example.com" />}。
 *
 * @param protocol 协议，http / https / net.tcp 等
 * @param ip       绑定 IP，"*" 表示全部未分配地址
 * @param port     绑定端口
 * @param host     绑定的主机名（可为空，表示不限定主机名）
 */
public record IisBinding(String protocol, String ip, int port, String host) {

    /** 解析 bindingInformation，格式固定为 {@code ip:port:host}。 */
    public static IisBinding parse(String protocol, String info) {
        String p = protocol == null || protocol.isBlank() ? "http" : protocol.trim();
        if (info == null || info.isBlank()) {
            return new IisBinding(p, "*", 0, "");
        }
        String[] parts = info.split(":", 3);
        String ip = parts.length > 0 && !parts[0].isBlank() ? parts[0].trim() : "*";
        int port = 0;
        if (parts.length > 1) {
            try {
                port = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException ignored) {
                port = 0;
            }
        }
        String host = parts.length > 2 ? parts[2].trim() : "";
        return new IisBinding(p, ip, port, host);
    }

    public boolean http() {
        return "http".equalsIgnoreCase(protocol);
    }

    /** 端口是否可用于被 WAF 前置防护：仅 HTTP、端口合法、且未绑定到回环以外的明确地址时才纳入。 */
    public boolean protectable() {
        return http() && port > 0 && port <= 65535;
    }

    public String describe() {
        return protocol + " " + ip + ":" + port + (host.isEmpty() ? "" : ":" + host);
    }

    public String hostLower() {
        return host == null ? "" : host.toLowerCase(Locale.ROOT);
    }
}
