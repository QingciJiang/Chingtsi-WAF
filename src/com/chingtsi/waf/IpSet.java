/*
 * Chingtsi WAF - IP 名单（支持 CIDR）
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 黑白名单集合。每行一个条目，支持 IPv4/IPv6 单地址与 CIDR 网段，<code>#</code> 为注释。
 */
public final class IpSet {

    private record Cidr(byte[] network, int prefix) {
    }

    private final transient List<Cidr> entries = new CopyOnWriteArrayList<>();
    private final String label;

    private IpSet(String label) {
        this.label = label;
    }

    public static IpSet load(Path file) {
        IpSet set = new IpSet(file == null ? "memory" : file.getFileName().toString());
        if (file == null || !Files.isRegularFile(file)) {
            return set;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                set.add(line);
            }
        } catch (IOException e) {
            System.out.println("[WARN ] " + set.label + " 读取失败: " + e.getMessage());
        }
        return set;
    }

    public void add(String rawEntry) {
        if (rawEntry == null) {
            return;
        }
        String s = rawEntry.trim();
        int hash = s.indexOf('#');
        if (hash >= 0) {
            s = s.substring(0, hash).trim();
        }
        if (s.isEmpty()) {
            return;
        }
        try {
            int slash = s.indexOf('/');
            String addr = slash < 0 ? s : s.substring(0, slash);
            InetAddress ia = InetAddress.getByName(addr);
            byte[] bytes = ia.getAddress();
            int prefix = slash < 0 ? bytes.length * 8 : Integer.parseInt(s.substring(slash + 1));
            int max = bytes.length * 8;
            if (prefix < 0) {
                prefix = 0;
            }
            if (prefix > max) {
                prefix = max;
            }
            entries.add(new Cidr(bytes, prefix));
        } catch (Exception e) {
            System.out.println("[WARN ] " + label + " 忽略非法条目: " + s);
        }
    }

    public boolean contains(String ip) {
        if (ip == null || ip.isEmpty() || entries.isEmpty()) {
            return false;
        }
        byte[] target;
        try {
            target = InetAddress.getByName(normalize(ip)).getAddress();
        } catch (Exception e) {
            return false;
        }
        for (Cidr c : entries) {
            if (c.network().length != target.length) {
                continue;
            }
            if (match(c.network(), target, c.prefix())) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String ip) {
        String s = ip.trim();
        if (s.startsWith("::ffff:")) {
            return s.substring(7);
        }
        return s;
    }

    private static boolean match(byte[] network, byte[] target, int prefix) {
        int fullBytes = prefix / 8;
        int remainBits = prefix % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (network[i] != target[i]) {
                return false;
            }
        }
        if (remainBits == 0) {
            return true;
        }
        int mask = 0xFF << (8 - remainBits);
        return (network[fullBytes] & mask) == (target[fullBytes] & mask);
    }

    public int size() {
        return entries.size();
    }

    public List<String> dump() {
        return new ArrayList<>(List.of(label + ":" + entries.size()));
    }
}
