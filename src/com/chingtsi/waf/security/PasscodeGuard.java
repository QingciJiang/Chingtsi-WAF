/*
 * Chingtsi WAF - 白名单管理口令（PBKDF2 口令哈希）
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 *
 * 白名单管理口令只用于保护“向 IP 白名单添加条目”的操作。
 * 口令本身不参与请求判定；已进入白名单的 IP 跳过全部检测，不受口令影响，直接放行。
 */
package com.chingtsi.waf.security;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * 白名单管理口令的设置与校验。
 * <p>
 * 口令哈希以 PBKDF2WithHmacSHA256 计算（100,000 次迭代、派生键 256 位、16 字节随机盐），
 * 保存到 {@code conf/security.properties}，格式为：
 * <pre>admin.password=&lt;Base64(盐)&gt;:&lt;Base64(PBKDF2 派生键)&gt;</pre>
 * 文件不存在或缺少该项时视为“尚未设置口令”。
 */
public final class PasscodeGuard {

    private static final String KEY = "admin.password";
    private static final int ITERATIONS = 100_000;
    private static final int KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasscodeGuard() {
    }

    /** 是否已设置白名单管理口令。 */
    public static boolean hasPassword(Path file) {
        return readHash(file) != null;
    }

    /**
     * 读取已保存的口令哈希（“Base64(盐):Base64(派生键)”），不存在则返回 null。
     */
    public static String readHash(Path file) {
        if (file == null || !Files.isRegularFile(file)) {
            return null;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#") || t.startsWith("!") || t.startsWith(";")) {
                    continue;
                }
                int eq = t.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                if (!KEY.equals(t.substring(0, eq).trim())) {
                    continue;
                }
                String v = t.substring(eq + 1).trim();
                return v.isEmpty() ? null : v;
            }
        } catch (IOException ignored) {
        }
        return null;
    }

    /** 校验口令是否与保存的哈希匹配。 */
    public static boolean verify(Path file, String password) {
        String stored = readHash(file);
        if (stored == null || password == null || password.isEmpty()) {
            return false;
        }
        int sep = stored.indexOf(':');
        if (sep < 0) {
            return false;
        }
        try {
            byte[] salt = Base64.getDecoder().decode(stored.substring(0, sep));
            byte[] expected = Base64.getDecoder().decode(stored.substring(sep + 1));
            byte[] actual = derive(password.toCharArray(), salt);
            return MessageDigest.isEqual(actual, expected);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * 设置（或替换）白名单管理口令。口令长度须为 6～64 个字符。
     * 保存前会对口令做 PBKDF2-SHA256 哈希，明文口令不落盘。
     */
    public static void setPassword(Path file, String password) {
        if (password == null) {
            throw new IllegalArgumentException("口令不能为空");
        }
        String p = password.trim();
        if (p.length() < 6 || p.length() > 64) {
            throw new IllegalArgumentException("口令长度须为 6～64 个字符");
        }
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] derived = derive(p.toCharArray(), salt);
        String entry = KEY + "=" + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(derived);

        try {
            if (!Files.isRegularFile(file)) {
                if (file.getParent() != null) {
                    Files.createDirectories(file.getParent());
                }
                Files.writeString(file,
                        "# Chingtsi WAF - 白名单管理口令\n"
                                + "# Copyright (c) 2026 Chingtsi Studio. All rights reserved.\n"
                                + "# 格式：admin.password=<Base64(盐)>:<Base64(PBKDF2-SHA256 派生键)>\n"
                                + "# 该口令用于保护向 IP 白名单添加条目的操作，不参与请求判定，不存储口令明文。\n",
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING);
            }
            String content = Files.readString(file, StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder(content.length() + 128);
            boolean replaced = false;
            for (String line : content.split("\r?\n", -1)) {
                String t = line.trim();
                if (!t.isEmpty() && !t.startsWith("#") && !t.startsWith("!") && !t.startsWith(";")) {
                    int eq = t.indexOf('=');
                    if (eq > 0 && KEY.equals(t.substring(0, eq).trim())) {
                        sb.append(entry);
                        replaced = true;
                        continue;
                    }
                }
                sb.append(line).append('\n');
            }
            if (!replaced) {
                if (sb.length() > 0 && !sb.toString().endsWith("\n")) {
                    sb.append('\n');
                }
                sb.append(entry).append('\n');
            }
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("保存白名单口令失败: " + file, e);
        }
    }

    private static byte[] derive(char[] password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 不可用", e);
        }
    }
}
