/*
 * Chingtsi WAF - 控制台用极简 JSON 解析器
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.ui;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 仅解析 WAF 日志中"扁平对象"结构的 JSON，零第三方依赖。
 * 不做完整 JSON 校验，遇到非法片段即跳过，保证读日志永不被脏数据打断。
 */
final class Json {

    private Json() {
    }

    static Map<String, String> parseObject(String s) {
        Map<String, String> out = new LinkedHashMap<>();
        if (s == null || s.isEmpty()) {
            return out;
        }
        int i = s.indexOf('{');
        if (i < 0) {
            return out;
        }
        int n = s.length();
        i++;
        while (i < n) {
            while (i < n && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ',')) {
                i++;
            }
            if (i >= n || s.charAt(i) == '}') {
                break;
            }
            if (s.charAt(i) != '"') {
                i++;
                continue;
            }
            int[] pos = {i};
            String key = readString(s, pos);
            i = pos[0];
            while (i < n && s.charAt(i) != ':') {
                i++;
            }
            i++;
            while (i < n && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
            if (i >= n) {
                break;
            }
            char c = s.charAt(i);
            if (c == '"') {
                int[] p2 = {i};
                String val = readString(s, p2);
                i = p2[0];
                out.put(key, val);
            } else {
                int start = i;
                while (i < n && s.charAt(i) != ',' && s.charAt(i) != '}') {
                    i++;
                }
                out.put(key, s.substring(start, i).trim());
            }
        }
        return out;
    }

    private static String readString(String s, int[] pos) {
        int i = pos[0] + 1;
        StringBuilder sb = new StringBuilder();
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i++);
            if (c == '"') {
                break;
            }
            if (c == '\\' && i < n) {
                char e = s.charAt(i++);
                switch (e) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> {
                        if (i + 4 <= n) {
                            try {
                                sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            } catch (NumberFormatException ignored) {
                                // 非法转义，忽略
                            }
                            i += 4;
                        }
                    }
                    default -> sb.append(e);
                }
            } else {
                sb.append(c);
            }
        }
        pos[0] = i;
        return sb.toString();
    }
}
