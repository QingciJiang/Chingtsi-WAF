/*
 * Chingtsi WAF - 单条规则
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 *
 * 语法参考 ModSecurity SecRule，做了裁剪与简化。
 */
package com.chingtsi.waf;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 一条检测规则。
 *
 * <pre>
 * SecRule 变量列表 "操作符 参数" "id:1001,score:5,msg:'描述',action:block"
 * </pre>
 *
 * 变量列表以 <code>|</code> 分隔；操作符支持 @rx @pm @contains @streq @eq @beginsWith @endsWith @ge @gt；
 * 动作支持 id / score / msg / action(block|pass|log)。
 */
public final class Rule {

    public enum Action { BLOCK, LOG_ONLY, PASS }

    private final String id;
    private final List<String> variables;
    private final String operator;
    private final String parameter;
    private final int score;
    private final String message;
    private final Action action;
    private final Pattern compiled;

    private Rule(String id, List<String> variables, String operator, String parameter,
                 int score, String message, Action action, Pattern compiled) {
        this.id = id;
        this.variables = variables;
        this.operator = operator;
        this.parameter = parameter;
        this.score = score;
        this.message = message;
        this.action = action;
        this.compiled = compiled;
    }

    /**
     * 解析一行 SecRule 定义，非规则行返回 null。
     */
    public static Rule parse(String rawLine, int defaultScore) {
        String line = rawLine.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            return null;
        }
        if (!line.regionMatches(true, 0, "SecRule", 0, 7)) {
            return null;
        }
        String rest = line.substring(7).trim();
        List<String> parts = Splitter.splitQuoted(rest);
        if (parts.size() < 3) {
            System.out.println("[WARN ] 规则格式不完整，已跳过: " + line);
            return null;
        }

        List<String> vars = List.of(parts.get(0).split("\\|"));
        String opExpr = parts.get(1).trim();
        String actions = parts.get(2);

        String op;
        String param = "";
        int sp = indexOfUnquotedSpace(opExpr);
        if (sp < 0) {
            op = opExpr.toLowerCase(Locale.ROOT);
        } else {
            op = opExpr.substring(0, sp).toLowerCase(Locale.ROOT);
            param = opExpr.substring(sp + 1).trim();
        }
        if (op.startsWith("@")) {
            op = op.substring(1);
        }

        String id = "0";
        int score = defaultScore;
        String msg = "";
        Action action = Action.BLOCK;

        for (String a : actions.split(",")) {
            String t = a.trim();
            if (t.isEmpty()) {
                continue;
            }
            int c = t.indexOf(':');
            String k = (c < 0 ? t : t.substring(0, c)).trim().toLowerCase(Locale.ROOT);
            String v = (c < 0 ? "" : t.substring(c + 1).trim());
            if (v.length() >= 2
                    && ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith("\"") && v.endsWith("\"")))) {
                v = v.substring(1, v.length() - 1);
            }
            switch (k) {
                case "id" -> id = v;
                case "score" -> score = safeInt(v, defaultScore);
                case "msg" -> msg = v;
                case "action", "deny" -> {
                    if ("pass".equalsIgnoreCase(v) || "log".equalsIgnoreCase(v)) {
                        action = Action.LOG_ONLY;
                    } else if ("allow".equalsIgnoreCase(v)) {
                        action = Action.PASS;
                    } else {
                        action = Action.BLOCK;
                    }
                }
                default -> {
                    // 忽略未知动作，保持与 ModSecurity 一致的宽松解析
                }
            }
        }

        Pattern compiled = null;
        if ("rx".equals(op)) {
            try {
                compiled = Pattern.compile(param, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
            } catch (PatternSyntaxException e) {
                System.out.println("[WARN ] 规则 " + id + " 正则非法，已跳过: " + e.getDescription());
                return null;
            }
        }

        return new Rule(id, vars, op, param, score, msg.isEmpty() ? "规则 " + id + " 命中" : msg,
                action, compiled);
    }

    private static int safeInt(String v, int def) {
        try {
            return Integer.parseInt(v.trim());
        } catch (RuntimeException e) {
            return def;
        }
    }

    private static int indexOfUnquotedSpace(String s) {
        boolean inSingle = false;
        boolean inDouble = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\'' && !inDouble) {
                inSingle = !inSingle;
            } else if (c == '"' && !inSingle) {
                inDouble = !inDouble;
            } else if (Character.isWhitespace(c) && !inSingle && !inDouble) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 判断单个待检字符串是否命中。
     */
    public boolean matches(String value) {
        if (value == null) {
            return false;
        }
        // 允许正则对空值判定（如 ^$ 匹配空 User-Agent），其余操作符空值无意义
        if (value.isEmpty() && !"rx".equals(operator)) {
            return false;
        }
        return switch (operator) {
            case "rx" -> compiled != null && compiled.matcher(value).find();
            case "pm" -> containsAny(parameter, value);
            case "contains" -> value.toLowerCase(Locale.ROOT).contains(parameter.toLowerCase(Locale.ROOT));
            case "streq" -> value.equals(parameter);
            case "eq" -> value.equalsIgnoreCase(parameter);
            case "beginswith" -> value.regionMatches(true, 0, parameter, 0, parameter.length());
            case "endswith" -> value.toLowerCase(Locale.ROOT).endsWith(parameter.toLowerCase(Locale.ROOT));
            case "gt", "ge" -> compareNumber(value, parameter, "ge".equals(operator));
            default -> false;
        };
    }

    private static boolean containsAny(String words, String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        for (String w : words.split("\\s+")) {
            if (!w.isEmpty() && lower.contains(w.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static boolean compareNumber(String value, String threshold, boolean orEqual) {
        try {
            long a = Long.parseLong(value.trim());
            long b = Long.parseLong(threshold.trim());
            return orEqual ? a >= b : a > b;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public String id() { return id; }
    public List<String> variables() { return variables; }
    public int score() { return score; }
    public String message() { return message; }
    public Action action() { return action; }

    @Override
    public String toString() {
        return "Rule{" + id + ", vars=" + variables + ", @" + operator + " " + parameter
                + ", score=" + score + ", " + action + "}";
    }

    /**
     * 把一行按引号切成若干段，去掉引号。
     */
    static final class Splitter {
        private Splitter() {
        }

        static java.util.List<String> splitQuoted(String s) {
            java.util.List<String> out = new java.util.ArrayList<>();
            StringBuilder cur = new StringBuilder();
            boolean inSingle = false;
            boolean inDouble = false;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '\'' && !inDouble) {
                    inSingle = !inSingle;
                    continue;
                }
                if (c == '"' && !inSingle) {
                    inDouble = !inDouble;
                    continue;
                }
                if (Character.isWhitespace(c) && !inSingle && !inDouble) {
                    if (cur.length() > 0) {
                        out.add(cur.toString());
                        cur.setLength(0);
                    }
                    continue;
                }
                cur.append(c);
            }
            if (cur.length() > 0) {
                out.add(cur.toString());
            }
            return out;
        }
    }
}
