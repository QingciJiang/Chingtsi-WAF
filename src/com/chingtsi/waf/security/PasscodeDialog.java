/*
 * Chingtsi WAF - 白名单管理口令对话框
 * Copyright (c) 2026 Chingtsi Studio. All rights reserved.
 */
package com.chingtsi.waf.security;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import java.awt.Component;
import java.awt.Window;
import java.nio.file.Path;

/** 白名单管理口令的交互对话框：初始设置、验证、修改。 */
public final class PasscodeDialog {

    private PasscodeDialog() {
    }

    /**
     * 确保已设置口令：未设置时反复弹出设置对话框，直至设置成功或用户选择退出。
     * 返回 true 表示已设置口令；false 表示用户取消并退出了设置流程。
     */
    public static boolean ensureSetup(Window owner, Path securityFile) {
        while (!PasscodeGuard.hasPassword(securityFile)) {
            if (!promptSet(owner, securityFile)) {
                int choice = JOptionPane.showConfirmDialog(owner,
                        "未设置白名单管理口令，将无法向 IP 白名单添加条目。是否重新设置？",
                        "白名单管理口令未设置", JOptionPane.YES_NO_CANCEL_OPTION,
                        JOptionPane.WARNING_MESSAGE);
                if (choice == JOptionPane.CANCEL_OPTION
                        || choice == JOptionPane.CLOSED_OPTION) {
                    return false;
                }
                // YES -> 继续循环，再次弹出设置对话框
            }
        }
        return true;
    }

    /**
     * 验证已设置的口令。未设置时先引导设置；设置成功后视为已验证并返回空字符串。
     * 已设置时弹出验证对话框，通过则返回输入的口令，取消则返回 null。
     */
    public static String verify(Window owner, Path securityFile) {
        if (!PasscodeGuard.hasPassword(securityFile)) {
            if (!ensureSetup(owner, securityFile)) {
                return null;
            }
            return "";
        }
        return promptVerify(owner, securityFile, false);
    }

    /** 修改口令：先验证旧口令，再设置新口令。返回 true 表示已修改。 */
    public static boolean change(Window owner, Path securityFile) {
        if (!PasscodeGuard.hasPassword(securityFile)) {
            return promptSet(owner, securityFile);
        }
        String old = promptVerify(owner, securityFile, true);
        if (old == null) {
            return false;
        }
        return promptSet(owner, securityFile);
    }

    // ---------------- 以下为 Swing 实现 ----------------

    private static boolean promptSet(Window owner, Path securityFile) {
        Component parent = owner instanceof Component ? (Component) owner : null;
        JPasswordField p1 = new JPasswordField(24);
        JPasswordField p2 = new JPasswordField(24);
        p1.setEchoChar('•');
        p2.setEchoChar('•');
        Object[] msg = {
                "<html><b>设置白名单管理口令</b><br>向 IP 白名单添加条目前，需先设置管理口令；此后每次添加都要输入该口令。</html>",
                "新口令：", p1,
                "再次输入：", p2,
        };
        int r = JOptionPane.showConfirmDialog(parent, msg, "设置白名单管理口令",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (r != JOptionPane.OK_OPTION) {
            clear(p1, p2);
            return false;
        }
        String a = new String(p1.getPassword());
        String b = new String(p2.getPassword());
        clear(p1, p2);
        if (a.isEmpty() || b.isEmpty()) {
            JOptionPane.showMessageDialog(parent, "口令不能为空。", "设置失败", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        if (!a.equals(b)) {
            JOptionPane.showMessageDialog(parent, "两次输入的口令不一致，请重试。", "设置失败",
                    JOptionPane.ERROR_MESSAGE);
            return false;
        }
        try {
            PasscodeGuard.setPassword(securityFile, a);
            return true;
        } catch (Exception e) {
            JOptionPane.showMessageDialog(parent, "保存失败：" + e.getMessage(), "设置失败",
                    JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    private static String promptVerify(Window owner, Path securityFile, boolean forChange) {
        Component parent = owner instanceof Component ? (Component) owner : null;
        JPasswordField p = new JPasswordField(24);
        p.setEchoChar('•');
        Object[] msg = {
                forChange
                        ? "<html><b>修改白名单管理口令</b><br>请先输入当前口令。</html>"
                        : "<html><b>验证白名单管理口令</b><br>添加白名单条目前，请输入管理口令。</html>",
                "口令：", p,
        };
        int r = JOptionPane.showConfirmDialog(parent, msg,
                forChange ? "修改白名单管理口令" : "验证白名单管理口令",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        String pw = new String(p.getPassword());
        clear(p);
        if (r != JOptionPane.OK_OPTION) {
            return null;
        }
        if (pw.isEmpty()) {
            JOptionPane.showMessageDialog(parent, "口令不能为空。", "验证失败", JOptionPane.ERROR_MESSAGE);
            return null;
        }
        if (!PasscodeGuard.verify(securityFile, pw)) {
            JOptionPane.showMessageDialog(parent, "口令错误，请重试。", "验证失败", JOptionPane.ERROR_MESSAGE);
            return null;
        }
        return pw;
    }

    private static void clear(JPasswordField... fields) {
        for (JPasswordField f : fields) {
            if (f != null) {
                f.setText("");
            }
        }
    }
}
