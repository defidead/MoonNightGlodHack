package com.hack.menu;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.app.AlertDialog;
import android.content.DialogInterface;
import java.util.ArrayList;
import java.util.List;

public class OverlayMenu implements View.OnClickListener, View.OnTouchListener {

    private Activity activity;
    private WindowManager wm;
    private WindowManager.LayoutParams wmParams;
    private LinearLayout container;
    private ScrollView scrollView;
    private LinearLayout contentArea;
    private TextView statusText;
    private EditText goldInput, hpInput, mpInput, actionInput, handcardsInput;
    private EditText equipInput, lostthingInput, cardInput;
    private Button toggleBtn;
    private Button autoSkillBtn;
    private boolean collapsed = false;
    private boolean autoSkillReset = false;
    private Handler autoResetHandler;
    private float density;

    // 拖动
    private int lastX, lastY;
    private float touchX, touchY;
    private boolean dragging = false;

    // 按钮 ID
    private static final int BTN_TOGGLE       = 0x7f000001;
    private static final int BTN_GOLD         = 0x7f000002;
    private static final int BTN_SKILL        = 0x7f000003;
    private static final int BTN_SKILL_AUTO   = 0x7f000004;
    private static final int BTN_HP           = 0x7f000005;
    private static final int BTN_MP           = 0x7f000006;
    private static final int BTN_ACTION       = 0x7f000007;
    private static final int BTN_HANDCARDS    = 0x7f000008;
    private static final int BTN_EQUIP        = 0x7f000009;
    private static final int BTN_LOSTTHING    = 0x7f00000A;
    private static final int BTN_CARD         = 0x7f00000B;
    private static final int BTN_MODIFY_ALL   = 0x7f00000C;
    private static final int BTN_P1           = 0x7f000010;
    private static final int BTN_P2           = 0x7f000011;
    private static final int BTN_P3           = 0x7f000012;
    private static final int BTN_P4           = 0x7f000013;
    private static final int BTN_BROWSE_EQUIP = 0x7f000020;
    private static final int BTN_BROWSE_CARD  = 0x7f000021;
    private static final int BTN_BROWSE_BLESS = 0x7f000022;

    // 物品类型常量 (与 C 层 do_enum_items 对应)
    private static final int ITEM_TYPE_CARD      = 1;
    private static final int ITEM_TYPE_LOSTTHING = 2;
    private static final int ITEM_TYPE_EQUIP     = 3;

    // JNI 回调（C 代码注册实现）
    public static native String nativeModifyGold(int amount);
    public static native String nativeResetSkillCD();
    public static native String nativeModifyHp(int maxHp);
    public static native String nativeModifyMp(int mp);
    public static native String nativeModifyAction(int action);
    public static native String nativeModifyHandcards(int handcards);
    public static native String nativeAddEquipment(int equipId);
    public static native String nativeAddLostThing(int lostThingId);
    public static native String nativeAddCard(int cardId);
    public static native String nativeModifyAll(int gold, int maxHp, int mp, int action, int handcards);
    public static native String nativeEnumItems(int type);

    /**
     * 从 C 代码调用的入口，在 UI 线程创建悬浮窗
     */
    public static void create(final Activity activity) {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                try {
                    new OverlayMenu(activity);
                } catch (Exception e) {
                    android.util.Log.e("GoldHack", "Overlay create failed: " + e);
                }
            }
        });
    }

    private OverlayMenu(Activity act) {
        this.activity = act;
        this.density = act.getResources().getDisplayMetrics().density;
        this.wm = act.getWindowManager();
        buildUI();
    }

    private int dp(int d) { return Math.round(d * density); }

    private void buildUI() {
        // ===== 主容器 =====
        container = new LinearLayout(activity);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(dp(12), dp(8), dp(12), dp(10));

        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xDD1A1A2E);
        bg.setCornerRadius(dp(14));
        bg.setStroke(dp(1), 0xFF7C3AED);
        container.setBackground(bg);

        // ===== 标题栏 (可拖动) =====
        LinearLayout titleBar = new LinearLayout(activity);
        titleBar.setOrientation(LinearLayout.HORIZONTAL);
        titleBar.setGravity(Gravity.CENTER_VERTICAL);
        titleBar.setOnTouchListener(this);

        TextView title = new TextView(activity);
        title.setText("\uD83C\uDF15 月圆之夜 修改器");
        title.setTextColor(0xFFE0E7FF);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        title.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        titleBar.addView(title);

        toggleBtn = makeBtn("\u2014", 0x33FFFFFF, BTN_TOGGLE);
        toggleBtn.setTextColor(0xFFA5B4FC);
        LinearLayout.LayoutParams tblp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(28));
        tblp.setMargins(dp(6), 0, 0, 0);
        toggleBtn.setLayoutParams(tblp);
        titleBar.addView(toggleBtn);

        container.addView(titleBar);

        // ===== 内容区 (可滚动) =====
        scrollView = new ScrollView(activity);
        LinearLayout.LayoutParams svlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(380));
        svlp.setMargins(0, dp(4), 0, 0);
        scrollView.setLayoutParams(svlp);

        contentArea = new LinearLayout(activity);
        contentArea.setOrientation(LinearLayout.VERTICAL);
        contentArea.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // ==================== 💰 金币 ====================
        addSectionLabel(contentArea, "\uD83D\uDCB0 金币", 0xFFFCD34D);
        goldInput = addInputRow(contentArea, "金币", "99999", BTN_GOLD, "修改");

        LinearLayout quickRow = new LinearLayout(activity);
        quickRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams qrlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        qrlp.setMargins(0, dp(3), 0, 0);
        quickRow.setLayoutParams(qrlp);
        int[] presets = {9999, 99999, 888888, 999999};
        int[] pids    = {BTN_P1, BTN_P2, BTN_P3, BTN_P4};
        for (int i = 0; i < presets.length; i++) {
            Button qb = makeBtn(String.valueOf(presets[i]), 0xFF374151, pids[i]);
            qb.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
            qb.setTag(presets[i]);
            LinearLayout.LayoutParams qblp = new LinearLayout.LayoutParams(0, dp(24), 1f);
            if (i > 0) qblp.setMargins(dp(3), 0, 0, 0);
            qb.setLayoutParams(qblp);
            quickRow.addView(qb);
        }
        contentArea.addView(quickRow);
        addDivider(contentArea);

        // ==================== ❤️ 血量上限 ====================
        addSectionLabel(contentArea, "\u2764\uFE0F 血量上限 (同时回满)", 0xFFEF4444);
        hpInput = addInputRow(contentArea, "血量", "999", BTN_HP, "修改");
        addDivider(contentArea);

        // ==================== 🔮 法力值 ====================
        addSectionLabel(contentArea, "\uD83D\uDD2E 法力值", 0xFF818CF8);
        mpInput = addInputRow(contentArea, "法力", "99", BTN_MP, "修改");
        addDivider(contentArea);

        // ==================== ⚡ 行动值 ====================
        addSectionLabel(contentArea, "\u26A1 行动值", 0xFF67E8F9);
        actionInput = addInputRow(contentArea, "行动值", "99", BTN_ACTION, "修改");
        addDivider(contentArea);

        // ==================== 🃏 手牌上限 ====================
        addSectionLabel(contentArea, "\uD83C\uDCCF 手牌上限", 0xFF4ADE80);
        handcardsInput = addInputRow(contentArea, "手牌上限", "10", BTN_HANDCARDS, "修改");
        addDivider(contentArea);

        // ==================== ⚔️ 添加装备 ====================
        addSectionLabel(contentArea, "\u2694\uFE0F 添加装备 (装备ID)", 0xFFFB923C);
        equipInput = addInputRow(contentArea, "装备ID", "", BTN_EQUIP, "添加");
        addBrowseRow(contentArea, BTN_BROWSE_EQUIP, "📂 浏览装备列表");
        addDivider(contentArea);

        // ==================== 🃏 添加卡牌 ====================
        addSectionLabel(contentArea, "\uD83C\uDCCF 添加卡牌 (卡牌ID)", 0xFF60A5FA);
        cardInput = addInputRow(contentArea, "卡牌ID", "", BTN_CARD, "添加");
        addBrowseRow(contentArea, BTN_BROWSE_CARD, "📂 浏览卡牌列表");
        addDivider(contentArea);

        // ==================== ✨ 祝福/遗物 ====================
        addSectionLabel(contentArea, "\u2728 添加祝福/遗物 (ID)", 0xFFFBBF24);
        lostthingInput = addInputRow(contentArea, "遗物ID", "", BTN_LOSTTHING, "添加");
        addBrowseRow(contentArea, BTN_BROWSE_BLESS, "📂 浏览祝福列表");
        addDivider(contentArea);

        // ==================== ⚡ 技能CD ====================
        addSectionLabel(contentArea, "\u26A1 技能CD", 0xFF67E8F9);
        LinearLayout skillRow = new LinearLayout(activity);
        skillRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams srlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        srlp.setMargins(0, dp(3), 0, 0);
        skillRow.setLayoutParams(srlp);

        Button skillBtn = makeBtn("重置CD", 0xFF0E7490, BTN_SKILL);
        skillBtn.setLayoutParams(new LinearLayout.LayoutParams(0, dp(32), 1f));
        skillRow.addView(skillBtn);

        autoSkillBtn = makeBtn("自动:关", 0xFF374151, BTN_SKILL_AUTO);
        LinearLayout.LayoutParams asblp = new LinearLayout.LayoutParams(0, dp(32), 1f);
        asblp.setMargins(dp(4), 0, 0, 0);
        autoSkillBtn.setLayoutParams(asblp);
        skillRow.addView(autoSkillBtn);
        contentArea.addView(skillRow);
        addDivider(contentArea);

        // ==================== 🚀 一键修改 ====================
        Button modAllBtn = makeBtn("\uD83D\uDE80 一键全部修改", 0xFF7C3AED, BTN_MODIFY_ALL);
        LinearLayout.LayoutParams mablp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(38));
        mablp.setMargins(0, dp(3), 0, 0);
        modAllBtn.setLayoutParams(mablp);
        modAllBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        contentArea.addView(modAllBtn);

        // --- 状态文本 ---
        statusText = new TextView(activity);
        statusText.setText("就绪 - 进入对局后使用");
        statusText.setTextColor(0xFF9CA3AF);
        statusText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        LinearLayout.LayoutParams stlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        stlp.setMargins(0, dp(6), 0, 0);
        statusText.setLayoutParams(stlp);
        contentArea.addView(statusText);

        scrollView.addView(contentArea);
        container.addView(scrollView);

        // ===== WindowManager 参数 =====
        wmParams = new WindowManager.LayoutParams(
                dp(240),
                ViewGroup.LayoutParams.WRAP_CONTENT,
                2,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                PixelFormat.TRANSLUCENT);
        wmParams.gravity = Gravity.TOP | Gravity.LEFT;
        wmParams.x = dp(10);
        wmParams.y = dp(80);

        wm.addView(container, wmParams);
        android.util.Log.i("GoldHack", "Overlay menu created");
    }

    // ===== 辅助: 添加区域标签 =====
    private void addSectionLabel(LinearLayout parent, String text, int color) {
        TextView label = new TextView(activity);
        label.setText(text);
        label.setTextColor(color);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        parent.addView(label);
    }

    // ===== 辅助: 添加输入行 =====
    private EditText addInputRow(LinearLayout parent, String hint, String defVal, int btnId, String btnText) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rlp.setMargins(0, dp(3), 0, 0);
        row.setLayoutParams(rlp);

        EditText input = new EditText(activity);
        input.setHint(hint);
        if (defVal != null && !defVal.isEmpty()) input.setText(defVal);
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(0xFF666688);
        input.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        input.setInputType(InputType.TYPE_CLASS_NUMBER);
        input.setSingleLine(true);
        input.setPadding(dp(6), dp(3), dp(6), dp(3));
        GradientDrawable ibg = new GradientDrawable();
        ibg.setColor(0xFF1E1E3F);
        ibg.setCornerRadius(dp(6));
        ibg.setStroke(dp(1), 0xFF4338CA);
        input.setBackground(ibg);
        input.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        final EditText fi = input;
        input.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                wmParams.flags = 0;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                fi.requestFocus();
            }
        });
        input.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View v, boolean hasFocus) {
                if (!hasFocus) {
                    wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                    try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                }
            }
        });
        row.addView(input);

        Button btn = makeBtn(btnText, 0xFF7C3AED, btnId);
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(30));
        blp.setMargins(dp(4), 0, 0, 0);
        btn.setLayoutParams(blp);
        row.addView(btn);

        parent.addView(row);
        return input;
    }

    private void addDivider(LinearLayout parent) {
        View div = new View(activity);
        div.setBackgroundColor(0xFF333366);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1));
        dlp.setMargins(0, dp(6), 0, dp(6));
        div.setLayoutParams(dlp);
        parent.addView(div);
    }

    // 添加 "浏览" 按钮行
    private void addBrowseRow(LinearLayout parent, int btnId, String label) {
        Button btn = makeBtn(label, 0xFF374151, btnId);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(26));
        lp.setMargins(0, dp(2), 0, 0);
        btn.setLayoutParams(lp);
        parent.addView(btn);
    }

    private Button makeBtn(String text, int bgColor, int id) {
        Button btn = new Button(activity);
        btn.setText(text);
        btn.setTextColor(Color.WHITE);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        btn.setAllCaps(false);
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(bgColor);
        gd.setCornerRadius(dp(8));
        btn.setBackground(gd);
        btn.setPadding(dp(10), dp(2), dp(10), dp(2));
        btn.setMinHeight(0);
        btn.setMinimumHeight(0);
        btn.setId(id);
        btn.setOnClickListener(this);
        return btn;
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == BTN_TOGGLE) {
            collapsed = !collapsed;
            if (collapsed) {
                scrollView.setVisibility(View.GONE);
                toggleBtn.setText("+");
                wmParams.width = ViewGroup.LayoutParams.WRAP_CONTENT;
            } else {
                scrollView.setVisibility(View.VISIBLE);
                toggleBtn.setText("\u2014");
                wmParams.width = dp(240);
            }
            wmParams.height = ViewGroup.LayoutParams.WRAP_CONTENT;
            try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
        } else if (id == BTN_GOLD) {
            doIntModify(goldInput, "nativeModifyGold");
        } else if (id == BTN_HP) {
            doIntModify(hpInput, "nativeModifyHp");
        } else if (id == BTN_MP) {
            doIntModify(mpInput, "nativeModifyMp");
        } else if (id == BTN_ACTION) {
            doIntModify(actionInput, "nativeModifyAction");
        } else if (id == BTN_HANDCARDS) {
            doIntModify(handcardsInput, "nativeModifyHandcards");
        } else if (id == BTN_EQUIP) {
            doIntModify(equipInput, "nativeAddEquipment");
        } else if (id == BTN_LOSTTHING) {
            doIntModify(lostthingInput, "nativeAddLostThing");
        } else if (id == BTN_CARD) {
            doIntModify(cardInput, "nativeAddCard");
        } else if (id == BTN_SKILL) {
            doSkillReset();
        } else if (id == BTN_SKILL_AUTO) {
            toggleAutoReset();
        } else if (id == BTN_MODIFY_ALL) {
            doModifyAll();
        } else if (id == BTN_BROWSE_EQUIP) {
            showItemPicker(ITEM_TYPE_EQUIP, equipInput, "nativeAddEquipment", "装备");
        } else if (id == BTN_BROWSE_CARD) {
            showItemPicker(ITEM_TYPE_CARD, cardInput, "nativeAddCard", "卡牌");
        } else if (id == BTN_BROWSE_BLESS) {
            showItemPicker(ITEM_TYPE_LOSTTHING, lostthingInput, "nativeAddLostThing", "祝福/遗物");
        } else if (id == BTN_P1 || id == BTN_P2 || id == BTN_P3 || id == BTN_P4) {
            Object tag = v.getTag();
            if (tag != null) goldInput.setText(tag.toString());
        }
    }

    private volatile boolean busy = false;

    private void setBusy(boolean b) {
        busy = b;
    }

    // 通用的单参数修改
    private void doIntModify(final EditText input, final String methodName) {
        if (busy) return;
        String text = input.getText().toString().trim();
        final int amount;
        try {
            amount = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            statusText.setText("\u274C 请输入有效数字");
            return;
        }
        setBusy(true);
        statusText.setText("\u23F3 修改中...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                try {
                    java.lang.reflect.Method m = OverlayMenu.class.getDeclaredMethod(methodName, int.class);
                    result = (String) m.invoke(null, amount);
                } catch (Exception e) {
                    result = "\u274C 调用失败: " + e.getMessage();
                }
                final String finalResult = result;
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        statusText.setText(finalResult);
                        setBusy(false);
                    }
                });
            }
        }).start();
    }

    // 一键修改所有数值属性
    private void doModifyAll() {
        if (busy) return;
        final int gold, hp, mp, action, hand;
        try {
            String s = goldInput.getText().toString().trim();
            gold = s.isEmpty() ? 0 : Integer.parseInt(s);
        } catch (NumberFormatException e) { statusText.setText("\u274C 金币输入无效"); return; }
        try {
            String s = hpInput.getText().toString().trim();
            hp = s.isEmpty() ? 0 : Integer.parseInt(s);
        } catch (NumberFormatException e) { statusText.setText("\u274C 血量输入无效"); return; }
        try {
            String s = mpInput.getText().toString().trim();
            mp = s.isEmpty() ? -1 : Integer.parseInt(s);
        } catch (NumberFormatException e) { statusText.setText("\u274C 法力输入无效"); return; }
        try {
            String s = actionInput.getText().toString().trim();
            action = s.isEmpty() ? 0 : Integer.parseInt(s);
        } catch (NumberFormatException e) { statusText.setText("\u274C 行动值输入无效"); return; }
        try {
            String s = handcardsInput.getText().toString().trim();
            hand = s.isEmpty() ? 0 : Integer.parseInt(s);
        } catch (NumberFormatException e) { statusText.setText("\u274C 手牌输入无效"); return; }
        setBusy(true);
        statusText.setText("\u23F3 一键修改中...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String result = nativeModifyAll(gold, hp, mp, action, hand);
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        statusText.setText(result);
                        setBusy(false);
                    }
                });
            }
        }).start();
    }

    private void doGoldModify() {
        doIntModify(goldInput, "nativeModifyGold");
    }

    private void doSkillReset() {
        if (busy) return;
        setBusy(true);
        statusText.setText("\u23F3 重置中...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String result = nativeResetSkillCD();
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        statusText.setText(result);
                        setBusy(false);
                    }
                });
            }
        }).start();
    }

    // ===== 自动重置技能CD =====
    private void toggleAutoReset() {
        autoSkillReset = !autoSkillReset;
        if (autoSkillReset) {
            autoSkillBtn.setText("自动:开");
            GradientDrawable gd = new GradientDrawable();
            gd.setColor(0xFF059669);
            gd.setCornerRadius(dp(8));
            autoSkillBtn.setBackground(gd);
            startAutoReset();
            statusText.setText("\uD83D\uDD04 自动重置已开启(每1秒)");
        } else {
            autoSkillBtn.setText("自动:关");
            GradientDrawable gd = new GradientDrawable();
            gd.setColor(0xFF374151);
            gd.setCornerRadius(dp(8));
            autoSkillBtn.setBackground(gd);
            stopAutoReset();
            statusText.setText("自动重置已关闭");
        }
    }

    private void startAutoReset() {
        if (autoResetHandler == null) {
            autoResetHandler = new Handler(Looper.getMainLooper());
        }
        final Runnable task = new Runnable() {
            @Override
            public void run() {
                if (!autoSkillReset) return;
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        final String result = nativeResetSkillCD();
                        if (autoSkillReset) {
                            autoResetHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    if (autoSkillReset) statusText.setText("\uD83D\uDD04 " + result);
                                }
                            });
                        }
                    }
                }).start();
                if (autoSkillReset) autoResetHandler.postDelayed(this, 1000);//设置自动重置间隔为1秒，过短可能会有性能影响，根据实际情况调整
            }
        };
        autoResetHandler.postDelayed(task, 500);
    }

    private void stopAutoReset() {
        if (autoResetHandler != null) {
            autoResetHandler.removeCallbacksAndMessages(null);
        }
    }

    // ===== 可视化物品选择器 =====
    // 从 C 层枚举物品 → 解析 JSON → 弹出搜索+多选对话框 → 添加选中项
    private void showItemPicker(final int itemType, final EditText targetInput,
                                 final String nativeAddMethod, final String title) {
        if (busy) return;
        setBusy(true);
        statusText.setText("\u23F3 加载" + title + "列表...");

        new Thread(new Runnable() {
            @Override
            public void run() {
                final String json = nativeEnumItems(itemType);
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        setBusy(false);
                        try {
                            showPickerDialog(json, title, nativeAddMethod, targetInput);
                        } catch (Exception e) {
                            statusText.setText("\u274C 解析失败: " + e.getMessage());
                        }
                    }
                });
            }
        }).start();
    }

    // 解析 JSON 并显示选择对话框
    private void showPickerDialog(String json, final String title,
                                   final String nativeAddMethod, final EditText targetInput) {
        // 手动解析简单 JSON 数组 [{"id":1,"n":"名字"},...]
        final List<int[]> ids = new ArrayList<int[]>();
        final List<String> names = new ArrayList<String>();

        try {
            json = json.trim();
            if (json.startsWith("[")) json = json.substring(1);
            if (json.endsWith("]")) json = json.substring(0, json.length() - 1);

            // 按 },{ 分割
            String[] parts = json.split("\\},\\s*\\{");
            for (String part : parts) {
                part = part.replace("{", "").replace("}", "").trim();
                if (part.isEmpty()) continue;
                int id = 0;
                String name = "???";
                String[] fields = part.split(",");
                for (String f : fields) {
                    f = f.trim();
                    if (f.startsWith("\"id\":")) {
                        try { id = Integer.parseInt(f.substring(5).trim()); } catch (Exception e) {}
                    } else if (f.startsWith("\"n\":")) {
                        name = f.substring(4).trim();
                        if (name.startsWith("\"")) name = name.substring(1);
                        if (name.endsWith("\"")) name = name.substring(0, name.length() - 1);
                        name = name.replace("\\\"", "\"").replace("\\\\", "\\");
                    }
                }
                if (id > 0) {
                    ids.add(new int[]{id});
                    names.add("[" + id + "] " + name);
                }
            }
        } catch (Exception e) {
            statusText.setText("\u274C JSON解析错误");
            return;
        }

        if (ids.isEmpty()) {
            statusText.setText("\u26A0\uFE0F 未找到" + title + "数据 (需先进入对局)");
            return;
        }

        statusText.setText("\u2705 找到 " + ids.size() + " 个" + title);

        // ===== 构建对话框 =====
        // 先让悬浮窗不抢焦点
        wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                       | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL;
        try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}

        LinearLayout dialogRoot = new LinearLayout(activity);
        dialogRoot.setOrientation(LinearLayout.VERTICAL);
        dialogRoot.setPadding(dp(8), dp(4), dp(8), dp(4));

        // 搜索框
        final EditText searchBox = new EditText(activity);
        searchBox.setHint("\uD83D\uDD0D 搜索...");
        searchBox.setTextColor(0xFF000000);
        searchBox.setHintTextColor(0xFF999999);
        searchBox.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        searchBox.setSingleLine(true);
        searchBox.setPadding(dp(8), dp(4), dp(8), dp(4));
        dialogRoot.addView(searchBox);

        // 物品计数
        final TextView countLabel = new TextView(activity);
        countLabel.setText("共 " + ids.size() + " 项 (已选 0)");
        countLabel.setTextColor(0xFF666666);
        countLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        countLabel.setPadding(dp(4), dp(2), 0, dp(2));
        dialogRoot.addView(countLabel);

        // 滚动列表
        ScrollView sv = new ScrollView(activity);
        sv.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(320)));

        final LinearLayout listLayout = new LinearLayout(activity);
        listLayout.setOrientation(LinearLayout.VERTICAL);
        listLayout.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        final boolean[] selected = new boolean[ids.size()];
        final CheckBox[] checkBoxes = new CheckBox[ids.size()];

        for (int i = 0; i < ids.size(); i++) {
            CheckBox cb = new CheckBox(activity);
            cb.setText(names.get(i));
            cb.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            cb.setChecked(false);
            final int idx = i;
            cb.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton b, boolean checked) {
                    selected[idx] = checked;
                    int cnt = 0;
                    for (boolean s : selected) if (s) cnt++;
                    countLabel.setText("共 " + ids.size() + " 项 (已选 " + cnt + ")");
                }
            });
            checkBoxes[i] = cb;
            listLayout.addView(cb);
        }

        sv.addView(listLayout);
        dialogRoot.addView(sv);

        // 搜索过滤
        searchBox.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
            @Override
            public void afterTextChanged(android.text.Editable s) {
                String q = s.toString().toLowerCase().trim();
                for (int i = 0; i < checkBoxes.length; i++) {
                    boolean visible = q.isEmpty() || names.get(i).toLowerCase().contains(q);
                    checkBoxes[i].setVisibility(visible ? View.VISIBLE : View.GONE);
                }
            }
        });

        AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        builder.setTitle("\u2728 选择" + title);
        builder.setView(dialogRoot);
        builder.setPositiveButton("添加选中", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                // 恢复悬浮窗
                wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}

                int addCount = 0;
                for (int i = 0; i < selected.length; i++) {
                    if (!selected[i]) continue;
                    addCount++;
                }

                if (addCount == 0) {
                    statusText.setText("未选择任何" + title);
                    return;
                }

                // 在后台线程批量添加
                final List<Integer> toAdd = new ArrayList<Integer>();
                for (int i = 0; i < selected.length; i++) {
                    if (selected[i]) toAdd.add(ids.get(i)[0]);
                }

                setBusy(true);
                statusText.setText("\u23F3 添加 " + toAdd.size() + " 个" + title + "...");
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        int ok = 0;
                        for (int itemId : toAdd) {
                            try {
                                java.lang.reflect.Method m = OverlayMenu.class.getDeclaredMethod(
                                        nativeAddMethod, int.class);
                                m.invoke(null, itemId);
                                ok++;
                            } catch (Exception e) { /* skip */ }
                        }
                        final int fOk = ok;
                        new Handler(Looper.getMainLooper()).post(new Runnable() {
                            @Override
                            public void run() {
                                statusText.setText("\u2705 已添加 " + fOk + " 个" + title);
                                setBusy(false);
                            }
                        });
                    }
                }).start();
            }
        });
        builder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
            }
        });
        builder.setCancelable(true);
        builder.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
            }
        });

        try {
            AlertDialog dlg = builder.create();
            if (dlg.getWindow() != null) {
                dlg.getWindow().setType(2);
            }
            dlg.show();
        } catch (Exception e) {
            statusText.setText("\u274C 无法显示对话框: " + e.getMessage());
            wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
            try { wm.updateViewLayout(container, wmParams); } catch (Exception e2) {}
        }
    }

    // 标题栏拖动
    @Override
    public boolean onTouch(View v, MotionEvent event) {
        switch (event.getAction()) {
            case MotionEvent.ACTION_DOWN:
                lastX = wmParams.x;
                lastY = wmParams.y;
                touchX = event.getRawX();
                touchY = event.getRawY();
                dragging = false;
                return true;
            case MotionEvent.ACTION_MOVE:
                float dx = event.getRawX() - touchX;
                float dy = event.getRawY() - touchY;
                if (Math.abs(dx) > 5 || Math.abs(dy) > 5) dragging = true;
                wmParams.x = lastX + (int) dx;
                wmParams.y = lastY + (int) dy;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                return true;
            case MotionEvent.ACTION_UP:
                return dragging;
        }
        return false;
    }
}
