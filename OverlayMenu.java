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
    private EditText lostthingInput, cardInput, cardCountInput, equipSlotsInput;
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
    private static final int BTN_EQUIP_SLOTS  = 0x7f000023;
    private static final int BTN_PRESCAN      = 0x7f000024;
    private static final int BTN_MANAGE_CARD  = 0x7f000025;
    private static final int BTN_MANAGE_BLESS = 0x7f000026;
    private static final int BTN_MANAGE_EQUIP = 0x7f000027;

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
    public static native String nativeModifyEquipSlots(int slots);
    public static native String nativePreScan();
    public static native String nativeGetCurrentItems(int type);
    public static native String nativeRemoveCard(int cardId);
    public static native String nativeRemoveLostThing(int lostThingId);
    public static native String nativeSetCardCount(int cardId, int count);

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
        container.setPadding(dp(10), dp(6), dp(10), dp(8));

        GradientDrawable bg = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{0xF00D0D1F, 0xF0141430});
        bg.setCornerRadius(dp(16));
        bg.setStroke(dp(1), 0x44818CF8);
        container.setBackground(bg);

        // ===== 标题栏 (可拖动) =====
        LinearLayout titleBar = new LinearLayout(activity);
        titleBar.setOrientation(LinearLayout.HORIZONTAL);
        titleBar.setGravity(Gravity.CENTER_VERTICAL);
        titleBar.setPadding(dp(2), dp(2), dp(2), dp(2));
        titleBar.setOnTouchListener(this);

        TextView title = new TextView(activity);
        title.setText("\uD83C\uDF15 月圆之夜");
        title.setTextColor(0xFFE0E7FF);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        title.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        titleBar.addView(title);

        TextView verLabel = new TextView(activity);
        verLabel.setText("v2.0");
        verLabel.setTextColor(0x66A5B4FC);
        verLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 9);
        LinearLayout.LayoutParams vlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        vlp.setMargins(0, 0, dp(6), 0);
        verLabel.setLayoutParams(vlp);
        titleBar.addView(verLabel);

        toggleBtn = makeBtn("\u2014", 0x33FFFFFF, BTN_TOGGLE);
        toggleBtn.setTextColor(0xFFA5B4FC);
        toggleBtn.setLayoutParams(new LinearLayout.LayoutParams(dp(28), dp(28)));
        titleBar.addView(toggleBtn);

        container.addView(titleBar);

        // 标题渐变下划线
        View accentLine = new View(activity);
        accentLine.setBackground(new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,
                new int[]{0xFF6366F1, 0xFF7C3AED, 0x006366F1}));
        LinearLayout.LayoutParams aclp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(2));
        aclp.setMargins(0, dp(1), 0, dp(4));
        accentLine.setLayoutParams(aclp);
        container.addView(accentLine);

        // ===== 内容区 (可滚动) =====
        scrollView = new ScrollView(activity);
        LinearLayout.LayoutParams svlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(400));
        scrollView.setLayoutParams(svlp);
        scrollView.setVerticalScrollBarEnabled(false);

        contentArea = new LinearLayout(activity);
        contentArea.setOrientation(LinearLayout.VERTICAL);
        contentArea.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // ==================== 🔄 预加载 ====================
        Button prescanBtn = makeGradientBtn("\uD83D\uDD04 预加载内存数据", 0xFF0E7490, 0xFF0D9488, BTN_PRESCAN);
        LinearLayout.LayoutParams pslp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(32));
        pslp.setMargins(0, 0, 0, dp(6));
        prescanBtn.setLayoutParams(pslp);
        prescanBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        contentArea.addView(prescanBtn);

        // ==================== ⚔️ 战斗属性 ====================
        LinearLayout statsCard = makeSectionCard(0xFF1A1A35, 0x337C3AED);
        addCardHeader(statsCard, "\u2694\uFE0F 战斗属性", 0xFFFCD34D);

        goldInput = addCompactInputRow(statsCard, "\uD83D\uDCB0 金币", "99999", BTN_GOLD, "修改");

        // 金币快捷按钮
        LinearLayout quickRow = new LinearLayout(activity);
        quickRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams qrlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        qrlp.setMargins(0, dp(1), 0, dp(3));
        quickRow.setLayoutParams(qrlp);
        int[] presets = {9999, 99999, 888888, 999999};
        int[] pids = {BTN_P1, BTN_P2, BTN_P3, BTN_P4};
        for (int i = 0; i < presets.length; i++) {
            Button qb = makeBtn(String.valueOf(presets[i]), 0xFF252545, pids[i]);
            qb.setTextSize(TypedValue.COMPLEX_UNIT_SP, 9);
            qb.setTextColor(0xFFAAAACC);
            qb.setTag(presets[i]);
            LinearLayout.LayoutParams qblp = new LinearLayout.LayoutParams(0, dp(22), 1f);
            if (i > 0) qblp.setMargins(dp(2), 0, 0, 0);
            qb.setLayoutParams(qblp);
            quickRow.addView(qb);
        }
        statsCard.addView(quickRow);

        hpInput = addCompactInputRow(statsCard, "\u2764\uFE0F 血量上限", "999", BTN_HP, "修改");
        mpInput = addCompactInputRow(statsCard, "\uD83D\uDD2E 法力值", "99", BTN_MP, "修改");
        actionInput = addCompactInputRow(statsCard, "\u26A1 行动值", "99", BTN_ACTION, "修改");
        handcardsInput = addCompactInputRow(statsCard, "\uD83C\uDCCF 手牌上限", "10", BTN_HANDCARDS, "修改");
        equipSlotsInput = addCompactInputRow(statsCard, "\u2694\uFE0F 装备槽", "6", BTN_EQUIP_SLOTS, "设置");

        contentArea.addView(statsCard);

        // ==================== 🃏 卡牌管理 ====================
        LinearLayout cardsCard = makeSectionCard(0xFF1A1A35, 0x3360A5FA);
        addCardHeader(cardsCard, "\uD83C\uDCCF 卡牌管理", 0xFF60A5FA);

        {
            LinearLayout cardRow = new LinearLayout(activity);
            cardRow.setOrientation(LinearLayout.HORIZONTAL);
            cardRow.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams crlp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            crlp.setMargins(0, dp(2), 0, 0);
            cardRow.setLayoutParams(crlp);

            cardInput = makeStyledInput("卡牌ID");
            cardInput.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            final EditText ciRef = cardInput;
            cardInput.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    wmParams.flags = 0; try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                    ciRef.requestFocus();
                }
            });
            cardRow.addView(cardInput);

            TextView xLabel = new TextView(activity);
            xLabel.setText(" x");
            xLabel.setTextColor(0xFF888899);
            xLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            cardRow.addView(xLabel);

            cardCountInput = makeStyledInput("1");
            cardCountInput.setText("1");
            cardCountInput.setLayoutParams(new LinearLayout.LayoutParams(dp(32), ViewGroup.LayoutParams.WRAP_CONTENT));
            final EditText ccRef = cardCountInput;
            cardCountInput.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    wmParams.flags = 0; try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                    ccRef.requestFocus();
                }
            });
            cardRow.addView(cardCountInput);

            Button cardAddBtn = makeBtn("添加", 0xFF6366F1, BTN_CARD);
            LinearLayout.LayoutParams cablp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, dp(28));
            cablp.setMargins(dp(3), 0, 0, 0);
            cardAddBtn.setLayoutParams(cablp);
            cardRow.addView(cardAddBtn);

            cardsCard.addView(cardRow);
        }

        addDualActionRow(cardsCard, BTN_BROWSE_CARD, "\uD83D\uDCC2 浏览全部", BTN_MANAGE_CARD, "\uD83D\uDCCB 管理当前");
        contentArea.addView(cardsCard);

        // ==================== ✨ 祝福/遗物 ====================
        LinearLayout blessCard = makeSectionCard(0xFF1A1A35, 0x33FBBF24);
        addCardHeader(blessCard, "\u2728 祝福/遗物", 0xFFFBBF24);

        lostthingInput = addCompactInputRow(blessCard, "遗物ID", "", BTN_LOSTTHING, "添加");
        addDualActionRow(blessCard, BTN_BROWSE_BLESS, "\uD83D\uDCC2 浏览全部", BTN_MANAGE_BLESS, "\uD83D\uDCCB 管理当前");

        contentArea.addView(blessCard);

        // ==================== ⚡ 技能CD ====================
        LinearLayout skillCard = makeSectionCard(0xFF1A1A35, 0x3367E8F9);
        addCardHeader(skillCard, "\u26A1 技能CD", 0xFF67E8F9);

        LinearLayout skillRow = new LinearLayout(activity);
        skillRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams srlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        srlp.setMargins(0, dp(2), 0, 0);
        skillRow.setLayoutParams(srlp);

        Button skillBtn = makeBtn("重置CD", 0xFF0E7490, BTN_SKILL);
        skillBtn.setLayoutParams(new LinearLayout.LayoutParams(0, dp(28), 1f));
        skillRow.addView(skillBtn);

        autoSkillBtn = makeBtn("自动:关", 0xFF2D2D4A, BTN_SKILL_AUTO);
        LinearLayout.LayoutParams asblp = new LinearLayout.LayoutParams(0, dp(28), 1f);
        asblp.setMargins(dp(3), 0, 0, 0);
        autoSkillBtn.setLayoutParams(asblp);
        skillRow.addView(autoSkillBtn);

        skillCard.addView(skillRow);
        contentArea.addView(skillCard);

        // ==================== 🚀 一键修改 ====================
        Button modAllBtn = makeGradientBtn("\uD83D\uDE80 一键全部修改", 0xFF6366F1, 0xFF7C3AED, BTN_MODIFY_ALL);
        LinearLayout.LayoutParams mablp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(36));
        mablp.setMargins(0, dp(6), 0, 0);
        modAllBtn.setLayoutParams(mablp);
        modAllBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        modAllBtn.setTypeface(null, android.graphics.Typeface.BOLD);
        contentArea.addView(modAllBtn);

        // --- 状态栏 ---
        statusText = new TextView(activity);
        statusText.setText("\u2705 就绪 - 进入对局后使用");
        statusText.setTextColor(0xFF9CA3AF);
        statusText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        statusText.setPadding(dp(6), dp(4), dp(6), dp(4));
        GradientDrawable stBg = new GradientDrawable();
        stBg.setColor(0x18FFFFFF);
        stBg.setCornerRadius(dp(6));
        statusText.setBackground(stBg);
        LinearLayout.LayoutParams stlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        stlp.setMargins(0, dp(6), 0, 0);
        statusText.setLayoutParams(stlp);
        contentArea.addView(statusText);

        scrollView.addView(contentArea);
        container.addView(scrollView);

        // ===== WindowManager 参数 =====
        wmParams = new WindowManager.LayoutParams(
                dp(250),
                ViewGroup.LayoutParams.WRAP_CONTENT,
                2,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                PixelFormat.TRANSLUCENT);
        wmParams.gravity = Gravity.TOP | Gravity.LEFT;
        wmParams.x = dp(10);
        wmParams.y = dp(80);

        wm.addView(container, wmParams);
        android.util.Log.i("GoldHack", "Overlay menu created (v2.0)");
    }

    // ===== 辅助: 创建区段卡片 =====
    private LinearLayout makeSectionCard(int bgColor, int borderColor) {
        LinearLayout card = new LinearLayout(activity);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(8), dp(6), dp(8), dp(6));
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(bgColor);
        gd.setCornerRadius(dp(10));
        gd.setStroke(dp(1), borderColor);
        card.setBackground(gd);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(4), 0, 0);
        card.setLayoutParams(lp);
        return card;
    }

    // ===== 辅助: 卡片标题 =====
    private void addCardHeader(LinearLayout parent, String text, int color) {
        TextView label = new TextView(activity);
        label.setText(text);
        label.setTextColor(color);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        label.setTypeface(null, android.graphics.Typeface.BOLD);
        label.setPadding(0, 0, 0, dp(2));
        parent.addView(label);
    }

    // ===== 辅助: 紧凑输入行 (标签+输入+按钮) =====
    private EditText addCompactInputRow(LinearLayout parent, String label, String defVal, int btnId, String btnText) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rlp.setMargins(0, dp(2), 0, 0);
        row.setLayoutParams(rlp);

        // 左侧标签
        TextView tv = new TextView(activity);
        tv.setText(label);
        tv.setTextColor(0xFFCCCCDD);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        tv.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.45f));
        row.addView(tv);

        // 输入框
        EditText input = makeStyledInput("");
        if (defVal != null && !defVal.isEmpty()) input.setText(defVal);
        input.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.35f));
        final EditText fi = input;
        input.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                wmParams.flags = 0;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                fi.requestFocus();
            }
        });
        input.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override public void onFocusChange(View v, boolean hasFocus) {
                if (!hasFocus) {
                    wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                    try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                }
            }
        });
        row.addView(input);

        // 按钮
        Button btn = makeBtn(btnText, 0xFF6366F1, btnId);
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(26));
        blp.setMargins(dp(3), 0, 0, 0);
        btn.setLayoutParams(blp);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        row.addView(btn);

        parent.addView(row);
        return input;
    }

    // ===== 辅助: 样式化输入框 =====
    private EditText makeStyledInput(String hint) {
        EditText input = new EditText(activity);
        input.setHint(hint);
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(0xFF555577);
        input.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        input.setInputType(InputType.TYPE_CLASS_NUMBER);
        input.setSingleLine(true);
        input.setPadding(dp(6), dp(3), dp(6), dp(3));
        GradientDrawable ibg = new GradientDrawable();
        ibg.setColor(0xFF16163A);
        ibg.setCornerRadius(dp(6));
        ibg.setStroke(dp(1), 0xFF333366);
        input.setBackground(ibg);
        return input;
    }

    // ===== 辅助: 双按钮行 =====
    private void addDualActionRow(LinearLayout parent, int btn1Id, String btn1Text, int btn2Id, String btn2Text) {
        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rlp.setMargins(0, dp(3), 0, 0);
        row.setLayoutParams(rlp);

        Button b1 = makeBtn(btn1Text, 0xFF252545, btn1Id);
        b1.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        b1.setTextColor(0xFFCCCCDD);
        b1.setLayoutParams(new LinearLayout.LayoutParams(0, dp(26), 1f));
        row.addView(b1);

        Button b2 = makeBtn(btn2Text, 0xFF252545, btn2Id);
        b2.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        b2.setTextColor(0xFFCCCCDD);
        LinearLayout.LayoutParams b2lp = new LinearLayout.LayoutParams(0, dp(26), 1f);
        b2lp.setMargins(dp(3), 0, 0, 0);
        b2.setLayoutParams(b2lp);
        row.addView(b2);

        parent.addView(row);
    }

    // ===== 辅助: 渐变按钮 =====
    private Button makeGradientBtn(String text, int color1, int color2, int id) {
        Button btn = new Button(activity);
        btn.setText(text);
        btn.setTextColor(Color.WHITE);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        btn.setAllCaps(false);
        GradientDrawable gd = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,
                new int[]{color1, color2});
        gd.setCornerRadius(dp(10));
        btn.setBackground(gd);
        btn.setPadding(dp(10), dp(2), dp(10), dp(2));
        btn.setMinHeight(0);
        btn.setMinimumHeight(0);
        btn.setId(id);
        btn.setOnClickListener(this);
        return btn;
    }

    private Button makeBtn(String text, int bgColor, int id) {
        Button btn = new Button(activity);
        btn.setText(text);
        btn.setTextColor(Color.WHITE);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        btn.setAllCaps(false);
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(bgColor);
        gd.setCornerRadius(dp(8));
        btn.setBackground(gd);
        btn.setPadding(dp(8), dp(2), dp(8), dp(2));
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
                wmParams.width = dp(250);
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
        } else if (id == BTN_EQUIP_SLOTS) {
            doIntModify(equipSlotsInput, "nativeModifyEquipSlots");
        } else if (id == BTN_LOSTTHING) {
            doIntModify(lostthingInput, "nativeAddLostThing");
        } else if (id == BTN_CARD) {
            doAddCardWithCount();
        } else if (id == BTN_SKILL) {
            doSkillReset();
        } else if (id == BTN_SKILL_AUTO) {
            toggleAutoReset();
        } else if (id == BTN_MODIFY_ALL) {
            doModifyAll();
        } else if (id == BTN_BROWSE_CARD) {
            showItemPicker(ITEM_TYPE_CARD, cardInput, "nativeAddCard", "卡牌");
        } else if (id == BTN_BROWSE_BLESS) {
            showItemPicker(ITEM_TYPE_LOSTTHING, lostthingInput, "nativeAddLostThing", "祝福/遗物");
        } else if (id == BTN_MANAGE_CARD) {
            showCardManageDialog();
        } else if (id == BTN_MANAGE_BLESS) {
            showManageDialog(ITEM_TYPE_LOSTTHING, "祝福/遗物", "nativeRemoveLostThing");
        } else if (id == BTN_PRESCAN) {
            doPreScan();
        } else if (id == BTN_P1 || id == BTN_P2 || id == BTN_P3 || id == BTN_P4) {
            Object tag = v.getTag();
            if (tag != null) goldInput.setText(tag.toString());
        }
    }

    private volatile boolean busy = false;

    private void setBusy(boolean b) {
        busy = b;
    }

    // 添加卡牌(支持数量)
    private void doAddCardWithCount() {
        if (busy) return;
        String idText = cardInput.getText().toString().trim();
        String countText = cardCountInput.getText().toString().trim();
        final int cardId, count;
        try {
            cardId = Integer.parseInt(idText);
        } catch (NumberFormatException e) { statusText.setText("\u274C 请输入卡牌ID"); return; }
        try {
            count = countText.isEmpty() ? 1 : Integer.parseInt(countText);
        } catch (NumberFormatException e) { statusText.setText("\u274C 数量无效"); return; }
        if (count <= 0 || count > 99) { statusText.setText("\u274C 数量范围 1-99"); return; }
        setBusy(true);
        statusText.setText("\u23F3 添加 " + count + " 张卡牌 " + cardId + "...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                int ok = 0;
                for (int i = 0; i < count; i++) {
                    try {
                        String r = nativeAddCard(cardId);
                        if (r != null && r.contains("\u2705")) ok++;
                    } catch (Exception e) { break; }
                }
                final int fOk = ok;
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        statusText.setText("\u2705 已添加 " + fOk + " 张卡牌 " + cardId);
                        setBusy(false);
                    }
                });
            }
        }).start();
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
            gd.setColor(0xFF2D2D4A);
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

    // ===== 预加载内存数据 =====
    private void doPreScan() {
        if (busy) return;
        setBusy(true);
        statusText.setText("\u23F3 正在扫描内存...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String result = nativePreScan();
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

    // ===== 卡牌管理 (查看数量 + 修改数量) =====
    private void showCardManageDialog() {
        if (busy) return;
        setBusy(true);
        statusText.setText("\u23F3 读取当前卡牌...");

        new Thread(new Runnable() {
            @Override
            public void run() {
                final String currentJson = nativeGetCurrentItems(ITEM_TYPE_CARD);
                final String enumJson = nativeEnumItems(ITEM_TYPE_CARD);
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        setBusy(false);
                        try {
                            buildCardManageDialog(currentJson, enumJson);
                        } catch (Exception e) {
                            statusText.setText("\u274C 解析失败: " + e.getMessage());
                        }
                    }
                });
            }
        }).start();
    }

    private void buildCardManageDialog(String currentJson, String enumJson) {
        final List<Integer> currentIds = parseIdList(currentJson);
        if (currentIds.isEmpty()) { statusText.setText("\u26A0\uFE0F 当前没有卡牌"); return; }

        final java.util.Map<Integer, String> nameMap = parseNameMap(enumJson);

        final java.util.Map<Integer, Integer> countMap = new java.util.LinkedHashMap<Integer, Integer>();
        for (int id : currentIds) {
            Integer c = countMap.get(id);
            countMap.put(id, c == null ? 1 : c + 1);
        }

        final List<Integer> uniqueIds = new ArrayList<Integer>(countMap.keySet());
        final int[] originalCounts = new int[uniqueIds.size()];
        final int[] newCounts = new int[uniqueIds.size()];
        for (int i = 0; i < uniqueIds.size(); i++) {
            originalCounts[i] = countMap.get(uniqueIds.get(i));
            newCounts[i] = originalCounts[i];
        }

        statusText.setText("\u2705 当前 " + currentIds.size() + " 张卡牌 (" + uniqueIds.size() + " 种)");

        // --- 构建深色风格对话框 ---
        wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL;
        try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}

        LinearLayout dialogRoot = new LinearLayout(activity);
        dialogRoot.setOrientation(LinearLayout.VERTICAL);
        dialogRoot.setPadding(dp(12), dp(8), dp(12), dp(8));
        dialogRoot.setBackgroundColor(0xFF1A1A2E);

        // 标题信息
        final TextView infoLabel = new TextView(activity);
        infoLabel.setText("\uD83C\uDCCF " + currentIds.size() + " 张卡牌 (" + uniqueIds.size() + " 种)");
        infoLabel.setTextColor(0xFFE0E7FF);
        infoLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        infoLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        infoLabel.setPadding(0, 0, 0, dp(6));
        dialogRoot.addView(infoLabel);

        // 搜索框
        final EditText searchBox = makeDialogSearchBox();
        dialogRoot.addView(searchBox);

        // 滚动列表
        ScrollView sv = new ScrollView(activity);
        sv.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(320)));
        sv.setVerticalScrollBarEnabled(false);

        final LinearLayout listLayout = new LinearLayout(activity);
        listLayout.setOrientation(LinearLayout.VERTICAL);
        listLayout.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        final LinearLayout[] cardRows = new LinearLayout[uniqueIds.size()];
        final List<String> displayNames = new ArrayList<String>();

        for (int i = 0; i < uniqueIds.size(); i++) {
            final int idx = i;
            int cardId = uniqueIds.get(i);
            String name = nameMap.containsKey(cardId) ? nameMap.get(cardId) : "???";
            String label = "[" + cardId + "] " + name;
            displayNames.add(label);

            LinearLayout row = new LinearLayout(activity);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(6), dp(4), dp(6), dp(4));
            LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rowLp.setMargins(0, dp(1), 0, dp(1));
            row.setLayoutParams(rowLp);

            GradientDrawable rowBg = new GradientDrawable();
            rowBg.setColor(i % 2 == 0 ? 0xFF202040 : 0xFF1C1C38);
            rowBg.setCornerRadius(dp(6));
            row.setBackground(rowBg);

            TextView nameLabel = new TextView(activity);
            nameLabel.setText(label);
            nameLabel.setTextColor(0xFFD0D0E0);
            nameLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            nameLabel.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            nameLabel.setSingleLine(true);
            row.addView(nameLabel);

            final EditText countEdit = new EditText(activity);
            countEdit.setText(String.valueOf(originalCounts[i]));
            countEdit.setTextColor(0xFFE0E7FF);
            countEdit.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            countEdit.setGravity(Gravity.CENTER);
            countEdit.setInputType(InputType.TYPE_CLASS_NUMBER);
            countEdit.setSingleLine(true);
            countEdit.setFocusable(true);
            countEdit.setFocusableInTouchMode(true);
            countEdit.setClickable(true);
            GradientDrawable ceBg = new GradientDrawable();
            ceBg.setColor(0xFF16163A);
            ceBg.setCornerRadius(dp(4));
            ceBg.setStroke(dp(1), 0xFF444477);
            countEdit.setBackground(ceBg);
            countEdit.setPadding(dp(4), dp(2), dp(4), dp(2));
            LinearLayout.LayoutParams celp = new LinearLayout.LayoutParams(dp(42), dp(28));
            celp.setMargins(dp(4), 0, 0, 0);
            countEdit.setLayoutParams(celp);
            countEdit.addTextChangedListener(new android.text.TextWatcher() {
                @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
                @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
                @Override
                public void afterTextChanged(android.text.Editable s) {
                    int val = originalCounts[idx];
                    try { val = Integer.parseInt(s.toString().trim()); } catch (Exception e) {}
                    newCounts[idx] = val;
                    countEdit.setTextColor(val != originalCounts[idx] ? 0xFFFF6B6B : 0xFFE0E7FF);
                    updateCardInfoLabel(infoLabel, uniqueIds, newCounts);
                }
            });
            row.addView(countEdit);

            cardRows[i] = row;
            listLayout.addView(row);
        }

        sv.addView(listLayout);
        dialogRoot.addView(sv);

        searchBox.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
            @Override
            public void afterTextChanged(android.text.Editable s) {
                String q = s.toString().toLowerCase().trim();
                for (int i = 0; i < cardRows.length; i++) {
                    boolean visible = q.isEmpty() || displayNames.get(i).toLowerCase().contains(q);
                    cardRows[i].setVisibility(visible ? View.VISIBLE : View.GONE);
                }
            }
        });

        // 底部按钮行
        LinearLayout btnRow = new LinearLayout(activity);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams brlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        brlp.setMargins(0, dp(8), 0, 0);
        btnRow.setLayoutParams(brlp);

        Button applyBtn = makeDialogBtn("\u2705 应用修改", 0xFF6366F1);
        applyBtn.setLayoutParams(new LinearLayout.LayoutParams(0, dp(34), 1f));
        btnRow.addView(applyBtn);

        Button closeBtn = makeDialogBtn("关闭", 0xFF374151);
        LinearLayout.LayoutParams cblp = new LinearLayout.LayoutParams(0, dp(34), 0.5f);
        cblp.setMargins(dp(4), 0, 0, 0);
        closeBtn.setLayoutParams(cblp);
        btnRow.addView(closeBtn);

        dialogRoot.addView(btnRow);

        // 显示对话框
        AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        builder.setView(dialogRoot);
        builder.setCancelable(true);

        final AlertDialog[] dlgRef = new AlertDialog[1];

        final Runnable restoreFlags = new Runnable() {
            @Override public void run() {
                wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
            }
        };

        applyBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                restoreFlags.run();
                if (dlgRef[0] != null) dlgRef[0].dismiss();
                final List<int[]> changes = new ArrayList<int[]>();
                for (int i = 0; i < uniqueIds.size(); i++) {
                    if (newCounts[i] != originalCounts[i])
                        changes.add(new int[]{uniqueIds.get(i), newCounts[i]});
                }
                if (changes.isEmpty()) { statusText.setText("未修改任何卡牌"); return; }
                setBusy(true);
                statusText.setText("\u23F3 应用 " + changes.size() + " 项修改...");
                new Thread(new Runnable() {
                    @Override public void run() {
                        int ok = 0;
                        for (int[] ch : changes) {
                            String r = nativeSetCardCount(ch[0], ch[1]);
                            if (r != null && r.contains("\u2705")) ok++;
                        }
                        final int fOk = ok;
                        new Handler(Looper.getMainLooper()).post(new Runnable() {
                            @Override public void run() {
                                statusText.setText("\u2705 已修改 " + fOk + "/" + changes.size() + " 种卡牌");
                                setBusy(false);
                            }
                        });
                    }
                }).start();
            }
        });
        closeBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                restoreFlags.run();
                if (dlgRef[0] != null) dlgRef[0].dismiss();
            }
        });
        builder.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override public void onCancel(DialogInterface d) { restoreFlags.run(); }
        });

        try {
            AlertDialog dlg = builder.create();
            dlgRef[0] = dlg;
            if (dlg.getWindow() != null) {
                dlg.getWindow().setType(2038);
                dlg.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
                dlg.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE);
                dlg.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
            }
            dlg.show();
        } catch (Exception e) {
            statusText.setText("\u274C 无法显示对话框: " + e.getMessage());
            restoreFlags.run();
        }
    }

    private void updateCardInfoLabel(TextView label, List<Integer> uniqueIds, int[] newCounts) {
        int total = 0;
        for (int c : newCounts) total += c;
        int kinds = 0;
        for (int c : newCounts) if (c > 0) kinds++;
        label.setText("\uD83C\uDCCF " + total + " 张卡牌 (" + kinds + " 种)");
    }

    // ===== 管理当前物品 (查看 + 删除) =====
    // 通用管理对话框 - 深色主题 + 全选功能
    //
    // 使用方法:
    //   buildManageDialog(currentJson, enumJson, "祝福", "nativeRemoveBlessing", ITEM_TYPE_BLESSING);
    //
    // currentJson: "[1,2,3,...]" 当前拥有的物品ID列表
    // enumJson: "[{id:1,n:"名称"},...]" 所有可选物品的枚举
    // title: 物品类型名称 (如 "祝福", "遗物")
    // nativeRemoveMethod: 原生删除方法名
    // itemType: 物品类型常量

    private void buildManageDialog(String currentJson, String enumJson, final String title,
                                    final String nativeRemoveMethod, final int itemType) {
        final List<Integer> currentIds = parseIdList(currentJson);
        if (currentIds.isEmpty()) { statusText.setText("\u26A0\uFE0F 当前没有" + title); return; }

        final java.util.Map<Integer, String> nameMap = parseNameMap(enumJson);

        final java.util.Map<Integer, Integer> countMap = new java.util.LinkedHashMap<Integer, Integer>();
        for (int id : currentIds) {
            Integer c = countMap.get(id);
            countMap.put(id, c == null ? 1 : c + 1);
        }

        final List<Integer> uniqueIds = new ArrayList<Integer>(countMap.keySet());
        final List<String> displayNames = new ArrayList<String>();
        for (int id : uniqueIds) {
            String name = nameMap.containsKey(id) ? nameMap.get(id) : "???";
            int cnt = countMap.get(id);
            String label = "[" + id + "] " + name;
            if (cnt > 1) label += " \u00D7" + cnt;
            displayNames.add(label);
        }

        statusText.setText("\u2705 当前 " + currentIds.size() + " 个" + title);

        wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                       | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL;
        try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}

        LinearLayout dialogRoot = new LinearLayout(activity);
        dialogRoot.setOrientation(LinearLayout.VERTICAL);
        dialogRoot.setPadding(dp(12), dp(8), dp(12), dp(8));
        dialogRoot.setBackgroundColor(0xFF1A1A2E);

        // 标题信息
        TextView infoLabel = new TextView(activity);
        infoLabel.setText("\uD83D\uDCCB 当前 " + currentIds.size() + " 个" + title + " (" + uniqueIds.size() + " 种)");
        infoLabel.setTextColor(0xFFE0E7FF);
        infoLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        infoLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        infoLabel.setPadding(0, 0, 0, dp(4));
        dialogRoot.addView(infoLabel);

        // 搜索框
        final EditText searchBox = makeDialogSearchBox();
        dialogRoot.addView(searchBox);

        // 计数 + 全选行
        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams trlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        trlp.setMargins(0, dp(2), 0, dp(4));
        topRow.setLayoutParams(trlp);

        final TextView countLabel = new TextView(activity);
        countLabel.setText("已选 0 项");
        countLabel.setTextColor(0xFF9CA3AF);
        countLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        countLabel.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        topRow.addView(countLabel);

        final boolean[] selected = new boolean[uniqueIds.size()];
        final CheckBox[] checkBoxes = new CheckBox[uniqueIds.size()];

        // 全选按钮
        final Button selectAllBtn = makeDialogBtn("\u2611 全选", 0xFF2D2D4A);
        selectAllBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        selectAllBtn.setTextColor(0xFFA5B4FC);
        selectAllBtn.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(24)));
        selectAllBtn.setOnClickListener(new View.OnClickListener() {
            boolean allSelected = false;
            @Override public void onClick(View v) {
                allSelected = !allSelected;
                for (int i = 0; i < checkBoxes.length; i++) {
                    if (checkBoxes[i] != null && ((View)checkBoxes[i].getParent()).getVisibility() == View.VISIBLE)
                        checkBoxes[i].setChecked(allSelected);
                }
                selectAllBtn.setText(allSelected ? "\u2612 取消全选" : "\u2611 全选");
            }
        });
        topRow.addView(selectAllBtn);
        dialogRoot.addView(topRow);

        // 滚动列表
        ScrollView sv = new ScrollView(activity);
        sv.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(320)));
        sv.setVerticalScrollBarEnabled(false);

        final LinearLayout listLayout = new LinearLayout(activity);
        listLayout.setOrientation(LinearLayout.VERTICAL);
        listLayout.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        for (int i = 0; i < uniqueIds.size(); i++) {
            final int idx = i;

            LinearLayout itemRow = new LinearLayout(activity);
            itemRow.setOrientation(LinearLayout.HORIZONTAL);
            itemRow.setGravity(Gravity.CENTER_VERTICAL);
            itemRow.setPadding(dp(6), dp(5), dp(6), dp(5));
            LinearLayout.LayoutParams irlp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            irlp.setMargins(0, dp(1), 0, 0);
            itemRow.setLayoutParams(irlp);
            GradientDrawable irBg = new GradientDrawable();
            irBg.setColor(i % 2 == 0 ? 0xFF202040 : 0xFF1C1C38);
            irBg.setCornerRadius(dp(6));
            itemRow.setBackground(irBg);

            CheckBox cb = new CheckBox(activity);
            cb.setText(displayNames.get(i));
            cb.setTextColor(0xFFD0D0E0);
            cb.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            cb.setChecked(false);
            cb.setLayoutParams(new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            cb.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override public void onCheckedChanged(CompoundButton b, boolean checked) {
                    selected[idx] = checked;
                    int cnt = 0;
                    for (boolean s : selected) if (s) cnt++;
                    countLabel.setText("已选 " + cnt + " 项");
                }
            });
            checkBoxes[i] = cb;
            itemRow.addView(cb);
            listLayout.addView(itemRow);
        }

        sv.addView(listLayout);
        dialogRoot.addView(sv);

        searchBox.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
            @Override
            public void afterTextChanged(android.text.Editable s) {
                String q = s.toString().toLowerCase().trim();
                for (int i = 0; i < checkBoxes.length; i++) {
                    View parent = (View) checkBoxes[i].getParent();
                    boolean visible = q.isEmpty() || displayNames.get(i).toLowerCase().contains(q);
                    parent.setVisibility(visible ? View.VISIBLE : View.GONE);
                }
            }
        });

        // 底部按钮行
        LinearLayout btnRow = new LinearLayout(activity);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams brlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        brlp.setMargins(0, dp(8), 0, 0);
        btnRow.setLayoutParams(brlp);

        final AlertDialog[] dlgRef = new AlertDialog[1];
        final Runnable restoreFlags = new Runnable() {
            @Override public void run() {
                wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
            }
        };

        if (nativeRemoveMethod != null) {
            Button deleteBtn = makeDialogBtn("\uD83D\uDDD1 删除选中", 0xFFDC2626);
            deleteBtn.setLayoutParams(new LinearLayout.LayoutParams(0, dp(34), 1f));
            deleteBtn.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    restoreFlags.run();
                    if (dlgRef[0] != null) dlgRef[0].dismiss();
                    final List<Integer> toRemove = new ArrayList<Integer>();
                    for (int i = 0; i < selected.length; i++)
                        if (selected[i]) toRemove.add(uniqueIds.get(i));
                    if (toRemove.isEmpty()) { statusText.setText("未选择任何" + title); return; }
                    setBusy(true);
                    statusText.setText("\u23F3 删除 " + toRemove.size() + " 个" + title + "...");
                    new Thread(new Runnable() {
                        @Override public void run() {
                            int ok = 0;
                            for (int itemId : toRemove) {
                                try {
                                    java.lang.reflect.Method m = OverlayMenu.class.getDeclaredMethod(
                                            nativeRemoveMethod, int.class);
                                    String r = (String) m.invoke(null, itemId);
                                    if (r != null && r.contains("\u2705")) ok++;
                                } catch (Exception e) {}
                            }
                            final int fOk = ok;
                            new Handler(Looper.getMainLooper()).post(new Runnable() {
                                @Override public void run() {
                                    statusText.setText("\u2705 已删除 " + fOk + "/" + toRemove.size() + " 个" + title);
                                    setBusy(false);
                                }
                            });
                        }
                    }).start();
                }
            });
            btnRow.addView(deleteBtn);
        }

        Button closeBtn = makeDialogBtn("关闭", 0xFF374151);
        LinearLayout.LayoutParams cblp = new LinearLayout.LayoutParams(0, dp(34),
                nativeRemoveMethod != null ? 0.5f : 1f);
        if (nativeRemoveMethod != null) cblp.setMargins(dp(4), 0, 0, 0);
        closeBtn.setLayoutParams(cblp);
        closeBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                restoreFlags.run();
                if (dlgRef[0] != null) dlgRef[0].dismiss();
            }
        });
        btnRow.addView(closeBtn);
        dialogRoot.addView(btnRow);

        AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        builder.setView(dialogRoot);
        builder.setCancelable(true);
        builder.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override public void onCancel(DialogInterface d) { restoreFlags.run(); }
        });

        try {
            AlertDialog dlg = builder.create();
            dlgRef[0] = dlg;
            if (dlg.getWindow() != null) {
                dlg.getWindow().setType(2038);
                dlg.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
            }
            dlg.show();
        } catch (Exception e) {
            statusText.setText("\u274C 无法显示对话框: " + e.getMessage());
            restoreFlags.run();
        }
    }

    // ===== 可视化物品选择器 =====
    // 通用物品浏览/添加对话框 - 深色主题
    //
    // 使用方法:
    //   showPickerDialog(json, "卡牌", "nativeAddCard", cardIdInput, ITEM_TYPE_CARD);

    // 解析 JSON 并显示选择对话框
    private void showPickerDialog(String json, final String title,
                                   final String nativeAddMethod, final EditText targetInput,
                                   final int itemType) {
        final List<int[]> ids = new ArrayList<int[]>();
        final List<String> names = new ArrayList<String>();

        try {
            json = json.trim();
            if (json.startsWith("[")) json = json.substring(1);
            if (json.endsWith("]")) json = json.substring(0, json.length() - 1);
            String[] parts = json.split("\\},\\s*\\{");
            for (String part : parts) {
                part = part.replace("{", "").replace("}", "").trim();
                if (part.isEmpty()) continue;
                int id = 0; String name = "???";
                String[] fields = part.split(",");
                for (String f : fields) {
                    f = f.trim();
                    if (f.startsWith("\"id\":"))
                        try { id = Integer.parseInt(f.substring(5).trim()); } catch (Exception e) {}
                    else if (f.startsWith("\"n\":")) {
                        name = f.substring(4).trim();
                        if (name.startsWith("\"")) name = name.substring(1);
                        if (name.endsWith("\"")) name = name.substring(0, name.length() - 1);
                        name = name.replace("\\\"", "\"").replace("\\\\", "\\");
                    }
                }
                if (id > 0) {
                    if (itemType == ITEM_TYPE_LOSTTHING) {
                        String tag = (id >= 8000 && id < 9000) ? "\uD83C\uDFAD" :
                                     (id >= 10000) ? "\uD83C\uDFC6" : "\u2728";
                        names.add(tag + " [" + id + "] " + name);
                    } else {
                        names.add("[" + id + "] " + name);
                    }
                    ids.add(new int[]{id});
                }
            }
        } catch (Exception e) { statusText.setText("\u274C JSON解析错误"); return; }

        if (ids.isEmpty()) {
            statusText.setText("\u26A0\uFE0F 未找到" + title + "数据 (需先进入对局)");
            return;
        }

        statusText.setText("\u2705 找到 " + ids.size() + " 个" + title);

        wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                       | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL;
        try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}

        LinearLayout dialogRoot = new LinearLayout(activity);
        dialogRoot.setOrientation(LinearLayout.VERTICAL);
        dialogRoot.setPadding(dp(12), dp(8), dp(12), dp(8));
        dialogRoot.setBackgroundColor(0xFF1A1A2E);

        // 标题
        TextView titleLabel = new TextView(activity);
        titleLabel.setText("\u2728 选择" + title + " (共 " + ids.size() + " 项)");
        titleLabel.setTextColor(0xFFE0E7FF);
        titleLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        titleLabel.setTypeface(null, android.graphics.Typeface.BOLD);
        titleLabel.setPadding(0, 0, 0, dp(4));
        dialogRoot.addView(titleLabel);

        // 搜索框
        final EditText searchBox = makeDialogSearchBox();
        dialogRoot.addView(searchBox);

        // 顶部操作行: 计数 + 全选
        LinearLayout topRow = new LinearLayout(activity);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams trlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        trlp.setMargins(0, dp(2), 0, dp(4));
        topRow.setLayoutParams(trlp);

        final TextView countLabel = new TextView(activity);
        countLabel.setText("已选 0 项");
        countLabel.setTextColor(0xFF9CA3AF);
        countLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        countLabel.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        topRow.addView(countLabel);

        final boolean[] selected = new boolean[ids.size()];
        final CheckBox[] checkBoxes = new CheckBox[ids.size()];

        final Button selectAllBtn = makeDialogBtn("\u2611 全选", 0xFF2D2D4A);
        selectAllBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        selectAllBtn.setTextColor(0xFFA5B4FC);
        selectAllBtn.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, dp(24)));
        selectAllBtn.setOnClickListener(new View.OnClickListener() {
            boolean allSelected = false;
            @Override public void onClick(View v) {
                allSelected = !allSelected;
                for (int i = 0; i < checkBoxes.length; i++) {
                    if (checkBoxes[i] != null && ((View)checkBoxes[i].getParent()).getVisibility() == View.VISIBLE)
                        checkBoxes[i].setChecked(allSelected);
                }
                selectAllBtn.setText(allSelected ? "\u2612 取消全选" : "\u2611 全选");
            }
        });
        topRow.addView(selectAllBtn);
        dialogRoot.addView(topRow);

        // 卡牌: 每种数量输入
        final EditText pickerCountInput;
        if (itemType == ITEM_TYPE_CARD) {
            LinearLayout cntRow = new LinearLayout(activity);
            cntRow.setOrientation(LinearLayout.HORIZONTAL);
            cntRow.setGravity(Gravity.CENTER_VERTICAL);
            LinearLayout.LayoutParams cntlp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            cntlp.setMargins(0, 0, 0, dp(4));
            cntRow.setLayoutParams(cntlp);

            TextView cntLabel = new TextView(activity);
            cntLabel.setText("每种添加:");
            cntLabel.setTextColor(0xFF9CA3AF);
            cntLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            cntRow.addView(cntLabel);

            pickerCountInput = new EditText(activity);
            pickerCountInput.setText("1");
            pickerCountInput.setTextColor(0xFFE0E7FF);
            pickerCountInput.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            pickerCountInput.setInputType(InputType.TYPE_CLASS_NUMBER);
            pickerCountInput.setSingleLine(true);
            GradientDrawable pcBg = new GradientDrawable();
            pcBg.setColor(0xFF16163A);
            pcBg.setCornerRadius(dp(4));
            pcBg.setStroke(dp(1), 0xFF444477);
            pickerCountInput.setBackground(pcBg);
            pickerCountInput.setPadding(dp(6), dp(2), dp(6), dp(2));
            LinearLayout.LayoutParams cilp = new LinearLayout.LayoutParams(dp(40), ViewGroup.LayoutParams.WRAP_CONTENT);
            cilp.setMargins(dp(4), 0, 0, 0);
            pickerCountInput.setLayoutParams(cilp);
            cntRow.addView(pickerCountInput);
            dialogRoot.addView(cntRow);
        } else {
            pickerCountInput = null;
        }

        // 滚动列表
        ScrollView sv = new ScrollView(activity);
        sv.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(320)));
        sv.setVerticalScrollBarEnabled(false);

        final LinearLayout listLayout = new LinearLayout(activity);
        listLayout.setOrientation(LinearLayout.VERTICAL);
        listLayout.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        for (int i = 0; i < ids.size(); i++) {
            final int idx = i;

            LinearLayout itemRow = new LinearLayout(activity);
            itemRow.setOrientation(LinearLayout.HORIZONTAL);
            itemRow.setGravity(Gravity.CENTER_VERTICAL);
            itemRow.setPadding(dp(6), dp(4), dp(6), dp(4));
            LinearLayout.LayoutParams irlp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            irlp.setMargins(0, dp(1), 0, 0);
            itemRow.setLayoutParams(irlp);
            GradientDrawable irBg = new GradientDrawable();
            irBg.setColor(i % 2 == 0 ? 0xFF202040 : 0xFF1C1C38);
            irBg.setCornerRadius(dp(6));
            itemRow.setBackground(irBg);

            CheckBox cb = new CheckBox(activity);
            cb.setText(names.get(i));
            cb.setTextColor(0xFFD0D0E0);
            cb.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            cb.setChecked(false);
            cb.setLayoutParams(new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            cb.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override public void onCheckedChanged(CompoundButton b, boolean checked) {
                    selected[idx] = checked;
                    int cnt = 0;
                    for (boolean s : selected) if (s) cnt++;
                    countLabel.setText("已选 " + cnt + " 项");
                }
            });
            checkBoxes[i] = cb;
            itemRow.addView(cb);
            listLayout.addView(itemRow);
        }

        sv.addView(listLayout);
        dialogRoot.addView(sv);

        searchBox.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
            @Override
            public void afterTextChanged(android.text.Editable s) {
                String q = s.toString().toLowerCase().trim();
                for (int i = 0; i < checkBoxes.length; i++) {
                    View parent = (View) checkBoxes[i].getParent();
                    boolean visible = q.isEmpty() || names.get(i).toLowerCase().contains(q);
                    parent.setVisibility(visible ? View.VISIBLE : View.GONE);
                }
            }
        });

        // 底部按钮行
        LinearLayout btnRow = new LinearLayout(activity);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams brlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        brlp.setMargins(0, dp(8), 0, 0);
        btnRow.setLayoutParams(brlp);

        final AlertDialog[] dlgRef = new AlertDialog[1];
        final Runnable restoreFlags = new Runnable() {
            @Override public void run() {
                wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
            }
        };

        Button addBtn = makeDialogBtn("\u2705 添加选中", 0xFF6366F1);
        addBtn.setLayoutParams(new LinearLayout.LayoutParams(0, dp(34), 1f));
        addBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                restoreFlags.run();
                if (dlgRef[0] != null) dlgRef[0].dismiss();
                final List<Integer> toAdd = new ArrayList<Integer>();
                for (int i = 0; i < selected.length; i++)
                    if (selected[i]) toAdd.add(ids.get(i)[0]);
                if (toAdd.isEmpty()) { statusText.setText("未选择任何" + title); return; }
                final int perCount;
                if (pickerCountInput != null) {
                    int pc = 1;
                    try { pc = Integer.parseInt(pickerCountInput.getText().toString().trim()); }
                    catch (Exception e) { pc = 1; }
                    if (pc < 1) pc = 1; if (pc > 99) pc = 99;
                    perCount = pc;
                } else { perCount = 1; }
                setBusy(true);
                final int totalItems = toAdd.size() * perCount;
                statusText.setText("\u23F3 添加 " + totalItems + " 个" + title + "...");
                new Thread(new Runnable() {
                    @Override public void run() {
                        int ok = 0;
                        for (int itemId : toAdd) {
                            for (int n = 0; n < perCount; n++) {
                                try {
                                    java.lang.reflect.Method m = OverlayMenu.class.getDeclaredMethod(
                                            nativeAddMethod, int.class);
                                    m.invoke(null, itemId);
                                    ok++;
                                } catch (Exception e) {}
                            }
                        }
                        final int fOk = ok;
                        new Handler(Looper.getMainLooper()).post(new Runnable() {
                            @Override public void run() {
                                statusText.setText("\u2705 已添加 " + fOk + " 个" + title);
                                setBusy(false);
                            }
                        });
                    }
                }).start();
            }
        });
        btnRow.addView(addBtn);

        Button closeBtn = makeDialogBtn("取消", 0xFF374151);
        LinearLayout.LayoutParams cblp = new LinearLayout.LayoutParams(0, dp(34), 0.5f);
        cblp.setMargins(dp(4), 0, 0, 0);
        closeBtn.setLayoutParams(cblp);
        closeBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                restoreFlags.run();
                if (dlgRef[0] != null) dlgRef[0].dismiss();
            }
        });
        btnRow.addView(closeBtn);
        dialogRoot.addView(btnRow);

        AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        builder.setView(dialogRoot);
        builder.setCancelable(true);
        builder.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override public void onCancel(DialogInterface d) { restoreFlags.run(); }
        });

        try {
            AlertDialog dlg = builder.create();
            dlgRef[0] = dlg;
            if (dlg.getWindow() != null) {
                dlg.getWindow().setType(2038);
                dlg.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
            }
            dlg.show();
        } catch (Exception e) {
            statusText.setText("\u274C 无法显示对话框: " + e.getMessage());
            restoreFlags.run();
        }
    }

    // ===== 对话框辅助方法 =====
    private EditText makeDialogSearchBox() {
        EditText searchBox = new EditText(activity);
        searchBox.setHint("\uD83D\uDD0D 搜索...");
        searchBox.setTextColor(0xFFE0E7FF);
        searchBox.setHintTextColor(0xFF666688);
        searchBox.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        searchBox.setSingleLine(true);
        searchBox.setPadding(dp(8), dp(5), dp(8), dp(5));
        GradientDrawable sbBg = new GradientDrawable();
        sbBg.setColor(0xFF16163A);
        sbBg.setCornerRadius(dp(8));
        sbBg.setStroke(dp(1), 0xFF333366);
        searchBox.setBackground(sbBg);
        LinearLayout.LayoutParams sblp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sblp.setMargins(0, dp(2), 0, dp(4));
        searchBox.setLayoutParams(sblp);
        return searchBox;
    }

    private Button makeDialogBtn(String text, int bgColor) {
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
        return btn;
    }

    private List<Integer> parseIdList(String json) {
        List<Integer> result = new ArrayList<Integer>();
        try {
            String s = json.trim();
            if (s.startsWith("[")) s = s.substring(1);
            if (s.endsWith("]")) s = s.substring(0, s.length() - 1);
            if (!s.isEmpty()) {
                for (String part : s.split(",")) {
                    part = part.trim();
                    if (!part.isEmpty()) {
                        int id = Integer.parseInt(part);
                        if (id != 0) result.add(id);
                    }
                }
            }
        } catch (Exception e) {}
        return result;
    }

    private java.util.Map<Integer, String> parseNameMap(String enumJson) {
        java.util.Map<Integer, String> nameMap = new java.util.HashMap<Integer, String>();
        try {
            String ej = enumJson.trim();
            if (ej.startsWith("[")) ej = ej.substring(1);
            if (ej.endsWith("]")) ej = ej.substring(0, ej.length() - 1);
            String[] parts = ej.split("\\},\\s*\\{");
            for (String part : parts) {
                part = part.replace("{", "").replace("}", "").trim();
                if (part.isEmpty()) continue;
                int id = 0; String name = "";
                String[] fields = part.split(",");
                for (String f : fields) {
                    f = f.trim();
                    if (f.startsWith("\"id\":"))
                        try { id = Integer.parseInt(f.substring(5).trim()); } catch (Exception e) {}
                    else if (f.startsWith("\"n\":")) {
                        name = f.substring(4).trim();
                        if (name.startsWith("\"")) name = name.substring(1);
                        if (name.endsWith("\"")) name = name.substring(0, name.length() - 1);
                        name = name.replace("\\\"", "\"").replace("\\\\", "\\");
                    }
                }
                if (id > 0 && !name.isEmpty()) nameMap.put(id, name);
            }
        } catch (Exception e) {}
        return nameMap;
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
