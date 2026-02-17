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
import android.widget.TextView;

public class OverlayMenu implements View.OnClickListener, View.OnTouchListener {

    private Activity activity;
    private WindowManager wm;
    private WindowManager.LayoutParams wmParams;
    private LinearLayout container;
    private LinearLayout contentArea;
    private TextView statusText;
    private EditText goldInput;
    private Button toggleBtn;
    private boolean collapsed = false;
    private float density;

    // 拖动
    private int lastX, lastY;
    private float touchX, touchY;
    private boolean dragging = false;

    // 按钮 ID (用 View.generateViewId 不可靠，用常量)
    private static final int BTN_TOGGLE = 0x7f000001;
    private static final int BTN_GOLD   = 0x7f000002;
    private static final int BTN_SKILL  = 0x7f000003;
    private static final int BTN_P1     = 0x7f000010;
    private static final int BTN_P2     = 0x7f000011;
    private static final int BTN_P3     = 0x7f000012;
    private static final int BTN_P4     = 0x7f000013;

    // JNI 回调（C 代码注册实现）
    public static native String nativeModifyGold(int amount);
    public static native String nativeResetSkillCD();

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
        title.setText("\uD83C\uDF15 月圆之夜");
        title.setTextColor(0xFFE0E7FF);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        title.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        titleBar.addView(title);

        toggleBtn = makeBtn("\u2014", 0x33FFFFFF, BTN_TOGGLE);
        toggleBtn.setTextColor(0xFFA5B4FC);
        LinearLayout.LayoutParams tblp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(28));
        tblp.setMargins(dp(6), 0, 0, 0);
        toggleBtn.setLayoutParams(tblp);
        titleBar.addView(toggleBtn);

        container.addView(titleBar);

        // ===== 内容区 =====
        contentArea = new LinearLayout(activity);
        contentArea.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams calp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        calp.setMargins(0, dp(6), 0, 0);
        contentArea.setLayoutParams(calp);

        addDivider(contentArea);

        // --- 金币区域 ---
        TextView goldLabel = new TextView(activity);
        goldLabel.setText("\uD83D\uDCB0 金币修改");
        goldLabel.setTextColor(0xFFFCD34D);
        goldLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        contentArea.addView(goldLabel);

        // 输入框 + 修改按钮
        LinearLayout goldRow = new LinearLayout(activity);
        goldRow.setOrientation(LinearLayout.HORIZONTAL);
        goldRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams grlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        grlp.setMargins(0, dp(4), 0, 0);
        goldRow.setLayoutParams(grlp);

        goldInput = new EditText(activity);
        goldInput.setHint("输入金币");
        goldInput.setText("99999");
        goldInput.setTextColor(Color.WHITE);
        goldInput.setHintTextColor(0xFF666688);
        goldInput.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        goldInput.setInputType(InputType.TYPE_CLASS_NUMBER);
        goldInput.setSingleLine(true);
        goldInput.setPadding(dp(8), dp(4), dp(8), dp(4));
        GradientDrawable inputBg = new GradientDrawable();
        inputBg.setColor(0xFF1E1E3F);
        inputBg.setCornerRadius(dp(6));
        inputBg.setStroke(dp(1), 0xFF4338CA);
        goldInput.setBackground(inputBg);
        goldInput.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        goldRow.addView(goldInput);

        // 点击输入框时允许聚焦
        goldInput.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                wmParams.flags = 0;
                try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                goldInput.requestFocus();
            }
        });
        goldInput.setOnFocusChangeListener(new View.OnFocusChangeListener() {
            @Override
            public void onFocusChange(View v, boolean hasFocus) {
                if (!hasFocus) {
                    wmParams.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
                    try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
                }
            }
        });

        Button goldBtn = makeBtn("修改", 0xFF7C3AED, BTN_GOLD);
        LinearLayout.LayoutParams gblp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(32));
        gblp.setMargins(dp(6), 0, 0, 0);
        goldBtn.setLayoutParams(gblp);
        goldRow.addView(goldBtn);

        contentArea.addView(goldRow);

        // 快捷金币按钮
        LinearLayout quickRow = new LinearLayout(activity);
        quickRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams qrlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        qrlp.setMargins(0, dp(4), 0, 0);
        quickRow.setLayoutParams(qrlp);

        int[] presets = {9999, 99999, 888888, 999999};
        int[] pids    = {BTN_P1, BTN_P2, BTN_P3, BTN_P4};
        for (int i = 0; i < presets.length; i++) {
            Button qb = makeBtn(String.valueOf(presets[i]), 0xFF374151, pids[i]);
            qb.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
            qb.setTag(presets[i]);
            LinearLayout.LayoutParams qblp = new LinearLayout.LayoutParams(0, dp(26), 1f);
            if (i > 0) qblp.setMargins(dp(3), 0, 0, 0);
            qb.setLayoutParams(qblp);
            quickRow.addView(qb);
        }
        contentArea.addView(quickRow);

        addDivider(contentArea);

        // --- 技能区域 ---
        TextView skillLabel = new TextView(activity);
        skillLabel.setText("\u26A1 探索技能");
        skillLabel.setTextColor(0xFF67E8F9);
        skillLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        contentArea.addView(skillLabel);

        Button skillBtn = makeBtn("重置所有技能CD", 0xFF0E7490, BTN_SKILL);
        LinearLayout.LayoutParams sblp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(34));
        sblp.setMargins(0, dp(4), 0, 0);
        skillBtn.setLayoutParams(sblp);
        contentArea.addView(skillBtn);

        // --- 状态文本 ---
        statusText = new TextView(activity);
        statusText.setText("就绪");
        statusText.setTextColor(0xFF9CA3AF);
        statusText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        LinearLayout.LayoutParams stlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        stlp.setMargins(0, dp(6), 0, 0);
        statusText.setLayoutParams(stlp);
        contentArea.addView(statusText);

        container.addView(contentArea);

        // ===== WindowManager 参数 =====
        wmParams = new WindowManager.LayoutParams(
                dp(220),
                ViewGroup.LayoutParams.WRAP_CONTENT,
                2, // TYPE_APPLICATION (进程内，不需要悬浮窗权限)
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                PixelFormat.TRANSLUCENT);
        wmParams.gravity = Gravity.TOP | Gravity.LEFT;
        wmParams.x = dp(10);
        wmParams.y = dp(100);

        wm.addView(container, wmParams);
        android.util.Log.i("GoldHack", "Overlay menu created");
    }

    private void addDivider(LinearLayout parent) {
        View div = new View(activity);
        div.setBackgroundColor(0xFF333366);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1));
        dlp.setMargins(0, dp(6), 0, dp(6));
        div.setLayoutParams(dlp);
        parent.addView(div);
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
                contentArea.setVisibility(View.GONE);
                toggleBtn.setText("+");
                wmParams.width = dp(120);
            } else {
                contentArea.setVisibility(View.VISIBLE);
                toggleBtn.setText("\u2014");
                wmParams.width = dp(220);
            }
            try { wm.updateViewLayout(container, wmParams); } catch (Exception e) {}
        } else if (id == BTN_GOLD) {
            doGoldModify();
        } else if (id == BTN_SKILL) {
            doSkillReset();
        } else if (id == BTN_P1 || id == BTN_P2 || id == BTN_P3 || id == BTN_P4) {
            Object tag = v.getTag();
            if (tag != null) goldInput.setText(tag.toString());
        }
    }

    private void doGoldModify() {
        String text = goldInput.getText().toString().trim();
        final int amount;
        try {
            amount = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            statusText.setText("\u274C 请输入有效数字");
            return;
        }
        statusText.setText("\u23F3 修改中...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String result = nativeModifyGold(amount);
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() { statusText.setText(result); }
                });
            }
        }).start();
    }

    private void doSkillReset() {
        statusText.setText("\u23F3 重置中...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String result = nativeResetSkillCD();
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() { statusText.setText(result); }
                });
            }
        }).start();
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
