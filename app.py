"""
Cyber Next | درع — جدار حماية الذكاء الاصطناعي المؤسسي
تعديل ستايل المهندسين (مستوحى من نبض الجاهزية - بنفسجي محترف بدون إيموجيز)
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

import demo_data
import eval_data as ed
from attacks import decode_tag_characters
from audit import AuditLog
from detectors import TYPE_INFO, detect
from gateway import Gateway, GatewayConfig
from llm import CANARY, DEFAULT_SYSTEM_PROMPT, SimulatedLLM

st.set_page_config(page_title="Cyber Next | درع", page_icon="🛡️", layout="wide")

# ============================================================================ ENTERPRISE PURPLE STYLING (Clean & Modern)
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@300;400;500;600;700&display=swap');

:root {
    --bg-main: #0a0514;
    --bg-card: #130a24;
    --border-color: #261545;
    --text-primary: #f1f5f9;
    --text-muted: #94a3b8;
    --accent-purple: #8b5cf6;
    --green-shield: #10b981;
    --red-alert: #f43f5e;
    --amber-warn: #f59e0b;
}

html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-main) !important;
    background-image: 
        radial-gradient(circle at 20% 30%, rgba(139, 92, 246, 0.08) 0%, transparent 50%),
        radial-gradient(circle at 80% 70%, rgba(99, 102, 241, 0.06) 0%, transparent 50%) !important;
    color: var(--text-primary) !important;
    direction: rtl;
    text-align: right;
    font-family: 'IBM Plex Sans Arabic', Tahoma, sans-serif !important;
}

[data-testid="stSidebar"] {
    background-color: #06030c !important;
    border-left: 1px solid var(--border-color) !important;
}

h1, h2, h3, h4 {
    color: var(--text-primary) !important;
    font-weight: 600;
}

/* بطاقات بتصميم هندسي ناعم (مثل نبض الجاهزية) */
.card-box {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 14px;
}
.card-red { border-right: 4px solid var(--red-alert); }
.card-green { border-right: 4px solid var(--green-shield); }
.card-amber { border-right: 4px solid var(--amber-warn); }

.tip-box {
    background: rgba(139, 92, 246, 0.08);
    border: 1px solid rgba(139, 92, 246, 0.25);
    border-radius: 10px;
    padding: 12px 16px;
    margin-top: 12px;
    font-size: 0.9rem;
    color: #ddd6fe;
}

.stButton>button {
    background: var(--accent-purple) !important;
    color: #ffffff !important;
    border: 0 !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-family: 'IBM Plex Sans Arabic', sans-serif !important;
    padding: 8px 20px !important;
    transition: background 0.2s ease !important;
}
.stButton>button:hover {
    background: #7c3aed !important;
}

button[data-baseweb="tab"] {
    font-family: 'IBM Plex Sans Arabic', sans-serif !important;
    font-weight: 500 !important;
    color: var(--text-muted) !important;
}
button[aria-selected="true"] {
    color: var(--text-primary) !important;
    border-bottom-color: var(--accent-purple) !important;
}
</style>
""", unsafe_allow_html=True)

TYPE_AR = {k: v["label_ar"] for k, v in TYPE_INFO.items()}
ACTION_AR = {"allowed": "مسموح", "allowed_with_warnings": "مسموح مع تحذير", "blocked": "موقوف", "error": "خطأ"}
SCENARIOS = demo_data.build_scenarios()
SC = {s["key"]: s for s in SCENARIOS}

if "audit" not in st.session_state:
    st.session_state.audit = AuditLog()
if "last" not in st.session_state:
    st.session_state.last = None

@st.cache_resource(show_spinner="جاري تحميل المحركات...")
def get_ml():
    import eval_data as _ed
    from ml_layer import MLConfig, MLLayer
    from normalize import normalize as _n
    import os
    ml = MLLayer(MLConfig.from_file(clf_path="dir_attack_clf" if os.path.isdir("dir_attack_clf") else ""), attack_bank=[_n(a["text"]).text for a in _ed.DEV_ATTACKS],
                 normal_bank=[_n(t).text for t in _ed.DEV_BENIGN])
    ml.load_all()
    return ml

# ============================================================================ SIDEBAR
with st.sidebar:
    st.markdown("### Cyber Next | درع")
    st.caption("بوابة حماية الذكاء الاصطناعي التوليدي")
    st.markdown("---")
    st.caption("وضع التشغيل: محلي وآمن (Zero-Trust)")
    
    trusted_raw = st.text_area("النطاقات الموثوقة", "", help="الروابط التابعة لهذه النطاقات لا تُعد تسريباً.")
    ttl = st.number_input("صلاحية الرموز (ثانية)", 60, 86400, 900, step=60)
    block_attacks = st.checkbox("حظر الهجمات تلقائياً", True)
    use_ml = st.checkbox("تفعيل الطبقة الهجينة (ML)", True)
    
    st.markdown("---")
    if st.button("إعادة ضبط السجل"):
        st.session_state.audit.clear()
        st.session_state.last = None
        st.rerun()

def make_gateway() -> Gateway:
    trusted = tuple(x.strip() for x in trusted_raw.splitlines() if x.strip())
    llm = SimulatedLLM()
    return Gateway(llm, GatewayConfig(ttl_seconds=int(ttl), trusted_domains=trusted, block_attacks=block_attacks,
                                      ml=get_ml() if use_ml else None), st.session_state.audit)

def run_both(user_text: str, documents: list) -> dict:
    doc_text = "".join(f"\n\n[بداية مستند: {n}]\n{t}\n[نهاية المستند]" for n, t in documents)
    raw_prompt = user_text + doc_text
    sim = SimulatedLLM()
    raw_reply = sim.complete([{"role": "system", "content": DEFAULT_SYSTEM_PROMPT}, {"role": "user", "content": raw_prompt}])
    gw = make_gateway()
    gw.new_session("enterprise_demo")
    res = gw.process(user_text, documents, session="enterprise_demo")
    return {"raw_prompt": raw_prompt, "raw_reply": raw_reply, "res": res, "user_text": user_text, "documents": documents}

# ============================================================================ TABS
tabs = st.tabs(["العرض المباشر", "لوحة إدارة الأمن والامتثال"])

# 1. LIVE SANDBOX
with tabs[0]:
    st.markdown("#### فحص وتنفيذ الطلبات اللحظي")
    keys = [s["key"] for s in SCENARIOS] + ["custom"]
    titles = {s["key"]: s["title_ar"] for s in SCENARIOS} | {"custom": "٥) إدخال سيناريو مخصص"}
    choice = st.radio("سيناريوهات الفحص", keys, format_func=lambda k: titles[k], horizontal=True, label_visibility="collapsed")

    if choice == "custom":
        user_text = st.text_area("رسالة المستخدم", "", height=120)
        doc_text = st.text_area("مستند مرفق (اختياري)", "", height=90)
        documents = [("مستند_عمل.txt", doc_text)] if doc_text.strip() else []
    else:
        s = SC[choice]
        st.info(s["story_ar"])
        user_text = st.text_area("رسالة المستخدم", s["user_text"], height=120, key=f"u_{choice}")
        documents = []
        for i, (name, text) in enumerate(s["documents"]):
            doc_text = st.text_area(f"مستند مرفق: {name}", text, height=110, key=f"d_{choice}_{i}")
            documents.append((name, doc_text))

    if st.button("فحص وتنفيذ الطلب عبر درع", type="primary"):
        if not user_text.strip():
            st.warning("الرجاء كتابة رسالة الفحص أولاً.")
        else:
            st.session_state.last = run_both(user_text, documents)

    last = st.session_state.last
    if last:
        res = last["res"]
        col_without, col_with = st.columns(2, gap="large")

        with col_without:
            st.markdown("##### بدون جدار حماية")
            raw_findings = [f for f in detect(last["raw_prompt"]) if f.mask]
            exfil = "?d=" in last["raw_reply"] and "![" in last["raw_reply"]
            st.markdown(f"<div class='card-box card-red'>البيانات المكشوفة للنموذج: <b>{len(raw_findings)} عنصر حساس</b>" + ("<br>تنبيه: تم تنفيذ أمر خفي وتسريب البيانات عبر رابط صورة" if exfil else "") + "</div>", unsafe_allow_html=True)
            st.markdown("**النص الواصل للنموذج (خام):**")
            st.code(last["raw_prompt"], language=None)
            st.markdown("**رد النموذج للمستخدم:**")
            st.code(last["raw_reply"], language=None)

        with col_with:
            st.markdown("##### مع جدار حماية Cyber Next (درع)")
            if res.action == "blocked":
                st.markdown(f"<div class='card-box card-red'>الحالة: تم الحظر — {res.message_ar}</div>", unsafe_allow_html=True)
            elif res.action == "allowed_with_warnings":
                st.markdown(f"<div class='card-box card-amber'>الحالة: مسموح مع تحذير — {res.message_ar}</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div class='card-box card-green'>الحالة: مسموح وآمن (تم حجب {len(res.tokens)} عنصر حساس)</div>", unsafe_allow_html=True)

            if res.tokens:
                masked_types = ", ".join(set(TYPE_AR[ty] for _, ty in res.tokens))
                st.markdown(f"""
                <div class="tip-box">
                    <b>إشعار الامتثال للموظف:</b> تم رصد وحجب عناصر ({masked_types}) وتشفيرها مؤقتاً لحماية البيانات وفقاً لنظام PDPL والمعايير المؤسسية.
                </div>
                """, unsafe_allow_html=True)

            m1, m2, m3 = st.columns(3)
            m1.metric("المخاطر قبل الضوابط", res.risk["inherent"])
            m2.metric("المخاطر بعد الضوابط", res.risk["residual"], delta=round(res.risk["residual"] - res.risk["inherent"], 1), delta_color="inverse")
            m3.metric("سرعة المعالجة", f"{res.latency_ms} م.ث")

            if res.sent_to_model:
                st.markdown("**النص المستلم بالنموذج (محجوب/مُشفر):**")
                st.code(res.model_input_text, language=None)
                st.markdown("**الرد النهائي الظاهر للموظف:**")
                st.code(res.final_reply, language=None)

            findings_rows = [{"نوع التهديد": f.family_ar, "درجة الخطورة": f.weight} for f in res.attack.findings]
            if findings_rows:
                st.markdown("**الهجمات المرصودة:**")
                st.dataframe(pd.DataFrame(findings_rows), hide_index=True)

# 2. CISO & PDPL DASHBOARD
with tabs[1]:
    st.markdown("#### لوحة إدارة الأمن وسجلات الامتثال")
    
    if st.button("تشغيل محاكاة العمليات"):
        for s in SCENARIOS:
            run_both(s["user_text"], s["documents"])
        st.rerun()
            
    stats = st.session_state.audit.stats()

    if stats["requests"] > 0:
        st.markdown(f"""
        <div class="card-box" style="border-color: rgba(139, 92, 246, 0.4); text-align: center;">
            <h4 style="color: #c4b5fd; margin-bottom: 6px;">ملخص امتثال نظام حماية البيانات الشخصية (PDPL)</h4>
            <p style="color: #cbd5e1; font-size: 0.95rem; margin: 0;">
                العناصر المحجوبة: <b>{stats['items_masked']}</b> &nbsp;|&nbsp; الهجمات المحظورة: <b>{stats['blocked']}</b> &nbsp;|&nbsp; مستوى الامتثال: <b>مطابق للمواصفات</b>
            </p>
        </div>
        """, unsafe_allow_html=True)

    if stats["requests"] == 0:
        st.info("لا توجد سجلات أمنية حالياً. قم بتشغيل المحاكاة أعلاه أو إرسال طلب من تبويب العرض المباشر.")
    else:
        k = st.columns(5)
        k[0].metric("إجمالي الطلبات", stats["requests"])
        k[1].metric("طلبات محظورة", stats["blocked"])
        k[2].metric("مستندات معزولة", stats["docs_quarantined"])
        k[3].metric("عناصر محمية", stats["items_masked"])
        k[4].metric("انخفاض المخاطر", f"{stats['avg_inherent']} ← {stats['avg_residual']}")
        
        st.markdown("---")
        st.markdown("**سجل التدقيق الأمني:**")
        st.dataframe(pd.DataFrame([{
            "الوقت": e["ts"][11:19], "الإجراء": ACTION_AR[e["action"]],
            "أنواع البيانات": "، ".join(f"{TYPE_AR[t]}×{c}" for t, c in e["data_types"].items()) or "-",
            "الهجوم": "، ".join(r["family_ar"] for r in e["attack_rules"][:1]) or "-",
            "قبل": e["inherent"], "بعد": e["residual"], "زمن (م.ث)": e["latency_ms"]} for e in reversed(st.session_state.audit.events)]), hide_index=True)