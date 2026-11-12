"""
Cyber Next | درع — Enterprise AI Security Gateway
واجهة عرض تفاعلية محسّنة مع إضافة الشعار وإصلاح فحص السيناريو المخصص.
"""

from __future__ import annotations

import html
import os
import pandas as pd
import streamlit as st

import demo_data
import eval_data as ed
import evaluate as ev
from audit import AuditLog
from detectors import TYPE_INFO, detect
from gateway import Gateway, GatewayConfig
from llm import CANARY, DEFAULT_SYSTEM_PROMPT, OpenAICompatibleLLM, SimulatedLLM

st.set_page_config(
    page_title="Cyber Next | درع",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Theme & Custom CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@300;400;500;600;700&display=swap');

    :root {
        --bg: #090817;
        --surface: rgba(20, 17, 43, .88);
        --surface-2: rgba(31, 25, 62, .88);
        --border: rgba(167, 139, 250, .20);
        --text: #f3efff;
        --muted: #aaa2c7;
        --purple: #a78bfa;
        --violet: #8b5cf6;
        --cyan: #67e8f9;
        --green: #5eead4;
        --amber: #fbbf72;
        --red: #fb7185;
    }

    html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
        background: var(--bg) !important;
        color: var(--text) !important;
        font-family: 'IBM Plex Sans Arabic', Tahoma, sans-serif !important;
        direction: rtl; text-align: right;
    }
    [data-testid="stAppViewContainer"] {
        background:
          radial-gradient(ellipse at 12% 8%, rgba(139,92,246,.22), transparent 32%),
          radial-gradient(ellipse at 88% 24%, rgba(103,232,249,.10), transparent 28%),
          radial-gradient(ellipse at 50% 100%, rgba(124,58,237,.13), transparent 42%),
          #090817 !important;
        position: relative;
    }
    [data-testid="stAppViewContainer"]::before {
        content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 0;
        background-image:
          linear-gradient(rgba(167,139,250,.055) 1px, transparent 1px),
          linear-gradient(90deg, rgba(167,139,250,.055) 1px, transparent 1px);
        background-size: 54px 54px;
        mask-image: linear-gradient(to bottom, black, transparent 88%);
        animation: gridDrift 28s linear infinite;
    }
    [data-testid="stAppViewContainer"]::after {
        content: ""; position: fixed; inset: -35%; pointer-events: none; z-index: 0;
        background:
          radial-gradient(circle at 25% 30%, rgba(139,92,246,.13), transparent 17%),
          radial-gradient(circle at 72% 58%, rgba(103,232,249,.08), transparent 16%),
          radial-gradient(circle at 48% 80%, rgba(192,132,252,.10), transparent 18%);
        filter: blur(22px);
        animation: auroraMove 18s ease-in-out infinite alternate;
    }
    @keyframes gridDrift { from { transform: translate3d(0,0,0); } to { transform: translate3d(54px,54px,0); } }
    @keyframes auroraMove {
        0% { transform: translate(-2%, -1%) scale(1); }
        50% { transform: translate(2%, 2%) scale(1.08); }
        100% { transform: translate(-1%, 3%) scale(1.02); }
    }
    [data-testid="stAppViewContainer"] > .main,
    [data-testid="stSidebar"], [data-testid="stHeader"] { position: relative; z-index: 1; }
    [data-testid="stSidebar"] {
        background: rgba(13, 10, 30, .96) !important;
        border-left: 1px solid var(--border);
        backdrop-filter: blur(18px);
    }
    [data-testid="stHeader"] { background: rgba(9,8,23,.72) !important; }
    h1, h2, h3, h4 { color: var(--text) !important; font-family: inherit !important; }
    p, label, [data-testid="stCaptionContainer"] { color: var(--muted); }
    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1480px; }

    .hero {
        padding: 30px 32px; border: 1px solid rgba(167,139,250,.34);
        border-radius: 24px; margin-bottom: 24px; position: relative; overflow: hidden;
        background: linear-gradient(115deg, rgba(31,22,65,.96), rgba(17,15,39,.94));
        box-shadow: 0 18px 55px rgba(0,0,0,.28), inset 0 1px rgba(255,255,255,.04);
    }
    .hero:before {
        content: ""; position: absolute; inset: -1px;
        background: linear-gradient(110deg, transparent 20%, rgba(167,139,250,.10) 48%, transparent 72%);
        transform: translateX(-100%); animation: heroShimmer 8s ease-in-out infinite;
    }
    .hero:after {
        content: ""; position: absolute; left: -65px; top: -110px;
        width: 290px; height: 290px; border-radius: 50%;
        border: 1px solid rgba(167,139,250,.25);
        box-shadow: 0 0 0 20px rgba(167,139,250,.035), 0 0 0 48px rgba(167,139,250,.025),
                    0 0 55px rgba(139,92,246,.14);
    }
    @keyframes heroShimmer { 0%, 65% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
    .eyebrow { color: var(--cyan); font-size: .76rem; font-weight: 700; letter-spacing: .15em; margin-bottom: 9px; }
    .hero-title { font-size: 2.05rem; font-weight: 700; margin: 0 0 8px; color: #faf7ff; }
    .hero-sub { color: #c1b9dc; font-size: .98rem; margin: 0; max-width: 850px; line-height: 1.9; }
    .section-title { font-size: 1.18rem; font-weight: 700; color: #f0eaff; margin: 8px 0 4px; }
    .section-hint { color: var(--muted); font-size: .86rem; margin-bottom: 16px; }

    .panel {
        background: linear-gradient(145deg, rgba(29,23,59,.92), rgba(18,16,42,.94));
        border: 1px solid var(--border); border-radius: 18px;
        padding: 19px 21px; margin-bottom: 15px;
        box-shadow: 0 10px 28px rgba(0,0,0,.16), inset 0 1px rgba(255,255,255,.025);
    }
    .status {
        padding: 15px 17px; border-radius: 14px; margin: 8px 0 15px;
        background: rgba(94,234,212,.08); border: 1px solid rgba(94,234,212,.26);
        border-right: 4px solid var(--green); color: #ddfff8;
        box-shadow: 0 6px 22px rgba(0,0,0,.12);
    }
    .status.red { background: rgba(251,113,133,.08); border-color: rgba(251,113,133,.27); border-right-color: var(--red); }
    .status.amber { background: rgba(251,191,114,.08); border-color: rgba(251,191,114,.27); border-right-color: var(--amber); }
    .soft-callout {
        background: linear-gradient(110deg, rgba(139,92,246,.13), rgba(103,232,249,.045));
        border: 1px solid rgba(167,139,250,.24); border-radius: 14px;
        padding: 14px 17px; color: #e2d9ff; margin: 13px 0; font-size: .9rem;
    }
    .mini-tag {
        display: inline-block; padding: 5px 11px; border-radius: 99px;
        background: rgba(139,92,246,.15); color: #d6c5ff; font-size: .74rem;
        border: 1px solid rgba(167,139,250,.27); margin-left: 5px;
    }

    div.stButton > button {
        border-radius: 12px !important; min-height: 2.8rem !important;
        border: 1px solid rgba(196,181,253,.34) !important;
        background: linear-gradient(105deg, #7c3aed, #6d5ce8 58%, #5367d9) !important;
        color: white !important; font-weight: 700 !important;
        box-shadow: 0 7px 22px rgba(109,75,220,.22);
        transition: .2s ease-in-out;
    }
    div.stButton > button:hover {
        border-color: rgba(103,232,249,.65) !important;
        box-shadow: 0 9px 28px rgba(139,92,246,.34);
        filter: brightness(1.12); transform: translateY(-2px);
    }
    button[data-baseweb="tab"] {
        color: #aaa2c7 !important; font-weight: 600 !important; padding: 12px 18px !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #d8c8ff !important; border-bottom-color: #a78bfa !important;
    }
    [data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input {
        background: rgba(13,11,31,.92) !important; color: #f3efff !important;
        border: 1px solid rgba(167,139,250,.24) !important;
        border-radius: 12px !important; text-align: right;
    }
    [data-testid="stSelectbox"] > div > div,
    [data-testid="stRadio"] label, [data-testid="stCheckbox"] label,
    [data-testid="stToggle"] label { color: var(--text) !important; }
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, rgba(35,27,72,.88), rgba(20,17,46,.92));
        border: 1px solid rgba(167,139,250,.22); padding: 14px 16px;
        border-radius: 16px; box-shadow: 0 8px 22px rgba(0,0,0,.14);
    }
    [data-testid="stMetricLabel"] { color: #b9afd8 !important; }
    [data-testid="stMetricValue"] { color: #f4efff !important; }
    [data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 13px; overflow: hidden; }
    [data-testid="stExpander"] {
        border: 1px solid rgba(167,139,250,.19) !important;
        border-radius: 13px !important; background: rgba(20,17,43,.58);
    }
    hr { border-color: rgba(167,139,250,.16) !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

TYPE_AR = {k: v["label_ar"] for k, v in TYPE_INFO.items()}
ACTION_AR = {
    "allowed": "مسموح",
    "allowed_with_warnings": "مسموح مع تحذير",
    "blocked": "موقوف",
    "error": "خطأ",
}
SCENARIOS = demo_data.build_scenarios()
SC = {scenario["key"]: scenario for scenario in SCENARIOS}

if "audit" not in st.session_state:
    st.session_state.audit = AuditLog()
if "last" not in st.session_state:
    st.session_state.last = None


@st.cache_resource(show_spinner="جاري تجهيز محرك كشف التهديدات...")
def get_ml():
    import eval_data as _ed
    from ml_layer import MLConfig, MLLayer
    from normalize import normalize as _normalize

    ml = MLLayer(
        MLConfig.from_file(
            clf_path="dir_attack_clf" if os.path.isdir("dir_attack_clf") else ""
        ),
        attack_bank=[_normalize(item["text"]).text for item in _ed.DEV_ATTACKS],
        normal_bank=[_normalize(item).text for item in _ed.DEV_BENIGN],
    )
    ml.load_all()
    return ml


# ---------------------------------------------------------------------------
# Sidebar & Logo Header
# ---------------------------------------------------------------------------
with st.sidebar:
    # عرض الشعار البصري
    logo_file = "image-removebg-preview.png"
    if os.path.exists(logo_file):
        col_l, col_r = st.columns([1, 2.5], vertical_alignment="center")
        with col_l:
            st.image(logo_file, use_container_width=True)
        with col_r:
            st.markdown("<h2 style='margin:0; padding:0; color:#c4b5fd; font-size:1.4rem;'>درع | Dir'</h2>", unsafe_allow_html=True)
            st.caption("AI Security Gateway")
    else:
        st.markdown("## <span style=\"color:#c4b5fd\">Cyber Next</span>")
        st.markdown("### درع | Dir'")

    st.markdown('<div style="margin-top:6px;"><span class="mini-tag">ZERO-TRUST</span><span class="mini-tag">LOCAL DEMO</span></div>', unsafe_allow_html=True)
    st.divider()

    st.markdown("**إعدادات الحماية**")
    trusted_raw = st.text_area(
        "النطاقات الموثوقة",
        "",
        height=80,
        placeholder="example.com\ncompany.sa",
        help="النطاقات التابعة لهذه القائمة لا تُعامل كرابط تسريب.",
    )
    ttl = st.number_input("صلاحية الرموز (ثانية)", 60, 86400, 900, step=60)
    block_attacks = st.toggle("حظر الهجمات تلقائياً", value=True)
    use_ml = st.toggle("تفعيل طبقة الكشف الهجينة (ML)", value=False)

    st.divider()
    st.caption("إدارة جلسة العرض")
    if st.button("مسح سجل التدقيق وإعادة البدء", use_container_width=True):
        st.session_state.audit.clear()
        st.session_state.last = None
        st.rerun()


def make_gateway() -> Gateway:
    trusted = tuple(value.strip() for value in trusted_raw.splitlines() if value.strip())
    return Gateway(
        SimulatedLLM(),
        GatewayConfig(
            ttl_seconds=int(ttl),
            trusted_domains=trusted,
            block_attacks=block_attacks,
            ml=get_ml() if use_ml else None,
        ),
        st.session_state.audit,
    )


def run_both(user_text: str, documents: list) -> dict:
    doc_text = "".join(
        f"\n\n[بداية مستند: {name}]\n{content}\n[نهاية المستند]"
        for name, content in documents
    )
    raw_prompt = user_text + doc_text
    raw_reply = SimulatedLLM().complete(
        [
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": raw_prompt},
        ]
    )
    gateway = make_gateway()
    gateway.new_session("enterprise_demo")
    result = gateway.process(user_text, documents, session="enterprise_demo")
    return {
        "raw_prompt": raw_prompt,
        "raw_reply": raw_reply,
        "res": result,
        "user_text": user_text,
        "documents": documents,
    }


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">CYBER NEXT · AI SECURITY LAYER</div>
      <div class="hero-title">درع — حماية ذكية قبل وصول الطلب للنموذج</div>
      <p class="hero-sub">بوابة أمنية تفحص الطلبات والمرفقات، تكشف محاولات التلاعب، وتحمي البيانات الحساسة قبل انتقالها إلى نموذج الذكاء الاصطناعي.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_live, tab_dashboard = st.tabs(["المختبر التفاعلي", "مركز الأمن والامتثال"])

# ---------------------------------------------------------------------------
# Interactive Sandbox Tab
# ---------------------------------------------------------------------------
with tab_live:
    st.markdown('<div class="section-title">جرّب درع بنفسك</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-hint">اختر سيناريو جاهزاً أو اكتب طلباً مخصصاً، ثم قارن ما يحدث قبل الحماية وبعدها.</div>',
        unsafe_allow_html=True,
    )

    scenario_keys = [item["key"] for item in SCENARIOS] + ["custom"]
    scenario_titles = {
        item["key"]: item["title_ar"] for item in SCENARIOS
    }
    scenario_titles["custom"] = "اختيار مخصص"

    selected = st.radio(
        "نوع الاختبار",
        scenario_keys,
        format_func=lambda key: scenario_titles[key],
        horizontal=True,
        label_visibility="collapsed",
    )

    # إصلاح شامل للسيناريو المخصص وربطه التام
    if selected == "custom":
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        user_text = st.text_area(
            "نص الطلب المخصص",
            "",
            height=135,
            placeholder="اكتب رسالة يحتوي على هوية ساريه 10xxxxxxxx، جوال 05xxxxxxx، آيبان SA... أو أوامر حقن تعليمات...",
            key="custom_user_text",
        )
        document_text = st.text_area(
            "محتوى مستند مرفق (اختياري)",
            "",
            height=105,
            placeholder="ألصق محتوى مستند يحتوي على بيانات شخصية أو تعليمات اختراق...",
            key="custom_document_text",
        )
        documents = [("مستند_مرفق.txt", document_text)] if document_text.strip() else []
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        scenario = SC[selected]
        st.markdown(
            f'<div class="soft-callout"><b>فكرة السيناريو:</b> {html.escape(scenario["story_ar"])}</div>',
            unsafe_allow_html=True,
        )
        user_text = st.text_area(
            "نص الطلب",
            scenario["user_text"],
            height=130,
            key=f"user_{selected}",
        )
        documents = []
        for index, (filename, content) in enumerate(scenario["documents"]):
            edited_content = st.text_area(
                f"المستند المرفق · {filename}",
                content,
                height=105,
                key=f"document_{selected}_{index}",
            )
            documents.append((filename, edited_content))

    run_col, hint_col = st.columns([1, 2], vertical_alignment="center")
    with run_col:
        run_clicked = st.button(
            "تشغيل الفحص الأمني",
            type="primary",
            use_container_width=True,
        )
    with hint_col:
        st.caption("سيتم تشغيل الطلب مرتين: مرة دون درع، ومرة عبر بوابة الحماية.")

    if run_clicked:
        if not user_text.strip() and not documents:
            st.warning("اكتب نص الطلب أو أدخل مستنداً مرفقاً أولاً حتى نتمكن من فحصه.")
        else:
            with st.spinner("درع يفحص الطلب والمرفقات..."):
                st.session_state.last = run_both(user_text, documents)

    last = st.session_state.last
    if last:
        result = last["res"]
        st.divider()
        st.markdown('<div class="section-title">نتيجة الفحص</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="section-hint">مقارنة مباشرة توضح الفرق الذي تصنعه طبقة الحماية.</div>',
            unsafe_allow_html=True,
        )

        without_col, with_col = st.columns(2, gap="large")

        with without_col:
            st.markdown("#### قبل الحماية")
            raw_findings = [finding for finding in detect(last["raw_prompt"]) if finding.mask]
            exfiltration = "?d=" in last["raw_reply"] and "![" in last["raw_reply"]
            warning_text = (
                "<br><b>تم رصد مؤشر تسريب عبر رابط صورة.</b>" if exfiltration else ""
            )
            st.markdown(
                f'<div class="status red">البيانات الحساسة المكتشفة: <b>{len(raw_findings)}</b>{warning_text}</div>',
                unsafe_allow_html=True,
            )
            with st.expander("عرض النص الذي وصل للنموذج", expanded=False):
                st.code(last["raw_prompt"], language=None)
            with st.expander("عرض رد النموذج دون حماية", expanded=False):
                st.code(last["raw_reply"], language=None)

        with with_col:
            st.markdown("#### بعد الحماية · درع")
            if result.action == "blocked":
                status_class = "red"
                status_title = "تم إيقاف الطلب"
                status_message = result.message_ar
            elif result.action == "allowed_with_warnings":
                status_class = "amber"
                status_title = "مسموح مع تحذير"
                status_message = result.message_ar
            else:
                status_class = ""
                status_title = "تم تمرير الطلب بأمان"
                status_message = f"تمت حماية {len(result.tokens)} عنصر حساس." if result.tokens else "لا توجد بيانات حساسة."

            st.markdown(
                f'<div class="status {status_class}"><b>{status_title}</b><br>{html.escape(str(status_message))}</div>',
                unsafe_allow_html=True,
            )

            if result.tokens:
                masked_types = "، ".join(
                    sorted({TYPE_AR.get(kind, kind) for _, kind in result.tokens})
                )
                st.markdown(
                    f'<div class="soft-callout"><b>إشعار الحماية:</b> تم رصد وحجب بيانات من الأنواع التالية: {html.escape(masked_types)}. جرى التعامل معها عبر آلية الحماية قبل إرسال الطلب.</div>',
                    unsafe_allow_html=True,
                )

            metric_a, metric_b, metric_c = st.columns(3)
            metric_a.metric("مستوى الخطر قبل", result.risk["inherent"])
            metric_b.metric(
                "مستوى الخطر بعد",
                result.risk["residual"],
                delta=round(result.risk["residual"] - result.risk["inherent"], 1),
                delta_color="inverse",
            )
            metric_c.metric("زمن المعالجة", f"{result.latency_ms} ms")

            if result.sent_to_model:
                with st.expander("عرض النص الآمن المرسل للنموذج", expanded=False):
                    st.code(result.model_input_text, language=None)
                with st.expander("عرض الرد النهائي", expanded=True):
                    st.code(result.final_reply, language=None)

            findings = [
                {"نوع التهديد": finding.family_ar, "درجة الخطورة": finding.weight, "الدليل": finding.evidence}
                for finding in result.attack.findings
            ]
            if findings:
                st.markdown("**التهديدات التي تم رصدها**")
                st.dataframe(
                    pd.DataFrame(findings),
                    hide_index=True,
                    use_container_width=True,
                )
            else:
                st.caption("لم يتم تسجيل تهديدات ضمن نتيجة هذا الاختبار.")

# ---------------------------------------------------------------------------
# Dashboard Tab
# ---------------------------------------------------------------------------
with tab_dashboard:
    st.markdown('<div class="section-title">مركز مراقبة الأمن والامتثال</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-hint">نظرة موحدة على الطلبات التي عالجها درع، والبيانات التي تمت حمايتها، وسجل القرارات الأمنية.</div>',
        unsafe_allow_html=True,
    )

    action_col, note_col = st.columns([1, 2], vertical_alignment="center")
    with action_col:
        simulate = st.button("تشغيل محاكاة جميع السيناريوهات", use_container_width=True)
    with note_col:
        st.caption("مفيد أثناء العرض أمام الحكام لإظهار لوحة بيانات تحتوي على نتائج فعلية من السيناريوهات التجريبية.")

    if simulate:
        progress = st.progress(0, text="بدء محاكاة السيناريوهات...")
        for index, scenario in enumerate(SCENARIOS, start=1):
            run_both(scenario["user_text"], scenario["documents"])
            progress.progress(index / len(SCENARIOS), text=f"تم تنفيذ {index} من {len(SCENARIOS)} سيناريو")
        progress.empty()
        st.rerun()

    stats = st.session_state.audit.stats()

    if stats["requests"] == 0:
        st.markdown(
            '<div class="panel"><b>لوحة المراقبة جاهزة</b><p>لا توجد سجلات بعد. شغّل محاكاة السيناريوهات أو نفّذ اختباراً من المختبر التفاعلي لعرض المؤشرات هنا.</p></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="panel">
              <div class="eyebrow">PDPL · COMPLIANCE OVERVIEW</div>
              <div style="font-size:1.15rem;font-weight:700;color:#e8eef7;margin-bottom:6px;">ملخص الحماية والامتثال</div>
              <div style="color:#aabbd0;font-size:.9rem;">
                تمت معالجة <b style="color:#83dfd2">{stats['requests']}</b> طلبات،
                وحجب <b style="color:#83dfd2">{stats['items_masked']}</b> عناصر حساسة،
                وإيقاف <b style="color:#ed9aa0">{stats['blocked']}</b> هجمات.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        cards = st.columns(5)
        metrics = [
            ("إجمالي الطلبات", stats["requests"]),
            ("طلبات موقوفة", stats["blocked"]),
            ("مستندات معزولة", stats["docs_quarantined"]),
            ("عناصر محمية", stats["items_masked"]),
            ("متوسط الخطر بعد الحماية", stats["avg_residual"]),
        ]
        for column, (label, value) in zip(cards, metrics):
            with column:
                st.metric(label, value)

        st.markdown("### تحليل مستوى المخاطر")
        chart_data = pd.DataFrame(
            {
                "المستوى": ["قبل الحماية", "بعد الحماية"],
                "درجة المخاطر": [stats["avg_inherent"], stats["avg_residual"]],
            }
        ).set_index("المستوى")
        st.bar_chart(chart_data, use_container_width=True, horizontal=True)

        st.divider()
        st.markdown("### سجل التدقيق الأمني")
        events = list(reversed(st.session_state.audit.events))
        log_rows = [
            {
                "الوقت": event["ts"][11:19],
                "القرار": ACTION_AR.get(event["action"], event["action"]),
                "أنواع البيانات": "، ".join(
                    f"{TYPE_AR.get(kind, kind)} × {count}"
                    for kind, count in event["data_types"].items()
                ) or "—",
                "التهديد": "، ".join(
                    rule["family_ar"] for rule in event["attack_rules"][:1]
                ) or "—",
                "الخطر قبل": event["inherent"],
                "الخطر بعد": event["residual"],
                "زمن المعالجة": f'{event["latency_ms"]} ms',
            }
            for event in events
        ]
        log_df = pd.DataFrame(log_rows)

        filter_options = ["الكل"] + sorted(log_df["القرار"].dropna().unique().tolist())
        chosen_filter = st.selectbox("تصفية السجل حسب القرار", filter_options)
        if chosen_filter != "الكل":
            log_df = log_df[log_df["القرار"] == chosen_filter]

        st.dataframe(
            log_df,
            hide_index=True,
            use_container_width=True,
            height=360,
        )

st.markdown(
    '<div style="text-align:center;color:#71839c;font-size:.76rem;padding:24px 0 4px;">CYBER NEXT · DERAA · AI SECURITY GATEWAY</div>',
    unsafe_allow_html=True,
)
