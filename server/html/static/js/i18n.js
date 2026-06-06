/* RemotePower i18n (v3.14.0) — minimal, build-free, CSP-safe.
 *
 * Strategy: translate-by-source-text. We do NOT tag hundreds of elements with
 * keys; instead we walk a curated set of clean text containers (sidebar nav
 * labels, group names, page/section titles, and anything carrying data-i18n)
 * and look up their English text in DICT. Anything not in DICT keeps its
 * English text — so partial coverage degrades gracefully and new UI needs no
 * i18n work to keep functioning.
 *
 * Languages: English (base) + Mandarin, Hindi, Spanish, Arabic. Arabic is RTL.
 * The English source string IS the key, so en has no table.
 *
 * Persistence: localStorage 'rp_lang' for instant paint; the authoritative copy
 * lives on the user record (GET /api/me .lang, POST /api/me/lang). app.js calls
 * RPi18n.adopt(me.lang) once /api/me resolves.
 */
(function () {
  'use strict';

  var LANGS = ['en', 'zh', 'hi', 'es', 'ar'];
  var RTL = { ar: true };
  // Endonyms for the picker.
  var NAMES = { en: 'English', zh: '中文', hi: 'हिन्दी', es: 'Español', ar: 'العربية' };

  // English source → per-language translation. Only the chrome that frames
  // every page (nav, groups, common actions). Extend freely; missing entries
  // fall back to English.
  var DICT = {
    // ── sidebar group + section labels ──
    'Main':        { zh: '主页', hi: 'मुख्य', es: 'Principal', ar: 'الرئيسية' },
    'Fleet':       { zh: '机群', hi: 'फ़्लीट', es: 'Flota', ar: 'الأسطول' },
    'Monitoring':  { zh: '监控', hi: 'निगरानी', es: 'Monitoreo', ar: 'المراقبة' },
    'Network':     { zh: '网络', hi: 'नेटवर्क', es: 'Red', ar: 'الشبكة' },
    'Security':    { zh: '安全', hi: 'सुरक्षा', es: 'Seguridad', ar: 'الأمان' },
    'Planning':    { zh: '规划', hi: 'योजना', es: 'Planificación', ar: 'التخطيط' },
    'Admin':       { zh: '管理', hi: 'व्यवस्थापक', es: 'Administración', ar: 'الإدارة' },
    'Help':        { zh: '帮助', hi: 'सहायता', es: 'Ayuda', ar: 'مساعدة' },
    // ── top-level nav ──
    'Home':        { zh: '主页', hi: 'होम', es: 'Inicio', ar: 'الرئيسية' },
    'Alerts':      { zh: '警报', hi: 'अलर्ट', es: 'Alertas', ar: 'التنبيهات' },
    'Links':       { zh: '链接', hi: 'लिंक', es: 'Enlaces', ar: 'الروابط' },
    // ── fleet ──
    'Devices':     { zh: '设备', hi: 'डिवाइस', es: 'Dispositivos', ar: 'الأجهزة' },
    'CMDB':        { zh: 'CMDB', hi: 'CMDB', es: 'CMDB', ar: 'CMDB' },
    'Agent Containers': { zh: '代理容器', hi: 'एजेंट कंटेनर', es: 'Contenedores del agente', ar: 'حاويات الوكيل' },
    'Proxmox LXC': { zh: 'Proxmox LXC', hi: 'Proxmox LXC', es: 'Proxmox LXC', ar: 'Proxmox LXC' },
    'Query':       { zh: '查询', hi: 'क्वेरी', es: 'Consulta', ar: 'استعلام' },
    // ── monitoring ──
    'Targets':     { zh: '目标', hi: 'लक्ष्य', es: 'Objetivos', ar: 'الأهداف' },
    'Device Metrics': { zh: '设备指标', hi: 'डिवाइस मेट्रिक्स', es: 'Métricas del dispositivo', ar: 'مقاييس الجهاز' },
    'Forecast':    { zh: '预测', hi: 'पूर्वानुमान', es: 'Pronóstico', ar: 'التنبؤ' },
    'Timeline':    { zh: '时间线', hi: 'टाइमलाइन', es: 'Cronología', ar: 'الجدول الزمني' },
    'Listening Ports': { zh: '监听端口', hi: 'सुनने वाले पोर्ट', es: 'Puertos de escucha', ar: 'المنافذ المستمعة' },
    'Custom Scripts': { zh: '自定义脚本', hi: 'कस्टम स्क्रिप्ट', es: 'Scripts personalizados', ar: 'نصوص مخصصة' },
    'Processes':   { zh: '进程', hi: 'प्रक्रियाएँ', es: 'Procesos', ar: 'العمليات' },
    'Services':    { zh: '服务', hi: 'सेवाएँ', es: 'Servicios', ar: 'الخدمات' },
    'Logs':        { zh: '日志', hi: 'लॉग', es: 'Registros', ar: 'السجلات' },
    // ── security ──
    'TLS / DNS Expiry': { zh: 'TLS / DNS 到期', hi: 'TLS / DNS समाप्ति', es: 'Vencimiento TLS / DNS', ar: 'انتهاء TLS / DNS' },
    'ACME Certificates': { zh: 'ACME 证书', hi: 'ACME प्रमाणपत्र', es: 'Certificados ACME', ar: 'شهادات ACME' },
    'Patches':     { zh: '补丁', hi: 'पैच', es: 'Parches', ar: 'التصحيحات' },
    'CVEs':        { zh: 'CVE', hi: 'CVE', es: 'CVE', ar: 'الثغرات (CVE)' },
    'Drift':       { zh: '漂移', hi: 'ड्रिफ्ट', es: 'Desviación', ar: 'الانحراف' },
    'SSH keys':    { zh: 'SSH 密钥', hi: 'SSH कुंजियाँ', es: 'Claves SSH', ar: 'مفاتيح SSH' },
    'Exposure':    { zh: '暴露面', hi: 'एक्सपोज़र', es: 'Exposición', ar: 'التعرّض' },
    'Storage':     { zh: '存储', hi: 'स्टोरेज', es: 'Almacenamiento', ar: 'التخزين' },
    'Thermal':     { zh: '温度', hi: 'तापीय', es: 'Térmico', ar: 'الحرارة' },
    'Power':       { zh: '电源', hi: 'पावर', es: 'Energía', ar: 'الطاقة' },
    'Predictive health': { zh: '预测健康', hi: 'पूर्वानुमानित स्वास्थ्य', es: 'Salud predictiva', ar: 'الصحة التنبؤية' },
    'Software policy': { zh: '软件策略', hi: 'सॉफ़्टवेयर नीति', es: 'Política de software', ar: 'سياسة البرامج' },
    'Risk':        { zh: '风险', hi: 'जोखिम', es: 'Riesgo', ar: 'المخاطر' },
    'Audit':       { zh: '审计', hi: 'ऑडिट', es: 'Auditoría', ar: 'التدقيق' },
    'Compliance':  { zh: '合规', hi: 'अनुपालन', es: 'Cumplimiento', ar: 'الامتثال' },
    // ── planning ──
    'Schedule':    { zh: '计划', hi: 'शेड्यूल', es: 'Programación', ar: 'الجدولة' },
    'Calendar':    { zh: '日历', hi: 'कैलेंडर', es: 'Calendario', ar: 'التقويم' },
    'Tasks':       { zh: '任务', hi: 'कार्य', es: 'Tareas', ar: 'المهام' },
    'Maintenance': { zh: '维护', hi: 'रखरखाव', es: 'Mantenimiento', ar: 'الصيانة' },
    'Rollouts':    { zh: '发布', hi: 'रोलआउट', es: 'Despliegues', ar: 'الإطلاقات' },
    'Auto-patch':  { zh: '自动补丁', hi: 'ऑटो-पैच', es: 'Parcheo automático', ar: 'الترقيع التلقائي' },
    'Backups':     { zh: '备份', hi: 'बैकअप', es: 'Copias de seguridad', ar: 'النسخ الاحتياطي' },
    'History':     { zh: '历史', hi: 'इतिहास', es: 'Historial', ar: 'السجل' },
    'Reports':     { zh: '报告', hi: 'रिपोर्ट', es: 'Informes', ar: 'التقارير' },
    'Trends':      { zh: '趋势', hi: 'रुझान', es: 'Tendencias', ar: 'الاتجاهات' },
    // ── admin ──
    'Settings':    { zh: '设置', hi: 'सेटिंग्स', es: 'Configuración', ar: 'الإعدادات' },
    'Users':       { zh: '用户', hi: 'उपयोगकर्ता', es: 'Usuarios', ar: 'المستخدمون' },
    'Sites':       { zh: '站点', hi: 'साइटें', es: 'Sitios', ar: 'المواقع' },
    'API Keys':    { zh: 'API 密钥', hi: 'API कुंजियाँ', es: 'Claves API', ar: 'مفاتيح API' },
    'Command Queue': { zh: '命令队列', hi: 'कमांड कतार', es: 'Cola de comandos', ar: 'قائمة الأوامر' },
    'Library':     { zh: '库', hi: 'लाइब्रेरी', es: 'Biblioteca', ar: 'المكتبة' },
    'Scripts':     { zh: '脚本', hi: 'स्क्रिप्ट', es: 'Scripts', ar: 'النصوص' },
    'Ansible':     { zh: 'Ansible', hi: 'Ansible', es: 'Ansible', ar: 'Ansible' },
    'Automation':  { zh: '自动化', hi: 'स्वचालन', es: 'Automatización', ar: 'الأتمتة' },
    'Release Signing': { zh: '发布签名', hi: 'रिलीज़ हस्ताक्षर', es: 'Firma de versiones', ar: 'توقيع الإصدارات' },
    'Confirmations': { zh: '确认', hi: 'पुष्टि', es: 'Confirmaciones', ar: 'التأكيدات' },
    'AI Assistant': { zh: 'AI 助手', hi: 'AI सहायक', es: 'Asistente de IA', ar: 'مساعد الذكاء الاصطناعي' },
    // ── help ──
    'About':       { zh: '关于', hi: 'परिचय', es: 'Acerca de', ar: 'حول' },
    'Documentation': { zh: '文档', hi: 'दस्तावेज़', es: 'Documentación', ar: 'التوثيق' },
    // ── My Account: language card ──
    'Language':    { zh: '语言', hi: 'भाषा', es: 'Idioma', ar: 'اللغة' },
    'Choose the interface language. Saved to your account and synced across devices.':
      { zh: '选择界面语言。已保存到您的账户并在设备间同步。',
        hi: 'इंटरफ़ेस भाषा चुनें। आपके खाते में सहेजी जाती है और सभी डिवाइसों में सिंक होती है।',
        es: 'Elija el idioma de la interfaz. Se guarda en su cuenta y se sincroniza entre dispositivos.',
        ar: 'اختر لغة الواجهة. تُحفظ في حسابك وتُزامن عبر الأجهزة.' },
    // ── a few common actions ──
    'Save':        { zh: '保存', hi: 'सहेजें', es: 'Guardar', ar: 'حفظ' },
    'Cancel':      { zh: '取消', hi: 'रद्द करें', es: 'Cancelar', ar: 'إلغاء' },
    'Refresh':     { zh: '刷新', hi: 'ताज़ा करें', es: 'Actualizar', ar: 'تحديث' },
    'Search':      { zh: '搜索', hi: 'खोजें', es: 'Buscar', ar: 'بحث' },
    'Delete':      { zh: '删除', hi: 'हटाएँ', es: 'Eliminar', ar: 'حذف' },
    'Close':       { zh: '关闭', hi: 'बंद करें', es: 'Cerrar', ar: 'إغلاق' }
  };

  // Selectors for clean, text-only containers we translate. We only touch
  // elements with NO element children (so we never clobber icon+text buttons
  // or anything structural), plus anything explicitly carrying [data-i18n].
  var SELECTOR = [
    '[data-i18n]',
    '.sidebar-label > span',
    '.sidebar-group-toggle > span',
    '.nav-btn > span',
    '.page-title',
    '.section-title',
    '.empty-title'
  ].join(',');

  var current = 'en';

  function normalizeLang(l) {
    return LANGS.indexOf(l) >= 0 ? l : 'en';
  }

  function translate(src) {
    if (current === 'en') return src;
    var row = DICT[src];
    return (row && row[current]) || src;
  }

  // Walk + retranslate. We stash the ORIGINAL English on the element the first
  // time we see it (dataset.i18nEn), so repeated language switches always
  // translate from English, never from an already-translated string.
  function apply(root) {
    var scope = root || document;
    var nodes = scope.querySelectorAll(SELECTOR);
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.children.length) continue;          // skip non-leaf (icon+text etc.)
      var en = el.dataset.i18nEn;
      if (en === undefined) {
        en = el.textContent.trim();
        if (!en) continue;
        el.dataset.i18nEn = en;
      }
      var out = translate(en);
      if (el.textContent !== out) el.textContent = out;
    }
  }

  function setDir(lang) {
    var html = document.documentElement;
    html.setAttribute('lang', lang);
    html.setAttribute('dir', RTL[lang] ? 'rtl' : 'ltr');
  }

  // Change the language now. persist=true also writes it to the user record.
  function setLang(lang, persist) {
    current = normalizeLang(lang);
    try { localStorage.setItem('rp_lang', current); } catch (e) {}
    setDir(current);
    apply();
    syncPicker();
    if (persist) {
      try {
        var tok = '';
        try { tok = localStorage.getItem('rp_token') || sessionStorage.getItem('rp_token') || ''; } catch (e) {}
        fetch('/api/me/lang', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Token': tok },
          body: JSON.stringify({ lang: current })
        }).catch(function () {});
      } catch (e) {}
    }
  }

  // Adopt the server's stored language (called once /api/me resolves). Only
  // applies if it differs from what we painted with, and never re-persists.
  function adopt(lang) {
    var l = normalizeLang(lang);
    if (l !== current) setLang(l, false);
  }

  function syncPicker() {
    var sel = document.getElementById('acct-lang');
    if (sel && sel.value !== current) sel.value = current;
  }

  function buildPicker() {
    var sel = document.getElementById('acct-lang');
    if (!sel || sel.dataset.built) return;
    sel.dataset.built = '1';
    for (var i = 0; i < LANGS.length; i++) {
      var o = document.createElement('option');
      o.value = LANGS[i];
      o.textContent = NAMES[LANGS[i]];
      sel.appendChild(o);
    }
    sel.value = current;
    sel.addEventListener('change', function () { setLang(sel.value, true); });
  }

  function init() {
    var saved;
    try { saved = localStorage.getItem('rp_lang'); } catch (e) {}
    current = normalizeLang(saved);
    setDir(current);
    buildPicker();
    apply();
  }

  window.RPi18n = {
    langs: LANGS,
    names: NAMES,
    t: translate,
    apply: apply,
    setLang: setLang,
    adopt: adopt,
    get current() { return current; }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
