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
    'Close':       { zh: '关闭', hi: 'बंद करें', es: 'Cerrar', ar: 'إغلاق' },
    // ── v4.1: full static-UI catalog — page titles, section titles, subtitles ──
    "6-hour rolling buffer across the fleet. Search, tail live, or manage alert rules.": { "zh": "全设备 6 小时滚动缓冲。搜索、实时跟踪或管理告警规则。", "hi": "पूरे fleet में 6-घंटे का रोलिंग बफ़र। खोजें, लाइव tail करें, या alert नियम प्रबंधित करें।", "es": "Búfer móvil de 6 horas en toda la flota. Busca, sigue en vivo o gestiona reglas de alerta.", "ar": "مخزن متجدد لمدة 6 ساعات عبر الأسطول. ابحث، أو تابع مباشرةً، أو أدر قواعد التنبيه." },
    "ACME certificates": { "zh": "ACME 证书", "hi": "ACME प्रमाणपत्र", "es": "Certificados ACME", "ar": "شهادات ACME" },
    "Accounts": { "zh": "账户", "hi": "खाते", "es": "Cuentas", "ar": "الحسابات" },
    "Alert rules": { "zh": "告警规则", "hi": "Alert नियम", "es": "Reglas de alerta", "ar": "قواعد التنبيه" },
    "Audit Log": { "zh": "审计日志", "hi": "Audit लॉग", "es": "Registro de auditoría", "ar": "سجل التدقيق" },
    "Backup jobs": { "zh": "备份任务", "hi": "Backup जॉब्स", "es": "Trabajos de copia de seguridad", "ar": "مهام النسخ الاحتياطي" },
    "CVE Findings": { "zh": "CVE 发现", "hi": "CVE निष्कर्ष", "es": "Hallazgos de CVE", "ar": "نتائج CVE" },
    "Command History": { "zh": "命令历史", "hi": "कमांड इतिहास", "es": "Historial de comandos", "ar": "سجل الأوامر" },
    "Command Library": { "zh": "命令库", "hi": "कमांड लाइब्रेरी", "es": "Biblioteca de comandos", "ar": "مكتبة الأوامر" },
    "Compose stacks": { "zh": "Compose 栈", "hi": "Compose stacks", "es": "Stacks de Compose", "ar": "حزم Compose" },
    "Configuration Management Database — asset metadata, documentation, and encrypted credentials per enrolled device.": { "zh": "配置管理数据库——每台已注册设备的资产元数据、文档及加密凭据。", "hi": "Configuration Management Database — प्रत्येक नामांकित device के लिए asset मेटाडेटा, दस्तावेज़ीकरण, और एन्क्रिप्टेड क्रेडेंशियल।", "es": "Base de datos de gestión de configuración: metadatos de activos, documentación y credenciales cifradas por cada dispositivo inscrito.", "ar": "قاعدة بيانات إدارة التهيئة — بيانات وصفية للأصول، وتوثيق، وبيانات اعتماد مشفّرة لكل جهاز مُسجَّل." },
    "Configuration drift": { "zh": "配置漂移", "hi": "कॉन्फ़िगरेशन drift", "es": "Desviación de configuración", "ar": "انحراف التهيئة" },
    "Containers": { "zh": "容器", "hi": "Containers", "es": "Contenedores", "ar": "الحاويات" },
    "Current violations": { "zh": "当前违规", "hi": "वर्तमान उल्लंघन", "es": "Infracciones actuales", "ar": "المخالفات الحالية" },
    "Custom roles": { "zh": "自定义角色", "hi": "कस्टम भूमिकाएँ", "es": "Roles personalizados", "ar": "الأدوار المخصّصة" },
    "Device Control": { "zh": "设备控制", "hi": "Device नियंत्रण", "es": "Control de dispositivos", "ar": "التحكم بالأجهزة" },
    "Device Settings": { "zh": "设备设置", "hi": "Device सेटिंग्स", "es": "Ajustes del dispositivo", "ar": "إعدادات الجهاز" },
    "Device metrics": { "zh": "设备指标", "hi": "Device मेट्रिक्स", "es": "Métricas del dispositivo", "ar": "مقاييس الجهاز" },
    "Drift profiles": { "zh": "漂移配置", "hi": "Drift प्रोफ़ाइल", "es": "Perfiles de desviación", "ar": "ملفات الانحراف" },
    "Email the posture report on a cron schedule. Leave recipients empty to use the configured notification recipients. Admin only.": { "zh": "按 cron 计划邮寄态势报告。收件人留空则使用已配置的通知收件人。仅限管理员。", "hi": "cron शेड्यूल पर posture रिपोर्ट ईमेल करें। कॉन्फ़िगर किए गए नोटिफिकेशन प्राप्तकर्ताओं का उपयोग करने के लिए प्राप्तकर्ता खाली छोड़ें। केवल Admin।", "es": "Envía por correo el informe de postura según una programación cron. Deja los destinatarios vacíos para usar los destinatarios de notificación configurados. Solo administradores.", "ar": "أرسل تقرير الوضع الأمني عبر البريد وفق جدول cron. اترك المستلمين فارغين لاستخدام مستلمي الإشعارات المُهيّأين. للمسؤول فقط." },
    "Enforcement policy": { "zh": "强制策略", "hi": "प्रवर्तन नीति", "es": "Política de aplicación", "ar": "سياسة الإنفاذ" },
    "Enrolled Devices": { "zh": "已注册设备", "hi": "नामांकित Devices", "es": "Dispositivos inscritos", "ar": "الأجهزة المُسجَّلة" },
    "Everything that needs your attention, in one screen.": { "zh": "所有需要关注的事项，尽在一屏。", "hi": "जिस पर आपका ध्यान चाहिए, सब कुछ एक स्क्रीन में।", "es": "Todo lo que requiere tu atención, en una sola pantalla.", "ar": "كل ما يحتاج إلى انتباهك، في شاشة واحدة." },
    "Exposed secrets on disk": { "zh": "磁盘上暴露的密钥", "hi": "डिस्क पर उजागर secrets", "es": "Secretos expuestos en disco", "ar": "أسرار مكشوفة على القرص" },
    "Fleet Query": { "zh": "设备群查询", "hi": "Fleet Query", "es": "Consulta de flota", "ar": "استعلام الأسطول" },
    "Fleet at a glance": { "zh": "设备群概览", "hi": "एक नज़र में fleet", "es": "Flota de un vistazo", "ar": "الأسطول في لمحة" },
    "Free-form chat against the configured provider. Local-model stats when running Ollama or LocalAI.": { "zh": "面向已配置提供方的自由对话。运行 Ollama 或 LocalAI 时显示本地模型统计。", "hi": "कॉन्फ़िगर किए गए प्रोवाइडर के साथ मुक्त-रूप चैट। Ollama या LocalAI चलाने पर local-model आँकड़े।", "es": "Chat libre con el proveedor configurado. Estadísticas de modelo local al usar Ollama o LocalAI.", "ar": "محادثة حرّة مع المزوّد المُهيّأ. إحصاءات النموذج المحلي عند تشغيل Ollama أو LocalAI." },
    "Grant exactly the actions this role may take. Hover for what each covers.": { "zh": "精确授予该角色可执行的操作。悬停查看各项涵盖范围。", "hi": "इस भूमिका को ठीक वही कार्य प्रदान करें जो वह कर सकती है। प्रत्येक क्या कवर करता है, यह देखने के लिए hover करें।", "es": "Concede exactamente las acciones que puede realizar este rol. Pasa el cursor para ver qué cubre cada una.", "ar": "امنح بالضبط الإجراءات المسموح بها لهذا الدور. مرّر المؤشر لمعرفة ما يغطّيه كلٌّ منها." },
    "Hosts seen by agents that ran a LAN scan (device drawer → Health &amp; Hardware → Scan LAN) and that aren't enrolled in RemotePower.": { "zh": "代理执行 LAN 扫描（设备抽屉 → Health &amp; Hardware → Scan LAN）时发现、但未注册到 RemotePower 的主机。", "hi": "LAN scan चलाने वाले agents द्वारा देखे गए hosts (device drawer → Health &amp; Hardware → Scan LAN) जो RemotePower में नामांकित नहीं हैं।", "es": "Hosts detectados por agentes que ejecutaron un escaneo de LAN (panel del dispositivo → Salud y hardware → Escanear LAN) y que no están inscritos en RemotePower.", "ar": "المضيفون الذين رصدتهم الوكلاء أثناء مسح الشبكة المحلية (درج الجهاز ← Health &amp; Hardware ← Scan LAN) وغير المُسجَّلين في RemotePower." },
    "Hosts whose latest memory / swap / disk reading deviates sharply from their own recent baseline (statistical, model-free).": { "zh": "最新内存 / swap / 磁盘读数与自身近期基线明显偏离的主机（统计法，无需模型）。", "hi": "वे hosts जिनकी नवीनतम memory / swap / disk रीडिंग अपनी ही हालिया baseline से तेज़ी से विचलित होती है (सांख्यिकीय, model-free)।", "es": "Hosts cuya última lectura de memoria / swap / disco se desvía notablemente de su propia línea base reciente (estadístico, sin modelo).", "ar": "المضيفون الذين تنحرف أحدث قراءات الذاكرة / swap / القرص لديهم انحرافًا حادًّا عن خط أساسهم الحديث (إحصائي، دون نموذج)." },
    "How to use RemotePower — quick reference for the common tasks": { "zh": "RemotePower 使用方法——常见任务快速参考", "hi": "RemotePower का उपयोग कैसे करें — सामान्य कार्यों के लिए त्वरित संदर्भ", "es": "Cómo usar RemotePower: referencia rápida para las tareas habituales", "ar": "كيفية استخدام RemotePower — مرجع سريع للمهام الشائعة" },
    "IaC Generator": { "zh": "IaC 生成器", "hi": "IaC जनरेटर", "es": "Generador de IaC", "ar": "مولّد IaC" },
    "Image updates": { "zh": "镜像更新", "hi": "Image अपडेट", "es": "Actualizaciones de imagen", "ar": "تحديثات الصور" },
    "Keys": { "zh": "密钥", "hi": "कुंजियाँ", "es": "Claves", "ar": "المفاتيح" },
    "LXC containers on the Proxmox node. Actions hit the Proxmox API directly.": { "zh": "Proxmox 节点上的 LXC 容器。操作直接调用 Proxmox API。", "hi": "Proxmox node पर LXC containers। क्रियाएँ सीधे Proxmox API पर पहुँचती हैं।", "es": "Contenedores LXC en el nodo Proxmox. Las acciones se ejecutan directamente contra la API de Proxmox.", "ar": "حاويات LXC على عقدة Proxmox. تستدعي الإجراءات واجهة Proxmox API مباشرةً." },
    "Log of all commands sent to devices": { "zh": "发送至设备的所有命令日志", "hi": "devices को भेजे गए सभी कमांड का लॉग", "es": "Registro de todos los comandos enviados a los dispositivos", "ar": "سجل بجميع الأوامر المُرسَلة إلى الأجهزة" },
    "MCP Confirmations": { "zh": "MCP 确认", "hi": "MCP पुष्टियाँ", "es": "Confirmaciones de MCP", "ar": "تأكيدات MCP" },
    "Maintenance Windows": { "zh": "维护窗口", "hi": "Maintenance Windows", "es": "Ventanas de mantenimiento", "ar": "نوافذ الصيانة" },
    "Manage and remotely control enrolled devices": { "zh": "管理并远程控制已注册设备", "hi": "नामांकित devices को प्रबंधित और दूरस्थ रूप से नियंत्रित करें", "es": "Gestiona y controla de forma remota los dispositivos inscritos", "ar": "إدارة الأجهزة المُسجَّلة والتحكم بها عن بُعد" },
    "My Account": { "zh": "我的账户", "hi": "मेरा खाता", "es": "Mi cuenta", "ar": "حسابي" },
    "Named non-expiring keys for scripts and CI pipelines": { "zh": "用于脚本和 CI 流水线的命名永久密钥", "hi": "scripts और CI pipelines के लिए नामित न-समाप्त होने वाली कुंजियाँ", "es": "Claves con nombre y sin caducidad para scripts y pipelines de CI", "ar": "مفاتيح مُسمّاة غير منتهية الصلاحية للنصوص البرمجية وخطوط CI" },
    "Network map": { "zh": "网络拓扑", "hi": "नेटवर्क मानचित्र", "es": "Mapa de red", "ar": "خريطة الشبكة" },
    "Overview of pending system updates across all devices — percentage only counts online devices with data": { "zh": "所有设备待装系统更新概览——百分比仅统计有数据的在线设备", "hi": "सभी devices में लंबित सिस्टम अपडेट का अवलोकन — प्रतिशत केवल डेटा वाले ऑनलाइन devices को गिनता है", "es": "Resumen de las actualizaciones del sistema pendientes en todos los dispositivos: el porcentaje solo cuenta dispositivos en línea con datos", "ar": "نظرة عامة على تحديثات النظام المعلّقة عبر جميع الأجهزة — لا تحتسب النسبة سوى الأجهزة المتصلة التي لديها بيانات" },
    "Package names only (no shell). Space- or comma-separated, up to 30.": { "zh": "仅填包名（不支持 shell）。以空格或逗号分隔，最多 30 个。", "hi": "केवल package नाम (कोई shell नहीं)। space- या comma-विभाजित, 30 तक।", "es": "Solo nombres de paquetes (sin shell). Separados por espacios o comas, hasta 30.", "ar": "أسماء الحزم فقط (دون shell). مفصولة بمسافة أو فاصلة، حتى 30." },
    "Patch Report": { "zh": "补丁报告", "hi": "Patch रिपोर्ट", "es": "Informe de parches", "ar": "تقرير الترقيع" },
    "Pending jobs": { "zh": "待处理任务", "hi": "लंबित जॉब्स", "es": "Trabajos pendientes", "ar": "المهام المعلّقة" },
    "Pending per device": { "zh": "各设备待处理数", "hi": "प्रति device लंबित", "es": "Pendientes por dispositivo", "ar": "المعلّق لكل جهاز" },
    "Pending updates aggregated by package — which update is waiting, and on how many hosts. The inverse of the device table above.": { "zh": "按软件包汇总的待装更新——哪个更新在等待、涉及多少主机。与上方设备表互为反向视图。", "hi": "package द्वारा एकत्रित लंबित अपडेट — कौन सा अपडेट प्रतीक्षारत है, और कितने hosts पर। ऊपर दी गई device तालिका का उलटा।", "es": "Actualizaciones pendientes agregadas por paquete: qué actualización está en espera y en cuántos hosts. Lo inverso de la tabla de dispositivos anterior.", "ar": "التحديثات المعلّقة مجمّعة حسب الحزمة — أيّ تحديث ينتظر، وعلى كم مضيفًا. عكس جدول الأجهزة أعلاه." },
    "Playbooks": { "zh": "Playbook", "hi": "Playbooks", "es": "Playbooks", "ar": "دفاتر اللعب" },
    "Policies": { "zh": "策略", "hi": "नीतियाँ", "es": "Políticas", "ar": "السياسات" },
    "Policy rules": { "zh": "策略规则", "hi": "नीति नियम", "es": "Reglas de política", "ar": "قواعد السياسة" },
    "Power &amp; energy": { "zh": "电源 &amp; 能耗", "hi": "Power &amp; ऊर्जा", "es": "Potencia y energía", "ar": "الطاقة &amp; الاستهلاك" },
    "Probes, device metrics, ports, and custom health checks": { "zh": "探针、设备指标、端口及自定义健康检查", "hi": "Probes, device मेट्रिक्स, ports, और कस्टम health जाँच", "es": "Sondas, métricas de dispositivo, puertos y comprobaciones de salud personalizadas", "ar": "المجسّات، ومقاييس الأجهزة، والمنافذ، وفحوص الصحة المخصّصة" },
    "Proxmox LXC containers": { "zh": "Proxmox LXC 容器", "hi": "Proxmox LXC containers", "es": "Contenedores LXC de Proxmox", "ar": "حاويات Proxmox LXC" },
    "Proxmox guest backups": { "zh": "Proxmox 客户机备份", "hi": "Proxmox guest backups", "es": "Copias de seguridad de invitados de Proxmox", "ar": "النسخ الاحتياطية لضيوف Proxmox" },
    "QEMU virtual machines on the Proxmox node. Start / shutdown actions call the Proxmox VE API directly from the RemotePower server.": { "zh": "Proxmox 节点上的 QEMU 虚拟机。启动 / 关闭操作由 RemotePower 服务器直接调用 Proxmox VE API。", "hi": "Proxmox node पर QEMU वर्चुअल मशीनें। Start / shutdown क्रियाएँ RemotePower server से सीधे Proxmox VE API को कॉल करती हैं।", "es": "Máquinas virtuales QEMU en el nodo Proxmox. Las acciones de inicio / apagado llaman a la API de Proxmox VE directamente desde el servidor de RemotePower.", "ar": "الأجهزة الافتراضية QEMU على عقدة Proxmox. تستدعي إجراءات التشغيل / الإيقاف واجهة Proxmox VE API مباشرةً من خادم RemotePower." },
    "Queue shutdown or reboot at a specific time": { "zh": "在指定时间排队执行关机或重启", "hi": "किसी विशिष्ट समय पर shutdown या reboot कतारबद्ध करें", "es": "Programa el apagado o reinicio a una hora concreta", "ar": "جدولة الإيقاف أو إعادة التشغيل في وقت محدّد" },
    "Quick Actions": { "zh": "快捷操作", "hi": "त्वरित क्रियाएँ", "es": "Acciones rápidas", "ar": "إجراءات سريعة" },
    "Recent Suppressions": { "zh": "近期抑制", "hi": "हाल की Suppressions", "es": "Supresiones recientes", "ar": "عمليات الكتم الأخيرة" },
    "Recent commands": { "zh": "近期命令", "hi": "हाल के कमांड", "es": "Comandos recientes", "ar": "الأوامر الأخيرة" },
    "Recent deliveries": { "zh": "近期投递", "hi": "हाल की डिलीवरी", "es": "Entregas recientes", "ar": "عمليات التسليم الأخيرة" },
    "Recent installs &amp; jobs": { "zh": "近期安装 &amp; 任务", "hi": "हाल के installs &amp; जॉब्स", "es": "Instalaciones y trabajos recientes", "ar": "عمليات التثبيت &amp; المهام الأخيرة" },
    "RemotePower — self-hosted device management": { "zh": "RemotePower——自托管设备管理", "hi": "RemotePower — सेल्फ-होस्टेड device प्रबंधन", "es": "RemotePower: gestión de dispositivos autoalojada", "ar": "RemotePower — إدارة أجهزة ذاتية الاستضافة" },
    "Rules": { "zh": "规则", "hi": "नियम", "es": "Reglas", "ar": "القواعد" },
    "SNMP devices": { "zh": "SNMP 设备", "hi": "SNMP devices", "es": "Dispositivos SNMP", "ar": "أجهزة SNMP" },
    "SSH key audit": { "zh": "SSH 密钥审计", "hi": "SSH कुंजी audit", "es": "Auditoría de claves SSH", "ar": "تدقيق مفاتيح SSH" },
    "Saved scripts": { "zh": "已保存脚本", "hi": "सहेजी गई scripts", "es": "Scripts guardados", "ar": "النصوص البرمجية المحفوظة" },
    "Saved shell command snippets — pick from the exec modal": { "zh": "已保存的 shell 命令片段——在执行弹窗中选用", "hi": "सहेजे गए shell कमांड snippets — exec modal से चुनें", "es": "Fragmentos de comandos de shell guardados: elígelos desde el modal de ejecución", "ar": "مقتطفات أوامر shell محفوظة — اخترها من نافذة التنفيذ" },
    "Scheduled Commands": { "zh": "计划命令", "hi": "शेड्यूल किए गए कमांड", "es": "Comandos programados", "ar": "الأوامر المجدولة" },
    "Scheduled windows suppress webhook alerts for specific devices, groups, or the whole fleet.": { "zh": "计划窗口可抑制指定设备、组或整个设备群的 webhook 告警。", "hi": "शेड्यूल किए गए windows विशिष्ट devices, समूहों, या पूरे fleet के लिए webhook alerts दबाते हैं।", "es": "Las ventanas programadas suprimen las alertas de webhook para dispositivos, grupos o toda la flota.", "ar": "تكتم النوافذ المجدولة تنبيهات webhook لأجهزة أو مجموعات محدّدة أو للأسطول بأكمله." },
    "Security audit trail — logins, commands, session revocations": { "zh": "安全审计记录——登录、命令、会话吊销", "hi": "सुरक्षा audit ट्रेल — logins, कमांड, session निरस्तीकरण", "es": "Rastro de auditoría de seguridad: inicios de sesión, comandos, revocaciones de sesión", "ar": "مسار التدقيق الأمني — عمليات تسجيل الدخول، والأوامر، وإلغاء الجلسات" },
    "Server configuration": { "zh": "服务器配置", "hi": "Server कॉन्फ़िगरेशन", "es": "Configuración del servidor", "ar": "تهيئة الخادم" },
    "Server status": { "zh": "服务器状态", "hi": "Server स्थिति", "es": "Estado del servidor", "ar": "حالة الخادم" },
    "Server-side cert and DNS watchlist. Probes run from the RemotePower server. Defaults: warn at 14 days, critical at 3 days.": { "zh": "服务器端证书与 DNS 监视列表。探测由 RemotePower 服务器发起。默认：14 天告警，3 天严重。", "hi": "Server-side cert और DNS watchlist। Probes RemotePower server से चलते हैं। डिफ़ॉल्ट: 14 दिनों पर चेतावनी, 3 दिनों पर critical।", "es": "Lista de vigilancia de certificados y DNS del lado del servidor. Las sondas se ejecutan desde el servidor de RemotePower. Valores por defecto: aviso a 14 días, crítico a 3 días.", "ar": "قائمة مراقبة للشهادات وDNS من جانب الخادم. تُشغَّل المجسّات من خادم RemotePower. الافتراضيات: تحذير عند 14 يومًا، حرِج عند 3 أيام." },
    "Shared events across all users — backups, deploys, renewals, anything you want to remember.": { "zh": "全体用户共享的事件——备份、部署、续期，以及任何你想记住的事项。", "hi": "सभी उपयोगकर्ताओं में साझा इवेंट्स — backups, deploys, नवीनीकरण, जो भी आप याद रखना चाहें।", "es": "Eventos compartidos entre todos los usuarios: copias de seguridad, despliegues, renovaciones, cualquier cosa que quieras recordar.", "ar": "أحداث مشتركة بين جميع المستخدمين — نسخ احتياطية، وعمليات نشر، وتجديدات، وأيّ شيء تريد تذكّره." },
    "Shared kanban board. Drag cards between columns. Optionally link a task to a device.": { "zh": "共享看板。在列间拖动卡片。可选择将任务关联到设备。", "hi": "साझा kanban बोर्ड। columns के बीच cards खींचें। वैकल्पिक रूप से किसी task को device से लिंक करें।", "es": "Tablero kanban compartido. Arrastra tarjetas entre columnas. Opcionalmente, vincula una tarea a un dispositivo.", "ar": "لوحة kanban مشتركة. اسحب البطاقات بين الأعمدة. يمكنك اختياريًّا ربط مهمة بجهاز." },
    "Sites &amp; teams": { "zh": "站点 &amp; 团队", "hi": "Sites &amp; टीमें", "es": "Sitios y equipos", "ar": "المواقع &amp; الفرق" },
    "Snippets": { "zh": "代码片段", "hi": "Snippets", "es": "Fragmentos", "ar": "المقتطفات" },
    "Software center — installed packages": { "zh": "软件中心——已安装软件包", "hi": "Software केंद्र — स्थापित packages", "es": "Centro de software: paquetes instalados", "ar": "مركز البرمجيات — الحزم المثبَّتة" },
    "Storage health": { "zh": "存储健康", "hi": "Storage health", "es": "Salud del almacenamiento", "ar": "صحة التخزين" },
    "TLS / DNS": { "zh": "TLS / DNS", "hi": "TLS / DNS", "es": "TLS / DNS", "ar": "TLS / DNS" },
    "Thermal health": { "zh": "散热健康", "hi": "Thermal health", "es": "Salud térmica", "ar": "الصحة الحرارية" },
    "Tokens": { "zh": "令牌", "hi": "टोकन", "es": "Tokens", "ar": "الرموز" },
    "Top Processes": { "zh": "进程占用排行", "hi": "शीर्ष Processes", "es": "Procesos principales", "ar": "أبرز العمليات" },
    "Unmanaged hosts on the LAN": { "zh": "局域网中的未托管主机", "hi": "LAN पर अप्रबंधित hosts", "es": "Hosts no gestionados en la LAN", "ar": "مضيفون غير مُدارين على الشبكة المحلية" },
    "Users &amp; Roles": { "zh": "用户 &amp; 角色", "hi": "उपयोगकर्ता &amp; भूमिकाएँ", "es": "Usuarios y roles", "ar": "المستخدمون &amp; الأدوار" },
    "Virtualization": { "zh": "虚拟化", "hi": "वर्चुअलाइज़ेशन", "es": "Virtualización", "ar": "المحاكاة الافتراضية" },
    "systemd units watched per device. Click a row to see history, logs, and configuration.": { "zh": "按设备监视的 systemd 单元。点击行可查看历史、日志和配置。", "hi": "प्रति device निगरानी की गई systemd units। इतिहास, लॉग्स, और कॉन्फ़िगरेशन देखने के लिए किसी row पर क्लिक करें।", "es": "Unidades de systemd vigiladas por dispositivo. Haz clic en una fila para ver el historial, los registros y la configuración.", "ar": "وحدات systemd المُراقَبة لكل جهاز. انقر صفًّا لعرض السجل والسجلات والتهيئة." },
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
    '.page-subtitle',
    '.section-title',
    '.empty-title',
    '.empty-text'
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
