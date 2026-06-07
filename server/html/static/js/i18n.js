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
    // ── v4.2: dynamic status / empty-state / toast strings ──
    "ACME rescan queued": { "zh": "ACME 重新扫描已排队", "hi": "ACME पुनः-scan कतारबद्ध", "es": "Reescaneo de ACME en cola", "ar": "تم إدراج إعادة فحص ACME في الطابور" },
    "AI: diagnose these failed units": { "zh": "AI：诊断这些失败的单元", "hi": "AI: इन failed units का निदान करें", "es": "IA: diagnosticar estas unidades fallidas", "ar": "الذكاء الاصطناعي: شخّص هذه الوحدات الفاشلة" },
    "Action row removed": { "zh": "操作行已移除", "hi": "Action row हटाई गई", "es": "Fila de acción eliminada", "ar": "تمت إزالة صف الإجراء" },
    "Add mute failed": { "zh": "添加静音失败", "hi": "म्यूट जोड़ना विफल", "es": "Error al añadir el silencio", "ar": "فشلت إضافة الكتم" },
    "After-hours watch off": { "zh": "非工作时间监视已关闭", "hi": "After-hours watch बंद", "es": "Vigilancia fuera de horario desactivada", "ar": "مراقبة ما بعد الدوام معطّلة" },
    "AirOS version": { "zh": "AirOS 版本", "hi": "AirOS संस्करण", "es": "Versión de AirOS", "ar": "إصدار AirOS" },
    "Alert webhook token created": { "zh": "告警 Webhook 令牌已创建", "hi": "Alert webhook token बनाया गया", "es": "Token de webhook de alertas creado", "ar": "تم إنشاء رمز Webhook التنبيه" },
    "All drifted baselines updated": { "zh": "所有偏移的基线已更新", "hi": "सभी drifted baselines अपडेट किए गए", "es": "Todas las líneas base con deriva actualizadas", "ar": "تم تحديث كل الأسس المنحرفة" },
    "All fields are required.": { "zh": "所有字段均为必填。", "hi": "सभी फ़ील्ड आवश्यक हैं।", "es": "Todos los campos son obligatorios.", "ar": "كل الحقول مطلوبة." },
    "Approved — action queued": { "zh": "已批准——操作已排队", "hi": "स्वीकृत — action कतारबद्ध", "es": "Aprobado: acción en cola", "ar": "تمت الموافقة — أُدرج الإجراء في الطابور" },
    "Assign failed:": { "zh": "分配失败：", "hi": "असाइन विफल:", "es": "Error al asignar:", "ar": "فشل التعيين:" },
    "Audit log cleared": { "zh": "审计日志已清除", "hi": "Audit लॉग साफ़ किया गया", "es": "Registro de auditoría borrado", "ar": "تم مسح سجل التدقيق" },
    "Backup failed:": { "zh": "备份失败：", "hi": "Backup विफल:", "es": "Error en la copia de seguridad:", "ar": "فشل النسخ الاحتياطي:" },
    "Backup monitor added": { "zh": "备份监控已添加", "hi": "Backup monitor जोड़ा गया", "es": "Monitor de copia de seguridad añadido", "ar": "تمت إضافة مراقب النسخ الاحتياطي" },
    "Backup monitor updated": { "zh": "备份监控已更新", "hi": "Backup monitor अपडेट किया गया", "es": "Monitor de copia de seguridad actualizado", "ar": "تم تحديث مراقب النسخ الاحتياطي" },
    "Backup queued — output appears in the device command history": { "zh": "备份已排队——输出将出现在设备命令历史中", "hi": "Backup कतारबद्ध — output device command इतिहास में दिखाई देता है", "es": "Copia de seguridad en cola: la salida aparece en el historial de comandos del dispositivo", "ar": "أُدرج النسخ الاحتياطي في الطابور — يظهر الناتج في تاريخ أوامر الجهاز" },
    "Baseline updated": { "zh": "基线已更新", "hi": "Baseline अपडेट किया गया", "es": "Línea base actualizada", "ar": "تم تحديث الأساس" },
    "Body required": { "zh": "正文为必填", "hi": "Body आवश्यक", "es": "Cuerpo obligatorio", "ar": "النص مطلوب" },
    "Both fields required": { "zh": "两个字段均为必填", "hi": "दोनों फ़ील्ड आवश्यक", "es": "Ambos campos son obligatorios", "ar": "الحقلان مطلوبان" },
    "Branding saved": { "zh": "品牌设置已保存", "hi": "Branding सहेजा गया", "es": "Marca guardada", "ar": "تم حفظ العلامة التجارية" },
    "Brute-force settings saved": { "zh": "暴力破解设置已保存", "hi": "Brute-force settings सहेजी गईं", "es": "Configuración de fuerza bruta guardada", "ar": "تم حفظ إعدادات القوة الغاشمة" },
    "Bulk action failed": { "zh": "批量操作失败", "hi": "Bulk action विफल", "es": "Error en la acción masiva", "ar": "فشل الإجراء المجمّع" },
    "CVE scan failed (see server log).": { "zh": "CVE 扫描失败（请查看服务器日志）。", "hi": "CVE scan विफल (server लॉग देखें)।", "es": "Error en el escaneo de CVE (consulta el log del servidor).", "ar": "فشل فحص CVE (راجع سجل الخادم)." },
    "Cancel request failed": { "zh": "取消请求失败", "hi": "रद्द करने का अनुरोध विफल", "es": "Error en la solicitud de cancelación", "ar": "فشل طلب الإلغاء" },
    "Cancel this queued command": { "zh": "取消此排队中的命令", "hi": "इस कतारबद्ध command को रद्द करें", "es": "Cancelar este comando en cola", "ar": "ألغِ هذا الأمر المُدرَج في الطابور" },
    "Cancel this queued command? It will not be delivered to the agent.": { "zh": "取消此排队中的命令？它将不会下发给 agent。", "hi": "इस कतारबद्ध command को रद्द करें? इसे agent को नहीं पहुँचाया जाएगा।", "es": "¿Cancelar este comando en cola? No se entregará al agente.", "ar": "إلغاء هذا الأمر المُدرَج في الطابور؟ لن يُسلَّم إلى الوكيل." },
    "Clear failed:": { "zh": "清除失败：", "hi": "साफ़ करना विफल:", "es": "Error al borrar:", "ar": "فشل المسح:" },
    "Cloud account added": { "zh": "云账户已添加", "hi": "Cloud खाता जोड़ा गया", "es": "Cuenta en la nube añadida", "ar": "تمت إضافة حساب سحابي" },
    "Command history cleared": { "zh": "命令历史已清除", "hi": "Command इतिहास साफ़ किया गया", "es": "Historial de comandos borrado", "ar": "تم مسح تاريخ الأوامر" },
    "Command queued — output on next heartbeat (~60s)": { "zh": "命令已排队——输出将在下次心跳时返回（约 60 秒）", "hi": "Command कतारबद्ध — output अगले heartbeat पर (~60s)", "es": "Comando en cola: salida en el próximo heartbeat (~60 s)", "ar": "أُدرج الأمر في الطابور — يظهر الناتج عند النبضة التالية (~60ث)" },
    "Container stopped / restarting": { "zh": "容器已停止 / 重启中", "hi": "Container रुका / restart हो रहा", "es": "Contenedor detenido / reiniciándose", "ar": "الحاوية متوقفة / تُعاد تشغيلها" },
    "Copy failed": { "zh": "复制失败", "hi": "Copy विफल", "es": "Error al copiar", "ar": "فشل النسخ" },
    "Copy failed — select and copy manually": { "zh": "复制失败——请手动选择并复制", "hi": "Copy विफल — मैन्युअल रूप से चुनें और copy करें", "es": "Error al copiar: selecciona y copia manualmente", "ar": "فشل النسخ — حدّد وانسخ يدوياً" },
    "Copy failed:": { "zh": "复制失败：", "hi": "Copy विफल:", "es": "Error al copiar:", "ar": "فشل النسخ:" },
    "Create failed": { "zh": "创建失败", "hi": "बनाना विफल", "es": "Error al crear", "ar": "فشل الإنشاء" },
    "Create failed:": { "zh": "创建失败：", "hi": "बनाना विफल:", "es": "Error al crear:", "ar": "فشل الإنشاء:" },
    "Cron expression copied": { "zh": "Cron 表达式已复制", "hi": "Cron expression कॉपी किया गया", "es": "Expresión cron copiada", "ar": "تم نسخ تعبير cron" },
    "Cron jobs (incl. RemotePower scheduled)": { "zh": "Cron 任务（含 RemotePower 计划任务）", "hi": "Cron jobs (RemotePower निर्धारित सहित)", "es": "Trabajos cron (incl. los programados por RemotePower)", "ar": "مهام cron (بما فيها المجدولة من RemotePower)" },
    "Debug logging disabled": { "zh": "调试日志已禁用", "hi": "Debug logging अक्षम", "es": "Registro de depuración desactivado", "ar": "تم تعطيل تسجيل التصحيح" },
    "Debug logging disabled via Settings": { "zh": "已通过设置禁用调试日志", "hi": "Settings के माध्यम से Debug logging अक्षम", "es": "Registro de depuración desactivado desde Configuración", "ar": "تم تعطيل تسجيل التصحيح عبر الإعدادات" },
    "Debug logging enabled via Settings": { "zh": "已通过设置启用调试日志", "hi": "Settings के माध्यम से Debug logging सक्षम", "es": "Registro de depuración activado desde Configuración", "ar": "تم تفعيل تسجيل التصحيح عبر الإعدادات" },
    "Debug logging enabled — logs at /var/lib/remotepower/debug.log": { "zh": "调试日志已启用——日志位于 /var/lib/remotepower/debug.log", "hi": "Debug logging सक्षम — logs /var/lib/remotepower/debug.log पर", "es": "Registro de depuración activado: logs en /var/lib/remotepower/debug.log", "ar": "تم تفعيل تسجيل التصحيح — السجلات في /var/lib/remotepower/debug.log" },
    "Delete failed": { "zh": "删除失败", "hi": "हटाना विफल", "es": "Error al eliminar", "ar": "فشل الحذف" },
    "Delete failed:": { "zh": "删除失败：", "hi": "हटाना विफल:", "es": "Error al eliminar:", "ar": "فشل الحذف:" },
    "Delete saved query": { "zh": "删除已保存的查询", "hi": "सहेजी गई query हटाएँ", "es": "Eliminar consulta guardada", "ar": "احذف الاستعلام المحفوظ" },
    "Device has not reported yet": { "zh": "设备尚未上报", "hi": "Device ने अभी तक रिपोर्ट नहीं की", "es": "El dispositivo aún no ha reportado", "ar": "لم يبلّغ الجهاز بعد" },
    "Device is required": { "zh": "设备为必填", "hi": "Device आवश्यक है", "es": "El dispositivo es obligatorio", "ar": "الجهاز مطلوب" },
    "Device quarantined — actions disabled.": { "zh": "设备已隔离——操作已禁用。", "hi": "Device quarantined — actions अक्षम।", "es": "Dispositivo en cuarentena: acciones desactivadas.", "ar": "الجهاز في الحجر — الإجراءات معطّلة." },
    "Device removed": { "zh": "设备已移除", "hi": "Device हटाया गया", "es": "Dispositivo eliminado", "ar": "تمت إزالة الجهاز" },
    "Digest failed:": { "zh": "摘要失败：", "hi": "Digest विफल:", "es": "Error en el resumen:", "ar": "فشل الملخص:" },
    "Download failed:": { "zh": "下载失败：", "hi": "Download विफल:", "es": "Error al descargar:", "ar": "فشل التنزيل:" },
    "Dry run failed": { "zh": "试运行失败", "hi": "Dry run विफल", "es": "Error en la ejecución de prueba", "ar": "فشل التشغيل التجريبي" },
    "Edit scheduled job": { "zh": "编辑计划任务", "hi": "निर्धारित job संपादित करें", "es": "Editar trabajo programado", "ar": "حرّر المهمة المجدولة" },
    "Enabled — not pushed yet.": { "zh": "已启用——尚未推送。", "hi": "सक्षम — अभी तक push नहीं किया गया।", "es": "Activado: aún no desplegado.", "ar": "مُفعَّل — لم يُدفَع بعد." },
    "Enabled — not synced yet.": { "zh": "已启用——尚未同步。", "hi": "सक्षम — अभी तक sync नहीं किया गया।", "es": "Activado: aún no sincronizado.", "ar": "مُفعَّل — لم يُزامَن بعد." },
    "Enforcement off": { "zh": "强制执行已关闭", "hi": "Enforcement बंद", "es": "Aplicación desactivada", "ar": "الإنفاذ معطّل" },
    "Enforcement policy added": { "zh": "强制执行策略已添加", "hi": "Enforcement policy जोड़ी गई", "es": "Política de aplicación añadida", "ar": "تمت إضافة سياسة الإنفاذ" },
    "Evidence pack failed (admin only)": { "zh": "证据包失败（仅限管理员）", "hi": "Evidence pack विफल (केवल admin)", "es": "Error en el paquete de evidencias (solo administradores)", "ar": "فشلت حزمة الأدلة (للمسؤول فقط)" },
    "Export failed": { "zh": "导出失败", "hi": "Export विफल", "es": "Error al exportar", "ar": "فشل التصدير" },
    "Failed to revoke session": { "zh": "吊销会话失败", "hi": "Session revoke करना विफल", "es": "Error al revocar la sesión", "ar": "فشل إبطال الجلسة" },
    "Failed to start collection": { "zh": "启动采集失败", "hi": "Collection शुरू करना विफल", "es": "Error al iniciar la recopilación", "ar": "فشل بدء الجمع" },
    "Feed refresh failed": { "zh": "信息流刷新失败", "hi": "Feed refresh विफल", "es": "Error al actualizar el feed", "ar": "فشل تحديث الموجز" },
    "Fetching patch history…": { "zh": "正在获取补丁历史…", "hi": "Patch इतिहास प्राप्त किया जा रहा है…", "es": "Obteniendo historial de parches…", "ar": "جارٍ جلب تاريخ الترقيع…" },
    "File path is required": { "zh": "文件路径为必填", "hi": "File path आवश्यक है", "es": "La ruta del archivo es obligatoria", "ar": "مسار الملف مطلوب" },
    "Fleet-wide rule added": { "zh": "全设备群规则已添加", "hi": "Fleet-wide नियम जोड़ा गया", "es": "Regla para toda la flota añadida", "ar": "تمت إضافة قاعدة على مستوى الأسطول" },
    "Fleet-wide rule removed": { "zh": "全设备群规则已移除", "hi": "Fleet-wide नियम हटाया गया", "es": "Regla para toda la flota eliminada", "ar": "تمت إزالة قاعدة على مستوى الأسطول" },
    "Fleet-wide rule updated": { "zh": "全设备群规则已更新", "hi": "Fleet-wide नियम अपडेट किया गया", "es": "Regla para toda la flota actualizada", "ar": "تم تحديث قاعدة على مستوى الأسطول" },
    "Force-rescan request failed": { "zh": "强制重新扫描请求失败", "hi": "Force-rescan अनुरोध विफल", "es": "Error en la solicitud de reescaneo forzado", "ar": "فشل طلب إعادة الفحص القسري" },
    "Force-upgrade scheduled": { "zh": "强制升级已计划", "hi": "Force-upgrade निर्धारित", "es": "Actualización forzada programada", "ar": "تمت جدولة الترقية القسرية" },
    "Forward test failed": { "zh": "转发测试失败", "hi": "Forward test विफल", "es": "Error en la prueba de reenvío", "ar": "فشل اختبار التمرير" },
    "Generation failed": { "zh": "生成失败", "hi": "उत्पादन विफल", "es": "Error en la generación", "ar": "فشل التوليد" },
    "GitOps disabled": { "zh": "GitOps 已禁用", "hi": "GitOps अक्षम", "es": "GitOps desactivado", "ar": "تم تعطيل GitOps" },
    "Group saved": { "zh": "分组已保存", "hi": "Group सहेजा गया", "es": "Grupo guardado", "ar": "تم حفظ المجموعة" },
    "Health alerts disabled": { "zh": "健康告警已禁用", "hi": "Health alerts अक्षम", "es": "Alertas de salud desactivadas", "ar": "تم تعطيل تنبيهات الصحة" },
    "Healthchecks watchdog disabled": { "zh": "Healthchecks 看门狗已禁用", "hi": "Healthchecks watchdog अक्षम", "es": "Watchdog de Healthchecks desactivado", "ar": "تم تعطيل مراقب Healthchecks" },
    "Hidden from Needs Attention": { "zh": "已从「需要关注」中隐藏", "hi": "Needs Attention से छिपाया गया", "es": "Oculto de Necesita atención", "ar": "مخفي من \"يحتاج انتباهاً\"" },
    "History cleared": { "zh": "历史已清除", "hi": "इतिहास साफ़ किया गया", "es": "Historial borrado", "ar": "تم مسح التاريخ" },
    "IP allowlist saved (not enforced — toggle is off)": { "zh": "IP 白名单已保存（未强制执行——开关已关闭）", "hi": "IP allowlist सहेजी गई (लागू नहीं — toggle बंद है)", "es": "Lista de IP permitidas guardada (no aplicada: el interruptor está desactivado)", "ar": "تم حفظ قائمة IP المسموح بها (غير مُنفَّذة — المفتاح معطّل)" },
    "Icon cleared": { "zh": "图标已清除", "hi": "Icon साफ़ किया गया", "es": "Icono borrado", "ar": "تم مسح الأيقونة" },
    "Ignore failed:": { "zh": "忽略失败：", "hi": "Ignore विफल:", "es": "Error al ignorar:", "ar": "فشل التجاهل:" },
    "Ignore request failed": { "zh": "忽略请求失败", "hi": "Ignore अनुरोध विफल", "es": "Error en la solicitud de ignorar", "ar": "فشل طلب التجاهل" },
    "Inbound webhook updated": { "zh": "入站 Webhook 已更新", "hi": "Inbound webhook अपडेट किया गया", "es": "Webhook entrante actualizado", "ar": "تم تحديث Webhook الوارد" },
    "Investigate with diagnostic + AI suggestion": { "zh": "用诊断 + AI 建议进行排查", "hi": "diagnostic + AI सुझाव के साथ जाँच करें", "es": "Investigar con diagnóstico + sugerencia de IA", "ar": "حقّق بالتشخيص + اقتراح الذكاء الاصطناعي" },
    "Job cancelled": { "zh": "任务已取消", "hi": "Job रद्द किया गया", "es": "Trabajo cancelado", "ar": "تم إلغاء المهمة" },
    "Job created": { "zh": "任务已创建", "hi": "Job बनाया गया", "es": "Trabajo creado", "ar": "تم إنشاء المهمة" },
    "Job deleted": { "zh": "任务已删除", "hi": "Job हटाया गया", "es": "Trabajo eliminado", "ar": "تم حذف المهمة" },
    "Job saved": { "zh": "任务已保存", "hi": "Job सहेजा गया", "es": "Trabajo guardado", "ar": "تم حفظ المهمة" },
    "Jobs cleared": { "zh": "任务已清除", "hi": "Jobs साफ़ किए गए", "es": "Trabajos borrados", "ar": "تم مسح المهام" },
    "Key deleted": { "zh": "密钥已删除", "hi": "Key हटाई गई", "es": "Clave eliminada", "ar": "تم حذف المفتاح" },
    "LAN scan queued — running on the device…": { "zh": "LAN 扫描已排队——正在设备上运行…", "hi": "LAN scan कतारबद्ध — device पर चल रहा है…", "es": "Escaneo de LAN en cola: ejecutándose en el dispositivo…", "ar": "أُدرج فحص LAN في الطابور — يجري التشغيل على الجهاز…" },
    "Label required": { "zh": "标签为必填", "hi": "Label आवश्यक", "es": "Etiqueta obligatoria", "ar": "التسمية مطلوبة" },
    "List failed:": { "zh": "列出失败：", "hi": "List विफल:", "es": "Error al listar:", "ar": "فشل السرد:" },
    "Loading options from Proxmox…": { "zh": "正在从 Proxmox 加载选项…", "hi": "Proxmox से options लोड हो रहे हैं…", "es": "Cargando opciones desde Proxmox…", "ar": "جارٍ تحميل الخيارات من Proxmox…" },
    "Loading terminal…": { "zh": "正在加载终端…", "hi": "Terminal लोड हो रहा है…", "es": "Cargando terminal…", "ar": "جارٍ تحميل الطرفية…" },
    "Loading viewer…": { "zh": "正在加载查看器…", "hi": "Viewer लोड हो रहा है…", "es": "Cargando visor…", "ar": "جارٍ تحميل العارض…" },
    "Mailbox monitor saved — the agent picks it up on its next heartbeat": { "zh": "邮箱监控已保存——agent 将在下次心跳时领取", "hi": "Mailbox monitor सहेजा गया — agent इसे अपने अगले heartbeat पर उठाता है", "es": "Monitor de buzón guardado: el agente lo recoge en su próximo heartbeat", "ar": "تم حفظ مراقب صندوق البريد — يلتقطه الوكيل عند نبضته التالية" },
    "Maintenance window created": { "zh": "维护窗口已创建", "hi": "Maintenance window बनाई गई", "es": "Ventana de mantenimiento creada", "ar": "تم إنشاء نافذة الصيانة" },
    "Maintenance window updated": { "zh": "维护窗口已更新", "hi": "Maintenance window अपडेट की गई", "es": "Ventana de mantenimiento actualizada", "ar": "تم تحديث نافذة الصيانة" },
    "Metric thresholds saved": { "zh": "指标阈值已保存", "hi": "Metric thresholds सहेजी गईं", "es": "Umbrales de métricas guardados", "ar": "تم حفظ عتبات المقاييس" },
    "Metrics push disabled": { "zh": "指标推送已禁用", "hi": "Metrics push अक्षम", "es": "Envío de métricas desactivado", "ar": "تم تعطيل دفع المقاييس" },
    "Migration failed — backend not switched": { "zh": "迁移失败——后端未切换", "hi": "Migration विफल — backend स्विच नहीं हुआ", "es": "Error en la migración: backend no cambiado", "ar": "فشلت الترحيل — لم تُبدَّل الخلفية" },
    "Monitor added": { "zh": "监控已添加", "hi": "Monitor जोड़ा गया", "es": "Monitor añadido", "ar": "تمت إضافة المراقب" },
    "Monitor alert state cleared": { "zh": "监控告警状态已清除", "hi": "Monitor alert स्थिति साफ़ की गई", "es": "Estado de alerta del monitor borrado", "ar": "تم مسح حالة تنبيه المراقب" },
    "Monitor updated": { "zh": "监控已更新", "hi": "Monitor अपडेट किया गया", "es": "Monitor actualizado", "ar": "تم تحديث المراقب" },
    "Monitoring disabled": { "zh": "监控已禁用", "hi": "Monitoring अक्षम", "es": "Supervisión desactivada", "ar": "تم تعطيل المراقبة" },
    "Monitoring enabled": { "zh": "监控已启用", "hi": "Monitoring सक्षम", "es": "Supervisión activada", "ar": "تم تفعيل المراقبة" },
    "Mute added": { "zh": "静音已添加", "hi": "म्यूट जोड़ा गया", "es": "Silencio añadido", "ar": "تمت إضافة الكتم" },
    "Mute failed": { "zh": "静音失败", "hi": "म्यूट विफल", "es": "Error al silenciar", "ar": "فشل الكتم" },
    "Mute removed": { "zh": "静音已移除", "hi": "म्यूट हटाया गया", "es": "Silencio eliminado", "ar": "تمت إزالة الكتم" },
    "Name and command required": { "zh": "名称和命令为必填", "hi": "Name और command आवश्यक", "es": "Nombre y comando obligatorios", "ar": "الاسم والأمر مطلوبان" },
    "Name and playbook content required": { "zh": "名称和 playbook 内容为必填", "hi": "Name और playbook सामग्री आवश्यक", "es": "Nombre y contenido del playbook obligatorios", "ar": "الاسم ومحتوى كتاب التشغيل مطلوبان" },
    "Name did not match — rollback cancelled": { "zh": "名称不匹配——回滚已取消", "hi": "Name मेल नहीं खाया — rollback रद्द किया गया", "es": "El nombre no coincide: reversión cancelada", "ar": "الاسم غير مطابق — أُلغي التراجع" },
    "Name is required": { "zh": "名称为必填", "hi": "Name आवश्यक है", "es": "El nombre es obligatorio", "ar": "الاسم مطلوب" },
    "Name required": { "zh": "名称为必填", "hi": "Name आवश्यक", "es": "Nombre obligatorio", "ar": "الاسم مطلوب" },
    "Name this view (current filters will be saved):": { "zh": "为此视图命名（当前筛选条件将被保存）：", "hi": "इस view को नाम दें (मौजूदा filters सहेजे जाएँगे):", "es": "Nombra esta vista (se guardarán los filtros actuales):", "ar": "سمِّ هذا العرض (ستُحفظ عوامل التصفية الحالية):" },
    "Needs Attention": { "zh": "需要关注", "hi": "ध्यान चाहिए", "es": "Necesita atención", "ar": "يحتاج انتباهاً" },
    "Needs attention": { "zh": "需要关注", "hi": "ध्यान चाहिए", "es": "Necesita atención", "ar": "يحتاج انتباهاً" },
    "Network configuration": { "zh": "网络配置", "hi": "Network कॉन्फ़िगरेशन", "es": "Configuración de red", "ar": "تكوين الشبكة" },
    "Never sent yet.": { "zh": "尚未发送过。", "hi": "अभी तक कभी नहीं भेजा गया।", "es": "Aún no se ha enviado nunca.", "ar": "لم يُرسَل أبداً بعد." },
    "New password required": { "zh": "新密码为必填", "hi": "नया password आवश्यक", "es": "Nueva contraseña obligatoria", "ar": "كلمة مرور جديدة مطلوبة" },
    "No API keys. Create one for scripting access.": { "zh": "无 API 密钥。创建一个以用于脚本访问。", "hi": "कोई API keys नहीं। scripting पहुँच के लिए एक बनाएँ।", "es": "No hay claves de API. Crea una para acceso por script.", "ar": "لا توجد مفاتيح API. أنشئ واحداً للوصول البرمجي." },
    "No CVE findings found.": { "zh": "未找到 CVE 发现。", "hi": "कोई CVE findings नहीं मिले।", "es": "No se encontraron hallazgos de CVE.", "ar": "لم يُعثر على نتائج CVE." },
    "No CVE findings to prioritise": { "zh": "无需要优先处理的 CVE 发现", "hi": "प्राथमिकता देने के लिए कोई CVE findings नहीं", "es": "No hay hallazgos de CVE que priorizar", "ar": "لا توجد نتائج CVE لتحديد أولوياتها" },
    "No CVE rows match the filter.": { "zh": "没有 CVE 行匹配该筛选条件。", "hi": "कोई CVE row filter से मेल नहीं खाता।", "es": "Ninguna fila de CVE coincide con el filtro.", "ar": "لا توجد صفوف CVE تطابق عامل التصفية." },
    "No SNMP devices match the filter.": { "zh": "没有 SNMP 设备匹配该筛选条件。", "hi": "कोई SNMP device filter से मेल नहीं खाता।", "es": "Ningún dispositivo SNMP coincide con el filtro.", "ar": "لا توجد أجهزة SNMP تطابق عامل التصفية." },
    "No active CVE findings to prioritise": { "zh": "无需要优先处理的活跃 CVE 发现", "hi": "प्राथमिकता देने के लिए कोई सक्रिय CVE findings नहीं", "es": "No hay hallazgos de CVE activos que priorizar", "ar": "لا توجد نتائج CVE نشطة لتحديد أولوياتها" },
    "No active CVEs": { "zh": "无活跃 CVE", "hi": "कोई सक्रिय CVEs नहीं", "es": "No hay CVE activos", "ar": "لا توجد ثغرات CVE نشطة" },
    "No active sessions.": { "zh": "无活跃会话。", "hi": "कोई सक्रिय sessions नहीं।", "es": "No hay sesiones activas.", "ar": "لا توجد جلسات نشطة." },
    "No audit entries yet.": { "zh": "暂无审计记录。", "hi": "अभी तक कोई audit entries नहीं।", "es": "Aún no hay entradas de auditoría.", "ar": "لا توجد إدخالات تدقيق بعد." },
    "No auto-patch policies. Create one to schedule fleet updates.": { "zh": "无自动补丁策略。创建一个以计划设备群更新。", "hi": "कोई auto-patch policies नहीं। fleet updates schedule करने के लिए एक बनाएँ।", "es": "No hay políticas de parcheo automático. Crea una para programar actualizaciones de la flota.", "ar": "لا توجد سياسات ترقيع تلقائي. أنشئ واحدة لجدولة تحديثات الأسطول." },
    "No backup jobs. Create one to run or schedule a backup command.": { "zh": "无备份任务。创建一个以运行或计划备份命令。", "hi": "कोई backup jobs नहीं। backup command चलाने या schedule करने के लिए एक बनाएँ।", "es": "No hay trabajos de copia de seguridad. Crea uno para ejecutar o programar un comando de copia.", "ar": "لا توجد مهام نسخ احتياطي. أنشئ واحدة لتشغيل أو جدولة أمر نسخ احتياطي." },
    "No commands logged yet.": { "zh": "暂无已记录的命令。", "hi": "अभी तक कोई commands लॉग नहीं किए गए।", "es": "Aún no hay comandos registrados.", "ar": "لم تُسجَّل أوامر بعد." },
    "No commands match the filter.": { "zh": "没有命令匹配该筛选条件。", "hi": "कोई command filter से मेल नहीं खाता।", "es": "Ningún comando coincide con el filtro.", "ar": "لا توجد أوامر تطابق عامل التصفية." },
    "No data": { "zh": "无数据", "hi": "कोई डेटा नहीं", "es": "Sin datos", "ar": "لا توجد بيانات" },
    "No data available for this device yet — has the agent checked in?": { "zh": "此设备暂无可用数据——agent 是否已签入？", "hi": "इस device के लिए अभी तक कोई डेटा उपलब्ध नहीं — क्या agent ने check in किया है?", "es": "Aún no hay datos disponibles para este dispositivo: ¿ha contactado el agente?", "ar": "لا توجد بيانات متاحة لهذا الجهاز بعد — هل سجّل الوكيل دخوله؟" },
    "No data provided": { "zh": "未提供数据", "hi": "कोई डेटा प्रदान नहीं किया गया", "es": "No se proporcionaron datos", "ar": "لم تُقدَّم بيانات" },
    "No data.": { "zh": "无数据。", "hi": "कोई डेटा नहीं।", "es": "Sin datos.", "ar": "لا توجد بيانات." },
    "No devices enrolled.": { "zh": "未纳管任何设备。", "hi": "कोई devices नामांकित नहीं।", "es": "No hay dispositivos inscritos.", "ar": "لا توجد أجهزة مسجّلة." },
    "No devices loaded — visit Devices first": { "zh": "未加载任何设备——请先访问 Devices", "hi": "कोई devices लोड नहीं हुए — पहले Devices पर जाएँ", "es": "No se cargaron dispositivos: visita primero Dispositivos", "ar": "لم تُحمَّل أجهزة — زُر الأجهزة أولاً" },
    "No devices match the current filter.": { "zh": "没有设备匹配当前筛选条件。", "hi": "कोई device मौजूदा filter से मेल नहीं खाता।", "es": "Ningún dispositivo coincide con el filtro actual.", "ar": "لا توجد أجهزة تطابق عامل التصفية الحالي." },
    "No devices match the filter.": { "zh": "没有设备匹配该筛选条件。", "hi": "कोई device filter से मेल नहीं खाता।", "es": "Ningún dispositivo coincide con el filtro.", "ar": "لا توجد أجهزة تطابق عامل التصفية." },
    "No devices to show metrics for.": { "zh": "没有可显示指标的设备。", "hi": "metrics दिखाने के लिए कोई devices नहीं।", "es": "No hay dispositivos para mostrar métricas.", "ar": "لا توجد أجهزة لعرض مقاييس لها." },
    "No devices.": { "zh": "无设备。", "hi": "कोई devices नहीं।", "es": "No hay dispositivos.", "ar": "لا توجد أجهزة." },
    "No entries match the current filter.": { "zh": "没有记录匹配当前筛选条件。", "hi": "कोई entry मौजूदा filter से मेल नहीं खाती।", "es": "Ninguna entrada coincide con el filtro actual.", "ar": "لا توجد إدخالات تطابق عامل التصفية الحالي." },
    "No findings match the filter.": { "zh": "没有发现匹配该筛选条件。", "hi": "कोई findings filter से मेल नहीं खाते।", "es": "Ningún hallazgo coincide con el filtro.", "ar": "لا توجد نتائج تطابق عامل التصفية." },
    "No jobs match the filter.": { "zh": "没有任务匹配该筛选条件。", "hi": "कोई job filter से मेल नहीं खाता।", "es": "Ningún trabajo coincide con el filtro.", "ar": "لا توجد مهام تطابق عامل التصفية." },
    "No journal lines": { "zh": "无日志行", "hi": "कोई journal lines नहीं", "es": "No hay líneas de journal", "ar": "لا توجد أسطر سجل" },
    "No key set yet.": { "zh": "尚未设置密钥。", "hi": "अभी तक कोई key सेट नहीं।", "es": "Aún no se ha establecido ninguna clave.", "ar": "لم يُعيَّن مفتاح بعد." },
    "No keys match the filter.": { "zh": "没有密钥匹配该筛选条件。", "hi": "कोई keys filter से मेल नहीं खातीं।", "es": "Ninguna clave coincide con el filtro.", "ar": "لا توجد مفاتيح تطابق عامل التصفية." },
    "No listening port data yet — agent reports ports with sysinfo (every ~10 min).": { "zh": "暂无监听端口数据——agent 随 sysinfo 上报端口（每约 10 分钟一次）。", "hi": "अभी तक कोई listening port डेटा नहीं — agent sysinfo के साथ ports रिपोर्ट करता है (हर ~10 मिनट)।", "es": "Aún no hay datos de puertos en escucha: el agente reporta los puertos con sysinfo (cada ~10 min).", "ar": "لا توجد بيانات منافذ استماع بعد — يبلّغ الوكيل عن المنافذ مع sysinfo (كل ~10 دقائق)." },
    "No logs returned yet — the host may be offline or slow to report. Try again shortly.": { "zh": "暂无日志返回——主机可能离线或上报缓慢。请稍后重试。", "hi": "अभी तक कोई logs नहीं लौटे — host offline हो सकता है या रिपोर्ट करने में धीमा। थोड़ी देर में फिर प्रयास करें।", "es": "Aún no se han devuelto logs: el host puede estar fuera de línea o tardar en reportar. Inténtalo de nuevo en breve.", "ar": "لم تُرجَع سجلات بعد — قد يكون المضيف غير متصل أو بطيء التبليغ. حاول مجدداً بعد قليل." },
    "No logs to explain": { "zh": "没有可解释的日志", "hi": "समझाने के लिए कोई logs नहीं", "es": "No hay logs que explicar", "ar": "لا توجد سجلات لشرحها" },
    "No maintenance windows defined.": { "zh": "未定义维护窗口。", "hi": "कोई maintenance windows परिभाषित नहीं।", "es": "No hay ventanas de mantenimiento definidas.", "ar": "لم تُعرَّف نوافذ صيانة." },
    "No matches": { "zh": "无匹配项", "hi": "कोई मेल नहीं", "es": "Sin coincidencias", "ar": "لا توجد تطابقات" },
    "No matching devices": { "zh": "无匹配设备", "hi": "कोई मेल खाते devices नहीं", "es": "No hay dispositivos coincidentes", "ar": "لا توجد أجهزة مطابقة" },
    "No monitors configured.": { "zh": "未配置任何监控。", "hi": "कोई monitors कॉन्फ़िगर नहीं किए गए।", "es": "No hay monitores configurados.", "ar": "لم تُكوَّن مراقبات." },
    "No monitors match the filter.": { "zh": "没有监控匹配该筛选条件。", "hi": "कोई monitor filter से मेल नहीं खाता।", "es": "Ningún monitor coincide con el filtro.", "ar": "لا توجد مراقبات تطابق عامل التصفية." },
    "No mutes — the audit alerts on every host.": { "zh": "无静音——审计对每台主机都会告警。", "hi": "कोई म्यूट नहीं — audit हर host पर alert करता है।", "es": "No hay silencios: la auditoría alerta en todos los hosts.", "ar": "لا توجد عمليات كتم — يُنبّه التدقيق على كل مضيف." },
    "No online monitored devices.": { "zh": "无在线的受监控设备。", "hi": "कोई online निगरानी किए गए devices नहीं।", "es": "No hay dispositivos supervisados en línea.", "ar": "لا توجد أجهزة مُراقَبة متصلة." },
    "No open alerts": { "zh": "无未决告警", "hi": "कोई खुले alerts नहीं", "es": "No hay alertas abiertas", "ar": "لا توجد تنبيهات مفتوحة" },
    "No pending MCP confirmations": { "zh": "无待处理的 MCP 确认", "hi": "कोई लंबित MCP पुष्टियाँ नहीं", "es": "No hay confirmaciones de MCP pendientes", "ar": "لا توجد تأكيدات MCP معلّقة" },
    "No pending packages to prioritise": { "zh": "无需要优先处理的待处理软件包", "hi": "प्राथमिकता देने के लिए कोई लंबित packages नहीं", "es": "No hay paquetes pendientes que priorizar", "ar": "لا توجد حزم معلّقة لتحديد أولوياتها" },
    "No playbooks match the filter.": { "zh": "没有 playbook 匹配该筛选条件。", "hi": "कोई playbook filter से मेल नहीं खाता।", "es": "Ningún playbook coincide con el filtro.", "ar": "لا توجد كتب تشغيل تطابق عامل التصفية." },
    "No playbooks yet. Create one to run against the fleet.": { "zh": "暂无 playbook。创建一个以对设备群运行。", "hi": "अभी तक कोई playbooks नहीं। fleet के विरुद्ध चलाने के लिए एक बनाएँ।", "es": "Aún no hay playbooks. Crea uno para ejecutarlo contra la flota.", "ar": "لا توجد كتب تشغيل بعد. أنشئ واحداً لتنفيذه مقابل الأسطول." },
    "No policies match the filter.": { "zh": "没有策略匹配该筛选条件。", "hi": "कोई policy filter से मेल नहीं खाती।", "es": "Ninguna política coincide con el filtro.", "ar": "لا توجد سياسات تطابق عامل التصفية." },
    "No projects found under /opt /home /docker /srv": { "zh": "在 /opt /home /docker /srv 下未找到任何项目", "hi": "/opt /home /docker /srv के अंतर्गत कोई projects नहीं मिले", "es": "No se encontraron proyectos en /opt /home /docker /srv", "ar": "لم يُعثر على مشاريع ضمن /opt /home /docker /srv" },
    "No runbook stored.": { "zh": "未存储任何 runbook。", "hi": "कोई runbook संग्रहीत नहीं।", "es": "No hay ningún runbook almacenado.", "ar": "لم يُخزَّن دليل تشغيل." },
    "No satellites yet.": { "zh": "暂无卫星节点。", "hi": "अभी तक कोई satellites नहीं।", "es": "Aún no hay satélites.", "ar": "لا توجد أقمار صناعية بعد." },
    "No scheduled jobs.": { "zh": "无计划任务。", "hi": "कोई निर्धारित jobs नहीं।", "es": "No hay trabajos programados.", "ar": "لا توجد مهام مجدولة." },
    "No secrets found in the scanned paths.": { "zh": "在扫描路径中未找到任何机密。", "hi": "scan किए गए paths में कोई secrets नहीं मिले।", "es": "No se encontraron secretos en las rutas escaneadas.", "ar": "لم يُعثر على أسرار في المسارات المفحوصة." },
    "No server signing key yet.": { "zh": "尚无服务器签名密钥。", "hi": "अभी तक कोई server signing key नहीं।", "es": "Aún no hay clave de firma del servidor.", "ar": "لا يوجد مفتاح توقيع للخادم بعد." },
    "No services match the filter.": { "zh": "没有服务匹配该筛选条件。", "hi": "कोई service filter से मेल नहीं खाती।", "es": "Ningún servicio coincide con el filtro.", "ar": "لا توجد خدمات تطابق عامل التصفية." },
    "No sites match the filter.": { "zh": "没有站点匹配该筛选条件。", "hi": "कोई site filter से मेल नहीं खाती।", "es": "Ningún sitio coincide con el filtro.", "ar": "لا توجد مواقع تطابق عامل التصفية." },
    "No sites yet. Create one to organise the fleet.": { "zh": "暂无站点。创建一个以组织设备群。", "hi": "अभी तक कोई sites नहीं। fleet को व्यवस्थित करने के लिए एक बनाएँ।", "es": "Aún no hay sitios. Crea uno para organizar la flota.", "ar": "لا توجد مواقع بعد. أنشئ واحداً لتنظيم الأسطول." },
    "No snippets match the filter.": { "zh": "没有片段匹配该筛选条件。", "hi": "कोई snippet filter से मेल नहीं खाता।", "es": "Ningún fragmento coincide con el filtro.", "ar": "لا توجد مقتطفات تطابق عامل التصفية." },
    "No snippets yet.": { "zh": "暂无片段。", "hi": "अभी तक कोई snippets नहीं।", "es": "Aún no hay fragmentos.", "ar": "لا توجد مقتطفات بعد." },
    "No targets": { "zh": "无目标", "hi": "कोई targets नहीं", "es": "No hay objetivos", "ar": "لا توجد أهداف" },
    "No upgrade listing in patch history, and no built-in listing": { "zh": "补丁历史中无升级列表，也无内置列表", "hi": "patch इतिहास में कोई upgrade सूची नहीं, और कोई अंतर्निहित सूची नहीं", "es": "No hay listado de actualizaciones en el historial de parches, ni listado integrado", "ar": "لا توجد قائمة ترقية في تاريخ الترقيع، ولا قائمة مدمجة" },
    "No users match the filter.": { "zh": "没有用户匹配该筛选条件。", "hi": "कोई user filter से मेल नहीं खाता।", "es": "Ningún usuario coincide con el filtro.", "ar": "لا يوجد مستخدمون يطابقون عامل التصفية." },
    "No users.": { "zh": "无用户。", "hi": "कोई users नहीं।", "es": "No hay usuarios.", "ar": "لا يوجد مستخدمون." },
    "No windows match the filter.": { "zh": "没有窗口匹配该筛选条件。", "hi": "कोई window filter से मेल नहीं खाती।", "es": "Ninguna ventana coincide con el filtro.", "ar": "لا توجد نوافذ تطابق عامل التصفية." },
    "Notes saved": { "zh": "备注已保存", "hi": "Notes सहेजे गए", "es": "Notas guardadas", "ar": "تم حفظ الملاحظات" },
    "Notifications enabled": { "zh": "通知已启用", "hi": "Notifications सक्षम", "es": "Notificaciones activadas", "ar": "تم تفعيل الإشعارات" },
    "Notifications turned off": { "zh": "通知已关闭", "hi": "Notifications बंद किए गए", "es": "Notificaciones desactivadas", "ar": "تم إيقاف الإشعارات" },
    "OIDC config saved": { "zh": "OIDC 配置已保存", "hi": "OIDC config सहेजा गया", "es": "Configuración de OIDC guardada", "ar": "تم حفظ تكوين OIDC" },
    "OTLP push failed": { "zh": "OTLP 推送失败", "hi": "OTLP push विफल", "es": "Error en el envío de OTLP", "ar": "فشل دفع OTLP" },
    "On-call & escalation saved": { "zh": "值班与升级已保存", "hi": "On-call & escalation सहेजा गया", "es": "Guardia y escalado guardados", "ar": "تم حفظ المناوبة والتصعيد" },
    "Package name is required": { "zh": "软件包名称为必填", "hi": "Package नाम आवश्यक है", "es": "El nombre del paquete es obligatorio", "ar": "اسم الحزمة مطلوب" },
    "Package scan queued — fresh list within ~60s": { "zh": "软件包扫描已排队——约 60 秒内得到最新列表", "hi": "Package scan कतारबद्ध — ~60s के भीतर ताज़ा सूची", "es": "Escaneo de paquetes en cola: lista actualizada en ~60 s", "ar": "أُدرج فحص الحزم في الطابور — قائمة جديدة خلال ~60ث" },
    "Password updated": { "zh": "密码已更新", "hi": "Password अपडेट किया गया", "es": "Contraseña actualizada", "ar": "تم تحديث كلمة المرور" },
    "Path required": { "zh": "路径为必填", "hi": "Path आवश्यक", "es": "Ruta obligatoria", "ar": "المسار مطلوب" },
    "Pattern added": { "zh": "模式已添加", "hi": "Pattern जोड़ा गया", "es": "Patrón añadido", "ar": "تمت إضافة النمط" },
    "Pattern is required": { "zh": "模式为必填", "hi": "Pattern आवश्यक है", "es": "El patrón es obligatorio", "ar": "النمط مطلوب" },
    "Pattern updated": { "zh": "模式已更新", "hi": "Pattern अपडेट किया गया", "es": "Patrón actualizado", "ar": "تم تحديث النمط" },
    "Pick a saved script": { "zh": "选择一个已保存的脚本", "hi": "एक saved script चुनें", "es": "Elige un script guardado", "ar": "اختر نصاً محفوظاً" },
    "Pick at least one CVE severity to alert on": { "zh": "至少选择一个要告警的 CVE 严重级别", "hi": "alert करने के लिए कम से कम एक CVE गंभीरता चुनें", "es": "Elige al menos una gravedad de CVE sobre la que alertar", "ar": "اختر خطورة CVE واحدة على الأقل للتنبيه عليها" },
    "Pick at least one section": { "zh": "至少选择一个板块", "hi": "कम से कम एक section चुनें", "es": "Elige al menos una sección", "ar": "اختر قسماً واحداً على الأقل" },
    "Playbook created": { "zh": "Playbook 已创建", "hi": "Playbook बनाया गया", "es": "Playbook creado", "ar": "تم إنشاء كتاب التشغيل" },
    "Playbook deleted": { "zh": "Playbook 已删除", "hi": "Playbook हटाया गया", "es": "Playbook eliminado", "ar": "تم حذف كتاب التشغيل" },
    "Playbook saved": { "zh": "Playbook 已保存", "hi": "Playbook सहेजा गया", "es": "Playbook guardado", "ar": "تم حفظ كتاب التشغيل" },
    "Policy created": { "zh": "策略已创建", "hi": "Policy बनाई गई", "es": "Política creada", "ar": "تم إنشاء السياسة" },
    "Policy deleted": { "zh": "策略已删除", "hi": "Policy हटाई गई", "es": "Política eliminada", "ar": "تم حذف السياسة" },
    "Policy saved": { "zh": "策略已保存", "hi": "Policy सहेजी गई", "es": "Política guardada", "ar": "تم حفظ السياسة" },
    "Poll interval updated": { "zh": "轮询间隔已更新", "hi": "Poll अंतराल अपडेट किया गया", "es": "Intervalo de sondeo actualizado", "ar": "تم تحديث فترة الاستطلاع" },
    "Primary domain is required": { "zh": "主域名为必填", "hi": "Primary domain आवश्यक है", "es": "El dominio principal es obligatorio", "ar": "النطاق الأساسي مطلوب" },
    "Process name required": { "zh": "进程名称为必填", "hi": "Process नाम आवश्यक", "es": "Nombre de proceso obligatorio", "ar": "اسم العملية مطلوب" },
    "Process threshold added": { "zh": "进程阈值已添加", "hi": "Process threshold जोड़ा गया", "es": "Umbral de proceso añadido", "ar": "تمت إضافة عتبة العملية" },
    "Profile created": { "zh": "配置文件已创建", "hi": "Profile बनाई गई", "es": "Perfil creado", "ar": "تم إنشاء الملف الشخصي" },
    "Profile deleted": { "zh": "配置文件已删除", "hi": "Profile हटाई गई", "es": "Perfil eliminado", "ar": "تم حذف الملف الشخصي" },
    "Profile picture removed": { "zh": "头像已移除", "hi": "Profile चित्र हटाया गया", "es": "Foto de perfil eliminada", "ar": "تمت إزالة صورة الملف الشخصي" },
    "Profile picture updated": { "zh": "头像已更新", "hi": "Profile चित्र अपडेट किया गया", "es": "Foto de perfil actualizada", "ar": "تم تحديث صورة الملف الشخصي" },
    "Profile updated": { "zh": "配置文件已更新", "hi": "Profile अपडेट की गई", "es": "Perfil actualizado", "ar": "تم تحديث الملف الشخصي" },
    "Proxmox settings saved": { "zh": "Proxmox 设置已保存", "hi": "Proxmox settings सहेजी गईं", "es": "Configuración de Proxmox guardada", "ar": "تم حفظ إعدادات Proxmox" },
    "Queued command cancelled": { "zh": "排队中的命令已取消", "hi": "कतारबद्ध command रद्द किया गया", "es": "Comando en cola cancelado", "ar": "تم إلغاء الأمر المُدرَج في الطابور" },
    "Quiet hours off": { "zh": "免打扰时段已关闭", "hi": "Quiet hours बंद", "es": "Horas de silencio desactivadas", "ar": "ساعات الهدوء معطّلة" },
    "Re-run failed": { "zh": "重新运行失败", "hi": "पुनः-चलाना विफल", "es": "Error al volver a ejecutar", "ar": "فشلت إعادة التشغيل" },
    "Reboot queued": { "zh": "重启已排队", "hi": "Reboot कतारबद्ध", "es": "Reinicio en cola", "ar": "أُدرجت إعادة التشغيل في الطابور" },
    "Reboot required": { "zh": "需要重启", "hi": "Reboot आवश्यक", "es": "Se requiere reinicio", "ar": "إعادة التشغيل مطلوبة" },
    "Refresh paused": { "zh": "刷新已暂停", "hi": "Refresh रोका गया", "es": "Actualización en pausa", "ar": "التحديث متوقف مؤقتاً" },
    "Region and access key ID required": { "zh": "区域和访问密钥 ID 为必填", "hi": "Region और access key ID आवश्यक", "es": "Región e ID de clave de acceso obligatorios", "ar": "المنطقة ومعرّف مفتاح الوصول مطلوبان" },
    "Reject write action": { "zh": "拒绝写操作", "hi": "write action अस्वीकार करें", "es": "Rechazar acción de escritura", "ar": "ارفض إجراء الكتابة" },
    "Remove mute failed": { "zh": "移除静音失败", "hi": "म्यूट हटाना विफल", "es": "Error al eliminar el silencio", "ar": "فشلت إزالة الكتم" },
    "Report deleted": { "zh": "报告已删除", "hi": "Report हटाई गई", "es": "Informe eliminado", "ar": "تم حذف التقرير" },
    "Report schedule saved": { "zh": "报告计划已保存", "hi": "Report schedule सहेजा गया", "es": "Programación de informes guardada", "ar": "تم حفظ جدول التقرير" },
    "Request failed": { "zh": "请求失败", "hi": "अनुरोध विफल", "es": "Error en la solicitud", "ar": "فشل الطلب" },
    "Request failed.": { "zh": "请求失败。", "hi": "अनुरोध विफल।", "es": "Error en la solicitud.", "ar": "فشل الطلب." },
    "Reset failed": { "zh": "重置失败", "hi": "Reset विफल", "es": "Error al restablecer", "ar": "فشلت إعادة التعيين" },
    "Restore failed": { "zh": "恢复失败", "hi": "Restore विफल", "es": "Error al restaurar", "ar": "فشل الاستعادة" },
    "Restore failed:": { "zh": "恢复失败：", "hi": "Restore विफल:", "es": "Error al restaurar:", "ar": "فشل الاستعادة:" },
    "Retention settings saved": { "zh": "保留设置已保存", "hi": "Retention settings सहेजी गईं", "es": "Configuración de retención guardada", "ar": "تم حفظ إعدادات الاحتفاظ" },
    "Revoke + remove queued": { "zh": "吊销 + 移除已排队", "hi": "Revoke + हटाना कतारबद्ध", "es": "Revocación + eliminación en cola", "ar": "أُدرج الإبطال + الإزالة في الطابور" },
    "Revoke failed": { "zh": "吊销失败", "hi": "Revoke विफल", "es": "Error al revocar", "ar": "فشل الإبطال" },
    "Role created": { "zh": "角色已创建", "hi": "Role बनाई गई", "es": "Rol creado", "ar": "تم إنشاء الدور" },
    "Role deleted": { "zh": "角色已删除", "hi": "Role हटाई गई", "es": "Rol eliminado", "ar": "تم حذف الدور" },
    "Role updated": { "zh": "角色已更新", "hi": "Role अपडेट की गई", "es": "Rol actualizado", "ar": "تم تحديث الدور" },
    "Rollback started": { "zh": "回滚已开始", "hi": "Rollback शुरू हुआ", "es": "Reversión iniciada", "ar": "بدأ التراجع" },
    "Rollout created (draft) — press Start to begin": { "zh": "发布已创建（草稿）——按「开始」以启动", "hi": "Rollout बनाया गया (draft) — शुरू करने के लिए Start दबाएँ", "es": "Despliegue creado (borrador): pulsa Iniciar para comenzar", "ar": "تم إنشاء الطرح (مسودة) — اضغط ابدأ للشروع" },
    "Rollout deleted": { "zh": "发布已删除", "hi": "Rollout हटाया गया", "es": "Despliegue eliminado", "ar": "تم حذف الطرح" },
    "RouterOS version": { "zh": "RouterOS 版本", "hi": "RouterOS संस्करण", "es": "Versión de RouterOS", "ar": "إصدار RouterOS" },
    "Rule added": { "zh": "规则已添加", "hi": "नियम जोड़ा गया", "es": "Regla añadida", "ar": "تمت إضافة القاعدة" },
    "Rule deleted": { "zh": "规则已删除", "hi": "नियम हटाया गया", "es": "Regla eliminada", "ar": "تم حذف القاعدة" },
    "Rule removed": { "zh": "规则已移除", "hi": "नियम हटाया गया", "es": "Regla eliminada", "ar": "تمت إزالة القاعدة" },
    "Rule saved": { "zh": "规则已保存", "hi": "नियम सहेजा गया", "es": "Regla guardada", "ar": "تم حفظ القاعدة" },
    "Rule updated": { "zh": "规则已更新", "hi": "नियम अपडेट किया गया", "es": "Regla actualizada", "ar": "تم تحديث القاعدة" },
    "Runbook copied as Markdown": { "zh": "Runbook 已复制为 Markdown", "hi": "Runbook Markdown के रूप में कॉपी किया गया", "es": "Runbook copiado como Markdown", "ar": "تم نسخ دليل التشغيل بصيغة Markdown" },
    "Runbook deleted": { "zh": "Runbook 已删除", "hi": "Runbook हटाया गया", "es": "Runbook eliminado", "ar": "تم حذف دليل التشغيل" },
    "Running maintenance…": { "zh": "正在运行维护…", "hi": "Maintenance चल रहा है…", "es": "Ejecutando mantenimiento…", "ar": "جارٍ تشغيل الصيانة…" },
    "Running processes": { "zh": "运行中的进程", "hi": "चल रहे processes", "es": "Procesos en ejecución", "ar": "العمليات الجارية" },
    "SCIM disabled": { "zh": "SCIM 已禁用", "hi": "SCIM अक्षम", "es": "SCIM desactivado", "ar": "تم تعطيل SCIM" },
    "SCIM enabled": { "zh": "SCIM 已启用", "hi": "SCIM सक्षम", "es": "SCIM activado", "ar": "تم تفعيل SCIM" },
    "SIEM test failed": { "zh": "SIEM 测试失败", "hi": "SIEM test विफल", "es": "Error en la prueba de SIEM", "ar": "فشل اختبار SIEM" },
    "SLA targets saved": { "zh": "SLA 目标已保存", "hi": "SLA targets सहेजे गए", "es": "Objetivos de SLA guardados", "ar": "تم حفظ أهداف SLA" },
    "SNMP config saved": { "zh": "SNMP 配置已保存", "hi": "SNMP config सहेजा गया", "es": "Configuración de SNMP guardada", "ar": "تم حفظ تكوين SNMP" },
    "SNMP save failed": { "zh": "SNMP 保存失败", "hi": "SNMP सहेजना विफल", "es": "Error al guardar SNMP", "ar": "فشل حفظ SNMP" },
    "SSH failed:": { "zh": "SSH 失败：", "hi": "SSH विफल:", "es": "Error de SSH:", "ar": "فشل SSH:" },
    "SSH poll OK — metrics updated": { "zh": "SSH 轮询成功——指标已更新", "hi": "SSH poll OK — metrics अपडेट किए गए", "es": "Sondeo SSH correcto: métricas actualizadas", "ar": "استطلاع SSH ناجح — تم تحديث المقاييس" },
    "SSH poll failed": { "zh": "SSH 轮询失败", "hi": "SSH poll विफल", "es": "Error en el sondeo SSH", "ar": "فشل استطلاع SSH" },
    "SSH user required": { "zh": "SSH 用户为必填", "hi": "SSH user आवश्यक", "es": "Usuario SSH obligatorio", "ar": "مستخدم SSH مطلوب" },
    "SSH username saved": { "zh": "SSH 用户名已保存", "hi": "SSH username सहेजा गया", "es": "Nombre de usuario SSH guardado", "ar": "تم حفظ اسم مستخدم SSH" },
    "Satellite created": { "zh": "卫星节点已创建", "hi": "Satellite बनाया गया", "es": "Satélite creado", "ar": "تم إنشاء القمر الصناعي" },
    "Satellite revoked": { "zh": "卫星节点已吊销", "hi": "Satellite revoke किया गया", "es": "Satélite revocado", "ar": "تم إبطال القمر الصناعي" },
    "Save failed": { "zh": "保存失败", "hi": "सहेजना विफल", "es": "Error al guardar", "ar": "فشل الحفظ" },
    "Save failed:": { "zh": "保存失败：", "hi": "सहेजना विफल:", "es": "Error al guardar:", "ar": "فشل الحفظ:" },
    "Saving & pushing metrics…": { "zh": "正在保存并推送指标…", "hi": "metrics सहेजे और push किए जा रहे हैं…", "es": "Guardando y enviando métricas…", "ar": "جارٍ الحفظ ودفع المقاييس…" },
    "Saving & sending test event…": { "zh": "正在保存并发送测试事件…", "hi": "test event सहेजा और भेजा जा रहा है…", "es": "Guardando y enviando evento de prueba…", "ar": "جارٍ الحفظ وإرسال حدث اختباري…" },
    "Saving and firing test event…": { "zh": "正在保存并触发测试事件…", "hi": "test event सहेजा और fire किया जा रहा है…", "es": "Guardando y disparando evento de prueba…", "ar": "جارٍ الحفظ وإطلاق حدث اختباري…" },
    "Scan request failed:": { "zh": "扫描请求失败：", "hi": "Scan अनुरोध विफल:", "es": "Error en la solicitud de escaneo:", "ar": "فشل طلب الفحص:" },
    "Scanning all devices… this can take several minutes; results update as they finish": { "zh": "正在扫描所有设备…这可能需要几分钟；结果会随完成情况更新", "hi": "सभी devices scan किए जा रहे हैं… इसमें कई मिनट लग सकते हैं; पूरा होते ही परिणाम अपडेट होते हैं", "es": "Escaneando todos los dispositivos… esto puede tardar varios minutos; los resultados se actualizan a medida que terminan", "ar": "جارٍ فحص كل الأجهزة… قد يستغرق هذا عدة دقائق؛ تتحدّث النتائج عند انتهائها" },
    "Scanning device… may take a minute": { "zh": "正在扫描设备…可能需要一分钟", "hi": "Device scan किया जा रहा है… एक मिनट लग सकता है", "es": "Escaneando dispositivo… puede tardar un minuto", "ar": "جارٍ فحص الجهاز… قد يستغرق دقيقة" },
    "Scanning is off — enable it in Settings → Security.": { "zh": "扫描已关闭——请在 Settings → Security 中启用。", "hi": "Scanning बंद है — इसे Settings → Security में सक्षम करें।", "es": "El escaneo está desactivado: actívalo en Configuración → Seguridad.", "ar": "الفحص معطّل — فعّله في الإعدادات → الأمان." },
    "Script created": { "zh": "脚本已创建", "hi": "Script बनाया गया", "es": "Script creado", "ar": "تم إنشاء النص" },
    "Script deleted": { "zh": "脚本已删除", "hi": "Script हटाया गया", "es": "Script eliminado", "ar": "تم حذف النص" },
    "Script updated": { "zh": "脚本已更新", "hi": "Script अपडेट किया गया", "es": "Script actualizado", "ar": "تم تحديث النص" },
    "Secret copied": { "zh": "机密已复制", "hi": "Secret कॉपी किया गया", "es": "Secreto copiado", "ar": "تم نسخ السر" },
    "Secrets scanning is disabled.": { "zh": "机密扫描已禁用。", "hi": "Secrets scanning अक्षम है।", "es": "El escaneo de secretos está desactivado.", "ar": "فحص الأسرار معطّل." },
    "Select for batch action": { "zh": "选择以进行批量操作", "hi": "batch action के लिए चुनें", "es": "Seleccionar para acción en lote", "ar": "حدّد لإجراء مجمّع" },
    "Session revoked": { "zh": "会话已吊销", "hi": "Session revoke किया गया", "es": "Sesión revocada", "ar": "تم إبطال الجلسة" },
    "Settings saved": { "zh": "设置已保存", "hi": "Settings सहेजी गईं", "es": "Configuración guardada", "ar": "تم حفظ الإعدادات" },
    "Settings ▸ Getting started": { "zh": "设置 ▸ 快速开始", "hi": "Settings ▸ शुरुआत करें", "es": "Configuración ▸ Primeros pasos", "ar": "الإعدادات ▸ البدء" },
    "Shutdown queued": { "zh": "关机已排队", "hi": "Shutdown कतारबद्ध", "es": "Apagado en cola", "ar": "أُدرج إيقاف التشغيل في الطابور" },
    "Signature enforcement on": { "zh": "签名强制执行已开启", "hi": "Signature enforcement चालू", "es": "Aplicación de firma activada", "ar": "إنفاذ التوقيع مفعّل" },
    "Site created": { "zh": "站点已创建", "hi": "Site बनाई गई", "es": "Sitio creado", "ar": "تم إنشاء الموقع" },
    "Site updated": { "zh": "站点已更新", "hi": "Site अपडेट की गई", "es": "Sitio actualizado", "ar": "تم تحديث الموقع" },
    "Snapshot creation started": { "zh": "快照创建已开始", "hi": "Snapshot बनाना शुरू हुआ", "es": "Creación de snapshot iniciada", "ar": "بدأ إنشاء اللقطة" },
    "Snapshot deleted": { "zh": "快照已删除", "hi": "Snapshot हटाया गया", "es": "Snapshot eliminado", "ar": "تم حذف اللقطة" },
    "Snippet added": { "zh": "片段已添加", "hi": "Snippet जोड़ा गया", "es": "Fragmento añadido", "ar": "تمت إضافة المقتطف" },
    "Snippet updated": { "zh": "片段已更新", "hi": "Snippet अपडेट किया गया", "es": "Fragmento actualizado", "ar": "تم تحديث المقتطف" },
    "Speed test queued — running on the device…": { "zh": "网速测试已排队——正在设备上运行…", "hi": "Speed test कतारबद्ध — device पर चल रहा है…", "es": "Prueba de velocidad en cola: ejecutándose en el dispositivo…", "ar": "أُدرج اختبار السرعة في الطابور — يجري التشغيل على الجهاز…" },
    "Stale agent version": { "zh": "agent 版本过时", "hi": "पुराना agent संस्करण", "es": "Versión de agente obsoleta", "ar": "إصدار وكيل قديم" },
    "Start and end are required": { "zh": "开始和结束为必填", "hi": "Start और end आवश्यक हैं", "es": "El inicio y el fin son obligatorios", "ar": "البداية والنهاية مطلوبتان" },
    "Status endpoint disabled": { "zh": "状态端点已禁用", "hi": "Status endpoint अक्षम", "es": "Endpoint de estado desactivado", "ar": "تم تعطيل نقطة نهاية الحالة" },
    "Sync failed": { "zh": "同步失败", "hi": "Sync विफल", "es": "Error de sincronización", "ar": "فشلت المزامنة" },
    "Syslog ingestion token created": { "zh": "Syslog 接入令牌已创建", "hi": "Syslog ingestion token बनाया गया", "es": "Token de ingesta de syslog creado", "ar": "تم إنشاء رمز استيعاب syslog" },
    "Systemd services (enabled)": { "zh": "systemd 服务（已启用）", "hi": "Systemd services (सक्षम)", "es": "Servicios de systemd (habilitados)", "ar": "خدمات systemd (مُفعَّلة)" },
    "Target is required": { "zh": "目标为必填", "hi": "Target आवश्यक है", "es": "El objetivo es obligatorio", "ar": "الهدف مطلوب" },
    "Test email sent": { "zh": "测试邮件已发送", "hi": "Test ईमेल भेजा गया", "es": "Correo de prueba enviado", "ar": "تم إرسال بريد اختباري" },
    "Test entry sent to the configured destination": { "zh": "测试条目已发送至已配置的目的地", "hi": "कॉन्फ़िगर किए गए destination को test entry भेजी गई", "es": "Entrada de prueba enviada al destino configurado", "ar": "تم إرسال إدخال اختباري إلى الوجهة المُكوَّنة" },
    "Test event sent to the configured SIEM": { "zh": "测试事件已发送至已配置的 SIEM", "hi": "कॉन्फ़िगर किए गए SIEM को test event भेजा गया", "es": "Evento de prueba enviado al SIEM configurado", "ar": "تم إرسال حدث اختباري إلى SIEM المُكوَّن" },
    "Test ping failed:": { "zh": "测试 ping 失败：", "hi": "Test ping विफल:", "es": "Error en el ping de prueba:", "ar": "فشل اختبار ping:" },
    "Test ping sent — check your Healthchecks.io dashboard": { "zh": "测试 ping 已发送——请查看你的 Healthchecks.io 仪表板", "hi": "Test ping भेजा गया — अपना Healthchecks.io dashboard देखें", "es": "Ping de prueba enviado: revisa tu panel de Healthchecks.io", "ar": "تم إرسال اختبار ping — تحقق من لوحة Healthchecks.io" },
    "Test sent — check the log below": { "zh": "测试已发送——请查看下方日志", "hi": "Test भेजा गया — नीचे लॉग देखें", "es": "Prueba enviada: revisa el log de abajo", "ar": "تم إرسال الاختبار — تحقق من السجل أدناه" },
    "Test — fire a 'test' event to this destination": { "zh": "测试——向此目的地触发一个「test」事件", "hi": "Test — इस destination को एक 'test' event fire करें", "es": "Prueba: dispara un evento de 'prueba' a este destino", "ar": "اختبار — أطلِق حدث 'test' إلى هذه الوجهة" },
    "Testing...": { "zh": "测试中…", "hi": "Testing...", "es": "Probando...", "ar": "جارٍ الاختبار..." },
    "Ticket request failed.": { "zh": "工单请求失败。", "hi": "Ticket अनुरोध विफल।", "es": "Error en la solicitud de ticket.", "ar": "فشل طلب التذكرة." },
    "Token revoked": { "zh": "令牌已吊销", "hi": "Token revoke किया गया", "es": "Token revocado", "ar": "تم إبطال الرمز" },
    "Unassign failed:": { "zh": "取消分配失败：", "hi": "Unassign विफल:", "es": "Error al desasignar:", "ar": "فشل إلغاء التعيين:" },
    "Unit is required": { "zh": "单元为必填", "hi": "Unit आवश्यक है", "es": "La unidad es obligatoria", "ar": "الوحدة مطلوبة" },
    "Unmute failed": { "zh": "取消静音失败", "hi": "Unmute विफल", "es": "Error al reactivar el sonido", "ar": "فشل إلغاء الكتم" },
    "Update agent on": { "zh": "更新 agent 于", "hi": "agent अपडेट करें इस पर", "es": "Actualizar agente en", "ar": "حدّث الوكيل على" },
    "Upgrade packages on": { "zh": "升级软件包于", "hi": "packages upgrade करें इस पर", "es": "Actualizar paquetes en", "ar": "رقِّ الحزم على" },
    "Upload failed:": { "zh": "上传失败：", "hi": "Upload विफल:", "es": "Error al subir:", "ar": "فشل الرفع:" },
    "Username and password required": { "zh": "用户名和密码为必填", "hi": "Username और password आवश्यक", "es": "Nombre de usuario y contraseña obligatorios", "ar": "اسم المستخدم وكلمة المرور مطلوبان" },
    "Username required": { "zh": "用户名为必填", "hi": "Username आवश्यक", "es": "Nombre de usuario obligatorio", "ar": "اسم المستخدم مطلوب" },
    "Webhook log cleared": { "zh": "Webhook 日志已清除", "hi": "Webhook लॉग साफ़ किया गया", "es": "Log de webhook borrado", "ar": "تم مسح سجل Webhook" },
    "Window deleted": { "zh": "窗口已删除", "hi": "Window हटाई गई", "es": "Ventana eliminada", "ar": "تم حذف النافذة" },
    "WoL failed": { "zh": "WoL 失败", "hi": "WoL विफल", "es": "Error de WoL", "ar": "فشل WoL" },
    "WoL failed after saving MAC": { "zh": "保存 MAC 后 WoL 失败", "hi": "MAC सहेजने के बाद WoL विफल", "es": "Error de WoL tras guardar la MAC", "ar": "فشل WoL بعد حفظ MAC" },
    "WoL request failed": { "zh": "WoL 请求失败", "hi": "WoL अनुरोध विफल", "es": "Error en la solicitud de WoL", "ar": "فشل طلب WoL" },
  };

  // v4.2: page-subtitle translations keyed by normalized English innerHTML
  // (markup-preserving — values keep the same <span>/<a> tags).
  var HTMLDICT = {
    "6-hour rolling buffer across the fleet. Search, tail live, or manage alert rules.": { "zh": "覆盖整个设备群的 6 小时滚动缓冲区。可搜索、实时跟踪或管理告警规则。", "hi": "पूरे फ्लीट में 6-घंटे का रोलिंग बफर। खोजें, लाइव tail करें, या alert नियम प्रबंधित करें।", "es": "Búfer rotativo de 6 horas en toda la flota. Busca, sigue en vivo o gestiona reglas de alerta.", "ar": "مخزن مؤقت متدحرج مدته 6 ساعات عبر الأسطول. ابحث، أو تابع مباشرةً، أو أدِر قواعد التنبيه." },
    "A per-asset risk score (0–100) computed on demand from everything RemotePower already knows — open CVEs, world-reachable services, software-policy violations, pending updates, contract/license expiry, mount issues and more. Every point is attributed. Findings you've <strong>ignored</strong> (CVEs) or <strong>muted</strong> (Exposure) don't count. Risk is a security-posture lens, independent of <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"about\" data-prevent-default class=\"c-accent\">fleet health</a>.": { "zh": "按资产计算的风险评分（0–100），基于 RemotePower 已掌握的所有信息按需计算——未修复的 CVE、可被公网访问的服务、软件策略违规、待安装更新、合同/许可证到期、挂载问题等。每一分都有归因。你已<strong>忽略</strong>（CVE）或<strong>静音</strong>（暴露面）的发现不计入。风险是一个安全态势视角，独立于<a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"about\" data-prevent-default class=\"c-accent\">设备群健康度</a>。", "hi": "हर asset के लिए एक risk स्कोर (0–100), जो RemotePower की पहले से ज्ञात हर जानकारी से माँग पर गणना किया जाता है — खुले CVE, world से पहुँच योग्य services, software-policy उल्लंघन, लंबित updates, contract/license समाप्ति, mount समस्याएँ और बहुत कुछ। हर अंक का कारण बताया जाता है। जिन findings को आपने <strong>अनदेखा</strong> (CVEs) या <strong>म्यूट</strong> (Exposure) किया है, वे नहीं गिने जाते। Risk एक security-posture लेंस है, जो <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"about\" data-prevent-default class=\"c-accent\">fleet health</a> से स्वतंत्र है।", "es": "Una puntuación de riesgo por activo (0–100) calculada bajo demanda a partir de todo lo que RemotePower ya conoce: CVE abiertos, servicios accesibles desde el exterior, infracciones de la política de software, actualizaciones pendientes, vencimiento de contratos/licencias, problemas de montaje y más. Cada punto está atribuido. Los hallazgos que has <strong>ignorado</strong> (CVE) o <strong>silenciado</strong> (Exposición) no cuentan. El riesgo es una lente de postura de seguridad, independiente de la <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"about\" data-prevent-default class=\"c-accent\">salud de la flota</a>.", "ar": "درجة مخاطر لكل أصل (0–100) تُحسب عند الطلب من كل ما يعرفه RemotePower مسبقاً — ثغرات CVE المفتوحة، والخدمات المتاحة للعالم، ومخالفات سياسة البرمجيات، والتحديثات المعلّقة، وانتهاء العقد/الترخيص، ومشكلات نقاط التحميل وغيرها. كل نقطة منسوبة إلى سببها. النتائج التي <strong>تجاهلتها</strong> (CVE) أو <strong>كتمتها</strong> (التعرّض) لا تُحتسب. المخاطر عدسة لوضع الأمان، مستقلة عن <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"about\" data-prevent-default class=\"c-accent\">صحة الأسطول</a>." },
    "A single chronological history — fleet events and command runs merged into one stream — for the whole fleet or one device. Pick the scope below. <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>.": { "zh": "单一时间顺序历史记录——将设备群事件与命令执行合并为一条流——适用于整个设备群或单台设备。请在下方选择范围。<a href=\"docs/features.md\" class=\"c-accent\">文档</a>。", "hi": "एक ही कालानुक्रमिक इतिहास — fleet events और command runs एक ही stream में मिलाए गए — पूरे फ्लीट या एक device के लिए। नीचे scope चुनें। <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>।", "es": "Un único historial cronológico —eventos de la flota y ejecuciones de comandos fusionados en un solo flujo— para toda la flota o un dispositivo. Elige el alcance abajo. <a href=\"docs/features.md\" class=\"c-accent\">Documentación</a>.", "ar": "سجل زمني واحد — أحداث الأسطول وعمليات تنفيذ الأوامر مدمجة في مسار واحد — للأسطول بأكمله أو لجهاز واحد. اختر النطاق أدناه. <a href=\"docs/features.md\" class=\"c-accent\">التوثيق</a>." },
    "Apply package updates automatically on a schedule across a group, tag, site, or the whole fleet. Queued upgrades respect maintenance windows and device quarantine.": { "zh": "按计划在分组、标签、站点或整个设备群范围内自动应用软件包更新。排队的升级会遵守维护窗口和设备隔离。", "hi": "किसी group, tag, site, या पूरे फ्लीट में निर्धारित schedule पर package updates स्वचालित रूप से लागू करें। कतारबद्ध upgrades maintenance windows और device quarantine का सम्मान करते हैं।", "es": "Aplica actualizaciones de paquetes automáticamente según una programación en un grupo, etiqueta, sitio o toda la flota. Las actualizaciones en cola respetan las ventanas de mantenimiento y la cuarentena de dispositivos.", "ar": "طبّق تحديثات الحزم تلقائياً وفق جدول عبر مجموعة أو وسم أو موقع أو الأسطول بأكمله. تحترم الترقيات المُدرَجة في الطابور نوافذ الصيانة وحجر الأجهزة." },
    "Commands waiting to be picked up by each agent on its next heartbeat — handy when a host is offline and you want to see (or cancel) what's pending before it comes back. Anything already delivered to the agent has left the queue.": { "zh": "等待各 agent 在下次心跳时领取的命令——当主机离线、你想在其恢复前查看（或取消）待处理项时很有用。已下发给 agent 的命令均已离开队列。", "hi": "हर agent द्वारा उसके अगले heartbeat पर उठाए जाने की प्रतीक्षा कर रहे commands — तब उपयोगी जब कोई host offline हो और आप वापस आने से पहले देखना (या रद्द करना) चाहते हों कि क्या लंबित है। agent को पहले ही पहुँचाया जा चुका कुछ भी कतार से निकल चुका है।", "es": "Comandos en espera de ser recogidos por cada agente en su próximo heartbeat: útil cuando un host está fuera de línea y quieres ver (o cancelar) lo pendiente antes de que vuelva. Todo lo ya entregado al agente ha salido de la cola.", "ar": "الأوامر التي تنتظر أن يلتقطها كل وكيل عند نبضته التالية — مفيدة عندما يكون المضيف غير متصل وتريد رؤية (أو إلغاء) ما هو معلّق قبل عودته. أي شيء سُلّم للوكيل بالفعل قد غادر الطابور." },
    "Configuration Management Database — asset metadata, documentation, and encrypted credentials per enrolled device.": { "zh": "配置管理数据库——每台已纳管设备的资产元数据、文档和加密凭据。", "hi": "Configuration Management Database — प्रति नामांकित device asset metadata, documentation, और एन्क्रिप्टेड credentials।", "es": "Base de datos de gestión de configuración (CMDB): metadatos de activos, documentación y credenciales cifradas por dispositivo inscrito.", "ar": "قاعدة بيانات إدارة التكوين CMDB — البيانات الوصفية للأصول والتوثيق والاعتمادات المشفّرة لكل جهاز مُسجّل." },
    "Containers whose pulled image is behind the registry's current digest for that tag. Notify-only — RemotePower flags staleness, you decide when to pull. <span id=\"image-updates-meta\" class=\"hint\"></span>": { "zh": "已拉取镜像落后于该标签在镜像仓库中当前摘要的容器。仅通知——RemotePower 标记过时，由你决定何时拉取。<span id=\"image-updates-meta\" class=\"hint\"></span>", "hi": "ऐसे containers जिनका pulled image उस tag के लिए registry के मौजूदा digest से पीछे है। केवल-सूचना — RemotePower पुरानेपन को flag करता है, आप तय करते हैं कि कब pull करना है। <span id=\"image-updates-meta\" class=\"hint\"></span>", "es": "Contenedores cuya imagen descargada está por detrás del digest actual del registro para esa etiqueta. Solo notificación: RemotePower marca la obsolescencia, tú decides cuándo descargar. <span id=\"image-updates-meta\" class=\"hint\"></span>", "ar": "الحاويات التي تتأخر صورتها المسحوبة عن البصمة الحالية للسجل لذلك الوسم. للإشعار فقط — يُعلِم RemotePower بالتقادم، وأنت تقرر متى تسحب. <span id=\"image-updates-meta\" class=\"hint\"></span>" },
    "Control-mapped PCI&nbsp;DSS / HIPAA / SOC&nbsp;2 checklist, scored from data RemotePower already collects. An audit-prep aid — never a formal attestation. <a href=\"docs/Manual.html\" class=\"c-accent\">Documentation</a>.": { "zh": "按控制项映射的 PCI&nbsp;DSS / HIPAA / SOC&nbsp;2 检查清单，依据 RemotePower 已采集的数据评分。仅为审计准备辅助工具——绝非正式认证。<a href=\"docs/Manual.html\" class=\"c-accent\">文档</a>。", "hi": "Control-mapped PCI&nbsp;DSS / HIPAA / SOC&nbsp;2 चेकलिस्ट, जो RemotePower द्वारा पहले से एकत्र किए गए डेटा से स्कोर किया जाता है। एक audit-तैयारी सहायक — कभी कोई औपचारिक प्रमाणन नहीं। <a href=\"docs/Manual.html\" class=\"c-accent\">Documentation</a>।", "es": "Lista de verificación PCI&nbsp;DSS / HIPAA / SOC&nbsp;2 mapeada por controles, puntuada con datos que RemotePower ya recopila. Una ayuda para preparar auditorías, nunca una certificación formal. <a href=\"docs/Manual.html\" class=\"c-accent\">Documentación</a>.", "ar": "قائمة تحقق PCI&nbsp;DSS / HIPAA / SOC&nbsp;2 مربوطة بالضوابط، مُقيَّمة من بيانات يجمعها RemotePower مسبقاً. أداة للتحضير للتدقيق — وليست إقراراً رسمياً أبداً. <a href=\"docs/Manual.html\" class=\"c-accent\">التوثيق</a>." },
    "Define a backup command per device (restic / borg / rsync / …), run it on demand, or schedule it with cron. Pairs with the backup-freshness monitoring in each device's drawer.": { "zh": "为每台设备定义备份命令（restic / borg / rsync / …），按需运行或用 cron 定时执行。与各设备抽屉中的备份新鲜度监控配套使用。", "hi": "प्रति device एक backup command परिभाषित करें (restic / borg / rsync / …), इसे माँग पर चलाएँ, या cron से schedule करें। हर device के drawer में backup-ताज़गी monitoring के साथ जुड़ता है।", "es": "Define un comando de copia de seguridad por dispositivo (restic / borg / rsync / …), ejecútalo bajo demanda o prográmalo con cron. Se combina con la supervisión de frescura de copias en el panel de cada dispositivo.", "ar": "عرّف أمر نسخ احتياطي لكل جهاز (restic / borg / rsync / …)، ونفّذه عند الطلب، أو جدوِله باستخدام cron. يقترن بمراقبة حداثة النسخ الاحتياطي في درج كل جهاز." },
    "Docker / Podman / Kubernetes pods reported by enrolled agents. For Docker/Podman you can start, stop, restart, and pull logs — and deploy compose stacks (below). Actions queue to the agent and run on its next heartbeat.": { "zh": "已纳管 agent 上报的 Docker / Podman / Kubernetes pod。对于 Docker/Podman，你可以启动、停止、重启并拉取日志——以及部署 compose 编排（见下文）。操作会排队至 agent 并在其下次心跳时运行。", "hi": "नामांकित agents द्वारा रिपोर्ट किए गए Docker / Podman / Kubernetes pods। Docker/Podman के लिए आप start, stop, restart, और logs pull कर सकते हैं — और compose stacks deploy कर सकते हैं (नीचे)। Actions agent के लिए कतारबद्ध होते हैं और उसके अगले heartbeat पर चलते हैं।", "es": "Pods de Docker / Podman / Kubernetes reportados por los agentes inscritos. Para Docker/Podman puedes iniciar, detener, reiniciar y obtener logs, y desplegar stacks de compose (abajo). Las acciones se ponen en cola para el agente y se ejecutan en su próximo heartbeat.", "ar": "حاويات Docker / Podman / Kubernetes التي تبلّغ عنها الوكلاء المسجّلون. بالنسبة لـ Docker/Podman يمكنك التشغيل والإيقاف وإعادة التشغيل وسحب السجلات — ونشر حزم compose (أدناه). تُدرَج الإجراءات في طابور الوكيل وتُنفَّذ عند نبضته التالية." },
    "Every <code>authorized_keys</code> entry across the fleet, with OpenSSH SHA256 fingerprints. Weak key types and keys reused across multiple hosts are listed first. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>.": { "zh": "整个设备群中的每条 <code>authorized_keys</code> 记录，附带 OpenSSH SHA256 指纹。弱密钥类型和被多台主机复用的密钥会优先列出。<a href=\"docs/v4.0.0.md\" class=\"c-accent\">文档</a>。", "hi": "पूरे फ्लीट में हर <code>authorized_keys</code> entry, OpenSSH SHA256 fingerprints के साथ। कमज़ोर key प्रकार और कई hosts में पुन: उपयोग की गई keys पहले सूचीबद्ध की जाती हैं। <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>।", "es": "Cada entrada <code>authorized_keys</code> de toda la flota, con huellas SHA256 de OpenSSH. Los tipos de clave débiles y las claves reutilizadas en varios hosts aparecen primero. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentación</a>.", "ar": "كل إدخال <code>authorized_keys</code> عبر الأسطول، مع بصمات OpenSSH SHA256. تُدرَج أنواع المفاتيح الضعيفة والمفاتيح المُعاد استخدامها عبر عدة مضيفين أولاً. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">التوثيق</a>." },
    "Every listening socket across the fleet, classified by where it can be reached from. <span class=\"fw-600\">World</span> = bound to a public/wildcard address; <span class=\"fw-600\">LAN</span> = private network; <span class=\"fw-600\">Local</span> = loopback only. A service first becoming world-reachable raises an alert. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentation</a>.": { "zh": "整个设备群中的每个监听套接字，按可访问来源分类。<span class=\"fw-600\">World</span> = 绑定到公网/通配地址；<span class=\"fw-600\">LAN</span> = 私有网络；<span class=\"fw-600\">Local</span> = 仅回环。服务首次变为可被公网访问时会触发告警。<a href=\"docs/v3.11.0.md\" class=\"c-accent\">文档</a>。", "hi": "पूरे फ्लीट में हर listening socket, इस आधार पर वर्गीकृत कि उस तक कहाँ से पहुँचा जा सकता है। <span class=\"fw-600\">World</span> = किसी public/wildcard पते से बँधा; <span class=\"fw-600\">LAN</span> = निजी network; <span class=\"fw-600\">Local</span> = केवल loopback। कोई service पहली बार world से पहुँच योग्य बनने पर एक alert उठाता है। <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentation</a>।", "es": "Cada socket en escucha de toda la flota, clasificado según desde dónde se puede acceder a él. <span class=\"fw-600\">World</span> = vinculado a una dirección pública/comodín; <span class=\"fw-600\">LAN</span> = red privada; <span class=\"fw-600\">Local</span> = solo loopback. Que un servicio pase a ser accesible desde el exterior por primera vez genera una alerta. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentación</a>.", "ar": "كل مقبس استماع عبر الأسطول، مصنَّف حسب الجهة التي يمكن الوصول إليه منها. <span class=\"fw-600\">العالم</span> = مرتبط بعنوان عام/شامل؛ <span class=\"fw-600\">LAN</span> = شبكة خاصة؛ <span class=\"fw-600\">محلي</span> = حلقة استرجاع فقط. أول مرة تصبح فيها خدمة متاحة للعالم يُثار تنبيه. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">التوثيق</a>." },
    "Everything that needs your attention, in one screen.": { "zh": "需要你关注的所有事项，集中在一个屏幕。", "hi": "वह सब कुछ जिस पर आपका ध्यान चाहिए, एक ही स्क्रीन में।", "es": "Todo lo que necesita tu atención, en una sola pantalla.", "ar": "كل ما يحتاج إلى انتباهك، في شاشة واحدة." },
    "Filter the fleet by ad-hoc criteria (all conditions are ANDed). Save the ones you run often. <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>.": { "zh": "按临时条件筛选设备群（所有条件为「与」关系）。保存你经常运行的筛选。<a href=\"docs/features.md\" class=\"c-accent\">文档</a>。", "hi": "तदर्थ मानदंडों द्वारा फ्लीट को फ़िल्टर करें (सभी शर्तें AND की जाती हैं)। जिन्हें आप अक्सर चलाते हैं उन्हें सहेजें। <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>।", "es": "Filtra la flota por criterios ad-hoc (todas las condiciones se combinan con AND). Guarda los que ejecutas a menudo. <a href=\"docs/features.md\" class=\"c-accent\">Documentación</a>.", "ar": "صفِّ الأسطول وفق معايير مخصصة (تُدمج كل الشروط بعامل AND). احفظ المعايير التي تستخدمها كثيراً. <a href=\"docs/features.md\" class=\"c-accent\">التوثيق</a>." },
    "Free-form chat against the configured provider. Local-model stats when running Ollama or LocalAI.": { "zh": "针对已配置提供方的自由对话。运行 Ollama 或 LocalAI 时显示本地模型统计。", "hi": "कॉन्फ़िगर किए गए provider के विरुद्ध मुक्त-रूप chat। Ollama या LocalAI चलाने पर local-model आँकड़े।", "es": "Chat libre contra el proveedor configurado. Estadísticas de modelo local al usar Ollama o LocalAI.", "ar": "محادثة حرة مع المزود المُكوَّن. إحصاءات النموذج المحلي عند تشغيل Ollama أو LocalAI." },
    "Generate Infrastructure-as-Code (Terraform, Ansible, Pulumi, Cloud-init) for any managed device. Server collects live state on demand, then the configured AI provider transforms it into IaC. Sensitive env vars and SSH keys are masked before leaving the host.": { "zh": "为任意受管设备生成 Infrastructure-as-Code（Terraform、Ansible、Pulumi、Cloud-init）。服务端按需采集实时状态，再由已配置的 AI 提供方将其转换为 IaC。敏感环境变量和 SSH 密钥在离开主机前会被掩码。", "hi": "किसी भी प्रबंधित device के लिए Infrastructure-as-Code (Terraform, Ansible, Pulumi, Cloud-init) उत्पन्न करें। Server माँग पर लाइव state एकत्र करता है, फिर कॉन्फ़िगर किया गया AI provider इसे IaC में बदल देता है। संवेदनशील env vars और SSH keys host छोड़ने से पहले मास्क कर दी जाती हैं।", "es": "Genera Infraestructura como Código (Terraform, Ansible, Pulumi, Cloud-init) para cualquier dispositivo gestionado. El servidor recopila el estado en vivo bajo demanda y luego el proveedor de IA configurado lo transforma en IaC. Las variables de entorno sensibles y las claves SSH se enmascaran antes de salir del host.", "ar": "ولّد البنية التحتية ككود IaC (Terraform، Ansible، Pulumi، Cloud-init) لأي جهاز مُدار. يجمع الخادم الحالة المباشرة عند الطلب، ثم يحوّلها مزود الذكاء الاصطناعي المُكوَّن إلى IaC. تُحجب متغيرات البيئة الحساسة ومفاتيح SSH قبل مغادرة المضيف." },
    "Group the fleet by location, team, or customer — one level above device groups. Assign a device to a site from its drawer. Super-admins always see every site.": { "zh": "按位置、团队或客户对设备群进行分组——高于设备分组一级。可在设备抽屉中将其分配到站点。超级管理员始终可见所有站点。", "hi": "फ्लीट को location, team, या ग्राहक के अनुसार समूहित करें — device groups से एक स्तर ऊपर। किसी device को उसके drawer से किसी site को असाइन करें। Super-admins हमेशा हर site देखते हैं।", "es": "Agrupa la flota por ubicación, equipo o cliente, un nivel por encima de los grupos de dispositivos. Asigna un dispositivo a un sitio desde su panel. Los superadministradores siempre ven todos los sitios.", "ar": "اجمع الأسطول حسب الموقع أو الفريق أو العميل — مستوى واحد فوق مجموعات الأجهزة. عيّن جهازاً لموقع من درجه. يرى المسؤولون الفائقون كل موقع دائماً." },
    "Hardware predicted at risk before it fails — disks (reactive SMART verdict + trends in reallocated/pending sectors and SSD wear) and hosts restarting unusually often. Most urgent first; an ETA appears once there's enough history. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>.": { "zh": "在硬件故障前预测其风险——磁盘（响应式 SMART 判定 + 重映射/待处理扇区及 SSD 磨损趋势）以及异常频繁重启的主机。最紧急的优先；积累足够历史后会显示预计时间。<a href=\"docs/v4.0.0.md\" class=\"c-accent\">文档</a>。", "hi": "Hardware जिसके विफल होने से पहले जोखिम में होने का अनुमान है — disks (reactive SMART निर्णय + reallocated/pending sectors और SSD wear में रुझान) और असामान्य रूप से बार-बार restart होने वाले hosts। सबसे अत्यावश्यक पहले; पर्याप्त इतिहास होने पर एक ETA दिखाई देता है। <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>।", "es": "Hardware que se prevé en riesgo antes de fallar: discos (veredicto SMART reactivo + tendencias en sectores reasignados/pendientes y desgaste de SSD) y hosts que se reinician con una frecuencia inusual. Lo más urgente primero; aparece una ETA cuando hay historial suficiente. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentación</a>.", "ar": "العتاد المتوقع تعرّضه للخطر قبل أن يتعطل — الأقراص (حكم SMART التفاعلي + اتجاهات القطاعات المُعاد تخصيصها/المعلّقة وتآكل SSD) والمضيفون الذين يُعاد تشغيلهم بتواتر غير معتاد. الأكثر إلحاحاً أولاً؛ يظهر الوقت المتوقع بمجرد توفّر تاريخ كافٍ. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">التوثيق</a>." },
    "Hosts seen by agents that ran a LAN scan (device drawer → Health &amp; Hardware → Scan LAN) and that aren't enrolled in RemotePower.": { "zh": "由运行过 LAN 扫描的 agent 发现（设备抽屉 → Health &amp; Hardware → Scan LAN）、但未纳管到 RemotePower 的主机。", "hi": "उन agents द्वारा देखे गए hosts जिन्होंने LAN scan चलाया (device drawer → Health &amp; Hardware → Scan LAN) और जो RemotePower में नामांकित नहीं हैं।", "es": "Hosts vistos por agentes que ejecutaron un escaneo de LAN (panel del dispositivo → Health &amp; Hardware → Scan LAN) y que no están inscritos en RemotePower.", "ar": "المضيفون الذين رصدهم الوكلاء الذين أجروا فحص LAN (درج الجهاز → الصحة والعتاد &amp; → فحص LAN) وغير المسجّلين في RemotePower." },
    "Hottest hosts across the fleet — CPU, chipset and disk temperatures the agents already report. Each host shows its single hottest sensor; the list is sorted hottest-first and anything ≥75 °C is flagged. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>.": { "zh": "整个设备群中温度最高的主机——agent 已上报的 CPU、芯片组和磁盘温度。每台主机显示其温度最高的单个传感器；列表按温度从高到低排序，任何 ≥75 °C 的项都会被标记。<a href=\"docs/v4.0.0.md\" class=\"c-accent\">文档</a>。", "hi": "पूरे फ्लीट में सबसे गर्म hosts — CPU, chipset और disk तापमान जो agents पहले से रिपोर्ट करते हैं। हर host अपना एकमात्र सबसे गर्म sensor दिखाता है; सूची सबसे-गर्म-पहले क्रम में है और ≥75 °C वाला कुछ भी flag किया जाता है। <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>।", "es": "Los hosts más calientes de toda la flota: temperaturas de CPU, chipset y disco que los agentes ya reportan. Cada host muestra su sensor más caliente; la lista se ordena de mayor a menor temperatura y se marca todo lo que esté ≥75 °C. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentación</a>.", "ar": "أكثر المضيفين سخونة عبر الأسطول — درجات حرارة المعالج والشرائح والأقراص التي يبلّغ عنها الوكلاء مسبقاً. يعرض كل مضيف أكثر مستشعراته سخونة؛ القائمة مرتبة من الأسخن أولاً ويُعلَّم أي شيء ≥75 °م. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">التوثيق</a>." },
    "How to use RemotePower — quick reference for the common tasks": { "zh": "如何使用 RemotePower——常见任务快速参考", "hi": "RemotePower का उपयोग कैसे करें — सामान्य कार्यों के लिए त्वरित संदर्भ", "es": "Cómo usar RemotePower: referencia rápida para las tareas comunes", "ar": "كيفية استخدام RemotePower — مرجع سريع للمهام الشائعة" },
    "LXC containers on the Proxmox node. Actions hit the Proxmox API directly.": { "zh": "Proxmox 节点上的 LXC 容器。操作直接调用 Proxmox API。", "hi": "Proxmox node पर LXC containers। Actions सीधे Proxmox API पर लगते हैं।", "es": "Contenedores LXC en el nodo Proxmox. Las acciones llaman directamente a la API de Proxmox.", "ar": "حاويات LXC على عقدة Proxmox. تتصل الإجراءات بـ API الخاص بـ Proxmox مباشرةً." },
    "Log of all commands sent to devices": { "zh": "发送给设备的所有命令日志", "hi": "devices को भेजे गए सभी commands का लॉग", "es": "Registro de todos los comandos enviados a los dispositivos", "ar": "سجل بكل الأوامر المُرسلة إلى الأجهزة" },
    "Manage and remotely control enrolled devices": { "zh": "管理并远程控制已纳管设备", "hi": "नामांकित devices को प्रबंधित करें और दूरस्थ रूप से नियंत्रित करें", "es": "Gestiona y controla de forma remota los dispositivos inscritos", "ar": "أدِر الأجهزة المسجّلة وتحكّم بها عن بُعد" },
    "Manage who can access this dashboard and what they can do. Built-in roles: <strong>admin</strong> (full control) and <strong>viewer</strong> (read-only). Define custom roles to grant specific actions on specific device groups/tags.": { "zh": "管理谁可以访问此仪表板以及他们能做什么。内置角色：<strong>admin</strong>（完全控制）和 <strong>viewer</strong>（只读）。可定义自定义角色，在特定设备分组/标签上授予特定操作权限。", "hi": "प्रबंधित करें कि इस dashboard तक कौन पहुँच सकता है और वे क्या कर सकते हैं। अंतर्निहित roles: <strong>admin</strong> (पूर्ण नियंत्रण) और <strong>viewer</strong> (केवल-पठन)। विशिष्ट device groups/tags पर विशिष्ट actions देने के लिए custom roles परिभाषित करें।", "es": "Gestiona quién puede acceder a este panel y qué puede hacer. Roles integrados: <strong>admin</strong> (control total) y <strong>viewer</strong> (solo lectura). Define roles personalizados para conceder acciones específicas sobre grupos/etiquetas de dispositivos específicos.", "ar": "أدِر مَن يمكنه الوصول إلى هذه اللوحة وما يمكنه فعله. الأدوار المدمجة: <strong>admin</strong> (تحكّم كامل) و<strong>viewer</strong> (قراءة فقط). عرّف أدواراً مخصصة لمنح إجراءات محددة على مجموعات/وسوم أجهزة محددة." },
    "Multi-line bash scripts. Lint with <code>bash -n</code> + dangerous-command detection before they go anywhere. Run on a single device from the device dropdown, or on a batch via the multi-select bar.": { "zh": "多行 bash 脚本。在执行前用 <code>bash -n</code> 检查并进行危险命令检测。可从设备下拉框在单台设备上运行，或通过多选栏批量运行。", "hi": "बहु-पंक्ति bash scripts। कहीं भी जाने से पहले <code>bash -n</code> + खतरनाक-command पहचान के साथ lint करें। device dropdown से किसी एक device पर चलाएँ, या multi-select बार के माध्यम से एक batch पर।", "es": "Scripts bash de varias líneas. Analízalos con <code>bash -n</code> + detección de comandos peligrosos antes de que vayan a ninguna parte. Ejecútalos en un solo dispositivo desde el menú desplegable de dispositivos, o en lote mediante la barra de selección múltiple.", "ar": "نصوص bash متعددة الأسطر. تُفحص باستخدام <code>bash -n</code> + كشف الأوامر الخطرة قبل أن تذهب إلى أي مكان. نفّذها على جهاز واحد من قائمة الأجهزة المنسدلة، أو على دفعة عبر شريط التحديد المتعدد." },
    "Named non-expiring keys for scripts and CI pipelines": { "zh": "供脚本和 CI 流水线使用的具名永不过期密钥", "hi": "scripts और CI pipelines के लिए नामित गैर-समाप्त होने वाली keys", "es": "Claves con nombre que no caducan para scripts y pipelines de CI", "ar": "مفاتيح مُسمّاة غير منتهية الصلاحية للنصوص ومسارات CI" },
    "One fleet posture report — health score, patches, CVEs, and compliance in a single export, on demand or emailed on a schedule. <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>.": { "zh": "一份设备群态势报告——将健康评分、补丁、CVE 和合规性汇入单次导出，可按需生成或按计划邮件发送。<a href=\"docs/features.md\" class=\"c-accent\">文档</a>。", "hi": "एक fleet posture रिपोर्ट — health स्कोर, patches, CVEs, और compliance एक ही export में, माँग पर या schedule पर ईमेल की गई। <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>।", "es": "Un único informe de postura de la flota: puntuación de salud, parches, CVE y cumplimiento en una sola exportación, bajo demanda o enviada por correo según una programación. <a href=\"docs/features.md\" class=\"c-accent\">Documentación</a>.", "ar": "تقرير وضع واحد للأسطول — درجة الصحة والترقيعات وثغرات CVE والامتثال في تصدير واحد، عند الطلب أو يُرسل بالبريد وفق جدول. <a href=\"docs/features.md\" class=\"c-accent\">التوثيق</a>." },
    "Operational alert inbox — acknowledge, resolve, and track every fired event. Recover events (device_online, service_recover, custom_script_recover) auto-resolve their matching open alert.": { "zh": "运维告警收件箱——确认、解决并跟踪每个已触发的事件。恢复类事件（device_online、service_recover、custom_script_recover）会自动解决其匹配的未决告警。", "hi": "Operational alert इनबॉक्स — हर fired event को स्वीकार करें, हल करें, और ट्रैक करें। Recover events (device_online, service_recover, custom_script_recover) अपने मेल खाते खुले alert को स्वतः हल कर देते हैं।", "es": "Bandeja de entrada de alertas operativas: reconoce, resuelve y haz seguimiento de cada evento disparado. Los eventos de recuperación (device_online, service_recover, custom_script_recover) resuelven automáticamente su alerta abierta correspondiente.", "ar": "صندوق وارد التنبيهات التشغيلية — أقرّ بكل حدث مُطلَق وحُلّه وتتبّعه. تحلّ أحداث الاسترداد (device_online، service_recover، custom_script_recover) تلقائياً تنبيهها المفتوح المطابق." },
    "Overview of pending system updates across all devices — percentage only counts online devices with data": { "zh": "所有设备待安装系统更新的概览——百分比仅统计有数据的在线设备", "hi": "सभी devices में लंबित system updates का अवलोकन — प्रतिशत केवल डेटा वाले online devices को गिनता है", "es": "Resumen de las actualizaciones del sistema pendientes en todos los dispositivos: el porcentaje solo cuenta los dispositivos en línea con datos", "ar": "نظرة عامة على تحديثات النظام المعلّقة عبر كل الأجهزة — تحتسب النسبة المئوية الأجهزة المتصلة ذات البيانات فقط" },
    "Package vulnerabilities per device, via <a href=\"https://osv.dev\" target=\"_blank\" class=\"c-accent\">OSV.dev</a> — scan checks installed packages against known CVEs.": { "zh": "每台设备的软件包漏洞，通过 <a href=\"https://osv.dev\" target=\"_blank\" class=\"c-accent\">OSV.dev</a>——扫描将已安装软件包与已知 CVE 进行比对。", "hi": "प्रति device package कमज़ोरियाँ, <a href=\"https://osv.dev\" target=\"_blank\" class=\"c-accent\">OSV.dev</a> के माध्यम से — scan स्थापित packages को ज्ञात CVEs के विरुद्ध जाँचता है।", "es": "Vulnerabilidades de paquetes por dispositivo, mediante <a href=\"https://osv.dev\" target=\"_blank\" class=\"c-accent\">OSV.dev</a>: el escaneo comprueba los paquetes instalados contra CVE conocidos.", "ar": "ثغرات الحزم لكل جهاز، عبر <a href=\"https://osv.dev\" target=\"_blank\" class=\"c-accent\">OSV.dev</a> — يفحص المسح الحزم المثبّتة مقابل ثغرات CVE المعروفة." },
    "Pending write actions queued by MCP clients against devices with <code>require_confirmation=true</code>. Each entry shows the originating AI host and the natural-language prompt that led to the action. Approve to run, reject to discard. Pending entries expire after 1 hour.": { "zh": "MCP 客户端针对设置了 <code>require_confirmation=true</code> 的设备排队的待执行写操作。每条记录显示发起的 AI 主机和导致该操作的自然语言提示词。批准以运行，拒绝以丢弃。待处理记录 1 小时后过期。", "hi": "<code>require_confirmation=true</code> वाले devices के विरुद्ध MCP clients द्वारा कतारबद्ध लंबित write actions। हर entry उत्पन्न करने वाले AI host और उस natural-language prompt को दिखाती है जिसने action तक पहुँचाया। चलाने के लिए स्वीकृत करें, त्यागने के लिए अस्वीकार करें। लंबित entries 1 घंटे के बाद समाप्त हो जाती हैं।", "es": "Acciones de escritura pendientes puestas en cola por clientes MCP contra dispositivos con <code>require_confirmation=true</code>. Cada entrada muestra el host de IA de origen y el prompt en lenguaje natural que originó la acción. Aprueba para ejecutar, rechaza para descartar. Las entradas pendientes caducan tras 1 hora.", "ar": "إجراءات الكتابة المعلّقة التي أدرجها عملاء MCP في الطابور مقابل الأجهزة ذات <code>require_confirmation=true</code>. يعرض كل إدخال مضيف الذكاء الاصطناعي المصدر والمُطالبة باللغة الطبيعية التي أدت إلى الإجراء. وافِق للتنفيذ، أو ارفض للتجاهل. تنتهي صلاحية الإدخالات المعلّقة بعد ساعة واحدة." },
    "Per-mount disk-fill projection across the fleet, from each host's daily metrics history. A least-squares trend on observed usage, extrapolated to capacity — lead time, not a guarantee. Ephemeral mounts (<code>/tmp</code>, <code>/run</code>, <code>/dev/shm</code>, …) are excluded, and a heavily-fluctuating mount shows <em>fluctuating</em> instead of a misleading date. <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>.": { "zh": "整个设备群的逐挂载点磁盘占满预测，依据各主机的每日指标历史。对观测到的用量做最小二乘趋势拟合，外推至容量上限——这是预留时间，而非保证。临时挂载点（<code>/tmp</code>、<code>/run</code>、<code>/dev/shm</code>、…）被排除，剧烈波动的挂载点显示 <em>fluctuating</em> 而非误导性日期。<a href=\"docs/features.md\" class=\"c-accent\">文档</a>。", "hi": "पूरे फ्लीट में प्रति-mount disk-भरने का अनुमान, हर host के दैनिक metrics इतिहास से। देखे गए उपयोग पर least-squares रुझान, क्षमता तक एक्सट्रापोलेट किया गया — लीड समय, गारंटी नहीं। Ephemeral mounts (<code>/tmp</code>, <code>/run</code>, <code>/dev/shm</code>, …) को बाहर रखा गया है, और भारी रूप से उतार-चढ़ाव वाला mount किसी भ्रामक तारीख के बजाय <em>fluctuating</em> दिखाता है। <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>।", "es": "Proyección de llenado de disco por montaje en toda la flota, a partir del historial de métricas diarias de cada host. Una tendencia por mínimos cuadrados sobre el uso observado, extrapolada hasta la capacidad: un margen de tiempo, no una garantía. Los montajes efímeros (<code>/tmp</code>, <code>/run</code>, <code>/dev/shm</code>, …) se excluyen, y un montaje con grandes fluctuaciones muestra <em>fluctuante</em> en lugar de una fecha engañosa. <a href=\"docs/features.md\" class=\"c-accent\">Documentación</a>.", "ar": "توقّع امتلاء القرص لكل نقطة تحميل عبر الأسطول، من تاريخ المقاييس اليومي لكل مضيف. اتجاه المربعات الصغرى على الاستخدام المرصود، مُستقرأ حتى السعة — مهلة استباقية، لا ضمان. تُستثنى نقاط التحميل المؤقتة (<code>/tmp</code>، <code>/run</code>، <code>/dev/shm</code>، …)، وتعرض نقطة التحميل شديدة التذبذب <em>متذبذبة</em> بدلاً من تاريخ مضلِّل. <a href=\"docs/features.md\" class=\"c-accent\">التوثيق</a>." },
    "Probes, device metrics, ports, and custom health checks": { "zh": "探测、设备指标、端口和自定义健康检查", "hi": "Probes, device metrics, ports, और custom health checks", "es": "Sondas, métricas de dispositivos, puertos y comprobaciones de salud personalizadas", "ar": "المجسّات ومقاييس الأجهزة والمنافذ وفحوصات الصحة المخصصة" },
    "Push an upgrade or saved script to the fleet in ordered rings — canary, then pilot, then broad. Each ring is verified (upgrades use post-deploy verification) before the next is released, automatically or on your approval.": { "zh": "按有序的环将升级或已保存脚本推送至设备群——金丝雀、然后试点、再到全量。每个环都经过验证（升级使用部署后验证）后才会自动或经你批准发布下一个环。", "hi": "किसी upgrade या saved script को क्रमबद्ध rings में फ्लीट पर push करें — canary, फिर pilot, फिर broad। हर ring अगले के जारी होने से पहले सत्यापित किया जाता है (upgrades post-deploy सत्यापन का उपयोग करते हैं), स्वचालित रूप से या आपकी स्वीकृति पर।", "es": "Despliega una actualización o un script guardado a la flota en anillos ordenados: canario, luego piloto, luego amplio. Cada anillo se verifica (las actualizaciones usan verificación posterior al despliegue) antes de liberar el siguiente, de forma automática o con tu aprobación.", "ar": "ادفع ترقية أو نصاً محفوظاً إلى الأسطول في حلقات مرتبة — كناري، ثم تجريبية، ثم واسعة. تُتحقَّق كل حلقة (تستخدم الترقيات تحققاً بعد النشر) قبل إطلاق التالية، تلقائياً أو بموافقتك." },
    "QEMU virtual machines on the Proxmox node. Start / shutdown actions call the Proxmox VE API directly from the RemotePower server.": { "zh": "Proxmox 节点上的 QEMU 虚拟机。启动 / 关机操作由 RemotePower 服务端直接调用 Proxmox VE API。", "hi": "Proxmox node पर QEMU virtual machines। Start / shutdown actions RemotePower server से सीधे Proxmox VE API को कॉल करते हैं।", "es": "Máquinas virtuales QEMU en el nodo Proxmox. Las acciones de inicio / apagado llaman directamente a la API de Proxmox VE desde el servidor de RemotePower.", "ar": "أجهزة QEMU الافتراضية على عقدة Proxmox. تستدعي إجراءات التشغيل / الإيقاف واجهة Proxmox VE API مباشرةً من خادم RemotePower." },
    "Queue shutdown or reboot at a specific time": { "zh": "在指定时间排队执行关机或重启", "hi": "किसी विशिष्ट समय पर shutdown या reboot कतारबद्ध करें", "es": "Pon en cola un apagado o reinicio a una hora específica", "ar": "أدرِج إيقاف التشغيل أو إعادة التشغيل في وقت محدد" },
    "Redacted findings from the opt-in agent scan — keys, tokens and passwords found in files. Values are never collected; each row shows a masked preview and a fingerprint. Enable the scan in <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"settings\" data-prevent-default class=\"c-accent\">Settings → Security</a>. Mute a false positive to stop it alerting.": { "zh": "来自可选 agent 扫描的脱敏发现——在文件中找到的密钥、令牌和密码。绝不采集明文值；每行显示掩码预览和指纹。在 <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"settings\" data-prevent-default class=\"c-accent\">Settings → Security</a> 中启用扫描。静音误报以停止其告警。", "hi": "ऑप्ट-इन agent scan से संपादित findings — फ़ाइलों में मिले keys, tokens और passwords। मान कभी एकत्र नहीं किए जाते; हर row एक मास्क किया गया preview और एक fingerprint दिखाती है। scan को <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"settings\" data-prevent-default class=\"c-accent\">Settings → Security</a> में सक्षम करें। किसी false positive को alert करने से रोकने के लिए म्यूट करें।", "es": "Hallazgos redactados del escaneo opcional del agente: claves, tokens y contraseñas encontrados en archivos. Los valores nunca se recopilan; cada fila muestra una vista previa enmascarada y una huella. Activa el escaneo en <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"settings\" data-prevent-default class=\"c-accent\">Configuración → Seguridad</a>. Silencia un falso positivo para que deje de alertar.", "ar": "نتائج مُنقَّحة من فحص الوكيل الاختياري — المفاتيح والرموز وكلمات المرور الموجودة في الملفات. لا تُجمع القيم أبداً؛ يعرض كل صف معاينة مُقنّعة وبصمة. فعّل الفحص في <a href=\"#\" data-action-btn=\"_showPageBtn\" data-page=\"settings\" data-prevent-default class=\"c-accent\">الإعدادات → الأمان</a>. اكتم نتيجة إيجابية كاذبة لإيقاف تنبيهها." },
    "RemotePower watching itself — disk, devices, webhooks, audit, backups. <a href=\"docs/self-monitoring.md\" class=\"c-accent\">Documentation</a>.": { "zh": "RemotePower 监控自身——磁盘、设备、Webhook、审计、备份。<a href=\"docs/self-monitoring.md\" class=\"c-accent\">文档</a>。", "hi": "RemotePower स्वयं को देख रहा है — disk, devices, webhooks, audit, backups। <a href=\"docs/self-monitoring.md\" class=\"c-accent\">Documentation</a>।", "es": "RemotePower vigilándose a sí mismo: disco, dispositivos, webhooks, auditoría, copias de seguridad. <a href=\"docs/self-monitoring.md\" class=\"c-accent\">Documentación</a>.", "ar": "RemotePower يراقب نفسه — القرص والأجهزة وWebhooks والتدقيق والنسخ الاحتياطية. <a href=\"docs/self-monitoring.md\" class=\"c-accent\">التوثيق</a>." },
    "RemotePower — self-hosted device management": { "zh": "RemotePower——自托管设备管理", "hi": "RemotePower — स्व-होस्टेड device प्रबंधन", "es": "RemotePower: gestión de dispositivos autoalojada", "ar": "RemotePower — إدارة أجهزة ذاتية الاستضافة" },
    "Rules evaluated against every host's installed-package inventory: <span class=\"fw-600\">banned</span> (must not be installed), <span class=\"fw-600\">required</span> (must be installed), <span class=\"fw-600\">min&nbsp;version</span>. Optionally scope a rule to device tags. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentation</a>.": { "zh": "针对每台主机已安装软件包清单评估的规则：<span class=\"fw-600\">banned</span>（禁止安装）、<span class=\"fw-600\">required</span>（必须安装）、<span class=\"fw-600\">min&nbsp;version</span>。可选择将规则限定到设备标签。<a href=\"docs/v3.11.0.md\" class=\"c-accent\">文档</a>。", "hi": "हर host की स्थापित-package इन्वेंट्री के विरुद्ध मूल्यांकित नियम: <span class=\"fw-600\">banned</span> (स्थापित नहीं होना चाहिए), <span class=\"fw-600\">required</span> (स्थापित होना चाहिए), <span class=\"fw-600\">min&nbsp;version</span>। वैकल्पिक रूप से किसी नियम को device tags तक सीमित करें। <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentation</a>।", "es": "Reglas evaluadas contra el inventario de paquetes instalados de cada host: <span class=\"fw-600\">prohibido</span> (no debe estar instalado), <span class=\"fw-600\">obligatorio</span> (debe estar instalado), <span class=\"fw-600\">versión&nbsp;mínima</span>. Opcionalmente, limita una regla a etiquetas de dispositivos. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentación</a>.", "ar": "قواعد تُقيَّم مقابل جرد الحزم المثبّتة لكل مضيف: <span class=\"fw-600\">محظورة</span> (يجب ألا تُثبَّت)، <span class=\"fw-600\">مطلوبة</span> (يجب أن تُثبَّت)، <span class=\"fw-600\">أدنى&nbsp;إصدار</span>. اختيارياً حدّد نطاق قاعدة لوسوم الأجهزة. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">التوثيق</a>." },
    "Run Ansible playbooks against the fleet, with this server as the control node. Define a playbook, then run it against a group / tag / site over SSH. <span id=\"ansible-availability\" class=\"hint\"></span>": { "zh": "以此服务器为控制节点，对设备群运行 Ansible playbook。定义一个 playbook，然后通过 SSH 对分组 / 标签 / 站点运行。<span id=\"ansible-availability\" class=\"hint\"></span>", "hi": "इस server को control node के रूप में रखते हुए फ्लीट के विरुद्ध Ansible playbooks चलाएँ। एक playbook परिभाषित करें, फिर इसे SSH पर किसी group / tag / site के विरुद्ध चलाएँ। <span id=\"ansible-availability\" class=\"hint\"></span>", "es": "Ejecuta playbooks de Ansible contra la flota, con este servidor como nodo de control. Define un playbook y luego ejecútalo contra un grupo / etiqueta / sitio por SSH. <span id=\"ansible-availability\" class=\"hint\"></span>", "ar": "نفّذ كتب تشغيل Ansible مقابل الأسطول، مع هذا الخادم كعقدة تحكّم. عرّف كتاب تشغيل، ثم نفّذه مقابل مجموعة / وسم / موقع عبر SSH. <span id=\"ansible-availability\" class=\"hint\"></span>" },
    "Saved shell command snippets — pick from the exec modal": { "zh": "已保存的 shell 命令片段——从执行弹窗中选取", "hi": "सहेजे गए shell command snippets — exec modal से चुनें", "es": "Fragmentos de comandos de shell guardados: elige desde el modal de ejecución", "ar": "مقتطفات أوامر shell محفوظة — اختر من نافذة التنفيذ" },
    "Scheduled windows suppress webhook alerts for specific devices, groups, or the whole fleet.": { "zh": "计划窗口会抑制针对特定设备、分组或整个设备群的 Webhook 告警。", "hi": "निर्धारित windows विशिष्ट devices, groups, या पूरे फ्लीट के लिए webhook alerts को दबा देते हैं।", "es": "Las ventanas programadas suprimen las alertas de webhook para dispositivos, grupos o toda la flota.", "ar": "تكبت النوافذ المجدولة تنبيهات Webhook لأجهزة أو مجموعات محددة، أو للأسطول بأكمله." },
    "Security audit trail — logins, commands, session revocations": { "zh": "安全审计跟踪——登录、命令、会话吊销", "hi": "Security audit trail — logins, commands, session revocations", "es": "Registro de auditoría de seguridad: inicios de sesión, comandos, revocaciones de sesión", "ar": "مسار تدقيق الأمان — تسجيلات الدخول والأوامر وإبطال الجلسات" },
    "Server configuration": { "zh": "服务器配置", "hi": "Server कॉन्फ़िगरेशन", "es": "Configuración del servidor", "ar": "تكوين الخادم" },
    "Server-side cert and DNS watchlist. Probes run from the RemotePower server. Defaults: warn at 14 days, critical at 3 days.": { "zh": "服务端证书和 DNS 监视列表。探测从 RemotePower 服务器发起。默认值：14 天预警，3 天严重。", "hi": "Server-साइड cert और DNS watchlist। Probes RemotePower server से चलते हैं। डिफ़ॉल्ट: 14 दिनों पर चेतावनी, 3 दिनों पर critical।", "es": "Lista de vigilancia de certificados y DNS del lado del servidor. Las sondas se ejecutan desde el servidor de RemotePower. Valores predeterminados: aviso a los 14 días, crítico a los 3 días.", "ar": "قائمة مراقبة الشهادات وDNS من جانب الخادم. تُشغَّل المجسّات من خادم RemotePower. الإعدادات الافتراضية: تحذير عند 14 يوماً، حرِج عند 3 أيام." },
    "Shared bookmark dashboard. Card grid grouped by category. Click any card to open the link in a new tab. <strong>Internal</strong> links (LAN-only, behind VPN, etc.) are amber-bordered; <strong>external</strong> links are accent-bordered.": { "zh": "共享书签仪表板。按类别分组的卡片网格。点击任意卡片可在新标签页打开链接。<strong>内部</strong>链接（仅 LAN、VPN 内等）为琥珀色边框；<strong>外部</strong>链接为强调色边框。", "hi": "साझा bookmark dashboard। श्रेणी के अनुसार समूहित card grid। लिंक को नए टैब में खोलने के लिए किसी भी card पर क्लिक करें। <strong>Internal</strong> लिंक (केवल-LAN, VPN के पीछे, आदि) amber-बॉर्डर वाले होते हैं; <strong>external</strong> लिंक accent-बॉर्डर वाले होते हैं।", "es": "Panel de marcadores compartido. Cuadrícula de tarjetas agrupada por categoría. Haz clic en cualquier tarjeta para abrir el enlace en una pestaña nueva. Los enlaces <strong>internos</strong> (solo LAN, tras VPN, etc.) tienen borde ámbar; los enlaces <strong>externos</strong> tienen borde de acento.", "ar": "لوحة إشارات مرجعية مشتركة. شبكة بطاقات مجمّعة حسب الفئة. انقر أي بطاقة لفتح الرابط في علامة تبويب جديدة. الروابط <strong>الداخلية</strong> (LAN فقط، خلف VPN، إلخ) محاطة بإطار كهرماني؛ الروابط <strong>الخارجية</strong> محاطة بإطار مميّز." },
    "Shared events across all users — backups, deploys, renewals, anything you want to remember.": { "zh": "所有用户共享的事件——备份、部署、续期，以及任何你想记住的事项。", "hi": "सभी users में साझा events — backups, deploys, नवीनीकरण, जो कुछ भी आप याद रखना चाहते हैं।", "es": "Eventos compartidos entre todos los usuarios: copias de seguridad, despliegues, renovaciones, cualquier cosa que quieras recordar.", "ar": "أحداث مشتركة عبر كل المستخدمين — النسخ الاحتياطية وعمليات النشر والتجديدات، وأي شيء تريد تذكّره." },
    "Shared kanban board. Drag cards between columns. Optionally link a task to a device.": { "zh": "共享看板。在各列之间拖动卡片。可选择将任务关联到某台设备。", "hi": "साझा kanban board। columns के बीच cards खींचें। वैकल्पिक रूप से किसी task को किसी device से लिंक करें।", "es": "Tablero kanban compartido. Arrastra tarjetas entre columnas. Opcionalmente, vincula una tarea a un dispositivo.", "ar": "لوحة kanban مشتركة. اسحب البطاقات بين الأعمدة. اختيارياً اربط مهمة بجهاز." },
    "Sign the agent release so agents <strong>refuse any self-update that isn't validly signed</strong> by your key. <a href=\"docs/webhooks.md\" class=\"c-accent\">Documentation</a>.": { "zh": "对 agent 发布版本进行签名，使 agent <strong>拒绝任何未经你的密钥有效签名的自更新</strong>。<a href=\"docs/webhooks.md\" class=\"c-accent\">文档</a>。", "hi": "agent release पर हस्ताक्षर करें ताकि agents <strong>किसी भी ऐसे self-update को अस्वीकार करें जो आपकी key द्वारा वैध रूप से हस्ताक्षरित नहीं है</strong>। <a href=\"docs/webhooks.md\" class=\"c-accent\">Documentation</a>।", "es": "Firma la versión del agente para que los agentes <strong>rechacen cualquier autoactualización que no esté firmada válidamente</strong> con tu clave. <a href=\"docs/webhooks.md\" class=\"c-accent\">Documentación</a>.", "ar": "وقّع إصدار الوكيل حتى <strong>يرفض الوكلاء أي تحديث ذاتي غير موقّع بشكل صالح</strong> بمفتاحك. <a href=\"docs/webhooks.md\" class=\"c-accent\">التوثيق</a>." },
    "Time-series charts from the daily samples RemotePower already keeps — fleet health, compliance, and per-device resource history. Zero-dependency SVG.": { "zh": "基于 RemotePower 已保存的每日采样的时序图表——设备群健康度、合规性和逐设备资源历史。零依赖 SVG。", "hi": "RemotePower द्वारा पहले से रखे गए दैनिक नमूनों से time-series चार्ट — fleet health, compliance, और प्रति-device संसाधन इतिहास। शून्य-निर्भरता SVG।", "es": "Gráficos de series temporales a partir de las muestras diarias que RemotePower ya guarda: salud de la flota, cumplimiento e historial de recursos por dispositivo. SVG sin dependencias.", "ar": "مخططات سلاسل زمنية من العينات اليومية التي يحتفظ بها RemotePower مسبقاً — صحة الأسطول والامتثال وتاريخ موارد كل جهاز. SVG بلا اعتماديات." },
    "Topology view from manually-set <code>connected_to</code> links and tunnels (peer links). Drag nodes to reposition — positions persist across refresh. Add agentless devices on the Devices page.": { "zh": "基于手动设置的 <code>connected_to</code> 链接和隧道（对等链接）的拓扑视图。拖动节点可重新定位——位置在刷新后保留。可在 Devices 页面添加无 agent 设备。", "hi": "मैन्युअल रूप से सेट किए गए <code>connected_to</code> लिंक और tunnels (peer links) से topology दृश्य। पुनः स्थिति देने के लिए nodes खींचें — स्थितियाँ refresh के बाद भी बनी रहती हैं। agentless devices को Devices पेज पर जोड़ें।", "es": "Vista de topología a partir de enlaces <code>connected_to</code> establecidos manualmente y túneles (enlaces de pares). Arrastra los nodos para reposicionarlos: las posiciones persisten tras refrescar. Añade dispositivos sin agente en la página de Dispositivos.", "ar": "عرض الطوبولوجيا من روابط <code>connected_to</code> المُعيَّنة يدوياً والأنفاق (روابط الأقران). اسحب العقد لإعادة وضعها — تبقى المواضع عبر التحديث. أضف أجهزة بلا وكيل في صفحة الأجهزة." },
    "UPS status and measured power draw across the fleet. Hosts on battery are listed first. Set your electricity price to estimate energy cost from the live total. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>.": { "zh": "整个设备群的 UPS 状态和实测功耗。使用电池供电的主机会优先列出。设置你的电价即可根据实时总功率估算能耗成本。<a href=\"docs/v4.0.0.md\" class=\"c-accent\">文档</a>。", "hi": "पूरे फ्लीट में UPS स्थिति और मापा गया power draw। battery पर चल रहे hosts पहले सूचीबद्ध होते हैं। लाइव कुल से ऊर्जा लागत का अनुमान लगाने के लिए अपनी बिजली कीमत सेट करें। <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentation</a>।", "es": "Estado del UPS y consumo de energía medido en toda la flota. Los hosts con batería aparecen primero. Establece tu precio de la electricidad para estimar el coste energético a partir del total en vivo. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">Documentación</a>.", "ar": "حالة UPS وسحب الطاقة المُقاس عبر الأسطول. تُدرَج المضيفات العاملة على البطارية أولاً. عيّن سعر الكهرباء لتقدير تكلفة الطاقة من الإجمالي المباشر. <a href=\"docs/v4.0.0.md\" class=\"c-accent\">التوثيق</a>." },
    "Upload a docker-compose file and deploy it to a device — up / down / redeploy. Admin-only and audited, and only to devices where you've turned on compose deploys. RemotePower runs the file as-is on the host; it doesn't sandbox it.": { "zh": "上传 docker-compose 文件并部署到设备——up / down / redeploy。仅限管理员且会被审计，且仅限你已开启 compose 部署的设备。RemotePower 在主机上原样运行该文件，不对其做沙箱隔离。", "hi": "एक docker-compose फ़ाइल अपलोड करें और इसे किसी device पर deploy करें — up / down / redeploy। केवल-admin और ऑडिट किया गया, और केवल उन devices पर जहाँ आपने compose deploys चालू किया है। RemotePower फ़ाइल को host पर जैसी-है वैसी चलाता है; यह इसे sandbox नहीं करता।", "es": "Sube un archivo docker-compose y despliégalo en un dispositivo: up / down / redeploy. Solo para administradores y auditado, y únicamente en dispositivos donde hayas habilitado los despliegues de compose. RemotePower ejecuta el archivo tal cual en el host; no lo aísla en un sandbox.", "ar": "حمّل ملف docker-compose وانشره على جهاز — up / down / redeploy. للمسؤول فقط ومُدقَّق، وعلى الأجهزة التي فعّلت فيها عمليات نشر compose فقط. يشغّل RemotePower الملف كما هو على المضيف؛ ولا يعزله في صندوق رمل." },
    "Watched config files across the fleet. Agent hashes each file every few heartbeats; server alerts when a hash diverges from the stored baseline. Hash-only — no file content crosses the wire. <a href=\"docs/drift.md\" class=\"c-accent\">Documentation</a>.": { "zh": "整个设备群中被监视的配置文件。agent 每隔几次心跳对每个文件做哈希；当哈希与存储的基线不一致时服务端告警。仅哈希——文件内容不会通过网络传输。<a href=\"docs/drift.md\" class=\"c-accent\">文档</a>。", "hi": "पूरे फ्लीट में देखी गई config फ़ाइलें। Agent हर कुछ heartbeats पर हर फ़ाइल को hash करता है; जब कोई hash संग्रहीत baseline से भिन्न होता है तो server alert करता है। केवल-hash — कोई फ़ाइल सामग्री wire पार नहीं करती। <a href=\"docs/drift.md\" class=\"c-accent\">Documentation</a>।", "es": "Archivos de configuración vigilados en toda la flota. El agente calcula el hash de cada archivo cada pocos heartbeats; el servidor alerta cuando un hash difiere de la línea base almacenada. Solo hash: ningún contenido de archivo viaja por la red. <a href=\"docs/drift.md\" class=\"c-accent\">Documentación</a>.", "ar": "ملفات التكوين المُراقَبة عبر الأسطول. يجزّئ الوكيل كل ملف كل بضع نبضات؛ يُنبّه الخادم عندما يتباعد التجزئة عن الأساس المخزَّن. تجزئة فقط — لا يعبر محتوى الملف الشبكة. <a href=\"docs/drift.md\" class=\"c-accent\">التوثيق</a>." },
    "When an event fires on matching devices, run a saved script and/or notify a destination. Rules are evaluated on every event; each has a cooldown. <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>.": { "zh": "当事件在匹配的设备上触发时，运行已保存脚本和/或通知某个目的地。规则在每个事件上评估；每条规则都有冷却时间。<a href=\"docs/features.md\" class=\"c-accent\">文档</a>。", "hi": "जब मेल खाते devices पर कोई event fires होता है, तो एक saved script चलाएँ और/या किसी destination को सूचित करें। नियम हर event पर मूल्यांकित होते हैं; हर एक में एक cooldown होता है। <a href=\"docs/features.md\" class=\"c-accent\">Documentation</a>।", "es": "Cuando se dispara un evento en dispositivos coincidentes, ejecuta un script guardado y/o notifica a un destino. Las reglas se evalúan en cada evento; cada una tiene un tiempo de espera. <a href=\"docs/features.md\" class=\"c-accent\">Documentación</a>.", "ar": "عندما يُطلَق حدث على أجهزة مطابقة، نفّذ نصاً محفوظاً و/أو أخطِر وجهة. تُقيَّم القواعد عند كل حدث؛ ولكل منها فترة تهدئة. <a href=\"docs/features.md\" class=\"c-accent\">التوثيق</a>." },
    "Your personal settings — these apply to <strong id=\"acct-username\">you</strong> only, not the whole server.": { "zh": "你的个人设置——这些仅对<strong id=\"acct-username\">你</strong>生效，而非整个服务器。", "hi": "आपकी व्यक्तिगत settings — ये केवल <strong id=\"acct-username\">आप</strong> पर लागू होती हैं, पूरे server पर नहीं।", "es": "Tu configuración personal: esta se aplica solo a <strong id=\"acct-username\">ti</strong>, no a todo el servidor.", "ar": "إعداداتك الشخصية — تنطبق على <strong id=\"acct-username\">أنت</strong> فقط، لا على الخادم بأكمله." },
    "ZFS, mdadm and btrfs pool/array state across the fleet. Degraded or faulted arrays are listed first and raise an alert; ZFS scrub freshness is tracked. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentation</a>.": { "zh": "整个设备群的 ZFS、mdadm 和 btrfs 池/阵列状态。降级或故障的阵列会优先列出并触发告警；会跟踪 ZFS scrub 的新鲜度。<a href=\"docs/v3.11.0.md\" class=\"c-accent\">文档</a>。", "hi": "पूरे फ्लीट में ZFS, mdadm और btrfs pool/array स्थिति। Degraded या faulted arrays पहले सूचीबद्ध होते हैं और एक alert उठाते हैं; ZFS scrub ताज़गी ट्रैक की जाती है। <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentation</a>।", "es": "Estado de pools/arrays de ZFS, mdadm y btrfs en toda la flota. Los arrays degradados o con fallos aparecen primero y generan una alerta; se hace seguimiento de la frescura del scrub de ZFS. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">Documentación</a>.", "ar": "حالة تجمّعات/مصفوفات ZFS وmdadm وbtrfs عبر الأسطول. تُدرَج المصفوفات المتدهورة أو المعطوبة أولاً وتُثير تنبيهاً؛ وتُتتبَّع حداثة فحص ZFS. <a href=\"docs/v3.11.0.md\" class=\"c-accent\">التوثيق</a>." },
    "systemd units watched per device. Click a row to see history, logs, and configuration.": { "zh": "按设备监视的 systemd 单元。点击某行可查看历史、日志和配置。", "hi": "प्रति device देखे गए systemd units। इतिहास, logs, और कॉन्फ़िगरेशन देखने के लिए किसी row पर क्लिक करें।", "es": "Unidades de systemd vigiladas por dispositivo. Haz clic en una fila para ver el historial, los logs y la configuración.", "ar": "وحدات systemd المُراقَبة لكل جهاز. انقر صفاً لرؤية التاريخ والسجلات والتكوين." },
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

  // ── Translation engine (v4.2) ───────────────────────────────────────────
  // We translate (a) whole TEXT NODES whose trimmed text is in DICT — so
  // inline-markup text, dynamically-rendered status messages and labels all
  // get translated, not just curated leaf elements — and (b) `.page-subtitle`
  // elements by their normalized innerHTML via HTMLDICT, which preserves the
  // <span>/<a> markup inside a sentence. The original English is stashed in a
  // WeakMap so switching languages always translates from English. Anything
  // not in the dictionaries keeps its English text (graceful fallback).
  var _origText = (typeof WeakMap !== 'undefined') ? new WeakMap() : null;
  var _origHTML = (typeof WeakMap !== 'undefined') ? new WeakMap() : null;
  var SKIP_TAGS = { SCRIPT: 1, STYLE: 1, CODE: 1, PRE: 1, SVG: 1, TEXTAREA: 1, KBD: 1, SAMP: 1 };

  function _normWS(s) { return s.replace(/\s+/g, ' ').replace(/^\s+|\s+$/g, ''); }

  function translateTextNode(node) {
    if (!node || node.nodeType !== 3) return;
    var raw = node.nodeValue;
    if (!raw) return;
    var trimmed = raw.replace(/^\s+|\s+$/g, '');
    if (trimmed.length < 2 || trimmed.length > 200) return;
    var en = _origText ? _origText.get(node) : undefined;
    if (en === undefined) { en = trimmed; if (_origText) _origText.set(node, en); }
    var out = translate(en);
    var want = raw.match(/^\s*/)[0] + out + raw.match(/\s*$/)[0];
    if (node.nodeValue !== want) node.nodeValue = want;
  }

  function _skipText(parent, root) {
    var p = parent;
    while (p && p.nodeType === 1 && p !== (root.parentNode || null)) {
      if (SKIP_TAGS[p.tagName]) return true;
      if (p.classList && p.classList.contains('page-subtitle')) return true; // innerHTML path
      p = p.parentNode;
    }
    return false;
  }

  function translateTextNodes(root) {
    if (!document.createTreeWalker) return;
    var start = (root && (root.nodeType === 1 || root.nodeType === 9)) ? root : null;
    if (!start) { if (root && root.nodeType === 3) translateTextNode(root); return; }
    var walker = document.createTreeWalker(start, NodeFilter.SHOW_TEXT, null);
    var batch = [], n;
    while ((n = walker.nextNode())) { if (!_skipText(n.parentNode, start)) batch.push(n); }
    for (var i = 0; i < batch.length; i++) translateTextNode(batch[i]);
  }

  function translateSubtitles(root) {
    var scope = (root && root.querySelectorAll) ? root : document;
    var list = [];
    var els = scope.querySelectorAll('.page-subtitle');
    for (var i = 0; i < els.length; i++) list.push(els[i]);
    if (root && root.nodeType === 1 && root.classList && root.classList.contains('page-subtitle')) list.push(root);
    for (var j = 0; j < list.length; j++) {
      var el = list[j];
      var en = _origHTML ? _origHTML.get(el) : undefined;
      if (en === undefined) { en = _normWS(el.innerHTML); if (_origHTML) _origHTML.set(el, en); }
      if (current === 'en') { if (_normWS(el.innerHTML) !== en) el.innerHTML = en; continue; }
      var row = HTMLDICT[en];
      var out = row && row[current];
      if (out) { if (_normWS(el.innerHTML) !== _normWS(out)) el.innerHTML = out; }
      else if (_normWS(el.innerHTML) !== en) { el.innerHTML = en; }
    }
  }

  function apply(root) {
    var scope = root || document;
    translateSubtitles(scope);
    translateTextNodes(scope);
  }

  // Re-translate content rendered after first paint (only while non-English).
  var _observer = null, _pending = [], _flushQueued = false;
  function _scheduleFlush() {
    if (_flushQueued) return;
    _flushQueued = true;
    (window.requestAnimationFrame || function (f) { return setTimeout(f, 16); })(_flush);
  }
  function _flush() {
    _flushQueued = false;
    var nodes = _pending; _pending = [];
    if (current === 'en' || !nodes.length) return;
    if (_observer) _observer.disconnect();
    for (var i = 0; i < nodes.length; i++) {
      var nd = nodes[i];
      if (!nd || nd.isConnected === false) continue;
      if (nd.nodeType === 1) apply(nd);
      else if (nd.nodeType === 3) translateTextNode(nd);
    }
    if (_observer && current !== 'en') _observer.observe(document.body, { childList: true, subtree: true });
  }
  function startObserver() {
    if (_observer || typeof MutationObserver === 'undefined' || !document.body) return;
    _observer = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var added = muts[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var nd = added[j];
          if (nd.nodeType === 1 || nd.nodeType === 3) _pending.push(nd);
        }
      }
      if (_pending.length) _scheduleFlush();
    });
    _observer.observe(document.body, { childList: true, subtree: true });
  }
  function stopObserver() {
    if (_observer) { _observer.disconnect(); _observer = null; }
    _pending = [];
  }
  function _syncObserver() { if (current === 'en') stopObserver(); else startObserver(); }

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
    _syncObserver();
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
    _syncObserver();
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
