/**
 * Interface language and direction.
 *
 * Two things this does that a naive translation layer does not:
 *
 * 1. **Missing translations are visible, not silently English.** A key with no
 *    translation renders the English string wrapped in a marker the QA build
 *    shows, so a half-translated German UI looks half-translated instead of
 *    looking finished. A works council reading a screen that is 80% German and
 *    20% English notices; a screen that silently falls back looks fine to us
 *    and wrong to them.
 * 2. **RTL is a document direction, not a stylesheet.** Setting `dir="rtl"` on
 *    the root and using logical CSS properties flips the whole layout —
 *    including scrollbars, focus order and the nav — which mirroring margins by
 *    hand does not.
 *
 * Numbers, dates and lists go through Intl rather than being formatted by
 * hand, because "1,234" and "1.234" mean different numbers in different places
 * and a governance product that shows the wrong one has said something false.
 */

export const LOCALES = {
  en: { name: 'English', native: 'English', dir: 'ltr' },
  de: { name: 'German', native: 'Deutsch', dir: 'ltr' },
  fr: { name: 'French', native: 'Français', dir: 'ltr' },
  nl: { name: 'Dutch', native: 'Nederlands', dir: 'ltr' },
  sv: { name: 'Swedish', native: 'Svenska', dir: 'ltr' },
  es: { name: 'Spanish', native: 'Español', dir: 'ltr' },
  ja: { name: 'Japanese', native: '日本語', dir: 'ltr' },
  ar: { name: 'Arabic', native: 'العربية', dir: 'rtl' },
  he: { name: 'Hebrew', native: 'עברית', dir: 'rtl' }
};

/**
 * The interface strings.
 *
 * Deliberately not every string in the product: the screens render live data
 * whose content is the customer's, and machine-translating a fact would be a
 * governance failure, not a feature. What is translated is the chrome — the
 * things that tell a reader what they are looking at.
 */
export const STRINGS = {
  en: {
    'app.name': 'Vault',
    'app.tagline': 'The company\'s shared AI memory — with a guard at the door, a recorder that never stops, and proof you can verify yourself.',
    'auth.token': 'Access token',
    'auth.signin': 'Sign in',
    'auth.signout': 'Sign out',
    'auth.failed': 'That token was not accepted.',
    'nav.label': 'Screens',
    'nav.skip': 'Skip to main content',
    'action.refresh': 'Refresh',
    'action.close': 'Close',
    'action.cancel': 'Cancel',
    'action.confirm': 'Confirm',
    'state.loading': 'Loading…',
    'state.empty': 'Nothing here yet.',
    'state.error': 'Something went wrong.',
    'killswitch.label': 'Kill switch',
    'killswitch.normal': 'normal',
    'chain.verifying': 'verifying chain',
    'chain.ok': 'chain verified',
    'chain.broken': 'CHAIN BROKEN',
    'screen.map': 'Map',
    'screen.memory': 'Memory',
    'screen.review': 'Needs Review',
    'screen.rules': 'Rules',
    'screen.trace': 'Trace',
    'screen.archive': 'Archive',
    'screen.observability': 'Observability',
    'screen.cases': 'Cases',
    'screen.security': 'Security',
    'screen.comply': 'Comply',
    'screen.insure': 'Insure',
    'screen.value': 'Value',
    'screen.mydata': 'My Data',
    'screen.admin': 'Admin',
    'screen.setup': 'Setup',
    'screen.status': 'Status',
    'a11y.mainLandmark': 'Main content',
    'a11y.navLandmark': 'Primary navigation',
    'a11y.currentScreen': 'Current screen',
    'a11y.sortedBy': 'Sorted by',
    'a11y.riskScore': 'Risk score',
    'a11y.tableCaption': 'Data table',
    'lang.label': 'Interface language',
    'lang.note': 'This changes the interface only. Your memory content is never machine-translated.'
  },

  de: {
    'app.name': 'Vault',
    'app.tagline': 'Das gemeinsame KI-Gedächtnis des Unternehmens — mit einer Kontrolle an der Tür, einer lückenlosen Aufzeichnung und einem Nachweis, den Sie selbst prüfen können.',
    'auth.token': 'Zugangstoken',
    'auth.signin': 'Anmelden',
    'auth.signout': 'Abmelden',
    'auth.failed': 'Dieses Token wurde nicht akzeptiert.',
    'nav.label': 'Ansichten',
    'nav.skip': 'Zum Hauptinhalt springen',
    'action.refresh': 'Aktualisieren',
    'action.close': 'Schließen',
    'action.cancel': 'Abbrechen',
    'action.confirm': 'Bestätigen',
    'state.loading': 'Wird geladen…',
    'state.empty': 'Noch nichts vorhanden.',
    'state.error': 'Es ist ein Fehler aufgetreten.',
    'killswitch.label': 'Not-Aus',
    'killswitch.normal': 'normal',
    'chain.verifying': 'Kette wird geprüft',
    'chain.ok': 'Kette geprüft',
    'chain.broken': 'KETTE UNTERBROCHEN',
    'screen.map': 'Übersicht',
    'screen.memory': 'Gedächtnis',
    'screen.review': 'Zu prüfen',
    'screen.rules': 'Regeln',
    'screen.trace': 'Nachverfolgung',
    'screen.archive': 'Archiv',
    'screen.observability': 'Beobachtbarkeit',
    'screen.cases': 'Fälle',
    'screen.security': 'Sicherheit',
    'screen.comply': 'Compliance',
    'screen.insure': 'Versicherung',
    'screen.value': 'Nutzen',
    'screen.mydata': 'Meine Daten',
    'screen.admin': 'Verwaltung',
    'screen.setup': 'Einrichtung',
    'screen.status': 'Status',
    'a11y.mainLandmark': 'Hauptinhalt',
    'a11y.navLandmark': 'Hauptnavigation',
    'a11y.currentScreen': 'Aktuelle Ansicht',
    'a11y.sortedBy': 'Sortiert nach',
    'a11y.riskScore': 'Risikobewertung',
    'a11y.tableCaption': 'Datentabelle',
    'lang.label': 'Sprache der Oberfläche',
    'lang.note': 'Dies ändert nur die Oberfläche. Ihre Gedächtnisinhalte werden niemals maschinell übersetzt.'
  },

  fr: {
    'app.name': 'Vault',
    'app.tagline': 'La mémoire d\'IA partagée de l\'entreprise — avec un contrôle à l\'entrée, un enregistrement continu et une preuve que vous pouvez vérifier vous-même.',
    'auth.token': 'Jeton d\'accès',
    'auth.signin': 'Se connecter',
    'auth.signout': 'Se déconnecter',
    'auth.failed': 'Ce jeton n\'a pas été accepté.',
    'nav.label': 'Écrans',
    'nav.skip': 'Aller au contenu principal',
    'action.refresh': 'Actualiser',
    'action.close': 'Fermer',
    'action.cancel': 'Annuler',
    'action.confirm': 'Confirmer',
    'state.loading': 'Chargement…',
    'state.empty': 'Rien pour le moment.',
    'state.error': 'Une erreur est survenue.',
    'killswitch.label': 'Arrêt d\'urgence',
    'killswitch.normal': 'normal',
    'chain.verifying': 'vérification de la chaîne',
    'chain.ok': 'chaîne vérifiée',
    'chain.broken': 'CHAÎNE ROMPUE',
    'screen.map': 'Carte',
    'screen.memory': 'Mémoire',
    'screen.review': 'À examiner',
    'screen.rules': 'Règles',
    'screen.trace': 'Traçabilité',
    'screen.archive': 'Archives',
    'screen.observability': 'Observabilité',
    'screen.cases': 'Dossiers',
    'screen.security': 'Sécurité',
    'screen.comply': 'Conformité',
    'screen.insure': 'Assurance',
    'screen.value': 'Valeur',
    'screen.mydata': 'Mes données',
    'screen.admin': 'Administration',
    'screen.setup': 'Configuration',
    'screen.status': 'État',
    'a11y.mainLandmark': 'Contenu principal',
    'a11y.navLandmark': 'Navigation principale',
    'a11y.currentScreen': 'Écran actuel',
    'a11y.sortedBy': 'Trié par',
    'a11y.riskScore': 'Score de risque',
    'a11y.tableCaption': 'Tableau de données',
    'lang.label': 'Langue de l\'interface',
    'lang.note': 'Ceci ne change que l\'interface. Le contenu de votre mémoire n\'est jamais traduit automatiquement.'
  },

  ar: {
    'app.name': 'Vault',
    'app.tagline': 'الذاكرة المشتركة للذكاء الاصطناعي في الشركة — مع حارس على الباب، وتسجيل لا يتوقف، ودليل يمكنك التحقق منه بنفسك.',
    'auth.token': 'رمز الوصول',
    'auth.signin': 'تسجيل الدخول',
    'auth.signout': 'تسجيل الخروج',
    'auth.failed': 'لم يتم قبول هذا الرمز.',
    'nav.label': 'الشاشات',
    'nav.skip': 'تخطّي إلى المحتوى الرئيسي',
    'action.refresh': 'تحديث',
    'action.close': 'إغلاق',
    'action.cancel': 'إلغاء',
    'action.confirm': 'تأكيد',
    'state.loading': 'جارٍ التحميل…',
    'state.empty': 'لا يوجد شيء بعد.',
    'state.error': 'حدث خطأ ما.',
    'killswitch.label': 'مفتاح الإيقاف',
    'killswitch.normal': 'عادي',
    'chain.verifying': 'جارٍ التحقق من السلسلة',
    'chain.ok': 'تم التحقق من السلسلة',
    'chain.broken': 'السلسلة مكسورة',
    'screen.map': 'الخريطة',
    'screen.memory': 'الذاكرة',
    'screen.review': 'بحاجة إلى مراجعة',
    'screen.rules': 'القواعد',
    'screen.trace': 'التتبّع',
    'screen.archive': 'الأرشيف',
    'screen.observability': 'المراقبة',
    'screen.cases': 'الحالات',
    'screen.security': 'الأمن',
    'screen.comply': 'الامتثال',
    'screen.insure': 'التأمين',
    'screen.value': 'القيمة',
    'screen.mydata': 'بياناتي',
    'screen.admin': 'الإدارة',
    'screen.setup': 'الإعداد',
    'screen.status': 'الحالة',
    'a11y.mainLandmark': 'المحتوى الرئيسي',
    'a11y.navLandmark': 'التنقّل الرئيسي',
    'a11y.currentScreen': 'الشاشة الحالية',
    'a11y.sortedBy': 'مرتّب حسب',
    'a11y.riskScore': 'درجة المخاطر',
    'a11y.tableCaption': 'جدول بيانات',
    'lang.label': 'لغة الواجهة',
    'lang.note': 'هذا يغيّر الواجهة فقط. لا تتم ترجمة محتوى ذاكرتك آليًا أبدًا.'
  }
};

// Locales listed in LOCALES but without a STRINGS entry fall back to English,
// and coverage() reports exactly how far short they are. Shipping a language
// picker whose entries do nothing is worse than not offering them.
export function coverage() {
  const base = Object.keys(STRINGS.en);
  return Object.entries(LOCALES).map(([id, meta]) => {
    const table = STRINGS[id] || {};
    const translated = base.filter((k) => table[k] != null && table[k] !== STRINGS.en[k]).length;
    return {
      locale: id,
      name: meta.name,
      native: meta.native,
      dir: meta.dir,
      keys: base.length,
      translated: id === 'en' ? base.length : translated,
      percent: id === 'en' ? 100 : Math.round((translated / base.length) * 100),
      missing: id === 'en' ? [] : base.filter((k) => table[k] == null),
      // The honest label the picker shows next to the language name.
      status: id === 'en' ? 'complete'
        : translated === base.length ? 'complete'
          : translated === 0 ? 'not started — selecting this shows English'
            : `partial (${Math.round((translated / base.length) * 100)}%) — untranslated labels show in English`
    };
  });
}

export class I18n {
  /**
   * @param {object} [o]
   * @param {string} [o.locale]
   * @param {boolean} [o.markMissing] wrap untranslated strings so gaps are visible
   */
  constructor({ locale = 'en', markMissing = false } = {}) {
    this.markMissing = markMissing;
    this.missed = new Set();
    this.setLocale(locale);
  }

  setLocale(locale) {
    const id = STRINGS[locale] ? locale : (LOCALES[locale] ? locale : 'en');
    this.locale = id;
    this.dir = LOCALES[id]?.dir ?? 'ltr';
    this.table = STRINGS[id] || {};
    return { locale: this.locale, dir: this.dir };
  }

  /**
   * Translate. Interpolation uses {name} placeholders, and a placeholder with
   * no value is left visible rather than rendering "undefined" — a governance
   * screen that says "undefined facts were blocked" is worse than one that
   * says "{count} facts were blocked".
   */
  t(key, vars = null) {
    let s = this.table[key];
    if (s == null) {
      this.missed.add(key);
      s = STRINGS.en[key];
      if (s == null) return this.markMissing ? `⟦${key}⟧` : key;
      if (this.markMissing && this.locale !== 'en') s = `⟦${s}⟧`;
    }
    if (!vars) return s;
    return s.replace(/\{(\w+)\}/g, (whole, name) => (vars[name] != null ? String(vars[name]) : whole));
  }

  /** Numbers through Intl: "1,234" and "1.234" are different numbers elsewhere. */
  number(n, opts = {}) {
    if (n == null || Number.isNaN(n)) return '—';
    try { return new Intl.NumberFormat(this.locale, opts).format(n); } catch { return String(n); }
  }

  percent(fraction) {
    if (fraction == null) return '—';
    try { return new Intl.NumberFormat(this.locale, { style: 'percent', maximumFractionDigits: 0 }).format(fraction); } catch { return `${Math.round(fraction * 100)}%`; }
  }

  /**
   * Dates always carry their timezone.
   *
   * A retention deadline or a legal-hold date rendered in an ambiguous local
   * time is a date somebody will get wrong by a day, and in this product a day
   * is the difference between complying with a deletion order and not.
   */
  date(ts, { timeZone = 'UTC', style = 'medium' } = {}) {
    if (ts == null) return '—';
    try {
      // dateStyle/timeStyle cannot be combined with timeZoneName — ECMA-402
      // throws a TypeError — so the fields are spelled out. Getting this wrong
      // silently fell back to a raw ISO string, which is the one format that
      // ignores the reader's locale entirely.
      const long = style === 'long' || style === 'full';
      return new Intl.DateTimeFormat(this.locale, {
        year: 'numeric', month: long ? 'long' : 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', ...(long ? { second: '2-digit' } : {}),
        timeZone, timeZoneName: 'short'
      }).format(new Date(ts));
    } catch { return new Date(ts).toISOString(); }
  }

  relative(ts, from = Date.now()) {
    if (ts == null) return '—';
    const diff = ts - from;
    const units = [['year', 31536e6], ['month', 2592e6], ['week', 6048e5], ['day', 864e5], ['hour', 36e5], ['minute', 6e4], ['second', 1e3]];
    try {
      const rtf = new Intl.RelativeTimeFormat(this.locale, { numeric: 'auto' });
      for (const [unit, ms] of units) {
        if (Math.abs(diff) >= ms || unit === 'second') return rtf.format(Math.round(diff / ms), unit);
      }
    } catch { /* fall through */ }
    return new Date(ts).toISOString();
  }

  list(items, type = 'conjunction') {
    try { return new Intl.ListFormat(this.locale, { style: 'long', type }).format(items.map(String)); } catch { return items.join(', '); }
  }

  /** What the running interface is actually able to say, for the settings screen. */
  report() {
    return {
      locale: this.locale,
      dir: this.dir,
      available: coverage(),
      missingKeysSeenThisSession: [...this.missed],
      note: 'Interface chrome only. Facts, transcripts and evidence documents are never machine-translated — a mistranslated fact would be a governance failure, not a convenience.'
    };
  }
}

/** Pick the best supported locale from an Accept-Language header. */
export function negotiate(header, fallback = 'en') {
  if (!header) return fallback;
  const wanted = String(header).split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';');
      const q = params.map((p) => p.trim()).find((p) => p.startsWith('q='));
      return { tag: tag.trim().toLowerCase(), q: q ? Number(q.slice(2)) : 1 };
    })
    .filter((x) => x.tag && !Number.isNaN(x.q))
    .sort((a, b) => b.q - a.q);
  for (const { tag } of wanted) {
    if (LOCALES[tag]) return tag;
    const base = tag.split('-')[0];
    if (LOCALES[base]) return base;
  }
  return fallback;
}
