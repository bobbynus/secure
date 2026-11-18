import type { Lang } from './ui';

/** Static informational pages. Plain paragraphs; `code` allowed (see lib/format inline). */
export const STATIC_PAGES = ['about', 'privacy', 'contacts'] as const;
export type StaticPage = (typeof STATIC_PAGES)[number];

type Section = { id?: string; h?: string; p: string[] };

export const PAGES: Record<StaticPage, Record<Lang, Section[]>> = {
  about: {
    ru: [
      {
        p: [
          'secure.abramov.vip — публичный радар для системных и сетевых администраторов. Главный вопрос каждой карточки: что произошло, затронута ли моя инфраструктура и что проверить или предпринять.',
          'В одной ленте собраны три направления: уязвимости, атаки и инциденты, проблемные обновления (регрессии, отозванные релизы, ошибки установки).',
        ],
      },
      {
        h: 'Как появляются материалы',
        p: [
          'Сборщики регулярно опрашивают официальные фиды и API (каталог — на странице «Об источниках»). Сообщения из разных источников объединяются в одно событие со стабильным адресом; история изменений сохраняется.',
          'ИИ помогает с кратким пересказом, извлечением полей и переводом, но не является источником фактов. Версии, CVSS, сведения об эксплуатации и исправлениях берутся только из указанных источников; идентификаторы CVE/KB, URL и команды проверяются на неизменность во всех языковых версиях.',
        ],
      },
      {
        h: 'Уровни подтверждения',
        p: [
          '«Подтверждено производителем» — есть advisory, release notes или статус производителя. «Подтверждено официальным источником» — например, CISA KEV или национальный CERT. «Предварительные сообщения» — данные исследователей, СМИ или сообщества, пока без официального подтверждения. Одна жалоба не считается подтверждением массовой проблемы.',
        ],
      },
      {
        h: 'Приоритет и CVSS',
        p: [
          'Редакционный приоритет учитывает подтверждённую эксплуатацию, распространённость продукта и доступность исправления. Он не совпадает с CVSS: оценка CVSS показывается отдельно, с версией шкалы и источником.',
        ],
      },
    ],
    de: [
      {
        p: [
          'secure.abramov.vip ist ein öffentliches Radar für System- und Netzwerkadministratoren. Jede Karte beantwortet: Was ist passiert, ist meine Infrastruktur betroffen und was sollte ich prüfen oder tun?',
          'Ein Feed bündelt drei Bereiche: Schwachstellen, Angriffe und Vorfälle sowie fehlerhafte Updates (Regressionen, zurückgezogene Releases, Installationsfehler).',
        ],
      },
      {
        h: 'Wie Inhalte entstehen',
        p: [
          'Collector fragen regelmäßig offizielle Feeds und APIs ab (Katalog unter „Über die Quellen“). Meldungen aus verschiedenen Quellen werden zu einem Ereignis mit stabiler Adresse zusammengeführt; der Änderungsverlauf bleibt erhalten.',
          'KI hilft bei Zusammenfassung, Feldextraktion und Übersetzung, ist aber keine Faktenquelle. Versionen, CVSS, Angaben zu Ausnutzung und Fixes stammen ausschließlich aus den genannten Quellen; CVE/KB-Kennungen, URLs und Befehle werden in allen Sprachversionen auf Unverändertheit geprüft.',
        ],
      },
      {
        h: 'Bestätigungsstufen',
        p: [
          '„Vom Hersteller bestätigt“ – es gibt ein Advisory, Release Notes oder einen Herstellerstatus. „Offiziell bestätigt“ – z. B. CISA KEV oder ein nationales CERT. „Vorläufige Meldungen“ – Angaben von Forschern, Medien oder Community ohne offizielle Bestätigung. Eine einzelne Beschwerde gilt nicht als Bestätigung eines verbreiteten Problems.',
        ],
      },
      {
        h: 'Priorität und CVSS',
        p: [
          'Die redaktionelle Priorität berücksichtigt bestätigte Ausnutzung, Verbreitung des Produkts und Verfügbarkeit eines Fixes. Sie entspricht nicht dem CVSS: Der CVSS-Wert wird separat mit Version und Quelle angezeigt.',
        ],
      },
    ],
    en: [
      {
        p: [
          'secure.abramov.vip is a public radar for system and network administrators. Every card answers: what happened, is my infrastructure affected, and what should I check or do?',
          'One feed covers three areas: vulnerabilities, attacks and incidents, and problematic updates (regressions, pulled releases, installation failures).',
        ],
      },
      {
        h: 'How content is produced',
        p: [
          'Collectors regularly poll official feeds and APIs (see “About sources” for the catalog). Reports from different sources are merged into one event with a stable address; the change history is kept.',
          'AI helps with summaries, field extraction and translation, but it is not a source of facts. Versions, CVSS, exploitation and fix details come only from the cited sources; CVE/KB identifiers, URLs and commands are checked to be identical in every language version.',
        ],
      },
      {
        h: 'Confirmation levels',
        p: [
          '“Confirmed by vendor” — there is an advisory, release notes or a vendor status page. “Confirmed by official source” — e.g. CISA KEV or a national CERT. “Preliminary reports” — information from researchers, media or the community without official confirmation yet. A single complaint is not treated as confirmation of a widespread problem.',
        ],
      },
      {
        h: 'Priority and CVSS',
        p: [
          'Editorial priority considers confirmed exploitation, how widespread the product is and whether a fix is available. It is not the CVSS score: CVSS is shown separately, with its version and source.',
        ],
      },
    ],
  },
  privacy: {
    ru: [
      {
        p: [
          'Сайт статический: без регистрации, рекламы, cookie и сторонних трекеров. Шрифты и скрипты загружаются с этого же домена.',
          'Сайт размещён в Cloudflare. Как инфраструктурный провайдер, Cloudflare может обрабатывать технические данные запросов (например, IP-адрес) для доставки и защиты сайта.',
          'Ссылки на Ko-fi, GitHub и Telegram ведут на внешние сервисы со своими правилами конфиденциальности. Предложение источника публикуется как открытый GitHub Issue.',
        ],
      },
      {
        id: 'stats',
        h: 'Статистика просмотров и онлайн',
        p: [
          'Публичная статусная панель показывает приблизительные значения. «Просмотры сегодня» — зарегистрированные открытия страниц за текущие сутки UTC; «всего» — с запуска счётчика; просмотры статьи — сумма трёх языковых версий одного события.',
          '«Активные сессии» — число вкладок, которые за последние 2 минуты отправили сигнал активности (раз в ~50 секунд, только для видимой вкладки). Идентификатор — случайное значение, живущее в sessionStorage до закрытия вкладки. Это оценка, а не число людей.',
          'Не используются cookie, fingerprinting и постоянные идентификаторы; IP-адреса не сохраняются в данных приложения и применяются только для кратковременного ограничения частоты запросов. Очевидные боты отсеиваются, но блокировщики скриптов и накрутка возможны — статистика приблизительная. Отказ статистики не влияет на работу сайта.',
        ],
      },
      {
        h: 'Push-уведомления',
        p: [
          'При подписке сохраняются адрес подписки, выданный вашим браузером его push-сервисом (Google, Mozilla, Apple, Microsoft), ключи шифрования и выбранные настройки. Содержимое уведомлений шифруется. Отписка на странице «Push» удаляет эти данные.',
        ],
      },
      {
        h: 'Предложение источника',
        p: [
          'Форма создаёт открытый GitHub Issue от имени проекта. Контакты не запрашиваются; сохраняется только нормализованный адрес источника для проверки дублей.',
        ],
      },
    ],
    de: [
      {
        p: [
          'Die Seite ist statisch: keine Registrierung, keine Werbung, keine Cookies und keine Tracker von Drittanbietern. Schriften und Skripte werden von derselben Domain geladen.',
          'Die Seite wird bei Cloudflare gehostet. Als Infrastrukturanbieter kann Cloudflare technische Anfragedaten (z. B. die IP-Adresse) zur Auslieferung und zum Schutz der Seite verarbeiten.',
          'Links zu Ko-fi, GitHub und Telegram führen zu externen Diensten mit eigenen Datenschutzbestimmungen. Quellenvorschläge werden als öffentliche GitHub-Issues veröffentlicht.',
        ],
      },
      {
        id: 'stats',
        h: 'Aufrufstatistik und aktive Sitzungen',
        p: [
          'Die öffentliche Statusleiste zeigt ungefähre Werte. „Aufrufe heute“ – registrierte Seitenaufrufe am aktuellen UTC-Tag; „gesamt“ – seit Start des Zählers; Aufrufe eines Beitrags – Summe der drei Sprachversionen eines Ereignisses.',
          '„Aktive Sitzungen“ – Anzahl der Tabs, die in den letzten 2 Minuten ein Aktivitätssignal gesendet haben (etwa alle 50 Sekunden, nur sichtbare Tabs). Die Kennung ist ein Zufallswert in sessionStorage, der mit dem Tab verschwindet. Es ist eine Schätzung, keine Personenzahl.',
          'Es werden keine Cookies, kein Fingerprinting und keine dauerhaften Kennungen verwendet; IP-Adressen werden nicht in Anwendungsdaten gespeichert und nur kurzzeitig zur Ratenbegrenzung genutzt. Offensichtliche Bots werden herausgefiltert, Skriptblocker und Manipulation sind dennoch möglich – die Statistik ist ungefähr. Ein Ausfall beeinträchtigt die Seite nicht.',
        ],
      },
      {
        h: 'Push-Benachrichtigungen',
        p: [
          'Beim Abonnieren werden die von Ihrem Browser bei seinem Push-Dienst (Google, Mozilla, Apple, Microsoft) erzeugte Abonnement-Adresse, die Schlüssel und die gewählten Einstellungen gespeichert. Inhalte werden verschlüsselt übertragen. Abmelden auf der Seite „Push“ löscht diese Daten.',
        ],
      },
      {
        h: 'Quellenvorschläge',
        p: [
          'Das Formular erstellt ein öffentliches GitHub-Issue im Namen des Projekts. Kontaktdaten werden nicht abgefragt; gespeichert wird nur die normalisierte Quell-URL zur Dublettenprüfung.',
        ],
      },
    ],
    en: [
      {
        p: [
          'The site is static: no sign-up, no ads, no cookies and no third-party trackers. Fonts and scripts are served from this domain.',
          'The site is hosted on Cloudflare. As the infrastructure provider, Cloudflare may process technical request data (such as IP addresses) to deliver and protect the site.',
          'Links to Ko-fi, GitHub and Telegram lead to external services with their own privacy policies. Source suggestions are published as public GitHub issues.',
        ],
      },
      {
        id: 'stats',
        h: 'View statistics and active sessions',
        p: [
          'The public status bar shows approximate values. “Views today” are registered page opens during the current UTC day; “total” since the counter started; article views are the sum of an event’s three language versions.',
          '“Active sessions” is the number of tabs that sent an activity signal in the last 2 minutes (about every 50 seconds, visible tabs only). The identifier is a random value kept in sessionStorage until the tab is closed. It is an estimate, not a number of people.',
          'No cookies, fingerprinting or persistent identifiers are used; IP addresses are not stored in application data and are only used briefly for rate limiting. Obvious bots are filtered out, but script blockers and manipulation are possible — the numbers are approximate. A statistics outage does not affect the site.',
        ],
      },
      {
        h: 'Push notifications',
        p: [
          'When you subscribe, the subscription address issued by your browser’s push service (Google, Mozilla, Apple, Microsoft), its encryption keys and your settings are stored. Notification content is encrypted. Unsubscribing on the “Push” page deletes this data.',
        ],
      },
      {
        h: 'Source suggestions',
        p: [
          'The form creates a public GitHub issue on behalf of the project. No contact details are requested; only the normalised source URL is kept for duplicate checks.',
        ],
      },
    ],
  },
  contacts: {
    ru: [
      {
        p: [
          'Ошибки в материалах, неточные версии или неработающие ссылки — откройте Issue в репозитории проекта на GitHub. Новый источник — через форму «+ Источник».',
          'Пожалуйста, не присылайте конфиденциальные данные и сведения о неисправленных уязвимостях: о них сообщайте напрямую производителю.',
        ],
      },
    ],
    de: [
      {
        p: [
          'Fehler in Beiträgen, ungenaue Versionen oder defekte Links – bitte ein Issue im GitHub-Repository des Projekts eröffnen. Neue Quellen über das Formular „+ Quelle“.',
          'Bitte keine vertraulichen Daten und keine Informationen zu ungepatchten Schwachstellen senden: Diese bitte direkt an den Hersteller melden.',
        ],
      },
    ],
    en: [
      {
        p: [
          'Errors in articles, inaccurate versions or broken links — please open an issue in the project’s GitHub repository. New sources go through the “+ Source” form.',
          'Please do not send confidential data or details of unpatched vulnerabilities: report those directly to the vendor.',
        ],
      },
    ],
  },
};
