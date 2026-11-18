import type { Lang } from './ui';

/** Static informational pages. Plain paragraphs; `code` allowed (see lib/format inline). */
export const STATIC_PAGES = ['about', 'privacy', 'contacts'] as const;
export type StaticPage = (typeof STATIC_PAGES)[number];

type Section = { h?: string; p: string[] };

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
        h: 'Будущие функции',
        p: [
          'Счётчики просмотров и оценка активных сессий будут работать без cookie, fingerprinting и постоянных идентификаторов, без хранения IP в прикладных данных. Методика будет опубликована до включения. Эта страница будет обновлена.',
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
        h: 'Künftige Funktionen',
        p: [
          'Aufrufzähler und die Schätzung aktiver Sitzungen werden ohne Cookies, Fingerprinting und dauerhafte Kennungen arbeiten und keine IP-Adressen in Anwendungsdaten speichern. Die Methodik wird vor der Aktivierung veröffentlicht. Diese Seite wird dann aktualisiert.',
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
        h: 'Upcoming features',
        p: [
          'View counters and the active-session estimate will work without cookies, fingerprinting or persistent identifiers, and without storing IP addresses in application data. The methodology will be published before they are enabled. This page will be updated.',
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
