// The interface languages this build ships.  Upstream reads these from the
// .twosky.json at the root of the AdGuard Home tree, which is the configuration
// of AdGuard's translation service; the fork carries the list itself instead, so
// nothing outside web/client is needed to build the interface.
//
// Every key here must have a matching src/__locales/<key>.json.

export const LANGUAGES: Record<string, string> = {
    'ar': 'العربية',
    'be': 'Беларуская',
    'bg': 'Български',
    'cs': 'Český',
    'da': 'Dansk',
    'de': 'Deutsch',
    'en': 'English',
    'es': 'Español',
    'fa': 'فارسی',
    'fi': 'Suomi',
    'fr': 'Français',
    'hr': 'Hrvatski',
    'hu': 'Magyar',
    'id': 'Indonesian',
    'it': 'Italiano',
    'ja': '日本語',
    'ko': '한국어',
    'nl': 'Nederlands',
    'no': 'Norsk',
    'pl': 'Polski',
    'pt-br': 'Português (BR)',
    'pt-pt': 'Português (PT)',
    'ro': 'Română',
    'ru': 'Русский',
    'si-lk': 'සිංහල',
    'sk': 'Slovenčina',
    'sl': 'Slovenščina',
    'sr-cs': 'Srpski',
    'sv': 'Svenska',
    'th': 'ภาษาไทย',
    'tr': 'Türkçe',
    'uk': 'Українська',
    'vi': 'Tiếng Việt',
    'zh-cn': '简体中文',
    'zh-hk': '繁體中文（香港）',
    'zh-tw': '正體中文（台灣）',
};

export const BASE_LOCALE = 'en';
