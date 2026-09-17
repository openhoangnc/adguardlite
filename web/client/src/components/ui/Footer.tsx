import React, { useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useDispatch, useSelector } from 'react-redux';
import cn from 'classnames';

import { REPOSITORY, PRIVACY_POLICY_LINK, THEMES } from '../../helpers/constants';
import { LANGUAGES } from '../../helpers/languages';
import i18n from '../../i18n';

import Version from './Version';
import './Footer.css';
import './Select.css';

import { setHtmlLangAttr, setUITheme } from '../../helpers/helpers';

import { changeLanguage, changeTheme } from '../../actions';
import { RootState } from '../../initialState';

const linksData = [
    {
        href: REPOSITORY.URL,
        name: 'homepage',
    },
    {
        href: PRIVACY_POLICY_LINK,
        name: 'privacy_policy',
    },
    {
        href: REPOSITORY.ISSUES,
        className: 'btn btn-outline-primary btn-sm footer__link--report',
        name: 'report_an_issue',
    },
];

const Footer = () => {
    const { t } = useTranslation();
    const dispatch = useDispatch();

    const currentTheme = useSelector((state: RootState) => (state.dashboard ? state.dashboard.theme : THEMES.auto));
    const profileName = useSelector((state: RootState) => (state.dashboard ? state.dashboard.name : ''));
    const isLoggedIn = profileName !== '';
    const [currentThemeLocal, setCurrentThemeLocal] = useState(THEMES.auto);

    const onLanguageChange = (language: string) => {
        i18n.changeLanguage(language);
        setHtmlLangAttr(language);

        if (isLoggedIn) {
            dispatch(changeLanguage(language));
        }
    };

    const onThemeChange = (value: any) => {
        if (isLoggedIn) {
            dispatch(changeTheme(value));
        } else {
            setUITheme(value);
            setCurrentThemeLocal(value);
        }
    };

    // Two statements, because there are two works here: Sift, which is this
    // project's, and the interface, which is AdGuard's and which the GPL
    // requires be credited as theirs.  A bare "Copyright (c) AdGuard" claimed
    // the whole page for them and left this project's own work unattributed.
    const renderCopyright = () => (
        <div className="footer__column">
            <div className="footer__copyright">
                <Trans
                    components={[
                        <a
                            key="0"
                            target="_blank"
                            rel="noopener noreferrer"
                            href="https://www.gnu.org/licenses/gpl-3.0.html">
                            GPL-3.0
                        </a>,
                        <a
                            key="1"
                            target="_blank"
                            rel="noopener noreferrer"
                            href={REPOSITORY.URL}>
                            source code
                        </a>,
                    ]}>
                    copyright_notice
                </Trans>
            </div>

            <div className="footer__copyright footer__fork-notice">
                <Trans
                    components={[
                        <a
                            key="0"
                            target="_blank"
                            rel="noopener noreferrer"
                            href="https://adguard.com/en/welcome.html">
                            AdGuard Software Ltd.
                        </a>,
                        <a
                            key="1"
                            target="_blank"
                            rel="noopener noreferrer"
                            href="https://github.com/AdguardTeam/AdGuardHome">
                            AdGuard Home
                        </a>,
                    ]}>
                    fork_notice
                </Trans>
            </div>
        </div>
    );

    const renderLinks = (linksData: any) =>
        linksData.map(({ name, href, className = '' }: any) => (
            <a
                key={name}
                href={href}
                className={cn('footer__link', className)}
                target="_blank"
                rel="noopener noreferrer">
                {t(name)}
            </a>
        ));

    const renderThemeButtons = () => {
        const currentValue = isLoggedIn ? currentTheme : currentThemeLocal;

        const content = {
            auto: {
                desc: t('theme_auto_desc'),
                icon: '#auto',
                testId: 'theme_auto',
            },
            dark: {
                desc: t('theme_dark_desc'),
                icon: '#dark',
                testId: 'theme_dark',
            },
            light: {
                desc: t('theme_light_desc'),
                icon: '#light',
                testId: 'theme_light',
            },
        };

        return Object.values(THEMES)

            .map((theme: any) => (
                <button
                    key={theme}
                    type="button"
                    className="btn btn-sm btn-secondary footer__theme-button"
                    onClick={() => onThemeChange(theme)}
                    title={content[theme].desc}
                    data-testid={content[theme].testId}
                >
                    <svg className={cn('footer__theme-icon', { 'footer__theme-icon--active': currentValue === theme })}>
                        <use xlinkHref={content[theme].icon} />
                    </svg>
                </button>
            ));
    };

    return (
        <>
            <footer className="footer">
                <div className="container">
                    <div className="footer__row">
                        <div className="footer__column footer__column--links">{renderLinks(linksData)}</div>

                        <div className="footer__column footer__column--theme">
                            <div className="footer__themes">
                                <div className="btn-group">{renderThemeButtons()}</div>
                            </div>
                        </div>

                        <div className="footer__column footer__column--language">
                            <select
                                className="form-control select select--language"
                                value={i18n.language}
                                onChange={(e) => onLanguageChange(e.target.value)}>
                                {Object.keys(LANGUAGES).map((lang) => (
                                    <option key={lang} value={lang}>
                                        {LANGUAGES[lang]}
                                    </option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>
            </footer>

            <div className="footer">
                <div className="container">
                    <div className="footer__row">
                        {renderCopyright()}

                        <div className="footer__column footer__column--language">
                            <Version />
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
};

export default Footer;
