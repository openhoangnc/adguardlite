import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';

import * as api from '../api';
import { keepUnauthorizedHere } from '../api/client';
import { Notice } from '../components/ui';
import { Logo } from '../components/icons';
import { message } from '../lib/hooks';
import { applyTheme, rememberedTheme } from '../lib/theme';
import '../styles/app.css';

// A 401 here is the answer to a wrong password, not a lapsed session: showing
// it is the whole point of the page, so the redirect that every other page
// wants would be a reload loop.
keepUnauthorizedHere();
applyTheme(rememberedTheme());

function Login() {
    const [name, setName] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string>();
    const [busy, setBusy] = useState(false);

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        setBusy(true);
        setError(undefined);
        try {
            await api.login(name, password);
            // A full load, not a route change: the session cookie has to be on
            // the request that fetches the dashboard's own bundle.
            window.location.replace('./');
        } catch (err) {
            setError(message(err));
            setBusy(false);
        }
    };

    return (
        <div className="auth">
            <form className="auth-card" onSubmit={submit}>
                <div className="brand">
                    <Logo size={26} />
                    Sift
                </div>
                <p className="sub">Sign in</p>

                {error && <Notice kind="error">{error}</Notice>}

                <div className="field">
                    <label htmlFor="name">Username</label>
                    <input
                        id="name"
                        type="text"
                        autoComplete="username"
                        autoFocus
                        required
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                    />
                </div>

                <div className="field">
                    <label htmlFor="password">Password</label>
                    <input
                        id="password"
                        type="password"
                        autoComplete="current-password"
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                </div>

                <button type="submit" className="btn primary" style={{ width: '100%' }} disabled={busy}>
                    {busy && <span className="spinner" style={{ width: 13, height: 13, borderWidth: 2 }} />}
                    Sign in
                </button>
            </form>
        </div>
    );
}

createRoot(document.getElementById('root')!).render(
    <StrictMode>
        <Login />
    </StrictMode>,
);
