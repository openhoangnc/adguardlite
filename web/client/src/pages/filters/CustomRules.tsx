import { useEffect, useState } from 'react';

import * as api from '../../api';
import { Card, Loading, Notice, SaveButton, useToast } from '../../components/ui';
import { unlines } from '../../lib/format';
import { message, useAsync } from '../../lib/hooks';

/** What each form of rule does, shown under the editor. */
const EXAMPLES: [string, string][] = [
    ['||example.org^', 'block example.org and everything under it'],
    ['@@||example.org^', 'allow it again, overriding any list that blocks it'],
    ['||ads.example.org^$important', 'block it even if an allowlist says otherwise'],
    ['127.0.0.1 example.org', 'answer with this address, hosts-file style'],
    ['||example.org^$client=192.168.1.10', 'apply only to one client'],
    ['/^ads?[0-9]*\\./', 'match with a regular expression'],
    ['! a note to yourself', 'a comment; ignored'],
];

export default function CustomRules() {
    const toast = useToast();
    const status = useAsync(() => api.getFilteringStatus());
    const [text, setText] = useState('');

    useEffect(() => {
        if (status.data) {
            setText(unlines(status.data.user_rules));
        }
    }, [status.data]);

    if (!status.data) {
        return status.error ? <Notice kind="error">{status.error}</Notice> : <Loading />;
    }

    const save = async () => {
        try {
            // Blank lines are kept: a user's spacing in this box is theirs, and
            // the server stores the list verbatim.
            await api.setUserRules(text.split('\n'));
            await status.reload();
            toast.ok('Custom rules saved');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>Custom rules</h1>
                <p>Your own rules, checked before every list. One per line.</p>
            </div>

            <Card>
                <textarea
                    value={text}
                    spellCheck={false}
                    style={{ minHeight: 320 }}
                    placeholder="||example.org^"
                    onChange={(e) => setText(e.target.value)}
                />
                <div style={{ marginTop: 12 }}>
                    <SaveButton onClick={save}>Apply</SaveButton>
                </div>
            </Card>

            <Card title="Syntax">
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {EXAMPLES.map(([rule, what]) => (
                        <li key={rule} style={{ marginBottom: 6 }}>
                            <code className="mono">{rule}</code> — <span className="muted">{what}</span>
                        </li>
                    ))}
                </ul>
            </Card>
        </>
    );
}
