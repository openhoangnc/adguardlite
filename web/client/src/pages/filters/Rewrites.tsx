import { useState } from 'react';

import * as api from '../../api';
import type { Rewrite } from '../../api';
import { Card, Field, Loading, Modal, Notice, Table, useToast } from '../../components/ui';
import { IconEdit, IconPlus, IconTrash } from '../../components/icons';
import { message, useAsync } from '../../lib/hooks';

export default function Rewrites() {
    const toast = useToast();
    const list = useAsync(() => api.getRewrites());
    const [editing, setEditing] = useState<{ rule: Rewrite | null }>();

    if (!list.data && list.loading) {
        return <Loading />;
    }

    const rows = list.data ?? [];

    const remove = async (r: Rewrite) => {
        if (!window.confirm(`Delete the rewrite for "${r.domain}"?`)) {
            return;
        }

        try {
            await api.deleteRewrite(r);
            await list.reload();
            toast.ok(`Deleted the rewrite for ${r.domain}`);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const save = async (next: Rewrite, original: Rewrite | null) => {
        try {
            if (original) {
                await api.updateRewrite(original, next);
                toast.ok(`Saved the rewrite for ${next.domain}`);
            } else {
                await api.addRewrite(next);
                toast.ok(`Added a rewrite for ${next.domain}`);
            }
            setEditing(undefined);
            await list.reload();
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>DNS rewrites</h1>
                <p>Answer a name yourself instead of asking an upstream. Applies even while protection is off.</p>
            </div>

            {list.error && <Notice kind="error">{list.error}</Notice>}

            <Card
                actions={
                    <button type="button" className="btn primary" onClick={() => setEditing({ rule: null })}>
                        <IconPlus size={15} /> Add a rewrite
                    </button>
                }>
                <Table
                    className="rows"
                    empty="No rewrites yet."
                    head={
                        <>
                            <th>Name</th>
                            <th>Answer</th>
                            <th className="actions" />
                        </>
                    }>
                    {rows.map((r, i) => (
                        <tr key={`${r.domain}-${r.answer}-${i}`}>
                            <td className="mono" data-label="Name">
                                {r.domain}
                            </td>
                            <td className="mono" data-label="Answer">
                                {r.answer}
                            </td>
                            <td className="actions">
                                <button
                                    type="button"
                                    className="btn ghost icon"
                                    aria-label={`Edit ${r.domain}`}
                                    onClick={() => setEditing({ rule: r })}>
                                    <IconEdit size={16} />
                                </button>
                                <button
                                    type="button"
                                    className="btn ghost icon"
                                    aria-label={`Delete ${r.domain}`}
                                    onClick={() => void remove(r)}>
                                    <IconTrash size={16} />
                                </button>
                            </td>
                        </tr>
                    ))}
                </Table>
            </Card>

            {editing && <Editor rule={editing.rule} onClose={() => setEditing(undefined)} onSave={save} />}
        </>
    );
}

function Editor({
    rule,
    onClose,
    onSave,
}: {
    rule: Rewrite | null;
    onClose: () => void;
    onSave: (next: Rewrite, original: Rewrite | null) => Promise<void>;
}) {
    const [domain, setDomain] = useState(rule?.domain ?? '');
    const [answer, setAnswer] = useState(rule?.answer ?? '');
    const [busy, setBusy] = useState(false);

    return (
        <Modal
            title={rule ? `Edit ${rule.domain}` : 'Add a rewrite'}
            onClose={onClose}
            footer={
                <>
                    <button type="button" className="btn" onClick={onClose}>
                        Cancel
                    </button>
                    <button
                        type="button"
                        className="btn primary"
                        disabled={busy || !domain.trim() || !answer.trim()}
                        onClick={async () => {
                            setBusy(true);
                            try {
                                await onSave({ domain: domain.trim(), answer: answer.trim() }, rule);
                            } finally {
                                setBusy(false);
                            }
                        }}>
                        Save
                    </button>
                </>
            }>
            <Field label="Name" hint="A wildcard such as *.example.org covers every subdomain.">
                <input value={domain} autoFocus placeholder="nas.home.lan" onChange={(e) => setDomain(e.target.value)} />
            </Field>
            <Field
                label="Answer"
                hint="An address, or another name to resolve instead. Write A to drop IPv4 answers and AAAA to drop IPv6.">
                <input value={answer} placeholder="192.168.1.50" onChange={(e) => setAnswer(e.target.value)} />
            </Field>
        </Modal>
    );
}
