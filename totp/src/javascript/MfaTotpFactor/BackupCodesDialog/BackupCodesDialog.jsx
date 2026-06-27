import React, {useState} from 'react';
import PropTypes from 'prop-types';
import {useTranslation} from 'react-i18next';
import {Button, Typography, Modal, ModalHeader, ModalBody, ModalFooter} from '@jahia/moonstone';
import copy from 'copy-to-clipboard';

// Moonstone's CSS reset can drop the native focus ring on raw <input> elements. This module's
// webpack only loads .scss (no plain .css loader), so the focus-visible rule is injected via a
// plain <style> element instead of a CSS module. Restores a high-contrast WCAG 2.2 focus ring.
const ADMIN_INPUT_FOCUS_STYLE = '.mfa-admin-input:focus-visible{outline:2px solid #00538b;outline-offset:2px;}';

const BackupCodesDialog = ({isOpen, codes, onClose}) => {
    const {t} = useTranslation('mfa-factors-totp');
    const [copyConfirmed, setCopyConfirmed] = useState(false);
    // One-shot codes must not be dismissed before the user acknowledges they saved them, so
    // backdrop/Esc closing is guarded and the close button stays disabled until acknowledged.
    const [acknowledged, setAcknowledged] = useState(false);

    const handleClose = () => {
        setCopyConfirmed(false);
        setAcknowledged(false);
        onClose();
    };

    const copyAll = () => {
        const ok = copy(codes.join('\n'));
        setCopyConfirmed(ok !== false);
    };

    const download = () => {
        const blob = new Blob([codes.join('\n') + '\n'], {type: 'text/plain'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'mfa-backup-codes.txt';
        a.click();
        URL.revokeObjectURL(url);
    };

    if (!isOpen) {
        return null;
    }

    return (
        <Modal isOpen={isOpen}
               size="small"
               onOpenChange={open => {
 if (!open && acknowledged) {
 handleClose();
}
}}
        >
            <div>
                <style>{ADMIN_INPUT_FOCUS_STYLE}</style>
                <ModalHeader title={t('backupCodesDialog.title')}/>
                <ModalBody>
                    <Typography style={{marginBottom: 16, display: 'block'}}>
                        {t('backupCodesDialog.warning')}
                    </Typography>
                    <pre data-testid="backup-codes-list"
                         style={{
                             fontFamily: 'monospace',
                             background: '#f6f6f6',
                             padding: 12,
                             borderRadius: 4,
                             margin: 0
                         }}
                    >
                        {codes.join('\n')}
                    </pre>
                    <Typography role="status"
                                aria-live="polite"
                                data-testid="backup-codes-copy-status"
                                style={{display: 'block', marginTop: 12, color: '#006600', minHeight: '1.2em'}}
                    >
                        {/* A leading checkmark glyph carries the success cue without relying on colour alone. */}
                        {copyConfirmed ? `✓ ${t('backupCodesDialog.copied')}` : ''}
                    </Typography>
                    <div style={{display: 'flex', alignItems: 'flex-start', gap: 8, marginTop: 16}}>
                        <input id="backup-codes-ack"
                               type="checkbox"
                               checked={acknowledged}
                               data-testid="backup-codes-ack"
                               className="mfa-admin-input"
                               style={{marginTop: 4, cursor: 'pointer'}}
                               onChange={e => setAcknowledged(e.target.checked)}/>
                        <label htmlFor="backup-codes-ack" style={{cursor: 'pointer'}}>
                            {t('backupCodesDialog.acknowledge')}
                        </label>
                    </div>
                </ModalBody>
                <ModalFooter>
                    <Button label={t('backupCodesDialog.copy')} onClick={copyAll}/>
                    <Button label={t('backupCodesDialog.download')} onClick={download}/>
                    <Button color="accent"
                            data-testid="backup-codes-close-btn"
                            label={t('backupCodesDialog.close')}
                            isDisabled={!acknowledged}
                            onClick={handleClose}/>
                </ModalFooter>
            </div>
        </Modal>
    );
};

BackupCodesDialog.propTypes = {
    isOpen: PropTypes.bool.isRequired,
    codes: PropTypes.arrayOf(PropTypes.string).isRequired,
    onClose: PropTypes.func.isRequired
};

export default BackupCodesDialog;
