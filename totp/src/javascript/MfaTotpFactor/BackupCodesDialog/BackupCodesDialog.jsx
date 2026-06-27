import React, {useState} from 'react';
import PropTypes from 'prop-types';
import {useTranslation} from 'react-i18next';
import {Button, Typography, Modal, ModalHeader, ModalBody, ModalFooter} from '@jahia/moonstone';
import copy from 'copy-to-clipboard';

const BackupCodesDialog = ({isOpen, codes, onClose}) => {
    const {t} = useTranslation('mfa-factors-totp');
    const [copyConfirmed, setCopyConfirmed] = useState(false);

    const handleClose = () => {
        setCopyConfirmed(false);
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
 if (!open) {
 handleClose();
}
}}
        >
            <div>
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
                        {copyConfirmed ? t('backupCodesDialog.copied') : ''}
                    </Typography>
                </ModalBody>
                <ModalFooter>
                    <Button label={t('backupCodesDialog.copy')} onClick={copyAll}/>
                    <Button label={t('backupCodesDialog.download')} onClick={download}/>
                    <Button color="accent"
                            data-testid="backup-codes-close-btn"
                            label={t('backupCodesDialog.close')}
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
