import React, {useEffect, useState} from 'react';
import PropTypes from 'prop-types';
import {useTranslation} from 'react-i18next';
import {Button, Input, Typography, Modal, ModalHeader, ModalBody, ModalFooter} from '@jahia/moonstone';

// A bare 6-digit TOTP code, or a backup code (alphanumeric with optional dashes) when allowed.
const TOTP_CODE_LENGTH = 6;
const BACKUP_CODE_MIN_LENGTH = 8;

const CodePromptDialog = ({
    isOpen, title, description, acceptLabel, acceptColor, isBackupCodeAllowed,
    isLoading, errorKey, onCancel, onAccept
}) => {
    const {t} = useTranslation('mfa-factors-totp');
    const [code, setCode] = useState('');

    useEffect(() => {
        if (!isOpen) {
            setCode('');
        }
    }, [isOpen]);

    if (!isOpen) {
        return null;
    }

    // TOTP-only path: digits, exactly 6. Backup-code path: alphanumeric + dashes, longer.
    const sanitize = value => (isBackupCodeAllowed ?
        value.replace(/[^A-Za-z0-9-]/g, '') :
        value.replace(/\D/g, '').slice(0, TOTP_CODE_LENGTH));
    const isValid = isBackupCodeAllowed ?
        (/^\d{6}$/.test(code) || code.replace(/-/g, '').length >= BACKUP_CODE_MIN_LENGTH) :
        code.length === TOTP_CODE_LENGTH;
    const fieldLabel = isBackupCodeAllowed ? t('codePrompt.codeOrBackupLabel') : description;
    const fieldPlaceholder = isBackupCodeAllowed ? t('codePrompt.codeOrBackupPlaceholder') : '123456';

    return (
        <Modal isOpen={isOpen}
               size="small"
               onOpenChange={open => {
 if (!open) {
 onCancel();
}
}}
        >
            <div>
                <ModalHeader title={title}/>
                <ModalBody>
                    <Typography>{description}</Typography>
                    {isBackupCodeAllowed && (
                        <Typography variant="caption" style={{display: 'block', marginTop: 8, color: '#555'}}>
                            {t('codePrompt.backupHint')}
                        </Typography>
                    )}
                    <Input data-testid="code-prompt-input"
                           value={code}
                           maxLength={isBackupCodeAllowed ? 40 : TOTP_CODE_LENGTH}
                           inputMode={isBackupCodeAllowed ? 'text' : 'numeric'}
                           placeholder={fieldPlaceholder}
                           aria-label={fieldLabel}
                           aria-describedby={errorKey ? 'code-prompt-error' : undefined}
                           style={{marginTop: 12}}
                           onChange={e => setCode(sanitize(e.target.value))}/>
                    {errorKey && (
                        <Typography id="code-prompt-error"
                                    role="alert"
                                    style={{marginTop: 12, color: '#a00000', display: 'block'}}
                                    data-testid="code-prompt-error"
                        >
                            {t(errorKey)}
                        </Typography>
                    )}
                </ModalBody>
                <ModalFooter>
                    <Button label={t('cancel')} onClick={onCancel}/>
                    <Button color={acceptColor || 'accent'}
                            data-testid="code-prompt-accept-btn"
                            label={acceptLabel}
                            isDisabled={isLoading || !isValid}
                            onClick={() => onAccept(code)}/>
                </ModalFooter>
            </div>
        </Modal>
    );
};

CodePromptDialog.propTypes = {
    isOpen: PropTypes.bool.isRequired,
    title: PropTypes.string.isRequired,
    description: PropTypes.string.isRequired,
    acceptLabel: PropTypes.string.isRequired,
    acceptColor: PropTypes.string,
    isBackupCodeAllowed: PropTypes.bool,
    isLoading: PropTypes.bool,
    errorKey: PropTypes.string,
    onCancel: PropTypes.func.isRequired,
    onAccept: PropTypes.func.isRequired
};

export default CodePromptDialog;
