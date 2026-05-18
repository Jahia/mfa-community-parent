import React, {useEffect, useState} from 'react';
import PropTypes from 'prop-types';
import {useTranslation} from 'react-i18next';
import {Dialog, DialogTitle, DialogContent, DialogActions} from '@material-ui/core';
import {Button, Input, Typography} from '@jahia/moonstone';

const CodePromptDialog = ({
    isOpen, title, description, acceptLabel, acceptColor,
    isLoading, errorKey, onCancel, onAccept
}) => {
    const {t} = useTranslation('mfa-totp-factor');
    const [code, setCode] = useState('');

    useEffect(() => {
        if (!isOpen) {
            setCode('');
        }
    }, [isOpen]);

    return (
        <Dialog open={isOpen} onClose={onCancel} maxWidth="xs" fullWidth>
            <DialogTitle>{title}</DialogTitle>
            <DialogContent>
                <Typography>{description}</Typography>
                <Input data-testid="code-prompt-input"
                       value={code}
                       maxLength={10}
                       placeholder="123456"
                       style={{marginTop: 12}}
                       onChange={e => setCode(e.target.value.replace(/[^A-Za-z0-9-]/g, ''))}/>
                {errorKey && (
                    <Typography style={{marginTop: 12, color: '#c00'}} data-testid="code-prompt-error">
                        {t(errorKey)}
                    </Typography>
                )}
            </DialogContent>
            <DialogActions>
                <Button label={t('cancel')} onClick={onCancel}/>
                <Button color={acceptColor || 'accent'}
                        data-testid="code-prompt-accept-btn"
                        label={acceptLabel}
                        isDisabled={isLoading || code.length < 6}
                        onClick={() => onAccept(code)}/>
            </DialogActions>
        </Dialog>
    );
};

CodePromptDialog.propTypes = {
    isOpen: PropTypes.bool.isRequired,
    title: PropTypes.string.isRequired,
    description: PropTypes.string.isRequired,
    acceptLabel: PropTypes.string.isRequired,
    acceptColor: PropTypes.string,
    isLoading: PropTypes.bool,
    errorKey: PropTypes.string,
    onCancel: PropTypes.func.isRequired,
    onAccept: PropTypes.func.isRequired
};

export default CodePromptDialog;
