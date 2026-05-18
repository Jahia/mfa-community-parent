import React, {useEffect, useRef, useState} from 'react';
import PropTypes from 'prop-types';
import {useTranslation} from 'react-i18next';
import {Dialog, DialogTitle, DialogContent, DialogActions} from '@material-ui/core';
import {Button, Input, Typography} from '@jahia/moonstone';
import QRCode from 'qrcode';

const EnrollDialog = ({isOpen, enrollData, isLoading, errorKey, onCancel, onConfirm}) => {
    const {t} = useTranslation('mfa-totp-factor');
    const canvasRef = useRef(null);
    const [code, setCode] = useState('');

    useEffect(() => {
        if (isOpen && enrollData && canvasRef.current) {
            QRCode.toCanvas(canvasRef.current, enrollData.otpauthUri, {width: 224}, err => {
                if (err) {
                    console.error('QR render failed', err);
                }
            });
        }
    }, [isOpen, enrollData]);

    useEffect(() => {
        if (!isOpen) {
            setCode('');
        }
    }, [isOpen]);

    if (!isOpen || !enrollData) {
        return null;
    }

    return (
        <Dialog open={isOpen} onClose={onCancel} maxWidth="sm" fullWidth>
            <DialogTitle>{t('enrollDialog.title')}</DialogTitle>
            <DialogContent>
                <Typography>{t('enrollDialog.step1')}</Typography>
                <div style={{textAlign: 'center', margin: '16px 0'}}>
                    <canvas ref={canvasRef} data-testid="enroll-qr"/>
                </div>
                <Typography variant="caption" data-testid="enroll-secret"
                            style={{display: 'block', textAlign: 'center', fontFamily: 'monospace', wordBreak: 'break-all'}}>
                    {enrollData.secret}
                </Typography>
                <Typography style={{marginTop: 16}}>{t('enrollDialog.step2')}</Typography>
                <Input data-testid="enroll-code-input"
                       value={code}
                       maxLength={10}
                       placeholder="123456"
                       style={{marginTop: 8}}
                       onChange={e => setCode(e.target.value.replace(/\D/g, ''))}/>
                {errorKey && (
                    <Typography style={{marginTop: 12, color: '#c00'}} data-testid="enroll-error">
                        {t(errorKey)}
                    </Typography>
                )}
            </DialogContent>
            <DialogActions>
                <Button label={t('cancel')} onClick={onCancel}/>
                <Button color="accent"
                        data-testid="enroll-confirm-btn"
                        label={t('confirm')}
                        isDisabled={isLoading || code.length < 6}
                        onClick={() => onConfirm(code)}/>
            </DialogActions>
        </Dialog>
    );
};

EnrollDialog.propTypes = {
    isOpen: PropTypes.bool.isRequired,
    enrollData: PropTypes.shape({
        secret: PropTypes.string,
        otpauthUri: PropTypes.string,
        issuer: PropTypes.string,
        accountName: PropTypes.string
    }),
    isLoading: PropTypes.bool,
    errorKey: PropTypes.string,
    onCancel: PropTypes.func.isRequired,
    onConfirm: PropTypes.func.isRequired
};

export default EnrollDialog;
