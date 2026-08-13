import {describe, it, expect, afterEach} from 'vitest';
import {resolveSiteKey, mapAdminError} from './siteSettings.util';

describe('resolveSiteKey', () => {
    afterEach(() => {
        delete window.contextJsParameters;
        window.history.pushState({}, '', '/');
    });

    it('reads the site key from contextJsParameters when present', () => {
        window.contextJsParameters = {siteKey: 'mySite'};
        window.history.pushState({}, '', '/some/other/path');

        expect(resolveSiteKey()).toBe('mySite');
    });

    it('falls back to the /sites/<siteKey>/ URL segment when contextJsParameters is absent', () => {
        window.history.pushState({}, '', '/cms/edit/default/sites/mySite/home.html');

        expect(resolveSiteKey()).toBe('mySite');
    });

    it('prefers contextJsParameters over the URL when both are present', () => {
        window.contextJsParameters = {siteKey: 'fromContext'};
        window.history.pushState({}, '', '/sites/fromUrl/home.html');

        expect(resolveSiteKey()).toBe('fromContext');
    });

    it('returns null when neither contextJsParameters nor a /sites/ segment is available', () => {
        window.history.pushState({}, '', '/cms/edit/default/dashboard');

        expect(resolveSiteKey()).toBeNull();
    });
});

describe('mapAdminError', () => {
    it('maps a permission_denied GraphQL error to the permission-denied i18n key', () => {
        const err = {graphQLErrors: [{message: 'permission_denied'}]};

        expect(mapAdminError(err)).toBe('siteSettings.errors.permissionDenied');
    });

    it('maps a not_authenticated GraphQL error to the not-authenticated i18n key', () => {
        const err = {graphQLErrors: [{message: 'not_authenticated'}]};

        expect(mapAdminError(err)).toBe('siteSettings.errors.notAuthenticated');
    });

    it('maps an invalid_url GraphQL error to the invalid-url i18n key', () => {
        const err = {graphQLErrors: [{message: 'invalid_url'}]};

        expect(mapAdminError(err)).toBe('siteSettings.errors.invalidUrl');
    });

    it('falls back to the generic i18n key for an unrecognised error code', () => {
        const err = {graphQLErrors: [{message: 'some_unmapped_error'}]};

        expect(mapAdminError(err)).toBe('siteSettings.errors.generic');
    });

    it('falls back to the plain error message when there are no graphQLErrors', () => {
        const err = new Error('invalid_url: bad path');

        expect(mapAdminError(err)).toBe('siteSettings.errors.invalidUrl');
    });

    it('falls back to the generic i18n key when no error is supplied at all', () => {
        expect(mapAdminError(undefined)).toBe('siteSettings.errors.generic');
    });
});
