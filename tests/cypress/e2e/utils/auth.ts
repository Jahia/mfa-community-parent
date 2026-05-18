/**
 * Auth helpers adapted (subset) from
 * user-password-authentication/tests/cypress/e2e/utils/auth.ts
 *
 * Only includes the bits the TOTP specs need: user lifecycle + an MFA-initiation helper.
 */
import {addUserToGroup, createUser, deleteUser, getUserPath} from '@jahia/cypress';

/**
 * Creates a user with `privileged` group membership so the user can use the
 * authenticated GraphQL surface. Idempotent: deletes any pre-existing user
 * with the same username first.
 */
export const createUserForMFA = (
    username: string,
    password: string,
    email: string | undefined = undefined,
    preferredLanguage = 'en'
): void => {
    getUserPath(username).then(response => {
        if (response?.data?.admin?.userAdmin?.user) {
            cy.log('Deleting user ' + username + ' before creating it...');
            deleteUser(username);
        }
    });
    const properties = [
        {name: 'preferredLanguage', value: preferredLanguage},
        {name: 'j:firstName', value: ''},
        {name: 'j:lastName', value: ''}
    ];
    if (email) {
        properties.push({name: 'j:email', value: email});
    }

    createUser(username, password, properties);
    addUserToGroup(username, 'privileged');
    cy.log('User (username=' + username + ', password=' + password + ') created');
};

/**
 * Calls `upa.mfaInitiate` and asserts success.
 */
export function initiate(username: string, password: string, site: string = undefined) {
    cy.log('Initiating MFA process for user ' + username);
    cy.apollo({
        queryFile: 'initiate.graphql',
        variables: {username, password, site}
    }).then(response => {
        expect(response?.data?.upa?.mfaInitiate?.session?.initiated).be.true;
    });
}

export {deleteUser};
