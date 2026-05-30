import {defineConfig} from 'cypress';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const fs = require('fs');

export default defineConfig({
    reporter: 'cypress-multi-reporters',
    reporterOptions: {
        configFile: 'reporter-config.json'
    },
    screenshotsFolder: './results/screenshots',
    video: true,
    videosFolder: './results/videos',
    viewportWidth: 1366,
    viewportHeight: 768,
    watchForFileChanges: false,
    // The TOTP specs do significant PBKDF2 work on the server (backup-code hashing) and
    // exercise the JCR system session repeatedly. Bump Cypress's defaults so legitimate
    // round-trips and provisioning groovy reads don't trip the 4s/60s defaults.
    defaultCommandTimeout: 30000,
    requestTimeout: 30000,
    responseTimeout: 60000,
    e2e: {
        setupNodeEvents(on, config) {
            on(
                'after:spec',
                (spec: Cypress.Spec, results: CypressCommandLine.RunResult) => {
                    if (results && results.video && fs.existsSync(results.video)) {
                        const failures = results.tests.some(test =>
                            test.attempts.some(attempt => attempt.state === 'failed')
                        );
                        if (!failures) {
                            try {
                                fs.unlinkSync(results.video);
                            } catch (_e) {
                                // ignore — best-effort cleanup
                            }
                        }
                    }
                }
            );
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            return require('./cypress/plugins/index.js')(on, config);
        },
        excludeSpecPattern: '*.ignore.ts',
        // In CI the cypress container is given CYPRESS_baseUrl=http://jahia:8080 (internal
        // network DNS). The host-side fallback honours the remapped host port (default 8090)
        // so a local `cypress open` against this isolated stack hits the right port.
        baseUrl: process.env.CYPRESS_baseUrl || `http://localhost:${process.env.JAHIA_HTTP_PORT || '8090'}`
    },
    env: {
        MAILPIT_URL: process.env.MAILPIT_URL || `http://localhost:${process.env.MAILPIT_UI_PORT || '8035'}`,
        SUPER_USER_PASSWORD: process.env.SUPER_USER_PASSWORD || 'root1234'
    }
});
