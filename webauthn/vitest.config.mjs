import {defineConfig} from 'vitest/config';

export default defineConfig({
    test: {
        // jsdom gives the admin screens a real DOM to render into and interact with
        // via Testing Library (clicks, form fields, roles).
        environment: 'jsdom',
        include: ['src/javascript/**/*.test.{js,jsx}'],
        setupFiles: ['./vitest.setup.mjs']
    }
});
