const deps = require('./package.json').dependencies;

const sharedDeps = [
    'react',
    'react-dom',
    'react-i18next',
    'i18next',
    'graphql-tag',
    'react-apollo',
    '@jahia/ui-extender',
    '@jahia/moonstone',
    '@jahia/moonstone-alpha',
    '@apollo/react-hooks'
];

const singletonDeps = [
    'react',
    'react-dom',
    'react-i18next',
    'i18next',
    'react-apollo',
    '@jahia/moonstone',
    '@jahia/ui-extender',
    '@apollo/react-hooks'
];

module.exports = {
    ...sharedDeps.reduce((acc, item) => ({
        ...acc,
        [item]: {requiredVersion: deps[item]}
    }), {}),
    ...singletonDeps.reduce((acc, item) => ({
        ...acc,
        [item]: {singleton: true, requiredVersion: deps[item]}
    }), {})
};
