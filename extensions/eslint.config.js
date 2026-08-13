const {FlatCompat} = require('@eslint/eslintrc');

const compat = new FlatCompat({
    baseDirectory: __dirname
});

module.exports = [
    {
        files: ['**/*.js', '**/*.jsx']
    },
    ...compat.extends('@jahia/eslint-config'),
    {
        files: ['**/*.js', '**/*.jsx'],
        rules: {
            // Internal presentational components pass props locally; we don't require
            // PropTypes across the board (the GraphQL layer is the real contract).
            'react/prop-types': 'off'
        }
    }
];
