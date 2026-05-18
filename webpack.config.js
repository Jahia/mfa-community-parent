const path = require('path');
const {CleanWebpackPlugin} = require('clean-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const CaseSensitivePathsPlugin = require('case-sensitive-paths-webpack-plugin');
const ModuleFederationPlugin = require('webpack/lib/container/ModuleFederationPlugin');
const shared = require('./webpack.shared');

module.exports = (env, argv) => {
    const config = {
        entry: {
            main: [
                path.resolve(__dirname, 'src/main/javascript/publicPath'),
                path.resolve(__dirname, 'src/main/javascript/index.js')
            ]
        },
        output: {
            path: path.resolve(__dirname, 'src/main/resources/javascript/apps/'),
            filename: 'mfa-totp-factor.bundle.js',
            chunkFilename: '[name].mfa-totp-factor.[chunkhash:6].js'
        },
        resolve: {
            mainFields: ['module', 'main'],
            extensions: ['.mjs', '.js', '.jsx', 'json', 'scss']
        },
        module: {
            rules: [
                {test: /\.m?js$/, type: 'javascript/auto'},
                {
                    test: /\.(js|jsx)$/,
                    include: [path.join(__dirname, 'src')],
                    exclude: /node_modules/,
                    use: {
                        loader: 'babel-loader',
                        options: {
                            presets: [
                                ['@babel/preset-env', {
                                    modules: false,
                                    targets: {chrome: '60', edge: '44', firefox: '54', safari: '12'}
                                }],
                                '@babel/preset-react'
                            ]
                        }
                    }
                },
                {
                    test: /\.css$/i,
                    sideEffects: true,
                    use: ['style-loader', 'css-loader']
                },
                {
                    test: /\.s[ac]ss$/i,
                    sideEffects: true,
                    use: [
                        'style-loader',
                        {loader: 'css-loader', options: {modules: {mode: 'local'}}},
                        'sass-loader'
                    ]
                }
            ]
        },
        plugins: [
            new ModuleFederationPlugin({
                name: 'mfaTotpFactor',
                library: {type: 'assign', name: 'appShell.remotes.mfaTotpFactor'},
                filename: 'remoteEntry.js',
                exposes: {
                    './init': './src/main/javascript/init'
                },
                remotes: {
                    '@jahia/app-shell': 'appShellRemote',
                    '@jahia/jahia-ui-root': 'appShell.remotes.jahiaUi'
                },
                shared
            }),
            new CleanWebpackPlugin({verbose: false}),
            new CopyWebpackPlugin({patterns: [{from: './package.json', to: ''}]}),
            new CaseSensitivePathsPlugin()
        ],
        mode: 'development'
    };

    config.devtool = (argv.mode === 'production') ? 'source-map' : 'eval-source-map';
    return config;
};
