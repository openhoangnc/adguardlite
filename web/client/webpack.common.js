import path from 'path';
import HtmlWebpackPlugin from 'html-webpack-plugin';
import { CleanWebpackPlugin } from 'clean-webpack-plugin';
import CopyPlugin from 'copy-webpack-plugin';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';
import * as url from 'url';
import { BUILD_ENVS } from './constants.js';

// eslint-disable-next-line no-underscore-dangle
const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

const RESOURCES_PATH = path.resolve(__dirname);
const ENTRY_REACT = path.resolve(RESOURCES_PATH, 'src/index.tsx');
const ENTRY_INSTALL = path.resolve(RESOURCES_PATH, 'src/install/index.tsx');
const ENTRY_LOGIN = path.resolve(RESOURCES_PATH, 'src/login/index.tsx');
const HTML_PATH = path.resolve(RESOURCES_PATH, 'public/index.html');
const HTML_INSTALL_PATH = path.resolve(RESOURCES_PATH, 'public/install.html');
const HTML_LOGIN_PATH = path.resolve(RESOURCES_PATH, 'public/login.html');
const ASSETS_PATH = path.resolve(RESOURCES_PATH, 'public/assets');

const PUBLIC_PATH = path.resolve(__dirname, '../build');
const PUBLIC_ASSETS_PATH = path.resolve(PUBLIC_PATH, 'assets');

const BUILD_ENV = BUILD_ENVS[process.env.BUILD_ENV];

const isDev = BUILD_ENV === BUILD_ENVS.dev;

const config = {
    mode: BUILD_ENV,
    target: 'web',
    context: RESOURCES_PATH,
    entry: {
        main: ENTRY_REACT,
        install: ENTRY_INSTALL,
        login: ENTRY_LOGIN,
    },
    output: {
        path: PUBLIC_PATH,
        // Content-addressed output goes under static/, and nothing else does.
        // That is what lets the server cache these forever without guessing
        // which names carry a hash: see is_content_addressed in
        // crates/agl-api/src/ui.rs.
        filename: 'static/[name].[chunkhash].js',
        chunkFilename: 'static/[name].[chunkhash].js',
        // The interface is always served from the root, and an absolute
        // reference survives being reached at a path the router invented.
        publicPath: '/',
    },
    resolve: {
        modules: ['node_modules'],
        extensions: ['.js', '.jsx', '.ts', '.tsx'],
    },
    module: {
        rules: [
            {
                test: /\.ya?ml$/,
                type: 'json',
                use: 'yaml-loader',
            },
            {
                test: /\.css$/i,
                use: [
                    {
                        loader: MiniCssExtractPlugin.loader,
                    },
                    {
                        loader: 'css-loader',
                        options: {
                            importLoaders: 1,
                        },
                    },
                    {
                        loader: 'postcss-loader',
                    },
                ],
            },
            {
                test: /\.tsx?$/,
                exclude: /node_modules/,
                use: {
                    loader: 'ts-loader',
                },
            },
        ],
    },
    plugins: [
        new CleanWebpackPlugin({
            root: PUBLIC_PATH,
            verbose: false,
            dry: false,
        }),
        new HtmlWebpackPlugin({
            inject: true,
            cache: false,
            chunks: ['main'],
            template: HTML_PATH,
        }),
        new HtmlWebpackPlugin({
            inject: true,
            cache: false,
            chunks: ['install'],
            filename: 'install.html',
            template: HTML_INSTALL_PATH,
        }),
        new HtmlWebpackPlugin({
            inject: true,
            cache: false,
            chunks: ['login'],
            filename: 'login.html',
            template: HTML_LOGIN_PATH,
        }),
        new MiniCssExtractPlugin({
            filename: isDev ? '[name].css' : 'static/[name].[contenthash].css',
            chunkFilename: isDev ? '[id].css' : 'static/[id].[contenthash].css',
        }),
        new CopyPlugin({
            patterns: [
                {
                    from: ASSETS_PATH,
                    to: PUBLIC_ASSETS_PATH,
                },
            ],
        }),
    ],
};

export default config;
