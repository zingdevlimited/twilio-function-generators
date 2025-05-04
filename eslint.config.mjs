import { defineConfig, globalIgnores } from "eslint/config";
import typescriptEslint from "@typescript-eslint/eslint-plugin";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

export default defineConfig([globalIgnores([
    "src/auth/web/templates/*.*",
    "**/.devcontainer",
    "**/.vscode",
    "**/.yarn",
    "**/dist",
    "**/node_modules",
    "src/auth/web/templates/compiled.ts",
    "**/.editorconfig",
    "**/.eslintignore",
    "**/.eslintrc",
    "**/.gitattributes",
    "**/.gitignore",
    "**/.prettierignore",
    "**/.prettierrc",
    "**/.yarnrc.yml",
    "**/LICENCE",
    "**/tsconfig.tsbuildinfo",
    "**/yarn.lock",
    "**/*.md",
    "**/*hbs",
    "**/.txt",
    "**/*.json",
]), {
    extends: compat.extends("eslint:recommended", "plugin:@typescript-eslint/recommended", "prettier"),

    plugins: {
        "@typescript-eslint": typescriptEslint,
    },

    languageOptions: {
        globals: {
            ...Object.fromEntries(Object.entries(globals.browser).map(([key]) => [key, "off"])),
        },

        parser: tsParser,
        ecmaVersion: 12,
        sourceType: "module",
    },

    rules: {
        "@typescript-eslint/no-unused-vars": "error",
        "@typescript-eslint/consistent-type-definitions": ["error", "type"],
        "@typescript-eslint/switch-exhaustiveness-check": "error",
    },
}]);