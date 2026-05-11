# AGENTS.md

## Coding Style

### File Renaming

Always use `git mv` to rename files — never `cp` + `rm` or OS-level rename.
After `git mv`, the file content is unchanged — apply any content edits separately.

### Variable Naming

- **camelCase** for all variables, functions, parameters, and module-level constants
- **PascalCase** for types, interfaces, classes
- **Exception**: stay as-is: `API`

## Dev environment tips

- package.json for available pnpm commands for this project.
- Always use Context7 when I need library/API documentation, code generation, setup or configuration steps without me having to explicitly ask.