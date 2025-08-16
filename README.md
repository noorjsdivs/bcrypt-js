# ts-bcrypt

Optimized bcrypt implementation in TypeScript with zero dependencies. A secure password hashing library built from scratch using Node.js crypto module, compatible with modern JavaScript environments and also working in the browser.

[![npm version](https://badge.fury.io/js/ts-bcrypt.svg)](https://badge.fury.io/js/ts-bcrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg)](http://www.typescriptlang.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/☕-Buy%20me%20a%20coffee-orange.svg?style=flat&logo=buy-me-a-coffee)](https://buymeacoffee.com/reactbd)
[![YouTube Channel](https://img.shields.io/badge/📺-YouTube%20Channel-red.svg?style=flat&logo=youtube)](https://www.youtube.com/@reactjsBD)

## Security Considerations

Besides incorporating a salt to protect against rainbow table attacks, this library uses PBKDF2 with SHA-256, an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant to brute-force search attacks even with increasing computation power.

While bcrypt-js provides similar security guarantees to traditional bcrypt implementations, it is built entirely in TypeScript/JavaScript using Node.js built-in crypto modules, making it dependency-free and more maintainable.

The maximum input length is 1024 bytes (note that UTF-8 encoded characters use up to 4 bytes) and the length of generated hashes varies based on the salt and iteration count used. The library includes built-in input validation and strength checking capabilities.

## Features

- **Secure Password Hashing**: Uses PBKDF2 with SHA-256 (no external dependencies)
- **Password Strength Validation**: Configurable strength requirements
- **Password Generation**: Generate secure passwords with custom options
- **Password Strength Scoring**: Calculate password strength with feedback
- **Async & Sync APIs**: Both asynchronous and synchronous methods
- **Fully Typed**: Complete TypeScript support
- **Zero Dependencies**: Built using only Node.js built-in modules

## Installation

### NPM

```bash
npm install ts-bcrypt
```

### Yarn

```bash
yarn add ts-bcrypt
```

### PNPM

```bash
pnpm add ts-bcrypt
```

### Bun

```bash
bun add ts-bcrypt
```

## Usage

### Basic Password Hashing

```ts
import {
  hashPassword,
  comparePassword,
  hashPasswordSync,
  comparePasswordSync,
} from "ts-bcrypt";

// Async hashing
const hash = await hashPassword("myPassword");
const isMatch = await comparePassword("myPassword", hash);

// Sync hashing
const hashSync = hashPasswordSync("myPassword");
const isMatchSync = comparePasswordSync("myPassword", hashSync);
```

### Salt Generation

```ts
import { generateSalt, genSalt } from "ts-bcrypt";

const salt = generateSalt(); // Random 16-byte salt
const customSalt = genSalt(12, 8); // Custom rounds and length
```

### Input Validation

```ts
import { truncates, getRounds } from "ts-bcrypt";

// Check if password will be truncated
const willTruncate = truncates("very long password...");

// Get iteration count from existing hash
const iterations = getRounds(existingHash);
```

### Password Strength Validation

```ts
import { isStrongPassword, safeHashPassword } from "ts-bcrypt";

// Check if password is strong
const isStrong = isStrongPassword("MyPassword123!");

// Custom strength requirements
const isStrongCustom = isStrongPassword("mypass", {
  minLength: 6,
  requireUppercase: false,
  requireSymbols: false,
});

// Hash only if password is strong
try {
  const hash = await safeHashPassword("MyPassword123!");
} catch (error) {
  console.log("Password not strong enough");
}
```

### Password Generation

```ts
import { generateSecurePassword } from "ts-bcrypt";

// Generate a secure password (default: 16 chars)
const password = generateSecurePassword();

// Custom length and character set
const customPassword = generateSecurePassword(20, {
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: false,
});
```

### Password Strength Analysis

```ts
import { calculatePasswordStrength } from "ts-bcrypt";

const analysis = calculatePasswordStrength("MyPassword123!");
console.log(analysis.score); // 0-100
console.log(analysis.feedback); // Array of improvement suggestions
```

### Salt Generation

```ts
import { generateSalt } from "ts-bcrypt";

const salt = generateSalt(); // Random 16-byte salt
const customSalt = generateSalt(8); // Custom length salt
```

## API Reference

### `hashPassword(password: string, saltRounds?: number, customSalt?: string): Promise<string>`

Hash a password asynchronously using PBKDF2.

### `hashPasswordSync(password: string, saltRounds?: number, customSalt?: string): string`

Hash a password synchronously.

### `comparePassword(password: string, hash: string): Promise<boolean>`

Compare a password with a hash asynchronously.

### `comparePasswordSync(password: string, hash: string): boolean`

Compare a password with a hash synchronously.

### `isStrongPassword(password: string, options?): boolean`

Check if a password meets strength requirements.

Options:

- `minLength?: number` (default: 8)
- `requireUppercase?: boolean` (default: true)
- `requireLowercase?: boolean` (default: true)
- `requireNumbers?: boolean` (default: true)
- `requireSymbols?: boolean` (default: true)

### `safeHashPassword(password: string, saltRounds?: number, strengthOptions?): Promise<string>`

Hash a password only if it meets strength requirements.

### `generateSecurePassword(length?: number, options?): string`

Generate a secure random password.

### `calculatePasswordStrength(password: string): { score: number, feedback: string[] }`

Calculate password strength score (0-100) with improvement feedback.

### `generateSalt(length?: number): string`

Generate a random salt for custom hashing implementations.

### `genSalt(rounds?: number, length?: number): string`

Generate a random salt with custom rounds and length (bcrypt.js compatible).

### `truncates(password: string): boolean`

Check if a password will be truncated due to length limits.

### `getRounds(hash: string): number`

Extract the iteration count from an existing hash string.

## Security Features

- **PBKDF2 with SHA-256**: Industry-standard key derivation function
- **Configurable Iterations**: Default 10,000 iterations (adjustable)
- **Random Salt Generation**: Cryptographically secure random salts
- **No External Dependencies**: Reduces attack surface
- **Timing-Safe Comparison**: Built-in protection against timing attacks

## License

MIT
