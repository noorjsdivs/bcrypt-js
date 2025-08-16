import { createHash, randomBytes, pbkdf2, pbkdf2Sync } from "crypto";

// Constants
const MAX_INPUT_LENGTH = 1024; // Maximum password length in bytes
const DEFAULT_SALT_ROUNDS = 10;
const DEFAULT_PBKDF2_ITERATIONS = 10000;

/**
 * Check if password will be truncated
 */
export function truncates(password: string): boolean {
  return Buffer.byteLength(password, "utf8") > MAX_INPUT_LENGTH;
}

/**
 * Get the number of rounds from a hash
 */
export function getRounds(hash: string): number {
  const parts = hash.split(":");
  return parts.length >= 3 ? parseInt(parts[0]) : DEFAULT_PBKDF2_ITERATIONS;
}

/**
 * Generate a random salt
 */
export function genSalt(rounds = DEFAULT_SALT_ROUNDS, length = 16): string {
  return randomBytes(length).toString("hex");
}

/**
 * Alias for genSalt for compatibility
 */
export function generateSalt(length = 16): string {
  return genSalt(DEFAULT_SALT_ROUNDS, length);
}

/**
 * Hash a password using PBKDF2 with SHA-256
 */
export async function hashPassword(
  password: string,
  saltRounds = 10000,
  customSalt?: string
): Promise<string> {
  return new Promise((resolve, reject) => {
    const salt = customSalt || generateSalt();
    const iterations = saltRounds;

    pbkdf2(password, salt, iterations, 64, "sha256", (err, derivedKey) => {
      if (err) reject(err);
      else {
        const hash = derivedKey.toString("hex");
        resolve(`${iterations}:${salt}:${hash}`);
      }
    });
  });
}

/**
 * Synchronous version of hashPassword
 */
export function hashPasswordSync(
  password: string,
  saltRounds = 10000,
  customSalt?: string
): string {
  const salt = customSalt || generateSalt();
  const iterations = saltRounds;
  const derivedKey = pbkdf2Sync(password, salt, iterations, 64, "sha256");
  const hash = derivedKey.toString("hex");
  return `${iterations}:${salt}:${hash}`;
}

/**
 * Compare a password with a hash
 */
export async function comparePassword(
  password: string,
  hashedPassword: string
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const [iterations, salt, hash] = hashedPassword.split(":");

    if (!iterations || !salt || !hash) {
      resolve(false);
      return;
    }

    pbkdf2(
      password,
      salt,
      parseInt(iterations),
      64,
      "sha256",
      (err, derivedKey) => {
        if (err) reject(err);
        else {
          const passwordHash = derivedKey.toString("hex");
          resolve(passwordHash === hash);
        }
      }
    );
  });
}

/**
 * Synchronous version of comparePassword
 */
export function comparePasswordSync(
  password: string,
  hashedPassword: string
): boolean {
  const [iterations, salt, hash] = hashedPassword.split(":");

  if (!iterations || !salt || !hash) {
    return false;
  }

  const derivedKey = pbkdf2Sync(
    password,
    salt,
    parseInt(iterations),
    64,
    "sha256"
  );
  const passwordHash = derivedKey.toString("hex");
  return passwordHash === hash;
}

/**
 * Check if a password meets strength requirements
 */
export function isStrongPassword(
  password: string,
  options: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSymbols?: boolean;
  } = {}
): boolean {
  const {
    minLength = 8,
    requireUppercase = true,
    requireLowercase = true,
    requireNumbers = true,
    requireSymbols = true,
  } = options;

  if (password.length < minLength) return false;
  if (requireUppercase && !/[A-Z]/.test(password)) return false;
  if (requireLowercase && !/[a-z]/.test(password)) return false;
  if (requireNumbers && !/\d/.test(password)) return false;
  if (requireSymbols && !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password))
    return false;

  return true;
}

/**
 * Hash and check strength in one step
 */
export async function safeHashPassword(
  password: string,
  saltRounds = 10000,
  strengthOptions?: Parameters<typeof isStrongPassword>[1]
): Promise<string> {
  if (!isStrongPassword(password, strengthOptions)) {
    throw new Error("Password does not meet strength requirements");
  }
  return await hashPassword(password, saltRounds);
}

/**
 * Generate a secure random password
 */
export function generateSecurePassword(
  length = 16,
  options: {
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSymbols?: boolean;
  } = {}
): string {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true,
  } = options;

  let charset = "";
  if (includeUppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (includeLowercase) charset += "abcdefghijklmnopqrstuvwxyz";
  if (includeNumbers) charset += "0123456789";
  if (includeSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!charset) throw new Error("At least one character type must be included");

  let password = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset[randomIndex];
  }

  return password;
}

/**
 * Calculate password strength score (0-100)
 */
export function calculatePasswordStrength(password: string): {
  score: number;
  feedback: string[];
} {
  let score = 0;
  const feedback: string[] = [];

  // Length scoring
  if (password.length >= 8) score += 25;
  else feedback.push("Password should be at least 8 characters long");

  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;

  // Character variety scoring
  if (/[a-z]/.test(password)) score += 15;
  else feedback.push("Add lowercase letters");

  if (/[A-Z]/.test(password)) score += 15;
  else feedback.push("Add uppercase letters");

  if (/\d/.test(password)) score += 15;
  else feedback.push("Add numbers");

  if (/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) score += 10;
  else feedback.push("Add special characters");

  // Bonus for no repeated characters
  if (!/(.)\1{2,}/.test(password)) score += 10;
  else feedback.push("Avoid repeating characters");

  return { score: Math.min(score, 100), feedback };
}
