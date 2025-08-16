import {
  hashPassword,
  comparePassword,
  hashPasswordSync,
  comparePasswordSync,
  generateSalt,
  genSalt,
  isStrongPassword,
  safeHashPassword,
  generateSecurePassword,
  calculatePasswordStrength,
  truncates,
  getRounds,
} from "../index";

describe("Password Hashing", () => {
  test("should hash password asynchronously", async () => {
    const password = "testPassword123!";
    const hash = await hashPassword(password);

    expect(hash).toBeDefined();
    expect(typeof hash).toBe("string");
    expect(hash.split(":")).toHaveLength(3); // iterations:salt:hash
  });

  test("should hash password synchronously", () => {
    const password = "testPassword123!";
    const hash = hashPasswordSync(password);

    expect(hash).toBeDefined();
    expect(typeof hash).toBe("string");
    expect(hash.split(":")).toHaveLength(3);
  });

  test("should compare passwords correctly", async () => {
    const password = "testPassword123!";
    const hash = await hashPassword(password);

    const isValid = await comparePassword(password, hash);
    const isInvalid = await comparePassword("wrongPassword", hash);

    expect(isValid).toBe(true);
    expect(isInvalid).toBe(false);
  });

  test("should compare passwords synchronously", () => {
    const password = "testPassword123!";
    const hash = hashPasswordSync(password);

    const isValid = comparePasswordSync(password, hash);
    const isInvalid = comparePasswordSync("wrongPassword", hash);

    expect(isValid).toBe(true);
    expect(isInvalid).toBe(false);
  });
});

describe("Salt Generation", () => {
  test("should generate random salts", () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();

    expect(salt1).toBeDefined();
    expect(salt2).toBeDefined();
    expect(salt1).not.toBe(salt2);
    expect(salt1.length).toBe(32); // 16 bytes = 32 hex chars
  });

  test("should generate salts of specified length", () => {
    const salt = generateSalt(8);
    expect(salt.length).toBe(16); // 8 bytes = 16 hex chars
  });
});

describe("Password Strength", () => {
  test("should validate strong passwords", () => {
    expect(isStrongPassword("StrongPass123!")).toBe(true);
    expect(isStrongPassword("weak")).toBe(false);
    expect(isStrongPassword("NoNumbers!")).toBe(false);
    expect(isStrongPassword("nonumbers123!")).toBe(false);
  });

  test("should use custom strength options", () => {
    const weakOptions = {
      minLength: 4,
      requireUppercase: false,
      requireSymbols: false,
    };

    expect(isStrongPassword("test123", weakOptions)).toBe(true);
    expect(isStrongPassword("test123")).toBe(false);
  });

  test("should safely hash strong passwords", async () => {
    const strongPassword = "StrongPass123!";
    const hash = await safeHashPassword(strongPassword);
    expect(hash).toBeDefined();

    await expect(safeHashPassword("weak")).rejects.toThrow(
      "Password does not meet strength requirements"
    );
  });
});

describe("Password Generation", () => {
  test("should generate secure passwords", () => {
    const password = generateSecurePassword();
    expect(password).toBeDefined();
    expect(password.length).toBe(16);
    expect(isStrongPassword(password)).toBe(true);
  });

  test("should generate passwords with custom length", () => {
    const password = generateSecurePassword(20);
    expect(password.length).toBe(20);
  });

  test("should generate passwords with custom character sets", () => {
    const password = generateSecurePassword(12, {
      includeUppercase: false,
      includeSymbols: false,
    });

    expect(password.length).toBe(12);
    expect(/[A-Z]/.test(password)).toBe(false);
    expect(/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>?]/.test(password)).toBe(false);
  });
});

describe("Password Strength Calculation", () => {
  test("should calculate password strength", () => {
    const result = calculatePasswordStrength("StrongPass123!");
    expect(result.score).toBeGreaterThan(80);
    expect(result.feedback.length).toBeLessThan(2);

    const weakResult = calculatePasswordStrength("weak");
    expect(weakResult.score).toBeLessThan(50);
    expect(weakResult.feedback.length).toBeGreaterThan(3);
  });
});

describe("Utility Functions", () => {
  test("should check password truncation", () => {
    const shortPassword = "shortpassword";
    const longPassword = "x".repeat(2000);

    expect(truncates(shortPassword)).toBe(false);
    expect(truncates(longPassword)).toBe(true);
  });

  test("should get rounds from hash", () => {
    const hash = "10000:salt:hash";
    expect(getRounds(hash)).toBe(10000);

    const invalidHash = "invalid";
    expect(getRounds(invalidHash)).toBe(10000); // default
  });

  test("should generate salt with genSalt", () => {
    const salt1 = genSalt();
    const salt2 = genSalt(12, 8);

    expect(salt1).toBeDefined();
    expect(salt2).toBeDefined();
    expect(salt1).not.toBe(salt2);
    expect(salt2.length).toBe(16); // 8 bytes = 16 hex chars
  });
});
