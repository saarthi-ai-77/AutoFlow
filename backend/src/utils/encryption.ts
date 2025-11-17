import crypto from 'crypto';
import { env } from '@/config/environment';
import { logger } from '@/utils/logger';

/**
 * Encryption service for sensitive data at rest
 * Uses AES-256-GCM encryption with secure key management
 */
export class EncryptionService {
  private key: Buffer;
  private readonly algorithm = 'aes-256-gcm';
  private readonly ivLength = 12; // For GCM, 12 bytes is recommended
  private readonly tagLength = 16; // 16 bytes for GCM tag

  constructor() {
    // In production, this should come from AWS KMS, Google Cloud KMS, or Docker secrets
    // Never hardcode the key in the codebase
    const keyString = env.CRYPTO_SECRET;
    
    if (!keyString || keyString.length < 32) {
      throw new Error('CRYPTO_SECRET must be at least 32 characters');
    }

    // Derive a proper 256-bit key from the provided secret
    this.key = crypto.scryptSync(keyString, 'autoflow-salt', 32);
  }

  /**
   * Encrypts sensitive data using AES-256-GCM
   */
  encrypt(plaintext: string): string {
    try {
      if (!plaintext) {
        throw new Error('Plaintext cannot be empty');
      }

      const iv = crypto.randomBytes(this.ivLength);
      const cipher = crypto.createCipher(this.algorithm, this.key);
      cipher.setAAD(Buffer.from('autoflow', 'utf8')); // Additional authenticated data

      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const tag = cipher.getAuthTag();

      // Combine: iv + encrypted_data + tag
      return `${iv.toString('hex')}:${encrypted}:${tag.toString('hex')}`;
    } catch (error) {
      logger.error('Encryption failed', { error });
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypts encrypted data using AES-256-GCM
   */
  decrypt(encryptedData: string): string {
    try {
      if (!encryptedData) {
        throw new Error('Encrypted data cannot be empty');
      }

      const parts = encryptedData.split(':');
      if (parts.length !== 3) {
        throw new Error('Invalid encrypted data format');
      }

      const [ivHex, encrypted, tagHex] = parts;
      const iv = Buffer.from(ivHex, 'hex');
      const tag = Buffer.from(tagHex, 'hex');

      const decipher = crypto.createDecipher(this.algorithm, this.key);
      decipher.setAAD(Buffer.from('autoflow', 'utf8')); // Additional authenticated data
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      logger.error('Decryption failed', { error, encryptedDataLength: encryptedData.length });
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Encrypts JSON data
   */
  encryptJSON(data: any): string {
    const jsonString = JSON.stringify(data);
    return this.encrypt(jsonString);
  }

  /**
   * Decrypts JSON data
   */
  decryptJSON<T = any>(encryptedData: string): T {
    const jsonString = this.decrypt(encryptedData);
    return JSON.parse(jsonString);
  }

  /**
   * Checks if data appears to be encrypted
   */
  isEncrypted(data: string | null | undefined): boolean {
    if (!data) return false;
    
    // Check if it matches the encrypted format (iv:encrypted:tag)
    const encryptedPattern = /^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/;
    return encryptedPattern.test(data) && data.includes(':');
  }

  /**
   * Encrypts object properties that are marked as sensitive
   */
  encryptSensitiveFields<T extends Record<string, any>>(
    obj: T, 
    fieldsToEncrypt: string[]
  ): T {
    const result = { ...obj };
    
    for (const field of fieldsToEncrypt) {
      if (result[field] && typeof result[field] === 'string') {
        result[field] = this.encrypt(result[field]) as any;
      }
    }
    
    return result;
  }

  /**
   * Decrypts object properties that are marked as sensitive
   */
  decryptSensitiveFields<T extends Record<string, any>>(
    obj: T, 
    fieldsToDecrypt: string[]
  ): T {
    const result = { ...obj };
    
    for (const field of fieldsToDecrypt) {
      if (result[field] && typeof result[field] === 'string' && this.isEncrypted(result[field])) {
        try {
          result[field] = this.decrypt(result[field]) as any;
        } catch (error) {
          logger.warn(`Failed to decrypt field ${field}`, { error });
          // Leave as-is if decryption fails
        }
      }
    }
    
    return result;
  }

  /**
   * Generates a hash for API keys using the same key derivation
   */
  hashApiKey(apiKey: string): string {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(apiKey, salt, 10000, 64, 'sha256');
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
  }

  /**
   * Verifies an API key against its hash
   */
  verifyApiKey(apiKey: string, hash: string): boolean {
    try {
      const [salt, originalHash] = hash.split(':');
      const computedHash = crypto.pbkdf2Sync(apiKey, Buffer.from(salt, 'hex'), 10000, 64, 'sha256');
      return computedHash.toString('hex') === originalHash;
    } catch (error) {
      logger.error('API key verification failed', { error });
      return false;
    }
  }
}

// Export singleton instance
export const encryptionService = new EncryptionService();

// Database field encryption utilities
export const ENCRYPTED_FIELDS = {
  users: ['email', 'first_name', 'last_name'],
  workflows: ['description'],
  executions: ['trigger_data', 'error_message'],
  api_keys: ['name']
} as const;

export type EncryptedFields = typeof ENCRYPTED_FIELDS;

// Helper functions for database operations
export const encryptDatabaseField = (value: string | null | undefined): string | null => {
  if (!value) return null;
  return encryptionService.encrypt(value);
};

export const decryptDatabaseField = (value: string | null | undefined): string | null => {
  if (!value) return null;
  try {
    return encryptionService.decrypt(value);
  } catch (error) {
    logger.warn('Failed to decrypt database field', { error });
    return value; // Return original if decryption fails
  }
};