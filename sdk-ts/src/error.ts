/**
 * Error types following zhtp-cli patterns
 * Domain-specific errors with contextual information
 */

export class SdkError extends Error {
  constructor(
    public type: 'Identity' | 'Wallet' | 'Domain' | 'Deployment' | 'Network' | 'Validation',
    public context: Record<string, any>,
    message: string,
  ) {
    super(message);
    this.name = 'SdkError';
    Object.setPrototypeOf(this, SdkError.prototype);
  }
}

export class IdentityError extends SdkError {
  constructor(message: string, context: Record<string, any> = {}) {
    super('Identity', context, message);
    this.name = 'IdentityError';
  }
}

export class WalletError extends SdkError {
  constructor(message: string, context: Record<string, any> = {}) {
    super('Wallet', context, message);
    this.name = 'WalletError';
  }
}

export class DomainError extends SdkError {
  constructor(message: string, context: Record<string, any> = {}) {
    super('Domain', context, message);
    this.name = 'DomainError';
  }
}

export class DeploymentError extends SdkError {
  constructor(message: string, context: Record<string, any> = {}) {
    super('Deployment', context, message);
    this.name = 'DeploymentError';
  }
}

export class NetworkError extends SdkError {
  constructor(message: string, context: Record<string, any> = {}) {
    super('Network', context, message);
    this.name = 'NetworkError';
  }
}

export class ValidationError extends SdkError {
  errors: ValidationIssue[];

  constructor(message: string, errors: ValidationIssue[] = [], context: Record<string, any> = {}) {
    super('Validation', context, message);
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

export interface ValidationIssue {
  field: string;
  message: string;
  value?: any;
}

/**
 * Result type for operations that can fail
 */
export type SdkResult<T> = T | SdkError;

/**
 * Validation result with error accumulation
 */
export interface ValidationResult {
  valid: boolean;
  errors: ValidationIssue[];
}
