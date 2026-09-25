export interface User {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
  role: string;
  isActive: boolean;
  createdAt: string;
  lastLoginAt?: string | null;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string | null;
  expiration: string;
  tokenType: string;
  expiresIn: number;
}

export interface LoginRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface RegisterRequest {
  email: string;
  username: string;
  password: string;
  confirmPassword: string;
  recaptchaToken?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  message: string;
  data?: T;
  errorCode?: string;
  errors?: Record<string, string[]>;
}

export interface Secret {
  id: string;
  title: string;
  description?: string | null;
  category?: string | null;
  encryptedValue?: string | null;
  hasExpiration: boolean;
  expiresAt?: string | null;
  isExpired: boolean;
  userId: string;
  createdAt: string;
  updatedAt: string;
  lastAccessedAt?: string | null;
  accessCount: number;
}

export interface CreateSecretRequest {
  title: string;
  description?: string;
  rawValue: string;
  category?: string;
  expiresAt?: string | null;
}

export interface UpdateSecretRequest {
  id: string;
  title?: string;
  description?: string;
  newRawValue?: string;
  category?: string;
  expiresAt?: string | null;
}


export interface UpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
}

export interface ChangePasswordRequest {
  oldPassword: string;
  newPassword: string;
}


export interface AuditLog {
  id: string;
  userId: string;
  action: string;
  entityName: string;
  entityId?: string | null;
  timestamp: string;
  ipAddress: string;
  userAgent?: string | null;
  result: string;
  additionalData?: string | null;
  correlationId: string;
  duration?: number | null;
}