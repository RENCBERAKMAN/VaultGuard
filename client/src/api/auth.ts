import { apiClient } from "./client";
import type { ApiResponse, AuthTokens, LoginRequest, RegisterRequest, User } from "../types";

export const authApi = {
  login: (data: LoginRequest) =>
    apiClient.post<ApiResponse<AuthTokens>>("/Auth/login", data),

  register: (data: RegisterRequest) =>
    apiClient.post<ApiResponse<null>>("/Auth/register", data),

  logout: () => apiClient.post<ApiResponse<null>>("/Auth/logout"),

  me: () => apiClient.get<ApiResponse<User>>("/Users/me"),
};
