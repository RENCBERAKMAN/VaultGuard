import { apiClient } from "./client";
import type { ApiResponse, ChangePasswordRequest, UpdateProfileRequest, User } from "../types";

export const usersApi = {
  updateProfile: (data: UpdateProfileRequest) =>
    apiClient.put<ApiResponse<User>>("/Users/profile", data),

  changePassword: (data: ChangePasswordRequest) =>
    apiClient.post<ApiResponse<null>>("/Users/change-password", data),

  logoutAllDevices: () => apiClient.post<ApiResponse<null>>("/Users/logout-all"),
};