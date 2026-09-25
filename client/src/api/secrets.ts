import { apiClient } from "./client";
import type { ApiResponse, CreateSecretRequest, Secret, UpdateSecretRequest } from "../types";

export const secretsApi = {
  getAll: () => apiClient.get<ApiResponse<Secret[]>>("/Secrets"),

  getById: (id: string) => apiClient.get<ApiResponse<Secret>>(`/Secrets/${id}`),

  decrypt: (id: string) => apiClient.get<ApiResponse<string>>(`/Secrets/${id}/decrypt`),

  create: (data: CreateSecretRequest) =>
    apiClient.post<ApiResponse<Secret>>("/Secrets", data),

  update: (data: UpdateSecretRequest) =>
    apiClient.put<ApiResponse<Secret>>("/Secrets", data),

  remove: (id: string) => apiClient.delete<ApiResponse<null>>(`/Secrets/${id}`),
};
