import { apiClient } from "./client";
import type { ApiResponse, AuditLog } from "../types";

export const auditLogsApi = {
  getRecent: (count = 100) =>
    apiClient.get<ApiResponse<AuditLog[]>>("/AuditLogs/recent", { params: { count } }),

  getByUser: (userId: string, skip = 0, take = 100) =>
    apiClient.get<ApiResponse<AuditLog[]>>(`/AuditLogs/user/${userId}`, { params: { skip, take } }),

  getCount: () => apiClient.get<ApiResponse<number>>("/AuditLogs/count"),
};