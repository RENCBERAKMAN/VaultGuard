import axios from "axios";
import type { ApiResponse, AuthTokens } from "../types";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5217/api";

export const apiClient = axios.create({
  baseURL: API_URL,
  headers: { "Content-Type": "application/json" },
});

export function getAccessToken(): string | null {
  return localStorage.getItem("vg_access_token");
}

export function getRefreshToken(): string | null {
  return localStorage.getItem("vg_refresh_token");
}

export function setTokens(tokens: AuthTokens) {
  localStorage.setItem("vg_access_token", tokens.accessToken);
  if (tokens.refreshToken) {
    localStorage.setItem("vg_refresh_token", tokens.refreshToken);
  }
}

export function clearTokens() {
  localStorage.removeItem("vg_access_token");
  localStorage.removeItem("vg_refresh_token");
}

apiClient.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let isRefreshing = false;
let pendingQueue: Array<() => void> = [];

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      const refreshToken = getRefreshToken();
      if (!refreshToken) {
        clearTokens();
        window.location.href = "/login";
        return Promise.reject(error);
      }

      if (isRefreshing) {
        return new Promise((resolve) => {
          pendingQueue.push(() => resolve(apiClient(originalRequest)));
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const res = await axios.post<ApiResponse<AuthTokens>>(
          `${API_URL}/Auth/refresh-token`,
          { refreshToken }
        );

        if (res.data.success && res.data.data) {
          setTokens(res.data.data);
          pendingQueue.forEach((cb) => cb());
          pendingQueue = [];
          return apiClient(originalRequest);
        }
        throw new Error("Refresh failed");
      } catch (refreshError) {
        clearTokens();
        window.location.href = "/login";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);
