import axios from "axios";

export function extractErrorMessage(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    const data = err.response?.data as { message?: string } | undefined;
    if (data?.message) return data.message;
    if (err.code === "ERR_NETWORK") {
      return "Sunucuya ulaşılamıyor. API çalışıyor mu kontrol edin.";
    }
  }
  return fallback;
}