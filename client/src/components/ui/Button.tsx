import type { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost" | "danger";
}

export function Button({ variant = "primary", className = "", children, ...props }: ButtonProps) {
  const base =
    "inline-flex items-center justify-center rounded-xl text-sm font-medium px-4 py-2.5 transition-all duration-200 outline-none disabled:opacity-50 disabled:cursor-not-allowed";

  const variants: Record<string, string> = {
    primary:
      "bg-gradient-to-r from-accent to-accent-2 text-void font-semibold shadow-[0_6px_20px_-6px_rgba(91,141,239,0.45)] hover:shadow-[0_10px_28px_-6px_rgba(91,141,239,0.55)] hover:-translate-y-0.5 focus-visible:ring-2 focus-visible:ring-accent/40",
    ghost:
      "glass border border-line text-text-muted hover:text-text hover:border-accent/40 focus-visible:ring-2 focus-visible:ring-accent/25",
    danger:
      "bg-transparent text-danger border border-danger/30 hover:bg-danger/10 focus-visible:ring-2 focus-visible:ring-danger/25",
  };

  return (
    <button className={`${base} ${variants[variant]} ${className}`} {...props}>
      {children}
    </button>
  );
}