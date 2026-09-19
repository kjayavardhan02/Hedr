"use client";

import { useId, useState } from "react";

interface PasswordFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: string;
  minLength?: number;
  hint?: string;
  placeholder?: string;
}

export function PasswordField({
  label,
  value,
  onChange,
  autoComplete,
  minLength,
  hint,
  placeholder,
}: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);
  const id = useId();

  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="input-icon-wrap">
        <svg className="input-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect x="5" y="10.5" width="14" height="9.5" rx="2.2" stroke="currentColor" strokeWidth="1.6" />
          <path
            d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
          />
        </svg>
        <input
          id={id}
          type={visible ? "text" : "password"}
          className="has-icon has-trailing"
          autoComplete={autoComplete}
          required
          minLength={minLength}
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
        <button
          type="button"
          className="password-toggle"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? "Hide password" : "Show password"}
          tabIndex={-1}
        >
          {visible ? (
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M3 3l18 18M10.6 10.7a2.5 2.5 0 0 0 3.5 3.5M6.5 6.7C4.3 8.2 2.7 10.4 2 12c1.6 3.6 5.4 6.5 10 6.5 1.6 0 3.1-.35 4.4-.98M9.9 5.2A10.6 10.6 0 0 1 12 5.5c4.6 0 8.4 2.9 10 6.5-.5 1.15-1.25 2.3-2.2 3.3"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M2 12c1.6-3.6 5.4-6.5 10-6.5s8.4 2.9 10 6.5c-1.6 3.6-5.4 6.5-10 6.5S3.6 15.6 2 12Z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinejoin="round"
              />
              <circle cx="12" cy="12" r="2.6" stroke="currentColor" strokeWidth="1.6" />
            </svg>
          )}
        </button>
      </div>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  );
}
