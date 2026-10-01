"use client";

import { useEffect, useId, useRef } from "react";

const LENGTH = 6;

/** Six single-digit boxes for a one-time code. Digits only; paste fills every
 * box, backspace walks back, arrows move. Exposes one string via value/onChange. */
export function OtpInput({
  value,
  onChange,
  disabled = false,
  invalid = false,
  autoFocus = true,
}: {
  value: string;
  onChange: (next: string) => void;
  disabled?: boolean;
  invalid?: boolean;
  autoFocus?: boolean;
}) {
  const groupId = useId();
  const refs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    if (autoFocus) refs.current[0]?.focus();
  }, [autoFocus]);

  function focusAt(i: number) {
    refs.current[Math.max(0, Math.min(LENGTH - 1, i))]?.focus();
  }

  function setDigit(i: number, digit: string) {
    const chars = value.padEnd(LENGTH, " ").split("");
    chars[i] = digit || " ";
    onChange(chars.join("").replace(/\s+$/, "").replace(/ /g, ""));
  }

  return (
    <div className="otp-input" role="group" aria-label="Verification code">
      {Array.from({ length: LENGTH }, (_, i) => (
        <input
          key={i}
          id={`${groupId}-${i}`}
          ref={(el) => {
            refs.current[i] = el;
          }}
          className={`otp-box ${invalid ? "otp-box-invalid" : ""}`}
          type="text"
          inputMode="numeric"
          autoComplete={i === 0 ? "one-time-code" : "off"}
          maxLength={1}
          aria-label={`Digit ${i + 1} of ${LENGTH}`}
          disabled={disabled}
          value={value[i] ?? ""}
          onChange={(e) => {
            const digit = e.target.value.replace(/\D/g, "").slice(-1);
            if (!digit) return;
            setDigit(i, digit);
            if (i < LENGTH - 1) focusAt(i + 1);
          }}
          onKeyDown={(e) => {
            if (e.key === "Backspace") {
              e.preventDefault();
              if (value[i]) {
                setDigit(i, "");
              } else if (i > 0) {
                setDigit(i - 1, "");
                focusAt(i - 1);
              }
            } else if (e.key === "ArrowLeft") {
              e.preventDefault();
              focusAt(i - 1);
            } else if (e.key === "ArrowRight") {
              e.preventDefault();
              focusAt(i + 1);
            }
          }}
          onPaste={(e) => {
            const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, LENGTH);
            if (!pasted) return;
            e.preventDefault();
            onChange(pasted);
            focusAt(Math.min(pasted.length, LENGTH - 1));
          }}
          onFocus={(e) => e.target.select()}
        />
      ))}
    </div>
  );
}

export const OTP_LENGTH = LENGTH;
