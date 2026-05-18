"use client";

import { useEffect, useRef, useState } from "react";
import type { WsConfirmationRequestPayload } from "@/lib/types";

interface Props {
  confirmation: WsConfirmationRequestPayload;
  onApprove: (requestId: string) => void;
  onDeny: (requestId: string) => void;
}

const RISK_STYLE: Record<string, { bg: string; border: string; badge: string; label: string }> = {
  high: {
    bg:     "bg-red-50 dark:bg-red-950",
    border: "border-red-400",
    badge:  "bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100",
    label:  "HIGH RISK",
  },
  critical: {
    bg:     "bg-red-100 dark:bg-red-950",
    border: "border-red-600",
    badge:  "bg-red-600 text-white",
    label:  "CRITICAL RISK",
  },
};

export function ApprovalDialog({ confirmation, onApprove, onDeny }: Props) {
  const { request_id, tool_name, risk_level, params, reasoning, timeout_seconds } = confirmation;
  const [remaining, setRemaining] = useState(timeout_seconds);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const denyBtnRef = useRef<HTMLButtonElement | null>(null);
  const previousFocus = useRef<Element | null>(null);
  const style = RISK_STYLE[risk_level] ?? RISK_STYLE.high;
  const progress = (remaining / timeout_seconds) * 100;

  // Countdown timer
  useEffect(() => {
    setRemaining(timeout_seconds);
    const interval = setInterval(() => {
      setRemaining((r) => {
        if (r <= 1) {
          clearInterval(interval);
          onDeny(request_id);
          return 0;
        }
        return r - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [request_id, timeout_seconds, onDeny]);

  // Focus management + keyboard shortcuts (Escape = deny).
  useEffect(() => {
    previousFocus.current = document.activeElement;
    denyBtnRef.current?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onDeny(request_id);
      }
      // Crude focus trap so Tab cycles inside the dialog.
      if (e.key === "Tab" && dialogRef.current) {
        const focusables = dialogRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      (previousFocus.current as HTMLElement | null)?.focus?.();
    };
  }, [request_id, onDeny]);

  return (
    // Backdrop
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
      onClick={() => onDeny(request_id)}
    >
      <div
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="approval-title"
        aria-describedby="approval-body"
        onClick={(e) => e.stopPropagation()}
        className={`w-full max-w-lg rounded-xl border-2 shadow-2xl ${style.bg} ${style.border} overflow-hidden`}
      >
        {/* Header */}
        <div className={`px-5 py-4 border-b ${style.border}`}>
          <div className="flex items-center gap-3">
            <span className={`text-xs font-bold px-2 py-0.5 rounded ${style.badge}`}>
              {style.label}
            </span>
            <span id="approval-title" className="font-bold text-gray-900 dark:text-gray-50 text-lg">
              Action Requires Approval
            </span>
            <span
              className="ml-auto text-sm font-mono text-gray-500 dark:text-gray-400"
              aria-live="polite"
            >
              {remaining}s
            </span>
          </div>
          {/* Countdown bar */}
          <div
            className="mt-3 h-1.5 bg-gray-200 dark:bg-gray-800 rounded-full overflow-hidden"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={timeout_seconds}
            aria-valuenow={remaining}
          >
            <div
              className="h-full bg-red-500 transition-all duration-1000 ease-linear"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Body */}
        <div id="approval-body" className="px-5 py-4 space-y-4">
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium">Tool</p>
            <p className="font-mono font-semibold text-gray-900 dark:text-gray-100 text-base">
              {tool_name}
            </p>
          </div>

          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">
              Parameters
            </p>
            <pre className="text-xs bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded p-3 overflow-x-auto">
              {JSON.stringify(params, null, 2)}
            </pre>
          </div>

          {reasoning && (
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-medium mb-1">
                LLM Reasoning
              </p>
              <p className="text-sm text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded p-3">
                {reasoning}
              </p>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="px-5 py-4 border-t border-gray-200 dark:border-gray-700 flex gap-3">
          <button
            ref={denyBtnRef}
            onClick={() => onDeny(request_id)}
            className="flex-1 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-100 font-medium hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          >
            ✗ Deny  <span className="text-xs text-gray-400">(Esc)</span>
          </button>
          <button
            onClick={() => onApprove(request_id)}
            className="flex-1 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-bold transition-colors"
          >
            ✓ Approve
          </button>
        </div>
      </div>
    </div>
  );
}
