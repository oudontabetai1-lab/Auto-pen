"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createSession, runSession } from "@/lib/api";
import type { ScanProfile } from "@/lib/types";

const PROFILES: ScanProfile[] = ["web", "network", "cloud", "ctf"];
const LLM_PRESETS = [
  { label: "Ollama / llama3.1 (local)", provider: "ollama", model: "llama3.1" },
  { label: "Ollama / qwen2.5", provider: "ollama", model: "qwen2.5" },
  { label: "OpenAI / gpt-4o", provider: "openai", model: "gpt-4o" },
  { label: "Anthropic / claude-sonnet-4-6", provider: "anthropic", model: "claude-sonnet-4-6" },
];

export function NewSessionForm() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<ScanProfile>("web");
  const [authToken, setAuthToken] = useState("");
  const [scope, setScope] = useState("");
  const [llmPreset, setLlmPreset] = useState(0);
  const [maxSteps, setMaxSteps] = useState(40);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || !authToken.trim()) return;

    const preset = LLM_PRESETS[llmPreset];
    const allowed_hosts = scope.trim()
      ? [target, ...scope.split(",").map((s) => s.trim()).filter(Boolean)]
      : [target];

    setSubmitting(true);
    setError(null);
    try {
      const session = await createSession({
        target: target.trim(),
        profile,
        authorization_token: authToken.trim(),
        scope: { allowed_hosts },
        llm_provider: preset.provider,
        llm_model: preset.model,
      });

      await runSession(session.id, {
        llm_provider: preset.provider,
        llm_model: preset.model,
        max_steps: maxSteps,
      });

      router.push(`/sessions/${session.id}`);
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Target <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="192.168.1.1 | 10.0.0.0/24 | https://example.com"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Scan Profile</label>
        <div className="flex gap-2">
          {PROFILES.map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setProfile(p)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                profile === p
                  ? "bg-blue-600 text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              {p.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Authorization Statement <span className="text-red-500">*</span>
        </label>
        <textarea
          value={authToken}
          onChange={(e) => setAuthToken(e.target.value)}
          placeholder="I have written permission to perform security testing on this system..."
          rows={3}
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Additional Scope (optional)
        </label>
        <input
          type="text"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          placeholder="192.168.2.0/24, staging.example.com (comma-separated)"
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">LLM Backend</label>
        <select
          value={llmPreset}
          onChange={(e) => setLlmPreset(Number(e.target.value))}
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          {LLM_PRESETS.map((p, i) => (
            <option key={i} value={i}>{p.label}</option>
          ))}
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Max Steps: <span className="font-mono">{maxSteps}</span>
        </label>
        <input
          type="range"
          min={10}
          max={100}
          step={5}
          value={maxSteps}
          onChange={(e) => setMaxSteps(Number(e.target.value))}
          className="w-full"
        />
      </div>

      <button
        type="submit"
        disabled={submitting}
        className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white font-medium py-2.5 px-4 rounded-lg transition-colors"
      >
        {submitting ? "Starting..." : "▶ Start Penetration Test"}
      </button>
    </form>
  );
}
