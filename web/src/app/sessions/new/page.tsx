import { NewSessionForm } from "@/components/sessions/NewSessionForm";

export default function NewSessionPage() {
  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">New Penetration Test</h1>
      <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-sm">
        <NewSessionForm />
      </div>
    </div>
  );
}
