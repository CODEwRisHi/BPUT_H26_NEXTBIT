import React, { useState } from 'react';
import axios from 'axios';
import { ShieldAlert, CheckCircle, AlertTriangle, Terminal, Send } from 'lucide-react';

export default function App() {
  const [sourceType, setSourceType] = useState('email');
  const [content, setContent] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post('http://localhost:8000/api/v1/analyze', {
        source_type: sourceType,
        content: content
      });
      setResult(response.data.analysis);
    } catch (err) {
      console.error(err);
      alert('Failed to connect to backend engine.');
    } finally {
      setLoading(false);
    }
  };

  const getBadgeColor = (level) => {
    switch (level) {
      case 'Critical': return 'bg-red-600 text-white';
      case 'High': return 'bg-orange-500 text-white';
      case 'Medium': return 'bg-yellow-500 text-black';
      case 'Low': return 'bg-blue-500 text-white';
      default: return 'bg-green-600 text-white';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
      <header className="max-w-5xl mx-auto flex items-center justify-between pb-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-8 h-8 text-cyan-400" />
          <h1 className="text-2xl font-bold tracking-wide">CyberShield AI — SOC Dashboard</h1>
        </div>
        <span className="text-xs px-3 py-1 bg-cyan-950 border border-cyan-800 text-cyan-400 rounded-full">System Online</span>
      </header>

      <main className="max-w-5xl mx-auto mt-8 grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400" /> Telemetry Ingestion Simulator
          </h2>
          <form onSubmit={handleAnalyze} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Data Source Vector</label>
              <select 
                value={sourceType} 
                onChange={(e) => setSourceType(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="email">Phishing Email / Message</option>
                <option value="url">Malicious URL / Domain</option>
                <option value="auth_log">Authentication / Session Log</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-1">Payload Content / Log Data</label>
              <textarea 
                rows="5"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Paste suspicious email text, URL, or log snippet here..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500"
                required
              />
            </div>
            <button 
              type="submit" 
              disabled={loading}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2.5 rounded-lg transition flex items-center justify-center gap-2"
            >
              <Send className="w-4 h-4" /> {loading ? 'Analyzing Threat...' : 'Run AI Analysis'}
            </button>
          </form>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg flex flex-col justify-between">
          <div>
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-cyan-400" /> Explainable Risk Assessment
            </h2>
            {result ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-slate-400">Threat Risk Level:</span>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${getBadgeColor(result.risk_level)}`}>
                    {result.risk_level}
                  </span>
                </div>
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block mb-1">Calculated Score:</span>
                  <div className="text-2xl font-mono font-bold text-cyan-400">{(result.risk_score * 100).toFixed(0)}% / 100%</div>
                </div>
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block mb-2">Explainable AI (XAI) Indicators:</span>
                  <ul className="list-disc list-inside space-y-1 text-sm text-slate-300">
                    {result.explanation.map((exp, idx) => (
                      <li key={idx}>{exp}</li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-slate-600 text-center">
                <CheckCircle className="w-12 h-12 mb-2 opacity-40" />
                <p>Awaiting telemetry input. Submit a payload to generate analysis.</p>
              </div>
            )}
          </div>
          {result && (
            <div className="mt-4 pt-4 border-t border-slate-800 flex gap-2">
              <button 
                onClick={() => alert('Automated playbook triggered: IP/Domain Blocked & Session Revoked.')}
                className="flex-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-800 py-2 rounded-lg text-sm font-medium transition"
              >
                Trigger Mitigation Playbook
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}