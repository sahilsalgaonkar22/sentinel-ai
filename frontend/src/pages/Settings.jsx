import React, { useEffect, useState } from 'react';
import { settingsAPI } from '../api/client';
import {
  Settings as SettingsIcon,
  Bell,
  Shield,
  Brain,
  Users,
  Building2,
  Save,
  CheckCircle2,
  AlertCircle,
  Mail,
  MessageSquare,
  Server,
  Key,
  ChevronRight,
  Loader2,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const TABS = [
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'scanning', label: 'Scanning', icon: Shield },
  { id: 'ai', label: 'AI / LLM', icon: Brain },
  { id: 'organization', label: 'Organization', icon: Building2 },
  { id: 'users', label: 'Users', icon: Users },
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [settings, setSettings] = useState(null);
  const [profile, setProfile] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAll();
  }, []);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [settingsRes, profileRes] = await Promise.allSettled([
        settingsAPI.getSettings(),
        settingsAPI.getProfile(),
      ]);
      if (settingsRes.status === 'fulfilled') setSettings(settingsRes.value.data);
      if (profileRes.status === 'fulfilled') setProfile(profileRes.value.data);
    } catch (e) {
      setError('Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await settingsAPI.listUsers();
      setUsers(res.data.items || []);
    } catch {
      setUsers([]);
    }
  };

  useEffect(() => {
    if (activeTab === 'users') fetchUsers();
  }, [activeTab]);

  const handleSave = async (section, data) => {
    setSaving(true);
    setSaved(false);
    setError(null);
    try {
      if (section === 'alerts') await settingsAPI.updateAlerts(data);
      else if (section === 'scanning') await settingsAPI.updateScanning(data);
      else if (section === 'ai') await settingsAPI.updateAI(data);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      await fetchAll();
    } catch (e) {
      setError(e.response?.data?.detail || 'Save failed. Ensure you have admin permissions.');
    } finally {
      setSaving(false);
    }
  };

  const handleRoleChange = async (userId, newRole) => {
    try {
      await settingsAPI.updateUserRole(userId, newRole);
      fetchUsers();
    } catch (e) {
      setError(e.response?.data?.detail || 'Role update failed');
    }
  };

  if (loading) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <Loader2 className="w-12 h-12 animate-spin mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Loading Configuration...</span>
      </div>
    );
  }

  const alerts = settings?.alerts || {};
  const scanning = settings?.scanning || {};
  const ai = settings?.ai || {};

  return (
    <div className="space-y-6 page-entry">
      {/* Header */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Settings</h2>
          <p className="text-slate-400 mt-2 max-w-2xl text-sm leading-relaxed">
            Configure platform alerts, scanning preferences, AI engine, and organization settings.
          </p>
        </div>
        {saved && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-bold"
          >
            <CheckCircle2 className="w-4 h-4" /> Settings saved
          </motion.div>
        )}
      </div>

      {error && (
        <div className="px-5 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4" /> {error}
        </div>
      )}

      <div className="grid grid-cols-12 gap-6">
        {/* Tab Sidebar */}
        <div className="col-span-12 lg:col-span-3">
          <div className="glass-panel rounded-3xl border border-white/5 overflow-hidden bg-slate-950/40">
            <div className="p-4 space-y-1">
              {TABS.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl text-sm font-medium transition-all ${
                      activeTab === tab.id
                        ? 'bg-primary/10 text-primary border border-primary/20'
                        : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {tab.label}
                    <ChevronRight className={`w-3 h-3 ml-auto transition-transform ${activeTab === tab.id ? 'rotate-90' : ''}`} />
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="col-span-12 lg:col-span-9">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              {activeTab === 'alerts' && (
                <AlertsTab alerts={alerts} onSave={(data) => handleSave('alerts', data)} saving={saving} />
              )}
              {activeTab === 'scanning' && (
                <ScanningTab scanning={scanning} onSave={(data) => handleSave('scanning', data)} saving={saving} />
              )}
              {activeTab === 'ai' && (
                <AITab ai={ai} onSave={(data) => handleSave('ai', data)} saving={saving} />
              )}
              {activeTab === 'organization' && <OrgTab profile={profile} />}
              {activeTab === 'users' && <UsersTab users={users} onRoleChange={handleRoleChange} />}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

/* ── Alert Settings Tab ───────────────────────────────────────── */
function AlertsTab({ alerts, onSave, saving }) {
  const [form, setForm] = useState({ ...alerts });
  const set = (key, val) => setForm((f) => ({ ...f, [key]: val }));

  return (
    <div className="glass-panel rounded-3xl border border-white/5 bg-slate-950/40 overflow-hidden">
      <div className="px-8 py-6 border-b border-white/5 bg-white/5 flex items-center gap-3">
        <Mail className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-bold tracking-[0.15em] text-white uppercase font-headline">Alert Configuration</h3>
      </div>
      <div className="p-8 space-y-6">
        <div className="grid grid-cols-2 gap-6">
          <ToggleField label="Email Alerts" value={form.email_enabled} onChange={(v) => set('email_enabled', v)} />
          <ToggleField label="Slack Alerts" value={form.slack_enabled} onChange={(v) => set('slack_enabled', v)} />
        </div>
        {form.email_enabled && (
          <div className="grid grid-cols-2 gap-6 animate-entry">
            <InputField label="SMTP Host" value={form.smtp_host} onChange={(v) => set('smtp_host', v)} placeholder="smtp.gmail.com" />
            <InputField label="SMTP Port" value={form.smtp_port} onChange={(v) => set('smtp_port', parseInt(v) || 587)} type="number" />
            <InputField label="SMTP User" value={form.smtp_user} onChange={(v) => set('smtp_user', v)} placeholder="alerts@company.com" />
            <InputField label="SMTP Password" value={form.smtp_password} onChange={(v) => set('smtp_password', v)} type="password" />
            <div className="col-span-2">
              <InputField
                label="Alert Recipients (comma-separated)"
                value={Array.isArray(form.alert_recipients) ? form.alert_recipients.join(', ') : form.alert_recipients || ''}
                onChange={(v) => set('alert_recipients', v.split(',').map((s) => s.trim()).filter(Boolean))}
                placeholder="admin@company.com, security@company.com"
              />
            </div>
          </div>
        )}
        {form.slack_enabled && (
          <div className="animate-entry">
            <InputField label="Slack Webhook URL" value={form.slack_webhook} onChange={(v) => set('slack_webhook', v)} placeholder="https://hooks.slack.com/services/..." />
          </div>
        )}
        <div className="grid grid-cols-3 gap-6">
          <ToggleField label="Alert on Critical" value={form.alert_on_critical ?? true} onChange={(v) => set('alert_on_critical', v)} />
          <ToggleField label="Alert on High" value={form.alert_on_high ?? true} onChange={(v) => set('alert_on_high', v)} />
          <InputField label="Score Threshold" value={form.alert_on_score_below ?? 80} onChange={(v) => set('alert_on_score_below', parseInt(v) || 80)} type="number" />
        </div>
        <SaveButton onClick={() => onSave(form)} saving={saving} />
      </div>
    </div>
  );
}

/* ── Scanning Settings Tab ────────────────────────────────────── */
function ScanningTab({ scanning, onSave, saving }) {
  const [form, setForm] = useState({ ...scanning });
  const set = (key, val) => setForm((f) => ({ ...f, [key]: val }));

  return (
    <div className="glass-panel rounded-3xl border border-white/5 bg-slate-950/40 overflow-hidden">
      <div className="px-8 py-6 border-b border-white/5 bg-white/5 flex items-center gap-3">
        <Shield className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-bold tracking-[0.15em] text-white uppercase font-headline">Scan Configuration</h3>
      </div>
      <div className="p-8 space-y-6">
        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-3">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Execution Mode</label>
            <div className="grid grid-cols-2 gap-2">
              {['local', 'distributed'].map((m) => (
                <button
                  key={m}
                  onClick={() => set('default_scan_mode', m)}
                  className={`py-3 rounded-2xl text-[10px] font-bold uppercase tracking-widest border transition-all ${
                    form.default_scan_mode === m ? 'bg-primary/10 border-primary text-primary' : 'bg-white/5 border-transparent text-slate-500 hover:text-white'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>
          <InputField label="Max Concurrent Scans" value={form.max_concurrent_scans ?? 10} onChange={(v) => set('max_concurrent_scans', parseInt(v) || 10)} type="number" />
        </div>
        <div className="grid grid-cols-2 gap-6">
          <InputField label="Scan Timeout (seconds)" value={form.scan_timeout_seconds ?? 300} onChange={(v) => set('scan_timeout_seconds', parseInt(v) || 300)} type="number" />
          <ToggleField label="Allow Advanced Scans (Pentagi)" value={form.allow_advanced_scans} onChange={(v) => set('allow_advanced_scans', v)} />
        </div>
        <ToggleField label="Auto-Schedule Enabled" value={form.auto_schedule_enabled} onChange={(v) => set('auto_schedule_enabled', v)} />
        <SaveButton onClick={() => onSave(form)} saving={saving} />
      </div>
    </div>
  );
}

/* ── AI / LLM Settings Tab ────────────────────────────────────── */
function AITab({ ai, onSave, saving }) {
  const [form, setForm] = useState({ ...ai });
  const set = (key, val) => setForm((f) => ({ ...f, [key]: val }));

  return (
    <div className="glass-panel rounded-3xl border border-white/5 bg-slate-950/40 overflow-hidden">
      <div className="px-8 py-6 border-b border-white/5 bg-white/5 flex items-center gap-3">
        <Brain className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-bold tracking-[0.15em] text-white uppercase font-headline">AI Engine Configuration</h3>
      </div>
      <div className="p-8 space-y-6">
        <div className="grid grid-cols-2 gap-6">
          <InputField label="LLM API Key" value={form.llm_api_key || ''} onChange={(v) => set('llm_api_key', v)} type="password" placeholder="sk-..." />
          <InputField label="LLM Endpoint" value={form.llm_endpoint || 'https://api.openai.com/v1'} onChange={(v) => set('llm_endpoint', v)} />
        </div>
        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-3">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">LLM Model</label>
            <div className="grid grid-cols-3 gap-2">
              {['gpt-4', 'gpt-4o', 'gpt-3.5-turbo'].map((m) => (
                <button
                  key={m}
                  onClick={() => set('llm_model', m)}
                  className={`py-3 rounded-2xl text-[10px] font-bold uppercase tracking-widest border transition-all ${
                    form.llm_model === m ? 'bg-primary/10 border-primary text-primary' : 'bg-white/5 border-transparent text-slate-500 hover:text-white'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>
          <InputField label="FP Filter Threshold" value={form.false_positive_threshold ?? 0.5} onChange={(v) => set('false_positive_threshold', parseFloat(v) || 0.5)} type="number" />
        </div>
        <ToggleField label="Auto-Deduplicate Findings" value={form.auto_deduplicate ?? true} onChange={(v) => set('auto_deduplicate', v)} />
        <SaveButton onClick={() => onSave(form)} saving={saving} />
      </div>
    </div>
  );
}

/* ── Organization Tab ─────────────────────────────────────────── */
function OrgTab({ profile }) {
  if (!profile) return <div className="text-slate-500 text-sm p-8">No organization data available.</div>;
  return (
    <div className="glass-panel rounded-3xl border border-white/5 bg-slate-950/40 overflow-hidden">
      <div className="px-8 py-6 border-b border-white/5 bg-white/5 flex items-center gap-3">
        <Building2 className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-bold tracking-[0.15em] text-white uppercase font-headline">Organization Profile</h3>
      </div>
      <div className="p-8">
        <div className="grid grid-cols-2 gap-y-6 gap-x-12">
          <InfoRow label="Name" value={profile.name} />
          <InfoRow label="Slug" value={profile.slug} />
          <InfoRow label="Plan" value={profile.plan} />
          <InfoRow label="Status" value={profile.is_active ? 'Active' : 'Disabled'} />
          <InfoRow label="Max Scans/Day" value={profile.max_scans_per_day} />
          <InfoRow label="Max Assets" value={profile.max_assets} />
          <InfoRow label="Created" value={profile.created_at ? new Date(profile.created_at).toLocaleDateString() : '—'} />
        </div>
      </div>
    </div>
  );
}

/* ── Users Tab ────────────────────────────────────────────────── */
function UsersTab({ users, onRoleChange }) {
  return (
    <div className="glass-panel rounded-3xl border border-white/5 bg-slate-950/40 overflow-hidden">
      <div className="px-8 py-6 border-b border-white/5 bg-white/5 flex items-center gap-3">
        <Users className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-bold tracking-[0.15em] text-white uppercase font-headline">User Management</h3>
      </div>
      <div className="p-8">
        {users.length === 0 ? (
          <div className="text-slate-500 text-sm text-center py-8">No users found in this organization.</div>
        ) : (
          <div className="space-y-3">
            {users.map((u) => (
              <div key={u.id} className="flex items-center justify-between p-4 rounded-2xl bg-white/5 border border-white/5 hover:border-primary/20 transition-all">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center text-primary font-bold text-sm">
                    {(u.full_name || u.username || 'U').charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm font-bold text-white">{u.full_name || u.username}</div>
                    <div className="text-xs text-slate-500">{u.email}</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-[9px] font-bold px-2 py-1 rounded uppercase tracking-widest ${
                    u.is_active ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
                  }`}>
                    {u.is_active ? 'Active' : 'Disabled'}
                  </span>
                  <select
                    value={u.role}
                    onChange={(e) => onRoleChange(u.id, e.target.value)}
                    className="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:ring-1 focus:ring-primary/50 outline-none cursor-pointer"
                  >
                    <option value="admin">Admin</option>
                    <option value="analyst">Analyst</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Shared Components ────────────────────────────────────────── */
function InputField({ label, value, onChange, type = 'text', placeholder = '' }) {
  return (
    <div className="space-y-2">
      <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">{label}</label>
      <input
        type={type}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-3 text-sm text-white focus:ring-1 focus:ring-primary/50 outline-none placeholder:text-slate-600"
      />
    </div>
  );
}

function ToggleField({ label, value, onChange }) {
  return (
    <div className="flex items-center justify-between p-4 rounded-2xl bg-white/5 border border-white/5">
      <span className="text-sm text-slate-300 font-medium">{label}</span>
      <button
        onClick={() => onChange(!value)}
        className={`relative w-12 h-7 rounded-full transition-all ${value ? 'bg-primary' : 'bg-slate-700'}`}
      >
        <span className={`absolute top-1 w-5 h-5 rounded-full bg-white shadow transition-all ${value ? 'left-6' : 'left-1'}`} />
      </button>
    </div>
  );
}

function SaveButton({ onClick, saving }) {
  return (
    <div className="pt-4 flex justify-end">
      <button
        onClick={onClick}
        disabled={saving}
        className="px-8 py-3 rounded-2xl bg-primary text-black font-black text-xs uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(189,157,255,0.3)] hover:shadow-[0_0_50px_rgba(189,157,255,0.6)] transition-all active:scale-95 disabled:opacity-50 flex items-center gap-2"
      >
        {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
        {saving ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div>
      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">{label}</div>
      <div className="text-sm font-medium text-white">{value ?? '—'}</div>
    </div>
  );
}
