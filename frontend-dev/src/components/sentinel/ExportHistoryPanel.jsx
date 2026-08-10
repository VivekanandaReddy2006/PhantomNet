import React from 'react';

/**
 * ExportHistoryPanel Component
 * Displays playbook export audit trail (format, user, timestamp).
 */
export default function ExportHistoryPanel({ auditLogs }) {
  const exportLogs = (auditLogs || []).filter(
    (log) => log.action === 'export' || log.action === 'batch_approve' || log.action === 'approve'
  );

  return (
    <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 space-y-3">
      <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
        <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        Playbook Activity & Export Audit Trail
      </h4>

      {exportLogs.length === 0 ? (
        <p className="text-xs text-slate-500 italic">No recent export activity recorded.</p>
      ) : (
        <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
          {exportLogs.map((log) => (
            <div key={log.id} className="text-xs flex justify-between items-center bg-slate-950/40 p-2 rounded border border-slate-900">
              <div className="flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {log.action}
                </span>
                <span className="text-slate-300 font-mono">{log.playbook_id || 'System'}</span>
              </div>
              <div className="text-slate-500">
                <span>{log.user}</span> • <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
