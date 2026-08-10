import React from 'react';

/**
 * CampaignTimelineChart Component
 * Visualizes attack event density over time for a selected campaign.
 */
export default function CampaignTimelineChart({ timelineData, campaignId }) {
  if (!timelineData || timelineData.length === 0) {
    return (
      <div className="p-4 text-center text-slate-400 bg-slate-900/50 rounded-lg border border-slate-800">
        No campaign timeline data available.
      </div>
    );
  }

  const maxCount = Math.max(...timelineData.map((d) => d.count), 1);

  return (
    <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 space-y-3">
      <div className="flex justify-between items-center">
        <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          Campaign Timeline & Density ({campaignId || 'Active'})
        </h4>
        <span className="text-xs text-slate-400">
          Total Events: {timelineData.reduce((acc, curr) => acc + curr.count, 0)}
        </span>
      </div>

      <div className="h-32 flex items-end gap-2 pt-4 px-2 bg-slate-950/60 rounded-lg border border-slate-900">
        {timelineData.map((item, idx) => {
          const heightPct = Math.round((item.count / maxCount) * 100);
          return (
            <div key={idx} className="flex-1 flex flex-col items-center group relative">
              {/* Tooltip */}
              <div className="absolute -top-8 hidden group-hover:block bg-slate-800 text-xs text-slate-100 px-2 py-1 rounded shadow-lg z-10 whitespace-nowrap border border-slate-700">
                {item.timestamp}: <strong>{item.count} events</strong>
              </div>

              {/* Bar */}
              <div
                className="w-full bg-emerald-500/80 group-hover:bg-emerald-400 transition-all rounded-t"
                style={{ height: `${Math.max(heightPct, 5)}%` }}
              ></div>

              <span className="text-[10px] text-slate-500 mt-1 truncate max-w-[40px]">
                {item.timestamp.split(' ')[1] || item.timestamp}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
