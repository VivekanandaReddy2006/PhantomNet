import SentinelStatsPanel from "./SentinelStatsPanel";

export default {
  title: "Components/Sentinel/SentinelStatsPanel",
  component: SentinelStatsPanel,
};

export const LoadingState = {
  args: {
    loading: true,
    stats: null,
  },
};

export const PopulatedState = {
  args: {
    loading: false,
    stats: {
      total_playbooks: 24,
      pending: 4,
      approved: 18,
      rejected: 2,
      approval_rate: 90,
      avg_threat_score: 72.5,
      avg_confidence_score: 0.88,
      severity_distribution: {
        critical: 3,
        high: 9,
        medium: 10,
        low: 2,
      },
      generation_trends: [
        { date: "2026-07-24", count: 2 },
        { date: "2026-07-25", count: 4 },
        { date: "2026-07-26", count: 3 },
        { date: "2026-07-27", count: 8 },
        { date: "2026-07-28", count: 5 },
        { date: "2026-07-29", count: 12 },
        { date: "2026-07-30", count: 9 },
      ],
    },
  },
};

export const EmptyFallbackState = {
  args: {
    loading: false,
    stats: {
      total_playbooks: 0,
      pending: 0,
      approved: 0,
      rejected: 0,
      approval_rate: 0,
      severity_distribution: {},
      generation_trends: [],
    },
  },
};
