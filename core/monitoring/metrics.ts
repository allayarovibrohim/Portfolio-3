const counters = new Map<string, number>();

export const incrementMetric = (key: string, value = 1) => {
  counters.set(key, (counters.get(key) || 0) + value);
};

export const setMetric = (key: string, value: number) => {
  counters.set(key, value);
};

export const getMetricsSnapshot = () =>
  Array.from(counters.entries()).reduce<Record<string, number>>((acc, [key, value]) => {
    acc[key] = value;
    return acc;
  }, {});
