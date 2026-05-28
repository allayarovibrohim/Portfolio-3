export const sanitizeObject = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeObject(entry));
  }

  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).reduce<Record<string, unknown>>((acc, [key, entry]) => {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        return acc;
      }

      acc[key] = sanitizeObject(entry);
      return acc;
    }, {});
  }

  if (typeof value === "string") {
    return value.trim();
  }

  return value;
};
