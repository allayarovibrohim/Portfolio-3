import geoip from "geoip-lite";

export interface GeoLocationSnapshot {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
}

export const resolveGeoLocation = (ipAddress?: string): GeoLocationSnapshot => {
  if (!ipAddress) {
    return {};
  }

  const lookup = geoip.lookup(ipAddress);
  if (!lookup) {
    return {};
  }

  return {
    country: lookup.country,
    region: lookup.region,
    city: lookup.city,
    latitude: lookup.ll?.[0],
    longitude: lookup.ll?.[1],
  };
};
