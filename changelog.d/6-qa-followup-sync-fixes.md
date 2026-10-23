- Ignore Docker `GEV_KEY_SETUP_TRUSTED_PEERS` entries that are not exact IP
  addresses (hostnames, bracketed addresses, zone indexes, CIDR ranges, `*`,
  and `none` inside a list) instead of logging them as trusted. Provider
  Settings matches exact addresses only (#6).
- Update Vite to 6.4.4, the patched 6.x release for GHSA-587h-7wmj-h5pm (#6).
- Add the Taiwan Freeway Bureau CCTV feed to the live-sources table, and note
  that the test suite needs Node.js >= 24.14 (#6).
