# Vendored data

| File | Source | Licence | Notes |
|---|---|---|---|
| `common-passwords.txt.gz` | SecLists `Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt` (danielmiessler/SecLists) | MIT | NFKC + case-folded, entries ≥ 10 characters only (the password policy requires ≥ 12). Used to reject common passwords. |
| `ne_admin0.geojson.gz`, `ne_admin1.geojson.gz`, `world_places.json.gz` | Natural Earth v5.1.2 (nvkelso/natural-earth-vector), built by `scripts/build_geodata.py` | Public domain | Simplified country and admin-1 polygons used to generalize GPS positions to region level; major place names for visual clues. |
