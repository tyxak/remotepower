# Fleet Query

**Fleet → Query** filters the whole fleet by ad-hoc criteria — OS contains,
kernel version, package installed, tag, group, online/offline, agent
version, and more. All conditions are **ANDed**; the result is a live device
table you can act on.

- **Saved queries** — save the ones you run often; they re-run on demand.
- Results include unmonitored devices (flagged), so inventory questions get
  complete answers.
- Typical uses: "which hosts still run agent < X", "everything in group Y
  without package Z", "offline hosts tagged production".

For one-off numeric/telemetry questions, the [AI assistant](ai.md) can also
answer fleet queries in natural language using the same data.

## When you want more than ANDed conditions

Fleet Query is deliberately simple. When you need nested AND/OR/NOT, or you want
to query security posture (disk encryption, host firewall, sshd configuration),
capacity, or CVE and drift rows rather than devices, use the
**[Data Explorer](data-explorer.md)** — 45 device fields across three entities,
with the same saved-query store and the same scoping.
