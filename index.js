import { summary, alerts, securityBaseline, journalTail, diskTop } from './lib/server-ops.js'
import { registerJsonTool } from './lib/register-json-tool.js'

export const name = 'plugin-manage-server'
export const inject = ['tools']

export function apply(ctx) {
  registerJsonTool(ctx, {
    name: 'server_summary',
    description: 'CPU/mem/disk, key systemd units, listening ports snapshot',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => summary(),
  })
  registerJsonTool(ctx, {
    name: 'server_alerts',
    description: 'Disk, service, TLS expiry, failed units alerts',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => alerts(),
  })
  registerJsonTool(ctx, {
    name: 'server_security_baseline',
    description: 'Read-only SSH/update/listener baseline checklist (not an attack scanner)',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    execute: async () => securityBaseline(),
  })
  registerJsonTool(ctx, {
    name: 'server_journal',
    description: 'Tail journalctl for allowlisted units: dsh-web|nginx|frps|ssh|sshd|fail2ban',
    parameters: {
      type: 'object',
      properties: {
        unit: { type: 'string' },
        lines: { type: 'number' },
      },
      additionalProperties: false,
    },
    execute: async (args) => journalTail(args),
  })
  registerJsonTool(ctx, {
    name: 'server_disk_top',
    description: 'df -h plus largest paths under /var /root /opt (read-only, no delete)',
    parameters: {
      type: 'object',
      properties: { limit: { type: 'number' } },
      additionalProperties: false,
    },
    execute: async (args) => diskTop(args),
  })
  console.log('[plugin-manage-server] tools registered')
}
