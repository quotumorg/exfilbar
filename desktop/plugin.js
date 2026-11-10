import { host, useValue, useQuery, STATUSBAR_AREAS, ROUTES_AREA, SIDEBAR_NAV_AREA } from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

const RED = 'var(--ui-red)'
const GREEN = 'var(--ui-green)'
const MUTED = 'var(--ui-text-secondary)'
const FAINT = 'var(--ui-text-tertiary)'
const LINE = 'var(--ui-stroke-tertiary, color-mix(in srgb, var(--ui-text-secondary) 25%, transparent))'
const MONO = 'var(--font-mono, ui-monospace, monospace)'
const SAMPLE = 'routes:\n  - paths: ["reports/**"]\n    to: ["https://uploads.example/reports/*"]'

function localTime(value) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const time = [date.getHours(), date.getMinutes(), date.getSeconds()].map(n => String(n).padStart(2, '0')).join(':')
  return date.toDateString() === new Date().toDateString() ? time : date.toLocaleDateString() + ' ' + time
}

// Stored rule text ends with the route reference, e.g. "off route; allowed hosts: x · route 1" or "route 1, route 2".
function splitRule(rule) {
  const match = /^(.*?)(?:\s·\s)?((?:route \d+(?:, )?)+)$/.exec(rule || '')
  return match ? { reason: match[1], route: match[2] } : { reason: rule || '', route: '' }
}

function currentScope(name) {
  const owner = host.state.focusedSessionOwner?.get()
  const connection = host.state.connectionId?.get()
  const profile = host.state.profile.get()
  const session = name === 'feed' ? host.state.focusedStoredSessionId.get() : ''
  // The SDK's REST door has ambient routing only. Never read another owner
  // through it. The SDK captures its scope synchronously when ctx.rest runs.
  const supported = Boolean(owner?.connectionId && owner?.profile && connection &&
    typeof host.activeConnectionId === 'function')
  const matched = supported && owner.connectionId === connection && owner.profile === profile &&
    (host.activeConnectionId() || 'local') === connection
  return { connection: owner?.connectionId || '', profile: owner?.profile || '', session,
    issue: !supported ? 'Connection ownership unavailable. Update Hermes Desktop or resolve the focused chat owner.'
      : !matched ? 'This chat belongs to another connection or profile. Activate its gateway to read Exfilbar.' : '' }
}

function sameScope(left, right) {
  return !right.issue && left.connection === right.connection && left.profile === right.profile && left.session === right.session
}

function useScoped(ctx, name, path, enabled, interval) {
  // Subscribe even when reads are suppressed so a completed activation retries.
  useValue(host.state.profile)
  useValue(host.state.connectionId || host.state.profile)
  useValue(host.state.focusedSessionOwner || host.state.profile)
  useValue(host.state.focusedStoredSessionId)
  const scope = currentScope(name)
  const query = useQuery({
    queryKey: [ctx.source, 'exfilbar-' + name, scope.connection, scope.profile, scope.session, path],
    enabled: enabled && !scope.issue,
    queryFn: async () => {
      if (scope.issue || !sameScope(scope, currentScope(name))) throw new Error('Exfilbar owner changed before request')
      const data = await ctx.rest(path)
      if (!sameScope(scope, currentScope(name))) throw new Error('Exfilbar owner changed during request')
      return data
    },
    refetchInterval: interval,
    staleTime: interval - 1000,
    retry: false
  })
  return { ...query, data: scope.issue ? undefined : query.data, scopeIssue: scope.issue, scope }
}

function useFeed(ctx) {
  const session = useValue(host.state.focusedStoredSessionId)
  return useScoped(ctx, 'feed', '/feed?session_id=' + encodeURIComponent(session || ''), Boolean(session), 3000)
}

function Chip({ ctx }) {
  const session = useValue(host.state.focusedStoredSessionId)
  const { data, isError, scopeIssue } = useFeed(ctx)
  const label = !session ? 'exfil · no session' : scopeIssue ? 'exfil · owner unavailable' : isError ? 'exfil · unavailable' : !data ? 'exfil · loading' : `exfil · ${data.out} out · ${data.blocked} blocked`
  return jsx('button', {
    type: 'button', onClick: () => host.navigate('/exfilbar'),
    title: scopeIssue || 'Open inspected attempts. Delivery is not confirmed.',
    style: { color: data?.blocked ? RED : MUTED, padding: '2px 6px', fontSize: '11px' },
    children: label
  })
}

function Badge({ tone, children }) {
  return jsx('span', {
    style: {
      display: 'inline-block', padding: '1px 8px', borderRadius: '999px', fontSize: '11px', fontWeight: 600, lineHeight: '18px',
      color: tone, background: `color-mix(in srgb, ${tone} 14%, transparent)`, border: `1px solid color-mix(in srgb, ${tone} 35%, transparent)`
    },
    children
  })
}

function Code({ children }) {
  return jsx('code', { style: { fontFamily: MONO, fontSize: '12px', background: 'var(--ui-inline-code-background, transparent)', padding: '1px 4px', borderRadius: '4px' }, children })
}

function Card({ title, aside, children }) {
  return jsxs('section', {
    style: { border: `1px solid ${LINE}`, borderRadius: '10px', padding: '14px 16px', marginBottom: '16px', background: 'var(--ui-bg-elevated, transparent)' },
    children: [
      jsxs('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '10px' }, children: [
        jsx('h2', { style: { fontSize: '13px', fontWeight: 600, margin: 0 }, children: title }),
        aside ? jsx('span', { style: { fontSize: '12px', color: FAINT }, children: aside }) : null
      ] }),
      children
    ]
  })
}

function Routes({ ctx }) {
  const { data, isError, scopeIssue } = useScoped(ctx, 'routes', '/routes', true, 10000)
  const hint = jsxs('p', { style: { fontSize: '12px', color: FAINT, margin: '10px 0 0' }, children: [
    'Edit routes under ', jsx(Code, { children: 'plugins.entries.exfilbar.settings' }), ' in config.yaml. ', jsx(Code, { children: '/exfil routes' }), ' prints what Hermes loaded.'
  ] })
  if (scopeIssue) return jsx(Card, { title: 'Your routes', children: jsx('p', { role: 'status', children: scopeIssue }) })
  if (isError) return jsx(Card, { title: 'Your routes', children: jsx('p', { role: 'alert', children: 'Routes temporarily unavailable. Retrying automatically. If this persists, check the backend plugin and gateway.' }) })
  if (!data) return jsx(Card, { title: 'Your routes', children: jsx('p', { role: 'status', children: 'Loading routes…' }) })
  if (!data.known) return jsx(Card, { title: 'Your routes', children: [data.valid === false ? jsx('p', { role: 'alert', children: 'No valid policy has been loaded; run /exfil routes to verify settings.' }, 'warning') : null, jsx('p', { role: 'status', children: 'Routes appear here once Hermes loads Exfilbar. Enable the backend plugin, restart the gateway, then run /exfil routes.' }, 'p'), hint] })
  const loaded = data.updated ? 'last loaded ' + new Date(data.updated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }) : 'load time unknown'
  const status = [
    jsx('p', { style: { fontSize: '12px', color: FAINT }, children: 'host summary; ports and paths omitted. ' + loaded }, 'summary'),
    data.valid === false ? jsx('p', { role: 'alert', children: 'Current settings are invalid or unavailable; showing the last valid policy.' }, 'warning') : null
  ]
  if (!data.routes.length) {
    return jsx(Card, { title: 'Your routes', aside: 'none yet', children: [
      ...status,
      jsx('p', { style: { margin: '0 0 8px' }, children: 'No routes yet. Protected files and destination denies still apply. A route says which files may go where:' }, 'p'),
      jsx('pre', { style: { fontFamily: MONO, fontSize: '12px', margin: 0, padding: '10px 12px', borderRadius: '8px', background: 'var(--ui-terminal-surface-background, var(--ui-bg-editor, transparent))', whiteSpace: 'pre' }, children: SAMPLE }, 'pre'),
      hint
    ] })
  }
  return jsx(Card, {
    title: 'Last mirrored routes', aside: `${data.routes.length} configured`,
    children: [
      ...status,
      jsx('ul', { style: { listStyle: 'none', margin: 0, padding: 0 }, children: data.routes.map(route => jsxs('li', {
        style: { display: 'grid', gridTemplateColumns: '72px 1fr', gap: '8px', padding: '6px 0', borderTop: route.position > 1 ? `1px solid ${LINE}` : 'none', alignItems: 'baseline' },
        children: [
          jsx('span', { style: { fontSize: '12px', color: MUTED, fontVariantNumeric: 'tabular-nums' }, children: 'route ' + route.position }),
          jsxs('span', { style: { overflowWrap: 'anywhere' }, children: [
            jsx('span', { style: { fontFamily: MONO, fontSize: '12px' }, children: route.paths.join(', ') }),
            jsx('span', { style: { color: FAINT, margin: '0 8px' }, children: 'may go to' }),
            jsx('span', { style: { fontFamily: MONO, fontSize: '12px' }, children: route.hosts.map(h => h === '*' ? 'any destination' : h).join(', ') }),
            (route.paths_omitted || route.hosts_omitted || route.paths_shortened || route.hosts_shortened) ? jsx('small', {
              style: { display: 'block', color: FAINT },
              children: `Summary truncated: ${route.paths_omitted || 0} paths and ${route.hosts_omitted || 0} hosts omitted; ${route.paths_shortened || 0} path patterns and ${route.hosts_shortened || 0} host patterns shortened.`
            }) : null
          ] })
        ]
      }, route.position)) }, 'ul'),
      hint
    ]
  })
}

function Decision({ event }) {
  const { reason, route } = splitRule(event.rule)
  const blocked = event.decision === 'blocked'
  return jsxs('div', { children: [
    jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }, children: [
      jsx(Badge, { tone: blocked ? RED : GREEN, children: event.decision }),
      route ? jsx('span', { style: { fontSize: '12px', color: MUTED }, children: route }) : null
    ] }),
    reason ? jsx('div', { style: { fontSize: '12px', color: blocked ? RED : MUTED, marginTop: '4px' }, children: reason }) : null
  ] })
}

function Feed({ ctx }) {
  const session = useValue(host.state.focusedStoredSessionId)
  const { data, isError, scopeIssue, scope } = useFeed(ctx)
  const message = !session ? 'Choose a chat session to see its transfers.'
    : scopeIssue ? scopeIssue
    : isError ? 'Feed temporarily unavailable. Retrying automatically. If this persists, check the backend plugin and gateway.'
    : !data ? 'Loading session feed…'
    : !data.events.length ? 'No recognized transfers inspected in this session yet. Run /exfil demo in chat for an isolated route comparison, or python3 demo/routes.py from the plugin directory. Dry runs do not populate this feed.'
    : ''
  const cell = { padding: '10px 8px', textAlign: 'left', verticalAlign: 'top', overflowWrap: 'anywhere', borderBottom: `1px solid ${LINE}` }
  const head = { ...cell, fontSize: '11px', fontWeight: 600, color: MUTED, textTransform: 'none' }
  return jsxs('section', {
    style: { padding: '24px 28px', color: 'var(--ui-text-primary)', height: '100%', overflow: 'auto', maxWidth: '1100px' },
    children: [
      jsx('h1', { style: { fontSize: '20px', margin: '0 0 6px' }, children: 'Exfilbar' }),
      scope.connection && scope.profile ? jsx('p', { style: { margin: '0 0 8px', color: MUTED, overflowWrap: 'anywhere' }, children: `connection ${scope.connection} · profile ${scope.profile}` }) : null,
      jsx('p', { style: { margin: '0 0 18px', color: MUTED }, children: 'Recognized uploads are checked against your routes before they run. Unmatched files follow your default rules. Delivery is not confirmed.' }),
      jsx(Routes, { ctx }),
      jsx(Card, {
        title: 'This session',
        aside: data && !message ? `${data.out} out · ${data.blocked} blocked` : undefined,
        children: message ? jsx('p', { role: isError ? 'alert' : 'status', style: { margin: 0, color: isError ? RED : 'inherit' }, children: message }) : jsxs('table', {
          style: { width: '100%', fontSize: '13px', borderCollapse: 'collapse', tableLayout: 'fixed' },
          children: [
            jsx('caption', { style: { position: 'absolute', width: '1px', height: '1px', overflow: 'hidden', clip: 'rect(0 0 0 0)' }, children: `${data.out} out · ${data.blocked} blocked · retained attempts` }),
            jsx('colgroup', { children: ['15%', '10%', '24%', '21%', '30%'].map((w, i) => jsx('col', { style: { width: w } }, i)) }),
            jsx('thead', { children: jsx('tr', { children: ['Time', 'Tool', 'Files', 'Destination', 'Decision'].map(label => jsx('th', { scope: 'col', style: head, children: label }, label)) }) }),
            jsx('tbody', { children: [...data.events].reverse().map((event, i) => jsxs('tr', {
              style: event.decision === 'blocked' ? { background: `color-mix(in srgb, ${RED} 5%, transparent)` } : undefined,
              children: [
                jsx('td', { title: event.time, style: { ...cell, color: MUTED, fontVariantNumeric: 'tabular-nums' }, children: localTime(event.time) }),
                jsx('td', { style: { ...cell, color: MUTED }, children: event.tool }),
                jsx('td', { style: { ...cell, fontFamily: MONO, fontSize: '12px' }, children: (event.paths.join(', ') || 'unresolved') + (event.paths_truncated ? ' (truncated)' : '') }),
                jsx('td', { style: { ...cell, fontFamily: MONO, fontSize: '12px' }, children: event.destination }),
                jsx('td', { style: cell, children: jsx(Decision, { event }) })
              ]
            }, i)) })
          ]
        })
      }),
      jsx('p', { style: { fontSize: '12px', color: FAINT, margin: '4px 0 0' }, children: 'Checks recognized terminal and submitted-Python transfer syntax against configured routes; not a sandbox. The latest 128 transfers per session are retained.' })
    ]
  })
}

export default {
  id: 'exfilbar', name: 'Exfilbar', defaultEnabled: false,
  register(ctx) {
    ctx.register({ id: 'chip', area: STATUSBAR_AREAS.right, order: 140, render: () => jsx(Chip, { ctx }) })
    ctx.register({ id: 'feed', area: ROUTES_AREA, data: { path: '/exfilbar' }, render: () => jsx(Feed, { ctx }) })
    ctx.register({ id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: '/exfilbar', label: 'Exfilbar', codicon: 'shield' } })
  }
}
