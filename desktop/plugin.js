import { host, useValue, useQuery, STATUSBAR_AREAS, ROUTES_AREA, SIDEBAR_NAV_AREA } from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

function localTime(value) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const time = [date.getHours(), date.getMinutes(), date.getSeconds()].map(n => String(n).padStart(2, '0')).join(':')
  return date.toDateString() === new Date().toDateString() ? time : date.toLocaleDateString() + ' ' + time
}

function useFeed(ctx) {
  const session = useValue(host.state.focusedStoredSessionId)
  const profile = useValue(host.state.profile)
  const gateway = useValue(host.state.gateway)
  return useQuery({
    queryKey: [ctx.source, 'exfilbar-feed', profile, gateway, session],
    enabled: Boolean(session),
    queryFn: () => ctx.rest('/feed?session_id=' + encodeURIComponent(session)),
    refetchInterval: 3000,
    staleTime: 2000,
    retry: false
  })
}

function Chip({ ctx }) {
  const session = useValue(host.state.focusedStoredSessionId)
  const { data, isError } = useFeed(ctx)
  const label = !session ? 'exfil · no session' : isError ? 'exfil · unavailable' : !data ? 'exfil · loading' : `exfil · ${data.out} out · ${data.blocked} blocked`
  return jsx('button', {
    type: 'button', onClick: () => host.navigate('/exfilbar'),
    title: 'Open inspected attempts. Delivery is not confirmed.',
    style: { color: data?.blocked ? 'var(--ui-red)' : 'var(--ui-text-secondary)', padding: '2px 6px', fontSize: '11px' },
    children: label
  })
}

function Feed({ ctx }) {
  const session = useValue(host.state.focusedStoredSessionId)
  const { data, isError } = useFeed(ctx)
  const message = !session ? 'Choose a chat session to see its transfers.' : isError ? 'Feed unavailable. Enable the backend plugin, restart the gateway, and retry.' : !data ? 'Loading session feed…' : !data.events.length ? 'No recognized transfers inspected in this session.' : ''
  const cell = { padding: '8px', textAlign: 'left', verticalAlign: 'top', overflowWrap: 'anywhere', borderBottom: '1px solid color-mix(in srgb, var(--ui-text-secondary) 25%, transparent)' }
  return jsxs('section', {
    style: { padding: '20px', color: 'var(--ui-text-primary)', height: '100%', overflow: 'auto' },
    children: [
      jsx('h1', { style: { fontSize: '20px', marginBottom: '8px' }, children: 'Session egress' }),
      jsx('p', { children: 'Inspected attempts from terminal and execute_code. Delivery is not confirmed.' }),
      jsx('p', { style: { margin: '12px 0', color: 'var(--ui-text-secondary)' }, children: 'The latest 128 transfers per session are retained. Static recognition only; scripts and other tools can bypass it.' }),
      message ? jsx('p', { role: isError ? 'alert' : 'status', children: message }) : jsxs('table', {
        style: { width: '100%', fontSize: '12px', borderCollapse: 'collapse', tableLayout: 'fixed' },
        children: [
          jsx('caption', { style: { textAlign: 'left', padding: '12px 0' }, children: `${data.out} out · ${data.blocked} blocked · retained attempts` }),
          jsx('thead', { children: jsx('tr', { children: ['Time', 'Tool', 'Files', 'Destination', 'Decision / rule'].map(label => jsx('th', { scope: 'col', style: cell, children: label }, label)) }) }),
          jsx('tbody', { children: [...data.events].reverse().map((event, i) => jsx('tr', {
            children: [localTime(event.time), event.tool, (event.paths.join(', ') || 'unresolved') + (event.paths_truncated ? ' (truncated)' : ''), event.destination, event.decision + (event.rule ? ' · ' + event.rule : '')].map((value, j) => jsx('td', {
              title: j === 0 ? event.time : undefined,
              style: { ...cell, color: j === 4 && event.decision === 'blocked' ? 'var(--ui-red)' : 'inherit', fontVariantNumeric: 'tabular-nums' }, children: value
            }, j))
          }, i)) })
        ]
      })
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
