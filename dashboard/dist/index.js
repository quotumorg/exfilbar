/* Web dashboard SDK; uses the host's React and authenticated fetchJSON. */
(() => {
  const SDK = window.__HERMES_PLUGIN_SDK__
  const { createElement: h } = SDK.React
  const { useEffect, useState } = SDK.hooks

  function localTime(value) {
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    const time = [date.getHours(), date.getMinutes(), date.getSeconds()].map(n => String(n).padStart(2, '0')).join(':')
    return date.toDateString() === new Date().toDateString() ? time : date.toLocaleDateString() + ' ' + time
  }

  function Feed() {
    const [sessions, setSessions] = useState([])
    const [selected, setSelected] = useState('')
    const [data, setData] = useState(null)
    const [failed, setFailed] = useState(false)
    useEffect(() => {
      let active = true
      let busy = false
      setData(null)
      const load = async () => {
        if (busy) return
        busy = true
        try {
          const list = await SDK.fetchJSON('/api/plugins/exfilbar/sessions')
          if (!active) return
          setSessions(list.sessions)
          const key = selected || list.sessions[0]?.key
          const feed = key ? await SDK.fetchJSON('/api/plugins/exfilbar/feed?key=' + encodeURIComponent(key)) : { events: [], out: 0, blocked: 0 }
          if (active) { setData(feed); setFailed(false) }
        } catch {
          if (active) { setFailed(true); setData(null) }
        } finally { busy = false }
      }
      load()
      const timer = setInterval(load, 3000)
      return () => { active = false; clearInterval(timer) }
    }, [selected])
    const cell = { padding: '8px', textAlign: 'left', verticalAlign: 'top', overflowWrap: 'anywhere', borderBottom: '1px solid var(--border)' }
    return h('section', { style: { padding: '20px' } },
      h('h1', { style: { fontSize: '20px', marginBottom: '8px' } }, 'Session egress'),
      h('p', null, 'Inspected attempts only. Delivery is not confirmed. Latest 128 transfers per session; up to 32 sessions.'),
      h('label', { style: { display: 'block', margin: '16px 0' } }, 'Session ',
        h('select', { value: selected, onChange: e => setSelected(e.target.value), style: { maxWidth: '100%', background: 'var(--background)', color: 'var(--foreground)' } },
          h('option', { value: '' }, 'Most recently inspected'),
          ...sessions.map(s => h('option', { key: s.key, value: s.key }, s.time + ' · ' + s.key.slice(0, 8))))),
      failed ? h('p', { role: 'alert' }, 'Feed temporarily unavailable. Retrying automatically. If this persists, check the backend plugin and gateway.') : !data ? h('p', { role: 'status' }, 'Loading session feed…') : !data.events.length ? h('p', null, 'No recognized transfers inspected.') :
        h('table', { style: { width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse', fontSize: '12px' } },
          h('caption', { style: { textAlign: 'left', margin: '12px 0' } }, `${data.out} out · ${data.blocked} blocked · retained attempts`),
          h('thead', null, h('tr', null, ...['Time', 'Tool', 'Files', 'Destination', 'Decision / rule'].map(label => h('th', { key: label, scope: 'col', style: cell }, label)))),
          h('tbody', null, ...[...data.events].reverse().map((e, i) => h('tr', { key: i },
            ...[localTime(e.time), e.tool, (e.paths.join(', ') || 'unresolved') + (e.paths_truncated ? ' (truncated)' : ''), e.destination, e.decision + (e.rule ? ' · ' + e.rule : '')].map((value, j) => h('td', { key: j, title: j === 0 ? e.time : undefined, style: { ...cell, color: j === 4 && e.decision === 'blocked' ? 'var(--destructive)' : 'inherit', fontVariantNumeric: 'tabular-nums' } }, value)))))),
      h('p', { style: { marginTop: '16px' } }, 'Static recognition only. Scripts, hidden call targets and uncovered tools can bypass inspection.'))
  }
  window.__HERMES_PLUGINS__.register('exfilbar', Feed)
})()
