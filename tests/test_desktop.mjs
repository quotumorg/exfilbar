// SDK contract harness, not a running Hermes Desktop. No transfers or network.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import vm from 'node:vm'
import test from 'node:test'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'

process.env.TZ = 'Asia/Bangkok'
const now = '2026-11-08T00:30:00+00:00'
class FixedDate extends Date {
  constructor(...args) { super(...(args.length ? args : [now])) }
  static now() { return new Date(now).getTime() }
}

const fixture = {
  events: [{ time: '2000-01-01T00:00:00+00:00', tool: 'terminal', paths: ['reports/weekly.csv'], paths_truncated: false, destination: 'https://elsewhere.example', decision: 'blocked', rule: 'off route; allowed hosts: uploads.example · route 1' }],
  out: 1, blocked: 1, limit: 128
}
const jsx = (type, props) => ({ type, props })
const expand = value => {
  if (value == null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(expand)
  if (typeof value.type === 'function') return expand(value.type(value.props))
  return { type: value.type, props: { ...value.props, children: expand(value.props.children) } }
}
const text = node => JSON.stringify(expand(node))

const atom = value => ({ value, get() { return this.value } })

async function desktop(options = {}) {
  const calls = []
  const selected = atom('session-a')
  const host = { state: { focusedStoredSessionId: selected, profile: atom('default'), gateway: atom('open'),
    connectionId: atom('gateway-a'), focusedSessionOwner: atom({ connectionId: 'gateway-a', profile: 'default' }) },
    activeConnectionId: () => host.state.connectionId.value, navigate: path => calls.push(path) }
  const queries = []
  const result = { data: structuredClone(fixture), isError: false }
  const sdk = { host, useValue: atom => atom.value, useQuery: config => { queries.push(config); return options.useQuery ? options.useQuery(config) : result }, STATUSBAR_AREAS: { right: 'statusBar.right' }, ROUTES_AREA: 'routes', SIDEBAR_NAV_AREA: 'sidebarNav' }
  const context = vm.createContext({ Date: FixedDate })
  const synthetic = entries => new vm.SyntheticModule(Object.keys(entries), function () {
    for (const [key, value] of Object.entries(entries)) this.setExport(key, value)
  }, { context })
  const modules = { '@hermes/plugin-sdk': synthetic(sdk), 'react/jsx-runtime': synthetic({ jsx, jsxs: jsx }) }
  const module = new vm.SourceTextModule(await readFile(new URL('../desktop/plugin.js', import.meta.url), 'utf8'), { context })
  await module.link(specifier => {
    assert.ok(modules[specifier], `Unsupported import: ${specifier}`)
    return modules[specifier]
  })
  await module.evaluate()
  const contributions = []
  const ctx = { source: 'fixture', register: contribution => contributions.push(contribution), rest: async url => { calls.push(url); return fixture } }
  module.namespace.default.register(ctx)
  return { module, selected, host, queries, result, calls, contributions, ctx }
}

test('Desktop registers chip, feed route, and navigation with SDK only', async () => {
  const app = await desktop()
  assert.equal(app.module.namespace.default.id, 'exfilbar')
  assert.equal(app.module.namespace.default.defaultEnabled, false)
  assert.deepEqual(app.contributions.map(c => c.area), ['statusBar.right', 'routes', 'sidebarNav'])
})

test('chip displays retained counts, red on a block, and opens the feed', async () => {
  const app = await desktop()
  const chip = expand(app.contributions[0].render())
  assert.equal(chip.props.children, 'exfil · 1 out · 1 blocked')
  assert.equal(chip.props.style.color, 'var(--ui-red)')
  chip.props.onClick()
  assert.equal(app.calls[0], '/exfilbar')
})

test('session changes select a distinct query and use encoded session IDs', async () => {
  const app = await desktop()
  expand(app.contributions[0].render())
  const first = app.queries.at(-1)
  app.selected.value = 'session-b/?'
  expand(app.contributions[0].render())
  const second = app.queries.at(-1)
  assert.notDeepEqual(first.queryKey, second.queryKey)
  await second.queryFn()
  assert.equal(app.calls[0], '/feed?session_id=session-b%2F%3F')
  assert.equal(second.refetchInterval, 3000)
})

test('Desktop handles loading, empty, backend error, and no session', async () => {
  const app = await desktop()
  app.result.data = null
  assert.match(text(app.contributions[1].render()), /Loading session feed/)
  app.result.data = { ...fixture, events: [], blocked: 0, out: 0 }
  assert.match(text(app.contributions[1].render()), /No recognized transfers/)
  app.result.isError = true
  assert.match(text(app.contributions[1].render()), /Feed temporarily unavailable/)
  assert.match(text(app.contributions[0].render()), /exfil · unavailable/)
  assert.match(text(app.contributions[1].render()), /Routes temporarily unavailable/)
  assert.doesNotMatch(text(app.contributions[1].render()), /1 out · 1 blocked/)
  app.result.isError = false
  app.result.data = structuredClone(fixture)
  assert.match(text(app.contributions[0].render()), /1 out · 1 blocked/)
  app.selected.value = null
  assert.match(text(app.contributions[0].render()), /exfil · no session/)
  assert.match(text(app.contributions[1].render()), /Choose a chat/)
  assert.equal(app.queries.filter(q => q.queryKey[1] === 'exfilbar-feed').at(-1).enabled, false)
})

test('Desktop feed renders text nodes with files, destination and decision', async () => {
  const app = await desktop()
  app.result.data.events[0].paths = ['<script>fixture</script>']
  const tree = expand(app.contributions[1].render())
  assert.match(JSON.stringify(tree), /<script>fixture<\/script>/)
  assert.doesNotMatch(JSON.stringify(tree), /dangerouslySetInnerHTML/)
  assert.match(JSON.stringify(tree), /Delivery is not confirmed/)
})

test('Desktop shows only the explicit verification status supplied by the feed', async () => {
  const app = await desktop()
  assert.doesNotMatch(text(app.contributions[1].render()), /chain intact/)
  app.result.data.chain = { intact: true, records: 2 }
  assert.match(text(app.contributions[1].render()), /chain intact · 2/)
  app.result.data.chain = { intact: false, records: 0, broken: 1 }
  assert.match(text(app.contributions[1].render()), /chain broken · index 1/)
  assert.doesNotMatch(text(app.contributions[0].render()), /chain/)
})

test('Desktop routes card shows configured routes, the empty state and the not-loaded state', async () => {
  const app = await desktop()
  const page = () => visible(expand(app.contributions[1].render()))
  app.result.data = { ...structuredClone(fixture), known: true, updated: now, routes: [
    { position: 1, paths: ['reports/**'], hosts: ['uploads.example'] },
    { position: 2, paths: ['exports/*.csv'], hosts: ['*'] }
  ] }
  let output = page()
  assert.match(output, /route 1reports\/\*\*may go touploads\.example/)
  assert.match(output, /route 2exports\/\*\.csvmay go toany destination/)
  assert.match(output, /2 configured/)
  app.result.data = { ...structuredClone(fixture), known: true, updated: now, routes: [] }
  output = page()
  assert.match(output, /No routes yet/)
  assert.match(output, /paths: \["reports\/\*\*"\]/)
  app.result.data = { ...structuredClone(fixture) }
  assert.match(page(), /Routes appear here once Hermes loads Exfilbar/)
  assert.ok(app.queries.some(q => q.queryKey.includes('/routes')))
})

async function dashboard(feed = structuredClone(fixture)) {
  let component
  let cursor = 0
  let effect
  const states = []
  const timers = new Map()
  const calls = []
  const sdk = {
    React: { createElement: (type, props, ...children) => jsx(type, { ...props, children }) },
    hooks: {
      useState: initial => {
        const i = cursor++
        if (!(i in states)) states[i] = initial
        return [states[i], next => { states[i] = next }]
      },
      useEffect: fn => { effect = fn }
    },
    fetchJSON: async url => {
      calls.push(url)
      return url.endsWith('/sessions') ? { sessions: [{ key: 'a'.repeat(64), time: feed.events[0].time }] } : feed
    }
  }
  const context = vm.createContext({
    Date: FixedDate,
    window: { __HERMES_PLUGIN_SDK__: sdk, __HERMES_PLUGINS__: { register: (name, fn) => { assert.equal(name, 'exfilbar'); component = fn } } },
    setInterval: (fn, ms) => { assert.equal(ms, 3000); timers.set(1, fn); return 1 },
    clearInterval: id => timers.delete(id)
  })
  new vm.Script(await readFile(new URL('../dashboard/dist/index.js', import.meta.url), 'utf8')).runInContext(context)
  return { states, timers, calls, sdk, render: () => { cursor = 0; return component() }, effect: () => effect() }
}
const tick = () => new Promise(resolve => setImmediate(resolve))

test('dashboard lists sessions and loads feed through authenticated SDK fetcher', async () => {
  const app = await dashboard()
  assert.match(text(app.render()), /Loading session feed/)
  const cleanup = app.effect()
  await tick()
  assert.equal(app.calls[1], '/api/plugins/exfilbar/feed?key=' + 'a'.repeat(64))
  assert.match(text(app.render()), /off route/)
  assert.match(text(app.render()), /1 out · 1 blocked/)
  cleanup()
  assert.equal(app.timers.size, 0)
})

test('dashboard adds the same small verification status to its caption', async () => {
  const feed = { ...structuredClone(fixture), chain: { intact: true, records: 2 } }
  const app = await dashboard(feed)
  app.render()
  const cleanup = app.effect()
  await tick()
  assert.match(text(app.render()), /chain intact · 2/)
  feed.chain = { intact: false, records: 0, broken: 1 }
  await app.timers.get(1)()
  assert.match(text(app.render()), /chain broken · index 1/)
  cleanup()
})

test('dashboard isolates stale asynchronous responses after cleanup', async () => {
  const app = await dashboard()
  let resolve
  app.sdk.fetchJSON = () => new Promise(done => { resolve = done })
  app.render()
  const cleanup = app.effect()
  cleanup()
  resolve({ sessions: [{ key: 'a'.repeat(64) }] })
  await tick()
  assert.equal(app.states[2], null)
  assert.equal(app.states[0].length, 0)
})

test('dashboard failure exposes recovery text without exception details', async () => {
  const app = await dashboard()
  app.sdk.fetchJSON = async () => { throw new Error('sensitive detail') }
  app.render()
  const cleanup = app.effect()
  await tick()
  const output = text(app.render())
  assert.match(output, /Feed temporarily unavailable/)
  assert.doesNotMatch(output, /sensitive detail/)
  app.sdk.fetchJSON = async url => url.endsWith('/sessions') ? { sessions: [{ key: 'a'.repeat(64) }] } : fixture
  await app.timers.get(1)()
  assert.match(text(app.render()), /1 out · 1 blocked/)
  assert.doesNotMatch(text(app.render()), /temporarily unavailable/)
  cleanup()
})

function elements(tree, type) {
  if (!tree || typeof tree !== 'object') return []
  if (Array.isArray(tree)) return tree.flatMap(node => elements(node, type))
  return [...(tree.type === type ? [tree] : []), ...elements(tree.props.children, type)]
}
function visible(tree) {
  if (tree == null) return ''
  if (Array.isArray(tree)) return tree.map(visible).join('')
  return typeof tree === 'object' ? visible(tree.props.children) : String(tree)
}

for (const surface of ['Desktop', 'dashboard']) {
  test(`${surface} renders local times, ISO tooltips, and decision wording once`, async () => {
    const cases = [
      ['2026-11-07T23:59:58+00:00', '06:59:58'], // UTC yesterday, local today.
      ['2026-11-07T17:00:00+00:00', '00:00:00'],
      ['2026-11-07T16:59:58+00:00', new Date('2026-11-07T16:59:58+00:00').toLocaleDateString() + ' 23:59:58'],
      ['2000-01-01T00:00:00+00:00', new Date('2000-01-01T00:00:00+00:00').toLocaleDateString() + ' 07:00:00'],
      ['invalid fixture timestamp', 'invalid fixture timestamp']
    ]
    const feed = {
      ...structuredClone(fixture), out: 4, blocked: 1,
      events: cases.map(([time], i) => ({
        ...fixture.events[0], time,
        decision: i === 0 ? 'blocked' : 'allowed',
        rule: i === 0 ? 'off route; allowed hosts: uploads.example · route 1' : i === 1 ? 'route 1, route 2' : i === 4 ? '' : 'route 1'
      }))
    }
    let tree
    if (surface === 'Desktop') {
      const app = await desktop()
      app.result.data = feed
      tree = expand(app.contributions[1].render())
    } else {
      const app = await dashboard(feed)
      app.render()
      const cleanup = app.effect()
      await tick()
      tree = expand(app.render())
      cleanup()
    }
    const rows = elements(elements(tree, 'tbody')[0], 'tr').reverse()
    assert.equal(rows.length, cases.length)
    for (const [i, row] of rows.entries()) {
      const cells = elements(row, 'td')
      assert.equal(visible(cells[0]), cases[i][1])
      assert.equal(cells[0].props.title, cases[i][0])
      if (surface === 'Desktop') {
        // Decision chip, then the route reference, then a block's reason on its own line.
        const route = i === 1 ? 'route 1, route 2' : i === 4 ? '' : 'route 1'
        const reason = i === 0 ? 'off route; allowed hosts: uploads.example' : ''
        assert.equal(visible(cells[4]), (i === 0 ? 'blocked' : 'allowed') + route + reason)
        const chip = elements(cells[4], 'span')[0]
        assert.equal(chip.props.style.color, i === 0 ? 'var(--ui-red)' : 'var(--ui-green)')
      } else {
        assert.equal(visible(cells[4]), i === 0 ? 'blocked · off route; allowed hosts: uploads.example · route 1' : i === 1 ? 'allowed · route 1, route 2' : i === 4 ? 'allowed' : 'allowed · route 1')
        assert.equal(cells[4].props.style.color, i === 0 ? 'var(--destructive)' : 'inherit')
      }
    }
    assert.doesNotMatch(visible(tree), /routes\[|allowed by route|dangerouslySetInnerHTML/)
  })
}


test('routes card exposes summary age, truncation, invalid policy and hostile text', async () => {
  const app = await desktop()
  app.result.data = { ...structuredClone(fixture), known: true, valid: false, updated: now, routes: [
    { position: 1, paths: ['<script>path</script>'], hosts: ['<img src=x onerror=alert(1)>', '*'], paths_omitted: 96, hosts_omitted: 1, paths_shortened: 2, hosts_shortened: 3 }
  ] }
  const tree = expand(app.contributions[1].render())
  const output = visible(tree)
  assert.match(output, /host summary; ports and paths omitted/)
  assert.match(output, /last loaded 07:30/)
  assert.match(output, /last valid policy/)
  assert.match(output, /96 paths and 1 hosts omitted; 2 path patterns and 3 host patterns shortened/)
  assert.match(output, /any destination/)
  assert.ok(output.includes('<script>path</script>'))
  assert.ok(output.includes('<img src=x onerror=alert(1)>'))
  assert.equal(elements(tree, 'script').length, 0)
  assert.equal(elements(tree, 'img').length, 0)
  assert.doesNotMatch(JSON.stringify(tree), /dangerouslySetInnerHTML/)
})

function activate(app, connection, profile = 'default', session = 'session-a') {
  app.host.state.connectionId.value = connection
  app.host.state.profile.value = profile
  app.host.state.focusedSessionOwner.value = { connectionId: connection, profile }
  app.selected.value = session
}

test('profile, connection and session keys change independently; socket status is not identity', async () => {
  const app = await desktop()
  const query = () => { expand(app.contributions[0].render()); return app.queries.at(-1) }
  const first = query()
  app.host.state.gateway.value = 'connecting'
  assert.deepEqual(query().queryKey, first.queryKey)
  activate(app, 'gateway-a', 'other')
  const profile = query()
  assert.notDeepEqual(profile.queryKey, first.queryKey)
  activate(app, 'gateway-b')
  const connection = query()
  assert.notDeepEqual(connection.queryKey, first.queryKey)
  await connection.queryFn()
  assert.match(visible(expand(app.contributions[1].render())), /connection gateway-b · profile default/)
  activate(app, 'gateway-b', 'default', 'session-b')
  assert.notDeepEqual(query().queryKey, connection.queryKey)
})

test('unknown owners, owner mismatch and unsupported SDKs suppress requests and cached rows', async () => {
  for (const change of [
    app => { app.host.state.focusedSessionOwner.value = null },
    app => { app.host.state.focusedSessionOwner.value = { connectionId: 'gateway-b', profile: 'default' } },
    app => { app.host.state.focusedSessionOwner.value = { connectionId: 'gateway-a', profile: 'other' } },
    app => { delete app.host.state.focusedSessionOwner },
    app => { delete app.host.state.connectionId },
    app => { delete app.host.activeConnectionId },
    app => { app.host.activeConnectionId = () => 'gateway-b' }
  ]) {
    const app = await desktop()
    change(app)
    const page = visible(expand(app.contributions[1].render()))
    assert.doesNotMatch(page, /weekly\.csv|1 out|1 blocked/)
    assert.match(page, /ownership unavailable|another connection or profile/)
    assert.match(visible(expand(app.contributions[0].render())), /owner unavailable/)
    for (const query of app.queries) {
      assert.equal(query.enabled, false)
      await assert.rejects(query.queryFn(), /owner changed before request/)
    }
    assert.equal(app.calls.length, 0)
  }
})

test('local legacy request scope is accepted only with an explicit local owner', async () => {
  const app = await desktop()
  activate(app, 'local')
  app.host.activeConnectionId = () => null
  expand(app.contributions[0].render())
  assert.equal(app.queries.at(-1).enabled, true)
  await app.queries.at(-1).queryFn()
})

// Use the host's already-installed query engine, with no package installation.
function queryEngine() {
  const source = process.env.HERMES_SOURCE || new URL('../../hermes/', import.meta.url).pathname
  return createRequire(resolve(source, 'apps/desktop/package.json'))('@tanstack/query-core')
}

test('real query cache isolates equal profile names and profile/session switches', async () => {
  const { QueryClient } = queryEngine()
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  try {
    const app = await desktop({ useQuery: config => ({ data: client.getQueryData(config.queryKey), isError: false }) })
    app.ctx.rest = async () => ({ ...fixture, out: app.host.state.connectionId.value === 'gateway-a' ? 11 : 22 })
    const query = () => { expand(app.contributions[0].render()); return app.queries.at(-1) }
    const first = query()
    await client.fetchQuery(first)
    assert.match(visible(expand(app.contributions[0].render())), /11 out/)
    for (const [connection, profile, session] of [
      ['gateway-b', 'default', 'session-a'], ['gateway-a', 'other', 'session-a'], ['gateway-a', 'default', 'session-b']
    ]) {
      activate(app, connection, profile, session)
      const next = query()
      assert.equal(client.getQueryData(next.queryKey), undefined)
      assert.match(visible(expand(app.contributions[0].render())), /loading/)
      await client.fetchQuery(next)
    }
    activate(app, 'gateway-a')
    assert.match(visible(expand(app.contributions[0].render())), /11 out/)
    assert.equal(client.getQueryData(first.queryKey).out, 11)
    assert.equal(client.getQueryCache().getAll().length, 4)
  } finally { client.clear() }
})

test('captured requests cannot dispatch or resolve after owner or session changes', async () => {
  const { QueryClient } = queryEngine()
  for (const [name, connection, profile, session] of [
    ['feed', 'gateway-b', 'default', 'session-a'], ['feed', 'gateway-a', 'other', 'session-a'],
    ['feed', 'gateway-a', 'default', 'session-b'], ['routes', 'gateway-b', 'default', 'session-a'],
    ['routes', 'gateway-a', 'other', 'session-a']
  ]) {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
    try {
      const app = await desktop()
      expand(app.contributions[1].render())
      const query = app.queries.find(q => q.queryKey[1] === 'exfilbar-' + name)
      let finish
      const requests = []
      app.ctx.rest = path => {
        requests.push([app.host.state.connectionId.get(), app.host.state.profile.get(), path])
        return new Promise(resolve => { finish = resolve })
      }
      const pending = client.fetchQuery(query)
      const rejected = assert.rejects(pending, /owner changed during request/)
      activate(app, connection, profile, session)
      finish(fixture)
      await rejected
      assert.equal(client.getQueryData(query.queryKey), undefined)
      await assert.rejects(query.queryFn(), /owner changed before request/)
      assert.equal(requests.length, 1)
      assert.deepEqual(requests[0].slice(0, 2), ['gateway-a', 'default'])
    } finally { client.clear() }
  }
})

test('real routes cache follows connection/profile and is shared between sessions of one owner', async () => {
  const { QueryClient } = queryEngine()
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  try {
    const app = await desktop({ useQuery: config => ({ data: client.getQueryData(config.queryKey), isError: false }) })
    app.ctx.rest = async () => ({ known: true, routes: [], owner: app.host.state.connectionId.get() })
    const query = () => {
      expand(app.contributions[1].render())
      return app.queries.filter(q => q.queryKey[1] === 'exfilbar-routes').at(-1)
    }
    const first = query()
    await client.fetchQuery(first)
    activate(app, 'gateway-b')
    const other = query()
    assert.equal(client.getQueryData(other.queryKey), undefined)
    await client.fetchQuery(other)
    assert.equal(client.getQueryData(other.queryKey).owner, 'gateway-b')
    activate(app, 'gateway-a', 'other')
    assert.equal(client.getQueryData(query().queryKey), undefined)
    activate(app, 'gateway-a', 'default', 'session-b')
    assert.deepEqual(query().queryKey, first.queryKey)
    assert.equal(client.getQueryData(first.queryKey).owner, 'gateway-a')
  } finally { client.clear() }
})

test('real query observers deduplicate chip/page reads and release both polling observers', async () => {
  const { QueryClient, QueryObserver } = queryEngine()
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } })
  const observers = []
  const disposers = []
  try {
    const app = await desktop({ useQuery: config => {
      const observer = new QueryObserver(client, config)
      observers.push(observer)
      disposers.push(observer.subscribe(() => {}))
      return observer.getCurrentResult()
    } })
    const finishes = []
    let count = 0
    app.ctx.rest = async () => { count++; return new Promise(resolve => { finishes.push(resolve) }) }
    // Both contributions subscribe to the same feed; the page also reads routes.
    expand(app.contributions[0].render())
    expand(app.contributions[1].render())
    assert.equal(count, 2)
    assert.equal(client.getQueryCache().getAll().length, 2)
    const feed = client.getQueryCache().getAll().find(q => q.queryKey[1] === 'exfilbar-feed')
    assert.equal(feed.getObserversCount(), 2)
    assert.ok(feed.isActive())
    finishes.forEach(finish => finish(fixture))
    await tick()
    disposers.forEach(dispose => dispose())
    observers.forEach(observer => observer.destroy())
    assert.equal(feed.getObserversCount(), 0)
    assert.equal(feed.isActive(), false)
  } finally {
    disposers.forEach(dispose => dispose())
    observers.forEach(observer => observer.destroy())
    client.clear()
  }
})

test('first-run empty state names the isolated route demo without promising feed rows', async () => {
  const app = await desktop()
  app.result.data = { ...fixture, events: [] }
  assert.match(visible(expand(app.contributions[1].render())), /python3 demo\/routes\.py/)
  assert.match(visible(expand(app.contributions[1].render())), /Dry runs do not populate this feed/)
})
