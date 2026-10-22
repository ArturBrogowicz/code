import http from 'k6/http';
import { Counter } from 'k6/metrics';

const status = {
  '2xx': new Counter('status_2xx'),
  '3xx': new Counter('status_3xx'),
  '4xx': new Counter('status_4xx'),
  '5xx': new Counter('status_5xx'),
  other: new Counter('status_other'),
};

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'p(99.9)'],
  scenarios: {
    load: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE),
      timeUnit: __ENV.TIME_UNIT,
      duration: __ENV.DURATION,
      preAllocatedVUs: Number(__ENV.PRE_VUS),
      maxVUs: Number(__ENV.MAX_VUS),
    },
  },
};

export default function () {
  const res = http.request(__ENV.METHOD, __ENV.URL, null, {
    headers: JSON.parse(__ENV.HEADERS),
    timeout: __ENV.TIMEOUT,
    redirects: 0,
  });
  const s = res.status;
  let k = 'other';
  if (s >= 200 && s < 300) k = '2xx';
  else if (s >= 300 && s < 400) k = '3xx';
  else if (s >= 400 && s < 500) k = '4xx';
  else if (s >= 500 && s < 600) k = '5xx';
  status[k].add(1);
}

function stat(data, name, key) {
  const m = data.metrics[name];
  if (!m) return null;
  const v = m.values || m;
  return v[key] === undefined ? null : v[key];
}

export function handleSummary(data) {
  const out = {
    schema: 1,
    duration_ms: data.state ? data.state.testRunDurationMs : null,
    requests: stat(data, 'http_reqs', 'count'),
    iterations: stat(data, 'iterations', 'count'),
    dropped_iterations: stat(data, 'dropped_iterations', 'count') || 0,
    status: {},
    latency_ms: {},
  };
  for (const k of Object.keys(status)) out.status[k] = stat(data, 'status_' + k, 'count') || 0;
  const keys = { avg: 'avg', min: 'min', p50: 'p(50)', p90: 'p(90)', p95: 'p(95)',
                 p99: 'p(99)', p999: 'p(99.9)', max: 'max' };
  for (const k of Object.keys(keys)) out.latency_ms[k] = stat(data, 'http_req_duration', keys[k]);
  return {
    [__ENV.OUT]: JSON.stringify(out),
    [__ENV.OUT + '.raw']: JSON.stringify(data),
  };
}
