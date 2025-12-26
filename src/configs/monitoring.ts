import client from 'prom-client'

// 1. Create a Registry (The container for all metrics)
export const register = new client.Registry()

// 2. Add Default Node.js Metrics (CPU, Memory, Event Loop Lag)
// This gives us free insights into "Is our server overloaded?"
client.collectDefaultMetrics({
  register,
  prefix: 'mph_backend_'
})

// 3. Custom Metric: Request Counter
export const httpRequestCounter = new client.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'], // Tags we can filter by
  registers: [register]
})

// 4. Custom Metric: Request Duration (Histogram)
export const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 1, 2, 5], // Buckets: <0.1s, <0.5s, <1s, etc.
  registers: [register]
})
