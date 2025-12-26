import { Request, Response } from 'express'
import responseTime from 'response-time'
import { httpRequestCounter, httpRequestDuration } from '../configs/monitoring'

/**
 * Middleware that automatically records metrics for every API call
 */
export const metricsMiddleware = responseTime(
  (req: Request, res: Response, time: number) => {
    // Ignore the metrics endpoint itself (otherwise it pollutes the data)
    if (req.path === '/metrics') return

    const method = req.method
    const route = req.route ? req.route.path : req.path
    const status = res.statusCode ? res.statusCode.toString() : '200'

    // 1. Count the request
    httpRequestCounter.labels(method, route, status).inc()

    // 2. Record the duration (time is in ms, convert to seconds)
    httpRequestDuration.labels(method, route, status).observe(time / 1000)
  }
)
