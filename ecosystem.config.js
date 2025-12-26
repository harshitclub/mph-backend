module.exports = {
  apps: [
    {
      name: 'mph_backend',
      script: './dist/index.js',
      instances: 'max',
      exec_mode: 'cluster',
      watch: false,
      env: {
        NODE_ENV: 'production'
      },
      env_production: {
        NODE_ENV: 'production'
      }
    },
    {
      name: 'mph_email_worker',
      script: './dist/workers/email.worker.js',
      instances: 1, // runs on single instance
      exec_mode: 'fork', // not cluster
      watch: false,
      env: {
        NODE_ENV: 'production'
      }
    }
  ]
}
