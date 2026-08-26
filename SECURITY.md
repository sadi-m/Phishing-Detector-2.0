# Security and deployment notes

For direct local launches, the application creates a cryptographically random
session key once in `instance/secret_key`. This local file is ignored by Git.
For a deployed service, set `FLASK_SECRET_KEY` in the hosting environment
instead. It must be at least 32 characters and must not be committed to source
control.

For the very first deployment, optionally set `BOOTSTRAP_ADMIN_USERNAME` and
`BOOTSTRAP_ADMIN_PASSWORD` (12+ characters). The application creates that
account only when it does not already exist. Remove both variables after the
administrator is created.

In production set `FLASK_ENV=production`, deploy behind HTTPS, and run a
production WSGI server (for example, Waitress or Gunicorn), not Flask's
built-in server. Back up `phishing_history.db` with encryption and restrict
filesystem access to the service account.

The former demo administrator credential is automatically demoted on startup
when its known legacy password is detected. Create a new administrator using
the bootstrap settings above before relying on administrative features.
