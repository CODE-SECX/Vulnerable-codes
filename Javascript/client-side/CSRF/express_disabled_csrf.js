// Disabling CSRF protection for API routes
const csrfProtection = csrf({ cookie: true });
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    // Dangerous pattern - skipping CSRF protection for API routes
    return next();
  }
  return csrfProtection(req, res, next);
});
