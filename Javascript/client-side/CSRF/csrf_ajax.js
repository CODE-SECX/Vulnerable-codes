// jQuery AJAX request without CSRF protection
function sendAjaxVulnerable() {
    $.ajax({
      url: '/api/user-settings',
      type: 'POST',
      data: { theme: 'dark', notifications: 'off' },
      xhrFields: {
        withCredentials: true  // Includes cookies but no CSRF token
      }
    });
  }
  