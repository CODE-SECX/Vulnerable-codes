// XHR request without CSRF protection
function sendXHRVulnerable() {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/sensitive-action', true);
    xhr.withCredentials = true;  // Includes cookies but no CSRF token
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('action=delete&id=123');
  }
  