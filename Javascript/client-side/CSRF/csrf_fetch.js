// Fetch request without CSRF protection
function updateUserDataVulnerable(userId, data) {
    fetch('/api/users/' + userId, {
      method: 'POST',
      body: JSON.stringify(data),
      credentials: 'include'  // Includes cookies but no CSRF token
    })
    .then(response => response.json())
    .then(data => console.log('Success:', data));
  }
  