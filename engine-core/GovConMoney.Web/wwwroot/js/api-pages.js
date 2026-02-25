window.govConApi = {
  fetchJson: async function (url) {
    const separator = url.includes('?') ? '&' : '?';
    const noCacheUrl = `${url}${separator}_ts=${Date.now()}`;

    const response = await fetch(noCacheUrl, {
      method: 'GET',
      cache: 'no-store',
      credentials: 'include',
      headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`Request failed (${response.status}) for ${url}`);
    }

    return await response.text();
  },
  postForm: async function (url, fields) {
    const form = new URLSearchParams();
    for (const [key, value] of Object.entries(fields || {})) {
      form.append(key, value == null ? '' : String(value));
    }

    const response = await fetch(url, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'include',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString()
    });

    if (!response.ok) {
      throw new Error(`Request failed (${response.status}) for ${url}`);
    }

    return await response.text();
  }
};
