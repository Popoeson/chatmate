// session.js
export const Auth = {
  getToken: () => {
    return localStorage.getItem("token") || sessionStorage.getItem("token") || null;
  },

  setToken: (token, rememberMe = false) => {
    if (rememberMe) localStorage.setItem("token", token);
    else sessionStorage.setItem("token", token);
  },

  clearToken: () => {
    localStorage.removeItem("token");
    sessionStorage.removeItem("token");
  },

  getUser: async () => {
    const token = Auth.getToken();
    if (!token) return null;

    try {
      const res = await fetch("https://chatmate-kbwz.onrender.com/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch user");
      const data = await res.json();
      return data.user || null;
    } catch (err) {
      console.error("Auth.getUser error:", err);
      Auth.clearToken();
      return null;
    }
  },

  // ===============================
  // Temporary session storage helpers
  // ===============================
  setTempData: (key, value) => {
    sessionStorage.setItem(key, JSON.stringify(value));
  },

  getTempData: (key) => {
    const val = sessionStorage.getItem(key);
    return val ? JSON.parse(val) : null;
  },

  clearTempData: (key) => {
    sessionStorage.removeItem(key);
  },

  clearAllTempData: () => {
    sessionStorage.clear();
  }
};