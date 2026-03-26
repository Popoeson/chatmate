// session.js
export const Auth = {
  // Get the token from localStorage or sessionStorage
  getToken: () => {
    return localStorage.getItem("token") || sessionStorage.getItem("token") || null;
  },

  // Save the token
  setToken: (token, rememberMe = false) => {
    if (rememberMe) localStorage.setItem("token", token);
    else sessionStorage.setItem("token", token);
  },

  // Remove the token
  clearToken: () => {
    localStorage.removeItem("token");
    sessionStorage.removeItem("token");
  },

  // Fetch the logged-in user info from backend
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
      Auth.clearToken(); // token invalid? clear it
      return null;
    }
  },
};