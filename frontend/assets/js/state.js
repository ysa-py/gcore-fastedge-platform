// Session/permission state with a tiny pub-sub so pages can react to
// step-up or logout events.

const listeners = new Set();
export const state = {
  session: null, // {username, role, permissions, step_up_active, ...}
};

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function notify() {
  for (const fn of listeners) fn(state);
}

export function setSession(s) {
  state.session = s;
  notify();
}

export function clearSession() {
  state.session = null;
  notify();
}

export function has(permission) {
  return !!(state.session && state.session.permissions && state.session.permissions.includes(permission));
}

export function isRole(role) {
  return state.session && state.session.role === role;
}

export function loggedIn() {
  return !!state.session;
}

export async function loadSession() {
  try {
    const s = await (await import("./api.js")).api.get("/api/auth/session");
    setSession(s);
    return s;
  } catch (e) {
    if (e.status === 401) { clearSession(); return null; }
    throw e;
  }
}

export async function logout() {
  try { await (await import("./api.js")).api.post("/api/auth/logout", {}); } catch { /* best effort */ }
  clearSession();
}
