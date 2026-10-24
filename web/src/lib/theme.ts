export type Theme = "dark" | "light";
const key = "openrmm.theme";

export function storedTheme(): Theme {
  try {
    return localStorage.getItem(key) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(theme: Theme) {
  document.documentElement.classList.toggle("dark", theme === "dark");
  try {
    localStorage.setItem(key, theme);
  } catch {
    // Theme still applies for this page when storage is unavailable.
  }
}
