// src/auth.js
export const isAuthenticated = () => {
    return !!localStorage.getItem("id_token");
  };
  
  export const saveToken = (token) => {
    localStorage.setItem("id_token", token);
  };
  
  export const logout = () => {
    localStorage.removeItem("id_token");
  };
  