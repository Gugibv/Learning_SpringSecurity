// src/PrivateRoute.js  	使用 auth.js 实现路由保护
import React, { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { isAuthenticated } from "./auth";

const PrivateRoute = ({ children }) => {
  const [checking, setChecking] = useState(true);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    const check = async () => {
      const result = await isAuthenticated();
      setAuthed(result);
      setChecking(false);
    };
    check();
  }, []);

  if (checking) {
    return <div style={{ padding: 50 }}>身份校验中...</div>;
  }

  return authed ? children : <Navigate to="/" replace />;
};

export default PrivateRoute;
