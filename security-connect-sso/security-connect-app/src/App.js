// src/App.js
import React, { useEffect } from "react";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import WelcomePage from "./pages/WelcomePage";
import HomePage from "./pages/HomePage";
import PrivateRoute from "./PrivateRoute";
import { saveToken } from "./auth";

const HandleCallback = () => {
  const location = useLocation();

  useEffect(() => {
    const url = new URL(window.location.href);
    const idToken = url.searchParams.get("id_token");
    if (idToken) {
      saveToken(idToken);
      window.location.href = "/home";
    }
  }, [location]);

  return <div>正在跳转，请稍候...</div>;
};

const App = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<WelcomePage />} />
        <Route path="/home" element={<PrivateRoute><HomePage /></PrivateRoute>} />
        <Route path="/callback" element={<HandleCallback />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
