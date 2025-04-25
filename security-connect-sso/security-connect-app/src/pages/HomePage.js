// src/pages/HomePage.js
import React from "react";
import { logout } from "../auth";

const HomePage = () => {
  return (
    <div style={{ padding: "40px", textAlign: "center" }}>
      <h1>欢迎回来！你已成功登录。</h1>
      <button onClick={() => {
        logout();
        window.location.href = "/";
      }}>退出登录</button>
    </div>
  );
};

export default HomePage;
