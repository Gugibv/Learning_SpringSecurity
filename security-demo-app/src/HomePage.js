// src/HomePage.js
import React from "react";
import { useNavigate } from "react-router-dom";
import api from "./axiosConfig";

function HomePage() {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await api.post("/logout"); // Spring Security 注销默认 POST
      console.log("✅ 已注销");
      navigate("/login");
    } catch (err) {
      console.error("❌ 注销失败", err);
    }
  };

  return (
    <div style={{ padding: "2rem", fontFamily: "Arial" }}>
      <h2>🏠 欢迎来到主页</h2>
      <p>您已成功登录，现在可以访问受保护资源了。</p>
      <button onClick={handleLogout} style={{ marginTop: "1rem" }}>
        退出登录
      </button>
    </div>
  );
}

export default HomePage;
