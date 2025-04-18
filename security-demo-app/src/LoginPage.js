// src/App.js
import React, { useState } from "react";
import api from "./axiosConfig"; // 替换原来的 axios

function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await api.post(
        "http://localhost:8081/login", // spring security login接口
        new URLSearchParams({ username, password }), // 表单格式
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          withCredentials: true, // 允许携带 cookie（session id）
        }
      );

      setMsg("✅ 登录成功！");
    } catch (error) {
      setMsg("❌ 登录失败：" + (error?.response?.status || error.message));
    }
  };

  return (
    <div style={{ padding: "2rem", fontFamily: "Arial" }}>
      <h2>React 登录页面</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>用户名：</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div>
          <label>密码：</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button type="submit">登录</button>
      </form>
      <p>{msg}</p>
    </div>
  );
}

export default App;
