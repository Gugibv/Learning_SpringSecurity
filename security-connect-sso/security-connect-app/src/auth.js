// src/auth.js  提供是否登录的判断逻辑
import axios from "axios";

axios.defaults.withCredentials = true; // 发送跨域 Cookie

// 调用后端 /me 接口判断用户是否已登录
export const isAuthenticated = async () => {
  try {
    const res = await axios.get("https://localhost:8080/api/sg/wb/v1/common/oidc/me");
    return res.status === 200;
  } catch (err) {
    return false;
  }
};

// 登出逻辑（后面可调用后端 logout）
export const logout = () => {
  // TODO: 可调用后端接口清除 Cookie 或跳转到 SSO logout 页面
  // window.location.href = 'http://localhost:8080/logout';
};
