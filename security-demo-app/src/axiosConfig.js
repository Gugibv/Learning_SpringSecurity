import axios from "axios";

// 创建 axios 实例
const api = axios.create({
  baseURL: "http://localhost:8081",
  withCredentials: true,
});

// 添加响应拦截器
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (
      error.response?.status === 401 ||
      error.response?.data?.status === "unauthorized"
    ) {
      console.warn("未登录或登录过期，跳转到登录页");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export default api;
