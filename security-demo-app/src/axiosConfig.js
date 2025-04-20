import axios from "axios";

// 创建 axios 实例
const api = axios.create({
  baseURL: "http://localhost:8081", // 根据你项目实际调整
  withCredentials: true,            // 必须开启，Spring Session 才能识别 cookie
});

// 添加响应拦截器
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const data = error?.response?.data;

    console.warn("响应状态码：", status);
    console.warn("响应数据：", data);

    // 如果是未登录（401），并且后端返回特定标识
    if (
      status === 401 &&
      data?.status === "unauthorized"
    ) {
      console.warn("未登录或登录过期，跳转到登录页");
      window.location.href = "/login"; // 改成你前端实际的登录页路径
    }

    return Promise.reject(error);
  }
);

export default api;
