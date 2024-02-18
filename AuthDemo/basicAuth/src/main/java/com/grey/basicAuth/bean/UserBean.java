package com.grey.basicAuth.bean;

import java.util.ArrayList;
import java.util.List;

public class UserBean {
    private String userId;
    private String userName;
    private String userPass;
    private List<RoleBean> userRoles = new ArrayList<>();
    private List<ResourceBean> resourceBeans = new ArrayList<>();

    public UserBean(){

    }
    public UserBean(String userId, String userName, String userPass) {
        this.userId = userId;
        this.userName = userName;
        this.userPass = userPass;
    }

    public boolean havaPermission(String resource) {
        return this.resourceBeans.stream()
                .filter(resourceBean -> resourceBean.getResourceName().equals(resource))
                .count()>0;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserPass() {
        return userPass;
    }

    public void setUserPass(String userPass) {
        this.userPass = userPass;
    }

    public List<RoleBean> getUserRoles() {
        return userRoles;
    }

    public void setUserRoles(List<RoleBean> userRoles) {
        this.userRoles = userRoles;
    }

    public List<ResourceBean> getResourceBeans() {
        return resourceBeans;
    }

    public void setResourceBeans(List<ResourceBean> resourceBeans) {
        this.resourceBeans = resourceBeans;
    }
}
