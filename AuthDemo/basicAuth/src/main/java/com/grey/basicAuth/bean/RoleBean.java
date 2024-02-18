package com.grey.basicAuth.bean;

import java.util.List;

public class RoleBean {
    private String roleId;
    private String roleName;
    private List<ResourceBean> resources;

    public RoleBean(){

    }

    public RoleBean(String roleId, String roleName) {
        this.roleId = roleId;
        this.roleName = roleName;
    }

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public List<ResourceBean> getResources() {
        return resources;
    }

    public void setResources(List<ResourceBean> resources) {
        this.resources = resources;
    }
}
