package com.grey.security.demo.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.grey.security.demo.entity.User;
import com.grey.security.demo.mapper.UserMapper;
import com.grey.security.demo.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
}