package com.grey.security.distributed.salary.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/salary")
public class SalaryController {

    @GetMapping("/test")
    public String test() {
        return "Hello Salary Resource ~";
    }
}
