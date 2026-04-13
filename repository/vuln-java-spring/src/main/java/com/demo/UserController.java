package com.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

@RestController
public class UserController {

    private final Connection connection;

    public UserController(Connection connection) {
        this.connection = connection;
    }

    @GetMapping("/user")
    public String getUser(@RequestParam String username) throws Exception {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql); // CWE-89 SQL Injection
        return rs.next() ? rs.getString("username") : "not found";
    }

    @GetMapping("/admin/users")
    public String adminUsers() {
        return "sensitive list"; // CWE-306 Missing Authentication
    }

    @GetMapping("/file")
    public String readFile(@RequestParam String name) throws Exception {
        Path p = Paths.get("/srv/docs/" + name); // CWE-22 Path Traversal
        return Files.readString(p);
    }
}
