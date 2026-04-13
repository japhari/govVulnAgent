import { readFileSync } from "fs";

export class AdminController {
  getProfileHtml(bio: string): string {
    return `<div>${bio}</div>`; // CWE-79 XSS
  }

  getAdminUsers(): string[] {
    return ["alice", "bob"]; // CWE-287/CWE-306 if exposed without auth guard
  }

  queryByEmail(db: any, email: string) {
    const sql = "SELECT * FROM users WHERE email = '" + email + "'";
    return db.query(sql); // CWE-89 SQL Injection
  }

  readTemplate(name: string): string {
    return readFileSync("/srv/templates/" + name, "utf8"); // CWE-22 Path Traversal
  }
}
