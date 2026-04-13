#!/usr/bin/env python3
"""
Create a realistic labeled seed dataset with real code snippets (Java/JS/TS).

This is intended for local benchmarking and pipeline validation when a full
curated benchmark is unavailable.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def sample(language: str, code: str, label: str, cwe_id: str, cwe_name: str) -> dict:
    return {
        "language": language,
        "code": code.strip("\n"),
        "label": label,
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
    }


def build_samples() -> list[dict]:
    data: list[dict] = []

    # ── Java: SQLi, Path Traversal, Missing Auth ──────────────────────────────
    data.append(sample(
        "Java",
        """
public User findByUsername(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, userMapper);
}
""",
        "vulnerable",
        "CWE-89",
        "SQL Injection",
    ))
    data.append(sample(
        "Java",
        """
public User findByUsername(String username) {
    String sql = "SELECT * FROM users WHERE username = ?";
    return jdbcTemplate.queryForObject(sql, new Object[]{username}, userMapper);
}
""",
        "clean",
        "",
        "",
    ))
    data.append(sample(
        "Java",
        """
public String readFile(String name) throws IOException {
    Path p = Paths.get("/srv/docs/" + name);
    return Files.readString(p);
}
""",
        "vulnerable",
        "CWE-22",
        "Path Traversal",
    ))
    data.append(sample(
        "Java",
        """
public String readFile(String name) throws IOException {
    Path base = Paths.get("/srv/docs").toAbsolutePath().normalize();
    Path p = base.resolve(name).normalize();
    if (!p.startsWith(base)) throw new SecurityException("Invalid path");
    return Files.readString(p);
}
""",
        "clean",
        "",
        "",
    ))
    data.append(sample(
        "Java",
        """
@GetMapping("/admin/users")
public List<User> allUsers() {
    return userService.findAll();
}
""",
        "vulnerable",
        "CWE-306",
        "Missing Authentication",
    ))
    data.append(sample(
        "Java",
        """
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> allUsers() {
    return userService.findAll();
}
""",
        "clean",
        "",
        "",
    ))

    # ── JavaScript: XSS, SQLi-like backend JS, weak auth flow ─────────────────
    data.append(sample(
        "JavaScript",
        """
function renderComment(comment) {
  document.getElementById("out").innerHTML = comment;
}
""",
        "vulnerable",
        "CWE-79",
        "Cross-site Scripting",
    ))
    data.append(sample(
        "JavaScript",
        """
function renderComment(comment) {
  const el = document.createElement("p");
  el.textContent = comment;
  document.getElementById("out").appendChild(el);
}
""",
        "clean",
        "",
        "",
    ))
    data.append(sample(
        "JavaScript",
        """
app.get("/login", async (req, res) => {
  const q = "SELECT * FROM users WHERE email='" + req.query.email + "'";
  const rows = await db.query(q);
  res.json(rows);
});
""",
        "vulnerable",
        "CWE-89",
        "SQL Injection",
    ))
    data.append(sample(
        "JavaScript",
        """
app.get("/login", async (req, res) => {
  const q = "SELECT * FROM users WHERE email = ?";
  const rows = await db.query(q, [req.query.email]);
  res.json(rows);
});
""",
        "clean",
        "",
        "",
    ))
    data.append(sample(
        "JavaScript",
        """
app.post("/admin/reset-password", async (req, res) => {
  await adminService.reset(req.body.userId);
  res.sendStatus(200);
});
""",
        "vulnerable",
        "CWE-306",
        "Missing Authentication",
    ))
    data.append(sample(
        "JavaScript",
        """
app.post("/admin/reset-password", requireAuth, requireRole("admin"), async (req, res) => {
  await adminService.reset(req.body.userId);
  res.sendStatus(200);
});
""",
        "clean",
        "",
        "",
    ))

    # ── TypeScript: Angular/Nest patterns ─────────────────────────────────────
    data.append(sample(
        "TypeScript",
        """
export function renderBio(input: string) {
  const el = document.getElementById("bio")!;
  el.innerHTML = input;
}
""",
        "vulnerable",
        "CWE-79",
        "Cross-site Scripting",
    ))
    data.append(sample(
        "TypeScript",
        """
export function renderBio(input: string) {
  const el = document.getElementById("bio")!;
  el.textContent = input;
}
""",
        "clean",
        "",
        "",
    ))
    data.append(sample(
        "TypeScript",
        """
@Controller("admin")
export class AdminController {
  @Get("users")
  getUsers() {
    return this.userService.findAll();
  }
}
""",
        "vulnerable",
        "CWE-287",
        "Improper Authentication",
    ))
    data.append(sample(
        "TypeScript",
        """
@UseGuards(AuthGuard, RolesGuard)
@Controller("admin")
export class AdminController {
  @Roles("admin")
  @Get("users")
  getUsers() {
    return this.userService.findAll();
  }
}
""",
        "clean",
        "",
        "",
    ))
    data.append(sample(
        "TypeScript",
        """
import { readFileSync } from "fs";
export function readTemplate(name: string): string {
  return readFileSync("/srv/templates/" + name, "utf8");
}
""",
        "vulnerable",
        "CWE-22",
        "Path Traversal",
    ))
    data.append(sample(
        "TypeScript",
        """
import { readFileSync } from "fs";
import path from "path";
export function readTemplate(name: string): string {
  const base = path.resolve("/srv/templates");
  const target = path.resolve(base, name);
  if (!target.startsWith(base)) throw new Error("invalid path");
  return readFileSync(target, "utf8");
}
""",
        "clean",
        "",
        "",
    ))

    return data


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Create realistic labeled seed dataset")
    p.add_argument(
        "--output",
        default="data/cwe/govrepo_tz_real_seed.jsonl",
        help="Output JSONL path",
    )
    p.add_argument(
        "--replicas",
        type=int,
        default=1,
        help="How many mutated replicas per base sample",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--shuffle",
        action="store_true",
        help="Shuffle final rows after generation",
    )
    return p.parse_args()


def mutate_code(code: str, variant_idx: int) -> str:
    """
    Apply light deterministic identifier mutations so replicas are not exact duplicates.
    """
    replacements = {
        "username": f"username_{variant_idx}",
        "comment": f"comment_{variant_idx}",
        "input": f"input_{variant_idx}",
        "userId": f"userId_{variant_idx}",
        "email": f"email_{variant_idx}",
        "name: string": f"name_{variant_idx}: string",
        "String name": f"String name_{variant_idx}",
        "String username": f"String username_{variant_idx}",
    }
    out = code
    for src, dst in replacements.items():
        out = out.replace(src, dst)
    return out


def main() -> None:
    args = parse_args()
    if args.replicas < 1:
        raise ValueError("--replicas must be >= 1")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    base = build_samples()
    rows = []
    for rep in range(1, args.replicas + 1):
        for t_idx, row in enumerate(base, start=1):
            new_row = dict(row)
            new_row["template_id"] = f"tmpl_{t_idx:02d}"
            new_row["variant"] = rep
            if rep > 1:
                new_row["code"] = mutate_code(new_row["code"], rep)
            rows.append(new_row)

    if args.shuffle:
        rnd = random.Random(args.seed)
        rnd.shuffle(rows)

    with out_path.open("w", encoding="utf-8") as f:
        for i, row in enumerate(rows, start=1):
            row = {"id": i, **row}
            f.write(json.dumps(row) + "\n")

    vuln = sum(1 for r in rows if r["label"] == "vulnerable")
    clean = sum(1 for r in rows if r["label"] == "clean")
    print(
        json.dumps(
            {
                "output": str(out_path),
                "replicas": args.replicas,
                "total": len(rows),
                "vulnerable": vuln,
                "clean": clean,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

