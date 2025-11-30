import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { readDb, writeDb } from "../../database/database.js";

const JWT_SECRET = "secret";

export default {
  async register({ username, password, profilePicture }) {
    const db = await readDb();
    const existingUser = db.users.find(u => u.username === username);
    if (existingUser) {
      const err = new Error("Username already taken");
      err.statusCode = 400;
      throw err;
    }
    const user = {
      id: crypto.randomUUID(),
      username: username,
      password: password,
      profilePicture: profilePicture || ""
    };
    db.users.push(user);
    await writeDb(db);
    return {
      id: user.id,
      username: user.username,
      profilePicture: user.profilePicture
    };
  },

  async login({ username, password }) {
    const db = await readDb();
    const user = db.users.find(u => u.username === username && u.password === password);
    if (!user) {
      const err = new Error("Invalid username or password");
      err.statusCode = 401;
      throw err;
    }
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    return {
      token: token,
      user: {
        id: user.id,
        username: user.username,
        profilePicture: user.profilePicture
      }
    };
  },
};