import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { readDb, writeDb } from "../../database/database.js";

const JWT_SECRET = "secret";

export default {
  async register({ username, password, profilePicture }) {
    // TODO: get ahold of the db using readDb();
    // TODO: check if there is an existing user with the same username
    // TODO: if there is, do the following:
    //       - construct a new Error("Username already taken");
    //       - set the statusCode of that error object to 400
    //       - throw the err
    // TODO: otherwise, create a user object. A user has:
    //       - id: a random string-based id (crypto.randomUUID())
    //       - username: a username
    //       - password: a password
    //       - profilePicture: their profile pic string or an empty string if no picture.
    // TODO:  push this user object into db.users
    // TODO:  call the writeDb(db) operation to save changes.
    // TODO:  return the user object but without their password  (only id, username, profilePicture)

    return {
      id: "dummy-id",
      username: "dummy-username",
      profilePicture: "",
    };
  },

  async login({ username, password }) {
    // TODO: get ahold of the db using readDb();
    // TODO: check the database for a user with a matching username and password
    // TODO: if there is no user:
    //       - construct a new Error("Invalid username or password");
    //       - set the statusCode of that error object to 401
    //       - throw the err
    // TODO: otherwise, create a login token. I'll help you out with this one:
    // const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" })
    // TODO:  return an object that contains 2 things:
    //  - token
    //  - user : { id: user.id, username: user.username, profilePicture: user.profilePicture }

    return {
      token,
      user: {
        id: "dummy-id",
        username: "dummy-username",
        profilePicture: "dummy-profilePicture",
      },
    };
  },
};
