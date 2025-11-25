import { readDb, writeDb } from "../../database/database.js";
import crypto from "node:crypto";

export default {
  async findAll() {
    // TODO: get ahold of the db using readDb();
    // TODO: return the tips from the db
  },

  async create({ title, userId }) {
    // TODO: get ahold of the db using readDb();
    // TODO: create a tip object containing { id: "some-random-id", title, userId }
    // TODO: push the tip object into tips list in the database
    // TODO: write changes to database with await writeDb(db)
    // TODO: return the id of the created tip
  },

  async update({ id, title, userId }) {
    // TODO: get ahold of the db using readDb();
    // TODO: find a tip in the db whose id & userId matches the incoming id & userId
    // TODO: if there is no matching tip, return false.
    // TODO: otherwise, set the found tip's title to the incoming title
    // TODO: write changes to database with await writeDb(db)
    // TODO: return true
  },

  async remove({ id, userId }) {
    // TODO: get ahold of the db using readDb();
    // TODO: find the INDEX of the tip in the db whose id & userId match the incoming id & userId
    // TODO: if there is no index (-1), return false.
    // TODO: otherwise, use splice to delete from db.tips the tip based on the index
    // TODO: write changes to database with await writeDb(db)
    // TODO: return true
  },
};
