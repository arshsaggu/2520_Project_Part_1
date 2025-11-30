import { readDb, writeDb } from "../../database/database.js";
import crypto from "node:crypto";

export default {
  async findAll() {
    const db = await readDb();
    return db.tips;
  },

  async create({ title, userId }) {
    const db = await readDb();

    const tip = {
      id: crypto.randomUUID(),
      title: title,
      userId: userId
    };

    db.tips.push(tip);
    await writeDb(db);

    return tip.id;
  },

  async update({ id, title, userId }) {
    const db = await readDb();

    const tip = db.tips.find(t => t.id === id && t.userId === userId);

    if (!tip) {
      return false;
    }

    tip.title = title;
    await writeDb(db);

    return true;
  },

  async remove({ id, userId }) {
    const db = await readDb();

    const index = db.tips.findIndex(t => t.id === id && t.userId === userId);

    if (index === -1) {
      return false;
    }

    db.tips.splice(index, 1);
    await writeDb(db);

    return true;
  },
};