// ─────────────────────────────────────────────────────────────────────────────
// user.model.js — modelul Mongoose pentru un UTILIZATOR al aplicației.
//
// Ce face, pe scurt: definește forma unui document din colecția "users".
// Un document = un cont de utilizator: nume, email, parola (salvată ca hash,
// niciodată în clar), rol (user/admin) și setările personale (AI activat,
// alerte, digest zilnic).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    // ── Date de identificare ───────────────────────────────────────────────
    name: {
      type: String,
      required: [true, "Username is required"],
      trim: true,
      minlength: 3,
      maxlength: 50,
    },
    // "unique: true" = MongoDB nu permite două conturi cu același email.
    // "match" = expresie regulată simplă care verifică formatul "ceva@ceva.ceva".
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/\S+@\S+\.\S+/, "Please provide a valid email address"],
    },
    // Parola NU se salvează niciodată în clar, ci doar hash-ul ei (rezultatul
    // unei funcții ireversibile aplicate parolei). "select: false" = acest
    // câmp nu e returnat automat la interogări (trebuie cerut explicit),
    // ca să nu apară din greșeală în răspunsurile API.
    passwordHash: {
      type: String,
      required: [true, "Password is required"],
      select: false,
    },
    // Rolul contului: "user" (normal) sau "admin". "enum" = lista valorilor
    // permise.
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },

    // ── Setările personale ale userului ─────────────────────────────────────
    settings: {
      // aiEnabled: dacă scanarea AI (Ollama) e activată pentru acest user.
      aiEnabled: {
        type: Boolean,
        default: true,
      },
      // alertsEnabled: dacă userul primește alerte (ex. notificări pentru
      // emailuri foarte riscante).
      alertsEnabled: {
        type: Boolean,
        default: false,
      },
      // digestEnabled / digestHour: dacă userul primește un rezumat zilnic
      // ("digest") și la ce oră (0-23) ar trebui trimis.
      digestEnabled: {
        type: Boolean,
        default: true,
      },
      digestHour: {
        type: Number,
        default: 8,
        min: 0,
        max: 23,
      },
    },
  },
  // timestamps: true => Mongoose adaugă automat createdAt și updatedAt.
  { timestamps: true },
);

const User = mongoose.model("User", userSchema);

export default User;
