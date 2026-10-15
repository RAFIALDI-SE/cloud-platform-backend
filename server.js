require("dotenv").config();

const http = require("node:http");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");

const PORT = Number(process.env.PORT || 3000);
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "zeixon_cloud";

if (!MONGO_URI) {
  console.error("MONGO_URI belum diatur di file .env");
  process.exit(1);
}

const client = new MongoClient(MONGO_URI);

const allowedOrigins = new Set([
  "https://zeixon.com",
  "https://www.zeixon.com",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:5501",
  "http://127.0.0.1:5501",
  "http://localhost:3001",
  "http://127.0.0.1:3001",
]);

let users;

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    let size = 0;

    req.on("data", (chunk) => {
      size += chunk.length;

      if (size > 16 * 1024) {
        const error = new Error("Ukuran request terlalu besar.");
        error.statusCode = 413;
        reject(error);
        req.destroy();
        return;
      }

      body += chunk.toString();
    });

    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        const error = new Error("Format JSON tidak valid.");
        error.statusCode = 400;
        reject(error);
      }
    });

    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }

  if (req.method === "OPTIONS") {
    if (origin && !allowedOrigins.has(origin)) {
      sendJson(res, 403, {
        status: "error",
        message: "Origin tidak diizinkan.",
      });
      return;
    }

    res.writeHead(204);
    res.end();
    return;
  }

  const pathname = new URL(req.url, `http://${req.headers.host || "localhost"}`)
    .pathname;

  if (pathname === "/api/health" && req.method === "GET") {
    sendJson(res, 200, {
      status: "ok",
      message: "ZeixonCloudHouse Backend is running",
    });
    return;
  }

  if (pathname === "/api/register" && req.method === "POST") {
    try {
      const body = await readJson(req);

      const name = typeof body.name === "string" ? body.name.trim() : "";

      const email =
        typeof body.email === "string" ? body.email.trim().toLowerCase() : "";

      const password = typeof body.password === "string" ? body.password : "";

      if (!name || !email || !password) {
        sendJson(res, 400, {
          status: "error",
          message: "Nama, email, dan password wajib diisi.",
        });
        return;
      }

      if (name.length > 100) {
        sendJson(res, 400, {
          status: "error",
          message: "Nama maksimal 100 karakter.",
        });
        return;
      }

      if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        sendJson(res, 400, {
          status: "error",
          message: "Format email tidak valid.",
        });
        return;
      }

      // Batas bcrypt: maksimal 72 byte untuk password UTF-8.
      if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
        sendJson(res, 400, {
          status: "error",
          message: "Password minimal 8 karakter dan maksimal 72 byte.",
        });
        return;
      }

      const existingUser = await users.findOne({ email });

      if (existingUser) {
        sendJson(res, 409, {
          status: "error",
          message: "Email sudah terdaftar.",
        });
        return;
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await users.insertOne({
        name,
        email,
        passwordHash,
        createdAt: new Date(),
      });

      sendJson(res, 201, {
        status: "success",
        message: "Pendaftaran berhasil.",
        user: {
          id: result.insertedId.toString(),
          name,
          email,
        },
      });
    } catch (error) {
      if (error.statusCode) {
        sendJson(res, error.statusCode, {
          status: "error",
          message: error.message,
        });
        return;
      }

      if (error.code === 11000) {
        sendJson(res, 409, {
          status: "error",
          message: "Email sudah terdaftar.",
        });
        return;
      }

      console.error("Kesalahan registrasi:", error);

      if (!res.headersSent) {
        sendJson(res, 500, {
          status: "error",
          message: "Terjadi kesalahan pada server.",
        });
      }
    }

    return;
  }

  sendJson(res, 404, {
    status: "error",
    message: "Endpoint tidak ditemukan.",
  });
});

async function startServer() {
  try {
    await client.connect();

    const db = client.db(DB_NAME);
    users = db.collection("users");

    // Menjamin email unik meskipun ada request bersamaan.
    await users.createIndex({ email: 1 }, { unique: true });

    server.listen(PORT, "127.0.0.1", () => {
      console.log(`Backend berjalan di http://127.0.0.1:${PORT}`);
      console.log(`Database terhubung: ${DB_NAME}`);
    });
  } catch (error) {
    console.error("Gagal memulai backend:", error.message);
    await client.close().catch(() => {});
    process.exit(1);
  }
}

async function shutdown() {
  server.close();
  await client.close();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

startServer();
