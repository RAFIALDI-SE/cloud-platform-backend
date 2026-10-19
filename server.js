require("dotenv").config();

const http = require("node:http");
const crypto = require("node:crypto");
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
const SESSION_COOKIE_NAME = "zeixon_session";
const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;

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
let sessions;

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

function getSessionToken(req) {
  const cookieHeader = req.headers.cookie || "";
  const sessionCookie = cookieHeader
    .split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(`${SESSION_COOKIE_NAME}=`));

  return sessionCookie ? sessionCookie.slice(SESSION_COOKIE_NAME.length + 1) : "";
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function setSessionCookie(req, res, token, maxAge) {
  const secure = req.headers.origin?.startsWith("https://") ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/api; Max-Age=${maxAge}${secure}`,
  );
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

async function verifyTurnstile(token, origin) {
  const secret = process.env.TURNSTILE_SECRET_KEY;

  if (!secret) {
    return {
      ok: false,
      statusCode: 503,
      message: "Verifikasi keamanan belum dikonfigurasi di server.",
    };
  }

  if (typeof token !== "string" || !token.trim()) {
    return {
      ok: false,
      statusCode: 400,
      message: "Selesaikan verifikasi keamanan terlebih dahulu.",
    };
  }

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          secret,
          response: token,
        }),
        signal: AbortSignal.timeout(10000),
      },
    );

    if (!response.ok) {
      console.error("Verifikasi Turnstile gagal dihubungi:", response.status);
      return {
        ok: false,
        statusCode: 502,
        message: "Layanan verifikasi keamanan sedang bermasalah. Coba lagi.",
      };
    }

    const result = await response.json();
    const originHostname = new URL(origin).hostname;

    if (
      !result.success ||
      typeof result.hostname !== "string" ||
      result.hostname !== originHostname
    ) {
      console.warn(
        "Token Turnstile ditolak:",
        result["error-codes"] || "hostname atau token tidak valid",
      );
      return {
        ok: false,
        statusCode: 400,
        message: "Verifikasi keamanan gagal atau kedaluwarsa. Coba lagi.",
      };
    }

    return { ok: true };
  } catch (error) {
    console.error("Kesalahan saat memverifikasi Turnstile:", error.message);
    return {
      ok: false,
      statusCode: 502,
      message: "Tidak dapat menghubungi layanan verifikasi keamanan.",
    };
  }
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Allow-Credentials", "true");
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

  if (pathname === "/api/session" && req.method === "GET") {
    try {
      if (origin && !allowedOrigins.has(origin)) {
        sendJson(res, 403, {
          status: "error",
          message: "Origin tidak diizinkan.",
        });
        return;
      }

      const token = getSessionToken(req);
      if (!token) {
        sendJson(res, 200, { status: "success", authenticated: false });
        return;
      }

      const session = await sessions.findOne({
        tokenHash: hashSessionToken(token),
        expiresAt: { $gt: new Date() },
      });
      if (!session) {
        setSessionCookie(req, res, "", 0);
        sendJson(res, 200, { status: "success", authenticated: false });
        return;
      }

      const user = await users.findOne(
        { _id: session.userId },
        { projection: { firstName: 1, lastName: 1, email: 1 } },
      );
      if (!user) {
        await sessions.deleteOne({ _id: session._id });
        setSessionCookie(req, res, "", 0);
        sendJson(res, 200, { status: "success", authenticated: false });
        return;
      }

      sendJson(res, 200, {
        status: "success",
        authenticated: true,
        user: {
          id: user._id.toString(),
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        },
      });
    } catch (error) {
      console.error("Gagal memeriksa sesi pengguna:", error);
      sendJson(res, 500, {
        status: "error",
        message: "Tidak dapat memeriksa sesi pengguna.",
      });
    }
    return;
  }

  if (pathname === "/api/login" && req.method === "POST") {
    try {
      if (!origin || !allowedOrigins.has(origin)) {
        sendJson(res, 403, {
          status: "error",
          message: "Origin tidak diizinkan.",
        });
        return;
      }

      const body = await readJson(req);
      const email =
        typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const password = typeof body.password === "string" ? body.password : "";

      if (
        !email ||
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        !password ||
        Buffer.byteLength(password, "utf8") > 72
      ) {
        sendJson(res, 400, {
          status: "error",
          message: "Masukkan email dan kata sandi yang valid.",
        });
        return;
      }

      const user = await users.findOne({ email });
      const passwordMatches =
        user &&
        typeof user.passwordHash === "string" &&
        (await bcrypt.compare(password, user.passwordHash));
      if (!passwordMatches) {
        sendJson(res, 401, {
          status: "error",
          message: "Email atau kata sandi salah.",
        });
        return;
      }

      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(
        Date.now() + SESSION_MAX_AGE_SECONDS * 1000,
      );
      await sessions.insertOne({
        tokenHash: hashSessionToken(token),
        userId: user._id,
        createdAt: new Date(),
        expiresAt,
      });
      setSessionCookie(req, res, token, SESSION_MAX_AGE_SECONDS);

      sendJson(res, 200, {
        status: "success",
        authenticated: true,
        user: {
          id: user._id.toString(),
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
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

      console.error("Kesalahan login:", error);
      sendJson(res, 500, {
        status: "error",
        message: "Terjadi kesalahan pada server.",
      });
    }
    return;
  }

  if (pathname === "/api/logout" && req.method === "POST") {
    try {
      if (!origin || !allowedOrigins.has(origin)) {
        sendJson(res, 403, {
          status: "error",
          message: "Origin tidak diizinkan.",
        });
        return;
      }

      const token = getSessionToken(req);
      if (token) {
        await sessions.deleteOne({ tokenHash: hashSessionToken(token) });
      }
      setSessionCookie(req, res, "", 0);
      sendJson(res, 200, { status: "success" });
    } catch (error) {
      console.error("Kesalahan logout:", error);
      sendJson(res, 500, {
        status: "error",
        message: "Tidak dapat mengakhiri sesi. Coba lagi.",
      });
    }
    return;
  }

  if (pathname === "/api/register" && req.method === "POST") {
    try {
      if (!origin || !allowedOrigins.has(origin)) {
        sendJson(res, 403, {
          status: "error",
          message: "Origin tidak diizinkan.",
        });
        return;
      }

      const body = await readJson(req);

      const firstName =
        typeof body.firstName === "string" ? body.firstName.trim() : "";
      const lastName =
        typeof body.lastName === "string" ? body.lastName.trim() : "";
      const name = `${firstName} ${lastName}`.trim();

      const email =
        typeof body.email === "string" ? body.email.trim().toLowerCase() : "";

      const password = typeof body.password === "string" ? body.password : "";
      const phone = typeof body.phone === "string" ? body.phone.trim() : "";
      const companyName =
        typeof body.companyName === "string" ? body.companyName.trim() : "";
      const address1 =
        typeof body.address1 === "string" ? body.address1.trim() : "";
      const address2 =
        typeof body.address2 === "string" ? body.address2.trim() : "";
      const city = typeof body.city === "string" ? body.city.trim() : "";
      const province =
        typeof body.province === "string" ? body.province.trim() : "";
      const postalCode =
        typeof body.postalCode === "string" ? body.postalCode.trim() : "";
      const country =
        typeof body.country === "string" ? body.country.trim() : "Indonesia";
      const currency =
        typeof body.currency === "string" ? body.currency.trim() : "IDR";
      const industry =
        typeof body.industry === "string" ? body.industry.trim() : "";
      const referralSource =
        typeof body.referralSource === "string"
          ? body.referralSource.trim()
          : "";

      if (
        !firstName ||
        !lastName ||
        !email ||
        !password ||
        !phone ||
        !companyName ||
        !address1 ||
        !city ||
        !province ||
        !postalCode ||
        !industry
      ) {
        sendJson(res, 400, {
          status: "error",
          message: "Lengkapi semua field wajib pada formulir registrasi.",
        });
        return;
      }

      if (
        firstName.length > 100 ||
        lastName.length > 100 ||
        name.length > 200
      ) {
        sendJson(res, 400, {
          status: "error",
          message: "Nama depan dan belakang maksimal 100 karakter masing-masing.",
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

      if (password.length < 10 || Buffer.byteLength(password, "utf8") > 72) {
        sendJson(res, 400, {
          status: "error",
          message: "Sandi minimal 10 karakter dan maksimal 72 byte.",
        });
        return;
      }

      const phoneDigits = phone.replace(/\D/g, "");
      if (
        phone.length > 32 ||
        !/^\+?[0-9(). -]+$/.test(phone) ||
        phoneDigits.length < 7 ||
        phoneDigits.length > 15
      ) {
        sendJson(res, 400, {
          status: "error",
          message: "Format nomor telepon tidak valid.",
        });
        return;
      }

      const addressFields = [
        [companyName, 150],
        [address1, 250],
        [address2, 250],
        [city, 100],
        [province, 100],
        [postalCode, 20],
      ];
      if (addressFields.some(([value, maxLength]) => value.length > maxLength)) {
        sendJson(res, 400, {
          status: "error",
          message: "Salah satu field alamat melebihi batas panjang.",
        });
        return;
      }

      const allowedCountries = new Set([
        "Indonesia",
        "Malaysia",
        "Singapore",
        "United States",
        "United Kingdom",
        "Other",
      ]);
      const allowedCurrencies = new Set(["IDR", "USD", "SGD", "MYR", "GBP"]);
      const allowedIndustries = new Set([
        "individual",
        "technology",
        "finance",
        "retail",
        "education",
        "healthcare",
        "manufacturing",
        "media",
        "government",
        "other",
      ]);
      const allowedReferralSources = new Set([
        "",
        "search",
        "social",
        "referral",
        "advertisement",
        "event",
        "other",
      ]);

      if (
        !allowedCountries.has(country) ||
        !allowedCurrencies.has(currency) ||
        !allowedIndustries.has(industry) ||
        !allowedReferralSources.has(referralSource)
      ) {
        sendJson(res, 400, {
          status: "error",
          message: "Pilihan negara, mata uang, sektor, atau sumber tidak valid.",
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

      const verification = await verifyTurnstile(
        body.turnstileToken,
        origin,
      );
      if (!verification.ok) {
        sendJson(res, verification.statusCode, {
          status: "error",
          message: verification.message,
        });
        return;
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await users.insertOne({
        name,
        firstName,
        lastName,
        email,
        phone,
        billingAddress: {
          companyName,
          address1,
          address2: address2 || null,
          city,
          province,
          postalCode,
          country,
        },
        currency,
        industry,
        referralSource: referralSource || null,
        passwordHash,
        createdAt: new Date(),
      });

      sendJson(res, 201, {
        status: "success",
        message: "Pendaftaran berhasil.",
        user: {
          id: result.insertedId.toString(),
          name,
          firstName,
          lastName,
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
    sessions = db.collection("sessions");

    // Menjamin email unik meskipun ada request bersamaan.
    await users.createIndex({ email: 1 }, { unique: true });
    await sessions.createIndex({ tokenHash: 1 }, { unique: true });
    await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

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
