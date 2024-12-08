const express = require("express");
const jose = require("node-jose");
const sqlite3 = require("sqlite3");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt");
const app = express();
const PORT = 8080;

// allow express to parse json
app.use(express.json());

// mock data
const payload = { username: "user", password: "password" };

// rate limiting
const rateLimit = new Map();
const authRateLimiter = (req, res, next) => {
	const ip = req.ip;
	const now = Date.now();

	if (!rateLimit.has(ip)) {
		rateLimit.set(ip, {
			count: 0,
			resetTime: now + 120 * 1000,
		});
	}

	const rateLimitData = rateLimit.get(ip);

	if (now > rateLimitData.resetTime) {
		rateLimitData.count = 0;
		rateLimitData.resetTime = now + 60 * 1000;
	}

	if (rateLimitData.count > 10) {
		return res.status(429).send("Rate limit exceeded");
	}

	rateLimitData.count++;
	rateLimit.set(ip, rateLimitData);

	next();
};

// create DB
const db = new sqlite3.Database(
	"./totally_not_my_privateKeys.db",
	sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
	(err) => {
		if (err) {
			console.error("Error opening DB:", err);
			process.exit(1);
		}
		console.log("sqlite3 DB opened");
	}
);

// create tables
db.serialize(() => {
	db.run("DROP TABLE IF EXISTS keys", (err) => {
		if (err) {
			console.error("DB failed to drop table:", err);
		}
	});

	db.run(
		`CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )`,
		(err) => {
			if (err) {
				console.error("DB failed to create table:", err);
			}
		}
	);

	db.run("DROP TABLE IF EXISTS users", (err) => {
		if (err) {
			console.error("DB failed to drop table:", err);
		}
	});

	db.run(
		`CREATE TABLE IF NOT EXISTS users(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP      
		)`,
		(err) => {
			if (err) {
				console.error("DB failed to create table:", err);
			}
		}
	);

	db.run("DROP TABLE IF EXISTS auth_logs", (err) => {
		if (err) {
			console.error("DB failed to drop table:", err);
		}
	});

	db.run(
		`
		CREATE TABLE IF NOT EXISTS auth_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_ip TEXT NOT NULL,
			request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,  
			FOREIGN KEY(user_id) REFERENCES users(id)
		);
		`,
		(err) => {
			if (err) {
				console.error("DB failed to create table:", err);
			}
		}
	);
});

// convert key to string and store it in the DB
async function storeKey(key, expiration) {
	return new Promise((resolve, reject) => {
		const keyString = JSON.stringify(key);
		const sql = `INSERT INTO keys (key, exp) VALUES (?, ?)`;
		db.run(sql, [keyString, expiration], function (err) {
			if (err) reject(err);
			else resolve(this.lastID);
		});
	});
}

// get a key from the DB, convert it to a JWK and return it
async function getKeyFromDB(expired = false) {
	const currentTime = Math.floor(Date.now() / 1000);
	const sql = expired
		? `SELECT * FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1`
		: `SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1`;

	return new Promise((resolve, reject) => {
		db.get(sql, [currentTime], async (err, row) => {
			if (err) {
				console.error("DB error:", err);
				reject(err);
			} else if (!row) {
				resolve(null);
			} else {
				try {
					const keyData = JSON.parse(row.key);
					const key = await jose.JWK.asKey(keyData);
					resolve(key);
				} catch (err) {
					console.error("Failed to get key:", err);
					reject(err);
				}
			}
		});
	});
}

// generate a key
async function generateAndStoreKey(expired = false) {
	const kid = expired ? "expired" : "current";
	const key = await jose.JWK.createKey("RSA", 2048, {
		use: "sig",
		kid: kid,
		alg: "RS256",
	});

	const expiration = expired
		? Math.floor(Date.now() / 1000) - 1000
		: Math.floor(Date.now() / 1000) + 3600;

	await storeKey(key.toJSON(true), expiration);
	return key;
}

// generate a JWT token based on the payload
async function getJWT(payload) {
	const expired = payload.exp < Math.floor(Date.now() / 1000);
	const key = await getKeyFromDB(expired);

	if (!key) {
		throw new Error(`No ${expired ? "expired" : "valid"} key found in DB`);
	}

	const token = await jose.JWS.createSign(
		{
			format: "compact",
			fields: { kid: key.kid, alg: "RS256", exp: payload.exp },
		},
		key
	)
		.update(JSON.stringify(payload))
		.final();
	return token;
}

// ignore non-POST requests
app.all("/auth", (req, res, next) => {
	if (req.method !== "POST") {
		return res.status(405).end();
	}
	next();
});

// generate a JWT token and return it (with ratelimiting)
app.post("/auth", authRateLimiter, async (req, res) => {
	try {
		const expired = req.query.expired === "true";
		const payloadCopy = { ...payload };
		payloadCopy.exp = expired
			? Math.floor(Date.now() / 1000) - 1000
			: Math.floor(Date.now() / 1000) + 3600;

		const id = payload.sub;
		const ip = req.ip;
		const sql = `INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)`;

		await new Promise((resolve, reject) => {
			db.run(sql, [ip, id], function (err) {
				if (err) {
					console.error("Failed to log auth endpoint:", err);
					reject(err);
				} else {
					resolve();
				}
			});
		});

		const token = await getJWT(payloadCopy);
		res.status(200).send(token);
	} catch (err) {
		console.error("Auth error:", err);
		res.status(500).send("Failed to generate JWT token");
	}
});

// ignore non-GET requests
app.all("/.well-known/jwks.json", (req, res, next) => {
	if (req.method !== "GET") {
		return res.status(405).end();
	}
	next();
});

// return the JWKS from DB
app.get("/.well-known/jwks.json", async (req, res) => {
	const currentTime = Math.floor(Date.now() / 1000);
	const sql = `SELECT * FROM keys WHERE exp > ?`;

	await new Promise((resolve, reject) => {
		return db.all(sql, [currentTime], async (err, rows) => {
			if (err) {
				console.error("DB error:", err);
				reject(err);
				return res.status(500).send("DB error");
			}

			Promise.all(
				rows.map(async (row) => {
					const keyData = JSON.parse(row.key);
					const key = await jose.JWK.asKey(keyData);
					return key.toJSON();
				})
			)
				.then((keys) => {
					resolve(keys);
					res.json({ keys });
				})
				.catch((err) => {
					reject(err);
					console.error("Failed to get JWKS from DB:", err);
					res.status(500).send("Failed to get JWKS from DB");
				});
		});
	}).catch((err) => {
		console.error("DB error:", err);
		res.status(500).send("DB error");
	});
});

// ignore non-post requests
app.all("/register", (req, res, next) => {
	if (req.method !== "POST") {
		return res.status(405).end();
	}
	next();
});

// register a user
app.post("/register", async (req, res) => {
	try {
		const { username, email } = req.body;
		const uuid = uuidv4();
		const hash = await bcrypt.hash(uuid, 1);

		const sql = `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`;

		db.run(sql, [username, hash, email], function (err) {
			if (err) {
				console.error("Failed to register user:", err);
				return res.status(500).send("Failed to register user");
			}

			res.status(200).json({
				password: uuid,
			});
		});
	} catch (error) {
		console.error("Registration error:", error);
		res.status(500).send("Server error during registration");
	}
});

// generate keys one current and one expired
generateAndStoreKey(false).catch((err) =>
	console.error("Error generating current key:", err)
);
generateAndStoreKey(true).catch((err) =>
	console.error("Error generating expired key:", err)
);

// start server
app.listen(PORT, "127.0.0.1", () => {
	console.log(`Server running at http://localhost:${PORT}`);
});

// close DB on shutdown  (kind of jank but works for development)
process.on("SIGINT", () => {
	db.close((err) => {
		if (err) {
			console.error("Error closing DB:", err);
		}
		process.exit(0);
	});
});
