const express = require("express");
const jose = require("node-jose");
const sqlite3 = require("sqlite3");
const app = express();
const PORT = 8080;

// mock data
const payload = { username: "user", password: "password" };

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

// create keys table
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

// generate a JWT token and return it
app.post("/auth", async (req, res) => {
	const expired = req.query.expired === "true";
	const payloadCopy = { ...payload };
	payloadCopy.exp = expired
		? Math.floor(Date.now() / 1000) - 1000
		: Math.floor(Date.now() / 1000) + 3600;

	await getJWT(payloadCopy)
		.then((token) => {
			res.status(200).send(token);
		})
		.catch((err) => {
			res.status(500).send("Failed to generate JWT token:", err);
		});
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
