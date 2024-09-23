const express = require("express");
const jose = require("node-jose");
const app = express();
const PORT = 8080;
const keystore = jose.JWK.createKeyStore();

// mock data
const payload = { username: "user", password: "password" };

// generate a key and add it to the keystore
async function generateJWKSKey(kid) {
	const key = await keystore.generate("RSA", 2048, { use: "sig", kid: kid });
	return key;
}

// generate a JWT token based on the payload
async function getJWT(payload) {
	let expired = payload.exp < Math.floor(Date.now() / 1000);
	let key = expired ? keystore.get("expired") : keystore.get("current");

	if (!key) {
		throw new Error(
			`Key not found for ${expired ? "expired" : "current"} token`
		);
	}

	const token = await jose.JWS.createSign(
		{
			format: "compact",
			fields: { kid: key.kid, alg: key.alg, exp: payload.exp },
		},
		key
	)
		.update(JSON.stringify(payload))
		.final();

	return token;
}

// ignore non-GET requests
app.all("/.well-known/jwks.json", (req, res, next) => {
	if (req.method !== "GET") {
		return res.status(405).end();
	}
	next();
});

// return the JWKS keystore
app.get("/.well-known/jwks.json", (_, res) => {
	let currentKey = keystore.get("current");
	let jwks = { keys: [currentKey.toJSON()] };
	return res.status(200).json(jwks);
});

// reject non-POST requests
app.all("/auth", (req, res, next) => {
	if (req.method !== "POST") {
		return res.status(405).end();
	}
	next();
});

// return a JWT token (expired or not) based on query params
app.post("/auth", async (req, res) => {
	const queries = req.query;
	const expired = queries.expired;
	const payloadCopy = JSON.parse(JSON.stringify(payload));

	if (expired) {
		payloadCopy.exp = Math.floor(Date.now() / 1000) - 1000; // 1000 seconds in the past
	} else {
		payloadCopy.exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour in the future
	}

	await getJWT(payloadCopy)
		.then((token) => {
			res.status(200).send(token);
		})
		.catch((err) => {
			console.error("Error generating JWT:", err);
			res.status(500).send("Error generating JWT");
		});
});

generateJWKSKey("current").catch((err) => {
	console.error("Error generating current key:", err);
});
generateJWKSKey("expired").catch((err) => {
	console.error("Error generating expired key:", err);
});

// listen for requests
app.listen(PORT, () => {
	console.log(`Server : http://localhost:${PORT}`);
});
