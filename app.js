const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const PORT = 8080;
const app = express();
app.use(express.json()); //using this so that I can take in body variables

const generateRSAKey = () => {
  //generates an RSA key that expires in 1 hour
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  const kid = crypto.randomBytes(16).toString("hex"); //make a random key id
  const expiry = Math.floor(Date.now() / 1000) + 3600; //expire in 1 hour

  return { kid, publicKey, privateKey, expiry };
};

const generateExpiredRSAKey = () => {
  //generates an RSA key that expired an hour ago
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  const kid = crypto.randomBytes(16).toString("hex"); //make a random key id
  const expiry = Math.floor(Date.now() / 1000) - 3600; //expired an hour ago

  return { kid, publicKey, privateKey, expiry };
};

let jwks = [];
let currentKey = generateRSAKey();

app.get("/.well-known/jwks.json", (req, res) => {
  //get endpoint for the JWKS server
  if (jwks.length === 0) {
    // Make a key if there are none
    jwks.push({
      kid: currentKey.kid,
      kty: "RSA",
      use: "sig",
      alg: "RS256",
      n: Buffer.from(currentKey.publicKey, "utf-8").toString("base64"),
      e: "AQAB",
    });
  }
  res.json({ keys: jwks }); //return jwks array
});

app.post("/auth", (req, res) => {
  //POST auth endpoint
  const expired = req.query.expired === "true"; //boolean val that tells me if an expired param was passed in
  let token;
  if (expired) {
    //if expired, make a token that expired an hour ago
    currentKey = generateExpiredRSAKey();
    token = jwt.sign(
      {
        username: req.body.username ? req.body.username : "No Username",
      },
      currentKey.privateKey,
      {
        algorithm: "RS256",
        expiresIn: "-1h",
        keyid: currentKey.kid,
      }
    );
    console.log("Expired KID: " + currentKey.kid); //TODO: REMOVE
  } else {
    //if not expired, make a token that expires in an hour
    token = jwt.sign(
      {
        username: req.body.username ? req.body.username : "No Username", //if username is provided, use that username
      },
      currentKey.privateKey,
      {
        algorithm: "RS256",
        expiresIn: "1h",
        keyid: currentKey.kid,
      }
    );
    console.log("KID: " + currentKey.kid); //TODO: REMOVE

    const newJwk = {
      //create a new JWK for the JWKS array
      kty: "RSA",
      use: "sig",
      kid: currentKey.kid,
      alg: "RS256",
      n: Buffer.from(currentKey.publicKey, "utf-8").toString("base64"),
      e: "AQAB",
    };
    jwks.push(newJwk);
  }

  //for formatting
  res.set("Content-Type", "text/plain");
  res.removeHeader("Connection");
  res.removeHeader("X-Powered-By");
  res.status(200).send(token);
});

//start server
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
module.exports = app; //did this so that I could do a testing file
