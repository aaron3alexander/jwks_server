const { expect } = require("chai");
const supertest = require("supertest");
const app = require("./app.js");

const request = supertest(app);

describe("JWT Server Tests", () => {
  it("should hit the POST /auth endpoint and should return a successful response", async () => {
    const response = await request.post("/auth");
    expect(response.status).to.equal(200);
  });

  it("should hit the GET /.well-known/jwks.json endpoint and should return a valid JWKS array", async () => {
    const response = await request.get("/.well-known/jwks.json");
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property("keys").that.is.an("array");

    const key = response.body.keys[0];
    expect(key).to.have.property("kid").that.is.a("string");
    expect(key).to.have.property("kty", "RSA");
    expect(key).to.have.property("alg", "RS256");
    expect(key).to.have.property("use", "sig");
    expect(key).to.have.property("n").that.is.a("string");
    expect(key).to.have.property("e", "AQAB");
  });
});
