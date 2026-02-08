const should = require("should");
const helper = require("node-red-node-test-helper");
const kanidmNode = require("../kanidm-verify.js");
const jose = require("jose");

helper.init(require.resolve("node-red"));

describe("kanidm-verify Node", function () {

    let keyPair;
    let validToken;
    let jwks;
    let originalFetch;

    const issuer = "https://idm.example.com";
    const audience = null;
    const jwksUri = `${issuer}/jwks.json`;

    before(async function () {
        // Generate a key pair for signing tokens
        const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
        keyPair = { publicKey, privateKey };

        // Export public key to JWKS format
        const jwk = await jose.exportJWK(publicKey);
        jwk.kid = "test-key-id";
        jwk.alg = "ES256";
        jwk.use = "sig";

        jwks = { keys: [jwk] };

        // Sign a valid token
        validToken = await new jose.SignJWT({ 'urn:example:claim': true })
            .setProtectedHeader({ alg: 'ES256', kid: 'test-key-id' })
            .setIssuedAt()
            .setIssuer(issuer)
            .setAudience(audience)
            .setExpirationTime('2h')
            .sign(privateKey);
    });

    beforeEach(function () {
        originalFetch = global.fetch;
        global.fetch = async (url) => {
            const urlStr = (typeof url === 'string') ? url : url.url;
            console.error(`Fetch called for: ${urlStr}`);
            if (urlStr === `${issuer}/.well-known/openid-configuration`) {
                return {
                    ok: true,
                    json: async () => ({ jwks_uri: jwksUri })
                };
            }
            if (urlStr === jwksUri) {
                return {
                    ok: true,
                    json: async () => jwks
                };
            }
            throw new Error(`Unexpected fetch to ${urlStr}`);
        };
    });

    afterEach(function () {
        helper.unload();
        global.fetch = originalFetch;
    });

    it("should be loaded", function (done) {
        const flow = [{ id: "n1", type: "kanidm-verify", name: "test-node", infoUrl: issuer, audience: audience }];
        helper.load(kanidmNode, flow, function () {
            const n1 = helper.getNode("n1");
            try {
                n1.should.have.property("name", "test-node");
                done();
            } catch (err) {
                done(err);
            }
        });
    });

    it("should verify a valid token", function (done) {
        const flow = [{ id: "n1", type: "kanidm-verify", name: "test-node", infoUrl: `${issuer}/.well-known/openid-configuration`, audience: audience, wires: [["n2"], ["n3"]] },
        { id: "n2", type: "helper" },
        { id: "n3", type: "helper" }];

        helper.load(kanidmNode, flow, function () {
            const n2 = helper.getNode("n2");
            const n3 = helper.getNode("n3");
            const n1 = helper.getNode("n1");

            n2.on("input", function (msg) {
                try {
                    msg.should.have.property("token");
                    msg.token.should.have.property("aud", audience);
                    done();
                } catch (err) {
                    done(err);
                }
            });

            n3.on("input", function (msg) {
                done(new Error("Should not have received message on failure output"));
            });

            // Wait until initialization logic (fetch) is done. 
            // In real node-red, the flow starts. Here, we can start input a bit later.
            // Since `fetch` is mocked and async, we need to give it a tick.
            setTimeout(() => {
                n1.receive({ payload: "foo", req: { headers: { authorization: `Bearer ${validToken}` } } });
            }, 100);
        });
    });

    it("should fail on invalid signature", function (done) {
        const flow = [{ id: "n1", type: "kanidm-verify", name: "test-node", infoUrl: `${issuer}/.well-known/openid-configuration`, audience: audience, wires: [["n2"], ["n3"]] },
        { id: "n2", type: "helper" },
        { id: "n3", type: "helper" }];

        helper.load(kanidmNode, flow, function () {
            const n1 = helper.getNode("n1");
            const n2 = helper.getNode("n2");
            const n3 = helper.getNode("n3");

            n2.on("input", function (msg) {
                done(new Error("Should not have received message on success output"));
            });

            n3.on("input", function (msg) {
                try {
                    msg.should.have.property("error");
                    msg.error.should.have.property("message");
                    msg.error.message.should.match(/JWT Verification failed/);
                    done();
                } catch (e) {
                    done(e);
                }
            });

            (async () => {
                const { privateKey: badKey } = await jose.generateKeyPair('ES256');
                const badToken = await new jose.SignJWT({})
                    .setProtectedHeader({ alg: 'ES256' })
                    .setAudience(audience)
                    .sign(badKey);

                setTimeout(() => {
                    n1.receive({ payload: "foo", req: { headers: { authorization: `Bearer ${badToken}` } } });
                }, 100);
            })();
        });
    });
});
