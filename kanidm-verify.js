const jose = require('jose');

module.exports = function (RED) {
    function KanidmVerifyNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        node.infoUrl = config.infoUrl;
        node.audience = config.audience;

        let JWKS;

        let jwksUrl = node.infoUrl;
        let ready = false;

        async function getJwksUrl(url) {
            if (url.includes('.well-known/openid-configuration')) {
                try {
                    const response = await fetch(url);
                    if (!response.ok) throw new Error('Failed to fetch OIDC config');
                    const data = await response.json();
                    return data.jwks_uri;
                } catch (err) {
                    node.error("Could not fetch OIDC configuration: " + err.message);
                    node.status({ fill: 'red', shape: 'ring', text: 'invalid-oidc-config' })
                    return null;
                }
            }
            return url;
        }

        (async () => {
            const resolvedUrl = await getJwksUrl(node.infoUrl);
            if (resolvedUrl) {
                JWKS = jose.createRemoteJWKSet(new URL(resolvedUrl));
                ready = true;
                node.status({ fill: 'blue', shape: 'ring', text: 'initialized' })
                node.log("Kanidm Verify Node initialized with JWKS URL: " + resolvedUrl);
            }
        })();


        node.on('input', async function (msg) {
            if (!ready) {
                node.status({ fill: 'red', shape: 'ring', text: 'not-initialized' })
                node.error("Node not initialized (JWKS URL not resolved yet)", msg);
                return;
            }

            let token = null;

            if (msg.req && msg.req.headers && msg.req.headers.authorization) {
                const parts = msg.req.headers.authorization.split(' ');
                if (parts.length === 2 && parts[0] === 'Bearer') {
                    token = parts[1];
                }
            } else if (msg.token) {
                token = msg.token;
            } else if (typeof msg.payload === 'string') {
                // Determine if payload looks like a token?
                // The prompt says: "As input expect an output from an http node. The token is in the Bearer header."
                // But generally good to be slightly flexible or strict. Let's stick to header primarily.
            }

            if (!token) {
                msg.error = { message: "No token found in Bearer header", code: "MISSING_TOKEN" };
                node.status({ fill: 'red', shape: 'ring', text: 'missing-token' })
                node.send([null, msg]);
                return;
            }

            try {
                const options = {
                    algorithms: ['ES256'],
                };
                if (node.audience != null) {
                    options.audience = node.audience;
                }

                const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, options);

                msg.token = payload;
                node.status({ fill: 'green', shape: 'ring', text: 'verified' })
                node.send([msg, null]);
            } catch (err) {
                msg.error = { message: "JWT Verification failed: " + err.message, code: "VERIFY_FAILED" };
                node.status({ fill: 'red', shape: 'ring', text: 'verify-failed' })
                node.send([null, msg]);
            }
        });
    }
    RED.nodes.registerType("kanidm-verify", KanidmVerifyNode);
}
