const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
app.use(cookieParser());

const PORT = 3000;

const USER = {
    id: "1",
    username: "Lucas",
    password: "Grenier"
};

const privatekey = "ma_cle_priv";

function checkAuth(req, res, next) {
    const username = req.query.username;
    const password = req.query.password;
    if (username != USER.username || password != USER.password) {
        res.sendStatus(401);
    } else {
        console.log("OK ");
        next();
    }
}

function hash(data) {
    console.log(data);
    return crypto
        .createHmac("sha256", "secret").update(data).digest("hex");
}

function cookieHandling(req, res, next) {
    const cookie = req.cookies.userCookie;
    if (cookie === undefined) {
        const sign = hash(USER.id + privatekey);
        res.cookie(
            "userCookie",
            JSON.stringify({
                value: USER.id,
                signature: sign
            })
        );
        console.log("cookie created successfully");
    } else {
        const { value, signature } = JSON.parse(cookie);
        const newHash = hash(value + privatekey);
        if (newHash == signature) {
            res.send("Logged");
        } else {
            res.sendStatus(401);
        }
        console.log("cookie exists", cookie);
    }
    next();
}

function basicAuth(req, res) {
    const auth = req.headers["authorization"];

    if (!auth) {
        res.statusCode = 401;
        res.setHeader("WWW-Authenticate", 'Basic realm="Secure Area"');
        res.end("Nope.");
    } else {
        let splitheader = auth.split(" ");
        let buffer = new Buffer(splitheader[1], "base64");
        let plain_auth = buffer.toString();

        let credentials = plain_auth.split(":");
        let username = credentials[0];
        let password = credentials[1];

        if (username == USER.username && password == USER.password) {
            next();
        } else {
            res.statusCode = 401;
            res.setHeader("WWW-Authenticate", 'Basic realm="Secure Area"');
            res.end("Nope. Wrong credentials.");
        }
    }
}

//app.use(basicAuth);

app.get("/", (req, res, next) => checkAuth(req, res, next));
app.use(cookieHandling);

app.listen(PORT, () => console.log("App is listening on port " + PORT + "!"));