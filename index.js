/*
 * Verify GitHub webhook signature header in Node.js
 * Written by stigok and others (see gist link for contributor comments)
 * https://gist.github.com/stigok/57d075c1cf2a609cb758898c0b202428
 * Licensed CC0 1.0 Universal
 */
const SECRET = process.env.SECRET;
const PORT = process.env.PORT || 8700;
const WORK_DIR = process.env.WORK_DIR;
const GIT_URL = process.env.GIT_URL;

const crypto = require("crypto");
const express = require("express");
const bodyParser = require("body-parser");
const { exec } = require("child_process");

// GitHub: X-Hub-Signature
// Gogs:   X-Gogs-Signature
const sigHeaderName = "X-Hub-Signature";

const app = express();
app.use(bodyParser.json());

function verifyPostData(req, res, next) {
  const payload = JSON.stringify(req.body);
  if (!payload) {
    return next("Request body empty");
  }

  const sig = req.get(sigHeaderName) || "";
  const hmac = crypto.createHmac("sha1", SECRET);
  const digest = Buffer.from(
    "sha1=" + hmac.update(payload).digest("hex"),
    "utf8"
  );
  const checksum = Buffer.from(sig, "utf8");
  if (
    checksum.length !== digest.length ||
    !crypto.timingSafeEqual(digest, checksum)
  ) {
    return next(
      `Request body digest (${digest}) did not match ${sigHeaderName} (${checksum})`
    );
  }
  return next();
}

app.post("/", verifyPostData, function (req, res) {
  exec("rm -rf temp");
  exec("git clone " + GIT_URL + " temp", handleOutput);
  exec(WORK_DIR + "/build.sh", handleOutput);
  exec("mv temp app");

  res.status(200).send("Request body was signed");
});

const handleOutput = (error, stdout, stderr) => {
  if (error) {
    console.log(`error: ${error.message}`);
    return;
  }
  if (stderr) {
    console.log(`stderr: ${stderr}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
};

app.use((err, req, res, next) => {
  if (err) console.error(err);
  res.status(403).send("Request body was not signed or verification failed");
});

app.listen(PORT);
