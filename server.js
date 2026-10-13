
const express = require("express");
const multer = require("multer");
const axios = require("axios");
const FormData = require("form-data");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /\.(wav|mp3)$/i.test(file.originalname);
    if (!allowed) {
      return cb(new Error("Only WAV or MP3 files are allowed."));
    }
    cb(null, true);
  }
});

// Health check
app.get("/", (req, res) => {
  res.status(200).send("Zadarma webhook is running!");
});

// Zadarma webhook verification
app.get("/webhook", (req, res) => {
  if (req.query.zd_echo !== undefined) {
    return res.status(200).send(String(req.query.zd_echo));
  }

  res.status(200).send("Zadarma webhook endpoint is ready.");
});

// Zadarma event notifications
app.post("/webhook", (req, res) => {
  const event = req.body || {};

  console.log("Zadarma event received:", {
    event: event.event,
    disposition: event.disposition,
    callback_dtmf: event.callback_dtmf,
    pbx_call_id: event.pbx_call_id
  });

  if (String(event.callback_dtmf || "") === "1") {
    console.log("Client pressed 1: verification confirmed.");
  }

  res.status(200).send("OK");
});

// Check the private upload/test token
function checkToken(req, res, next) {
  const expected = process.env.UPLOAD_TEST_TOKEN;
  const supplied = req.get("authorization") || "";

  if (!expected) {
    return res.status(503).json({
      error: "UPLOAD_TEST_TOKEN is not configured."
    });
  }

  const expectedBuffer = Buffer.from("Bearer " + expected);
  const suppliedBuffer = Buffer.from(supplied);

  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    return res.status(401).json({ error: "Invalid test token." });
  }

  next();
}

// Build Zadarma API signature.
// Parameters must be URL-encoded and sorted before signing.
function makeZadarmaSignature(method, params = {}) {
  const paramsString = Object.keys(params)
    .sort()
    .map(
      key =>
        encodeURIComponent(key) +
        "=" +
        encodeURIComponent(String(params[key]))
    )
    .join("&")
    .replace(/%20/g, "+");

  const md5 = crypto
    .createHash("md5")
    .update(paramsString)
    .digest("hex");

  const signatureBase = method + paramsString + md5;

  return crypto
    .createHmac("sha1", process.env.ZADARMA_API_SECRET)
    .update(signatureBase)
    .digest("base64");
}

// Browser page for the read-only API test
app.get("/admin/test-auth", (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zadarma API Test</title>
</head>
<body style="font:16px Arial;max-width:600px;margin:40px auto;padding:0 16px">
<h2>Zadarma API Authentication Test</h2>
<p>This checks your API connection using the balance endpoint.
It does not place calls or upload audio.</p>
<label>Private test token<br>
<input id="token" type="password" autocomplete="off"
style="box-sizing:border-box;width:100%;padding:12px;margin:8px 0">
</label>
<br>
<button id="test" style="padding:12px 18px">Test API connection</button>
<pre id="result" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>
<script>
document.getElementById("test").addEventListener("click", async () => {
  const token = document.getElementById("token").value;
  const result = document.getElementById("result");

  if (!token) {
    result.textContent = "Enter your private test token.";
    return;
  }

  result.textContent = "Checking Zadarma API...";
  try {
    const response = await fetch("/admin/test-auth", {
      method: "POST",
      headers: { "Authorization": "Bearer " + token }
    });
    const body = await response.json();
    result.textContent = JSON.stringify(body, null, 2);
  } catch (error) {
    result.textContent = "Request failed. Check Render logs.";
  }
});
</script>
</body>
</html>`);
});

// Read-only authentication test
app.post("/admin/test-auth", checkToken, async (req, res) => {
  try {
    const apiKey = process.env.ZADARMA_API_KEY;
    const apiSecret = process.env.ZADARMA_API_SECRET;

    if (!apiKey || !apiSecret) {
      return res.status(503).json({
        error: "Zadarma API credentials are missing."
      });
    }

    const method = "/v1/info/balance/";
    const signature = makeZadarmaSignature(method);

    const response = await axios.get(
      "https://api.zadarma.com" + method,
      {
        headers: {
          Authorization: apiKey + ":" + signature
        },
        timeout: 15000
      }
    );

    const data = response.data || {};

    // Do not expose the account balance in the browser response.
    res.status(200).json({
      message: "Zadarma API responded.",
      status: data.status || "response_received"
    });
  } catch (err) {
    console.error(
      "Zadarma auth test failed:",
      err.response?.status || err.message
    );

    res.status(502).json({
      error: "Zadarma API test failed.",
      httpStatus: err.response?.status || null,
      zadarma: err.response?.data || undefined
    });
  }
});

// Keep the upload page available, but pause uploads until
// API authentication has been confirmed.
app.get("/admin/upload", (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zadarma Audio Upload</title>
</head>
<body style="font:16px Arial;max-width:600px;margin:40px auto;padding:0 16px">
<h2>Zadarma IVR Audio Upload</h2>
<p>Audio uploads are temporarily paused while API authentication is tested.</p>
<p><a href="/admin/test-auth">Test Zadarma API connection first</a></p>
</body>
</html>`);
});

// Prevent another upload attempt until authentication is verified
app.post("/admin/upload", checkToken, upload.single("file"), (req, res) => {
  res.status(409).json({
    error: "Audio upload is temporarily paused. Test Zadarma API authentication first."
  });
});

// Handle invalid files and oversized uploads
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: "File is too large. Maximum size is 5 MB."
    });
  }

  if (err) {
    return res.status(400).json({
      error: err.message || "Invalid request."
    });
  }

  next();
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});
