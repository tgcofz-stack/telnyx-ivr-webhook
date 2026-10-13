
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
    cb(allowed ? null : new Error("Only WAV or MP3 files are allowed"), allowed);
  }
});

app.get("/", (req, res) => {
  res.status(200).send("Zadarma webhook is running!");
});

// Existing Zadarma webhook verification
app.get("/webhook", (req, res) => {
  if (req.query.zd_echo !== undefined) {
    return res.status(200).send(String(req.query.zd_echo));
  }
  res.status(200).send("Zadarma webhook endpoint is ready.");
});

// Existing Zadarma event notifications
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

// Browser upload page. Upload requests require a private token.
app.get("/admin/upload", (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zadarma Audio Upload</title>
</head>
<body style="font:16px Arial;max-width:600px;margin:40px auto;padding:0 16px">
<h2>Zadarma IVR Audio Upload</h2>
<p>Select a WAV or MP3 file (maximum 5 MB).</p>
<label>Upload token<br>
<input id="token" type="password" autocomplete="off"
style="width:100%;padding:10px;margin:8px 0">
</label>
<form id="uploadForm">
<label>Audio file<br>
<input id="audio" type="file" accept=".wav,.mp3,audio/wav,audio/mpeg"
required style="margin:12px 0">
</label><br>
<label>Sound name<br>
<input id="soundName" required maxlength="100"
placeholder="Business greeting" style="padding:10px;width:90%">
</label><br><br>
<button style="padding:12px 20px">Upload to Zadarma</button>
</form>
<pre id="result" style="white-space:pre-wrap"></pre>
<script>
document.getElementById("uploadForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const result = document.getElementById("result");
  const file = document.getElementById("audio").files[0];
  const token = document.getElementById("token").value;
  const name = document.getElementById("soundName").value.trim();

  if (!file || !token || !name) {
    result.textContent = "Please fill in all fields.";
    return;
  }

  const data = new FormData();
  data.append("file", file);
  data.append("name", name);

  result.textContent = "Uploading...";

  try {
    const response = await fetch("/admin/upload", {
      method: "POST",
      headers: { "Authorization": "Bearer " + token },
      body: data
    });
    const body = await response.json();
    result.textContent = JSON.stringify(body, null, 2);
  } catch (err) {
    result.textContent = "Upload request failed. Check the server logs.";
  }
});
</script>
</body>
</html>`);
});

// Protected upload endpoint
app.post("/admin/upload", (req, res, next) => {
  const expected = process.env.UPLOAD_TEST_TOKEN;
  const supplied = req.get("authorization") || "";

  if (!expected) {
    return res.status(503).json({ error: "Upload token is not configured on the server." });
  }

  const expectedBuffer = Buffer.from("Bearer " + expected);
  const suppliedBuffer = Buffer.from(supplied);

  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    return res.status(401).json({ error: "Invalid upload token." });
  }

  next();
}, upload.single("file"), async (req, res) => {
  try {
    const apiKey = process.env.ZADARMA_API_KEY;
    const apiSecret = process.env.ZADARMA_API_SECRET;

    if (!apiKey || !apiSecret) {
      return res.status(503).json({
        error: "Zadarma API credentials are missing from Render Environment."
      });
    }

    if (!req.file) {
      return res.status(400).json({ error: "Choose an audio file first." });
    }

    const name = String(req.body.name || "").trim();
    if (!name || name.length > 100) {
      return res.status(400).json({ error: "Enter a sound name up to 100 characters." });
    }

    // Zadarma signature for the documented request parameters.
    const params = { name };
    const paramsString = new URLSearchParams(
      Object.keys(params).sort().map(key => [key, params[key]])
    ).toString();

    const method = "/v1/pbx/ivr/sounds/upload";
    const signatureBase = method + paramsString + crypto
      .createHash("md5").update(paramsString).digest("hex");

    const signature = crypto
      .createHmac("sha1", apiSecret)
      .update(signatureBase)
      .digest("base64");

    const form = new FormData();
    form.append("name", name);
    form.append("file", req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    const response = await axios.post(
      "https://api.zadarma.com" + method,
      form,
      {
        headers: {
          ...form.getHeaders(),
          Authorization: apiKey + ":" + signature
        },
        timeout: 30000,
        maxBodyLength: 6 * 1024 * 1024
      }
    );

    res.status(200).json({
      message: "Zadarma responded to the upload request.",
      zadarma: response.data
    });
  } catch (err) {
    // Avoid logging credentials, tokens, or full request headers.
    console.error("Zadarma upload failed:", err.response?.status || err.message);
    res.status(502).json({
      error: "Upload failed. Check the Zadarma response and Render logs.",
      zadarma: err.response?.data || undefined
    });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: "File is too large or invalid." });
  }
  if (err) {
    return res.status(400).json({ error: err.message || "Invalid upload." });
  }
  next();
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});
