
const express = require("express");
const multer = require("multer");
const axios = require("axios");
const FormData = require("form-data");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const API_BASE = "https://api.zadarma.com";

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!/\.(wav|mp3)$/i.test(file.originalname)) {
      return cb(new Error("Only WAV and MP3 files are allowed."));
    }
    cb(null, true);
  }
});

app.get("/", (req, res) => {
  res.send("Zadarma webhook is running!");
});

// Zadarma webhook verification
app.get("/webhook", (req, res) => {
  if (req.query.zd_echo !== undefined) {
    return res.status(200).send(String(req.query.zd_echo));
  }

  res.status(200).send("Zadarma webhook endpoint is ready.");
});

// Call event notifications only; this route does not place calls.
app.post("/webhook", (req, res) => {
  const event = req.body || {};

  console.log("Zadarma event:", {
    event: event.event,
    disposition: event.disposition,
    callback_dtmf: event.callback_dtmf,
    pbx_call_id: event.pbx_call_id
  });

  res.status(200).send("OK");
});

// Protect administrative routes with a private token.
function checkToken(req, res, next) {
  const expected = process.env.UPLOAD_TEST_TOKEN;
  const supplied = req.get("authorization") || "";

  if (!expected) {
    return res.status(503).json({
      error: "UPLOAD_TEST_TOKEN is not configured in Render."
    });
  }

  const a = Buffer.from("Bearer " + expected);
  const b = Buffer.from(supplied);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({
      error: "Invalid private token."
    });
  }

  next();
}

// Match PHP http_build_query(..., PHP_QUERY_RFC1738).
function encodeParams(params) {
  return Object.keys(params)
    .sort()
    .map(key => {
      const encode = value =>
        encodeURIComponent(String(value))
          .replace(/[!'()*]/g, c =>
            "%" + c.charCodeAt(0).toString(16).toUpperCase()
          )
          .replace(/%20/g, "+");

      return encode(key) + "=" + encode(params[key]);
    })
    .join("&");
}

// Keep the signature method that passed the read-only auth test.
function makeSignature(method, params = {}) {
  const query = encodeParams(params);
  const md5 = crypto.createHash("md5").update(query).digest("hex");
  const base = method + query + md5;

  const hmacHex = crypto
    .createHmac("sha1", process.env.ZADARMA_API_SECRET)
    .update(base)
    .digest("hex");

  return Buffer.from(hmacHex, "utf8").toString("base64");
}

function apiHeaders(method, params = {}) {
  return {
    Authorization:
      process.env.ZADARMA_API_KEY + ":" + makeSignature(method, params)
  };
}

function checkCredentials(res) {
  if (
    !process.env.ZADARMA_API_KEY ||
    !process.env.ZADARMA_API_SECRET
  ) {
    res.status(503).json({
      error: "ZADARMA_API_KEY or ZADARMA_API_SECRET is missing in Render."
    });
    return false;
  }

  return true;
}

// Normalize phone numbers for the test-number allowlist.
function normalizePhone(value) {
  return String(value || "").replace(/[\s()-]/g, "");
}

// Admin page
app.get("/admin/upload", (req, res) => {
  res.type("html").send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zadarma Audio Admin</title>
</head>
<body style="font:16px Arial;max-width:700px;margin:35px auto;padding:0 16px">

<h2>Zadarma IVR Audio Admin</h2>
<p>Upload WAV or MP3 audio files (maximum 5 MB).</p>

<label>Private test token
<input id="token" type="password" autocomplete="off"
style="box-sizing:border-box;width:100%;padding:10px;margin:8px 0">
</label>

<hr>

<h3>Test Zadarma API Connection</h3>
<p>This is a read-only authentication test. It does not place a phone call.</p>
<button id="testAuth" style="padding:10px">Test API Connection</button>

<hr>

<h3>Audio management</h3>

<label>Audio file name
<input id="audioName" value="Business Greeting"
style="box-sizing:border-box;width:100%;padding:10px;margin:8px 0">
</label>

<label>Select audio file
<input id="file" type="file" accept=".wav,.mp3,audio/wav,audio/mpeg"
style="display:block;margin:12px 0">
</label>

<button id="upload" style="padding:10px">Upload audio</button>
<button id="list" style="padding:10px">List uploaded sounds</button>

<hr>

<h3>Test callback</h3>
<p>
This test can place a real call. Only the phone number configured in
Render as TEST_CALLBACK_TO is allowed. Use your own number.
</p>

<label>Your test phone number (international format)
<input id="testPhone" type="tel" placeholder="+855..."
style="box-sizing:border-box;width:100%;padding:10px;margin:8px 0">
</label>

<button id="callback" style="padding:10px">
Request test callback
</button>

<pre id="result"
style="white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:12px"></pre>

<script>
const result = document.getElementById("result");

async function request(path, options = {}) {
  const token = document.getElementById("token").value;

  if (!token) {
    result.textContent = "Enter your private test token first.";
    return;
  }

  result.textContent = "Please wait...";

  try {
    const response = await fetch(path, {
      ...options,
      headers: {
        ...(options.headers || {}),
        Authorization: "Bearer " + token
      }
    });

    const body = await response.json();
    result.textContent = JSON.stringify(body, null, 2);
  } catch (e) {
    result.textContent = "Request failed. Check Render logs.";
  }
}

// Read-only API authentication test; does not place a call.
document.getElementById("testAuth").onclick = async () => {
  await request("/admin/test-auth", {
    method: "POST"
  });
};

document.getElementById("upload").onclick = async () => {
  const fileInput = document.getElementById("file");
  const name = document.getElementById("audioName").value.trim();
  const file = fileInput.files[0];

  if (!name || !file) {
    result.textContent = "Enter a name and choose an audio file.";
    return;
  }

  const form = new FormData();
  form.append("name", name);
  form.append("file", file, file.name);

  await request("/admin/upload", {
    method: "POST",
    body: form
  });
};

document.getElementById("list").onclick = async () => {
  await request("/admin/sounds", {
    method: "GET"
  });
};

document.getElementById("callback").onclick = async () => {
  const to = document.getElementById("testPhone").value.trim();

  if (!to) {
    result.textContent = "Enter your own test phone number.";
    return;
  }

  if (!confirm(
    "This requests a real callback to your test phone. Continue?"
  )) {
    return;
  }

  await request("/admin/test-callback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ to })
  });
};
</script>

</body>
</html>`);
});

// Read-only Zadarma authentication test
app.post("/admin/test-auth", checkToken, async (req, res) => {
  if (!checkCredentials(res)) return;

  try {
    const method = "/v1/info/balance/";

    const response = await axios.get(API_BASE + method, {
      headers: apiHeaders(method),
      timeout: 15000
    });

    res.json({
      message: "Zadarma API responded.",
      status: response.data?.status || "response_received"
    });
  } catch (err) {
    console.error(
      "Auth test failed:",
      err.response?.status || err.message
    );

    res.status(502).json({
      error: "Zadarma authentication test failed.",
      httpStatus: err.response?.status || null,
      zadarma: err.response?.data || null
    });
  }
});

// Upload an IVR sound
app.post(
  "/admin/upload",
  checkToken,
  upload.single("file"),
  async (req, res) => {
    if (!checkCredentials(res)) return;

    if (!req.file) {
      return res.status(400).json({
        error: "Choose a WAV or MP3 file."
      });
    }

    const name = String(req.body.name || "").trim();

    if (!name) {
      return res.status(400).json({
        error: "Audio name is required."
      });
    }

    const method = "/v1/pbx/ivr/sounds/upload";
    const params = { name };
    const form = new FormData();

    form.append("name", name);
    form.append("file", req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    try {
      const response = await axios.post(
        API_BASE + method,
        form,
        {
          headers: {
            ...apiHeaders(method, params),
            ...form.getHeaders()
          },
          maxBodyLength: 6 * 1024 * 1024,
          timeout: 30000
        }
      );

      res.status(200).json({
        message: "Zadarma upload request completed.",
        result: response.data
      });
    } catch (err) {
      console.error(
        "Zadarma upload failed:",
        err.response?.status || err.message,
        err.response?.data || ""
      );

      res.status(502).json({
        error: "Zadarma audio upload failed.",
        httpStatus: err.response?.status || null,
        zadarma: err.response?.data || null
      });
    }
  }
);

// List uploaded IVR sounds
app.get("/admin/sounds", checkToken, async (req, res) => {
  if (!checkCredentials(res)) return;

  const method = "/v1/pbx/ivr/sounds/list";

  try {
    const response = await axios.get(API_BASE + method, {
      headers: apiHeaders(method),
      timeout: 15000
    });

    res.status(200).json({
      message: "Zadarma sound list response.",
      result: response.data
    });
  } catch (err) {
    console.error(
      "Sound list failed:",
      err.response?.status || err.message
    );

    res.status(502).json({
      error: "Could not retrieve Zadarma sound list.",
      httpStatus: err.response?.status || null,
      zadarma: err.response?.data || null
    });
  }
});

// Protected callback test. Only allows the phone number configured in
// TEST_CALLBACK_TO. Set this to your own test phone before enabling tests.
app.post("/admin/test-callback", checkToken, async (req, res) => {
  if (!checkCredentials(res)) return;

  const allowedPhone = normalizePhone(process.env.TEST_CALLBACK_TO);
  const to = normalizePhone(req.body.to);

  if (!allowedPhone) {
    return res.status(503).json({
      error: "Set TEST_CALLBACK_TO in Render to your own test phone number."
    });
  }

  if (!/^\+?[1-9]\d{7,14}$/.test(to)) {
    return res.status(400).json({
      error: "Enter a valid international phone number."
    });
  }

  if (to !== allowedPhone) {
    return res.status(403).json({
      error: "For safety, this endpoint only calls TEST_CALLBACK_TO."
    });
  }

  // Do not change this value until the intended PBX scenario is verified.
  const callbackFrom = process.env.ZADARMA_CALLBACK_FROM;

  if (!callbackFrom) {
    return res.status(503).json({
      error:
        "Set ZADARMA_CALLBACK_FROM only after verifying the correct PBX scenario in Zadarma."
    });
  }

  const method = "/v1/request/callback/";
  const params = {
    from: callbackFrom,
    to,
    predicted: "1"
  };

  try {
    const response = await axios.get(API_BASE + method, {
      params,
      headers: apiHeaders(method, params),
      timeout: 20000
    });

    res.status(200).json({
      message: "Zadarma callback response received.",
      result: response.data,
      note:
        "A successful API response does not prove that the greeting played or that DTMF routing works."
    });
  } catch (err) {
    console.error(
      "Callback test failed:",
      err.response?.status || err.message,
      err.response?.data || ""
    );

    res.status(502).json({
      error: "Zadarma callback request failed.",
      httpStatus: err.response?.status || null,
      zadarma: err.response?.data || null
    });
  }
});

// Return readable errors for invalid/oversized files.
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: "File upload error. Maximum file size is 5 MB."
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
  console.log("Zadarma server running on port " + PORT);
});
