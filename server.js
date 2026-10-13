
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

// Accept JSON and form-encoded requests
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Health check
app.get("/", (req, res) => {
  res.status(200).send("Zadarma webhook is running!");
});

// Zadarma webhook verification
app.get("/webhook", (req, res) => {
  if (req.query.zd_echo !== undefined) {
    return res
      .status(200)
      .send(String(req.query.zd_echo));
  }

  return res.status(200).send("Zadarma webhook endpoint is ready.");
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

  // Record verification confirmation only.
  // No new call is started at this stage.
  if (String(event.callback_dtmf || "") === "1") {
    console.log("Client pressed 1: verification confirmed.");
  }

  res.status(200).send("OK");
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
