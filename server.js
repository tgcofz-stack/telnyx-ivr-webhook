
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

// Zadarma notifications may arrive as form data
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Health check
app.get("/", (req, res) => {
  res.send("Zadarma webhook is running!");
});

// Zadarma notification endpoint
app.post("/webhook", (req, res) => {
  const event = req.body || {};

  console.log("Zadarma event received:", {
    event: event.event,
    disposition: event.disposition,
    callback_dtmf: event.callback_dtmf,
    pbx_call_id: event.pbx_call_id
  });

  // Verification confirmation only.
  // Do not initiate another call until the event
  // and the intended call flow are validated.
  if (event.callback_dtmf === "1") {
    console.log("Verification confirmed: button 1");
  }

  res.status(200).send("OK");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
