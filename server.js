
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Health check
app.get("/", (req, res) => {
  res.send("Telnyx IVR webhook is running!");
});

// Telnyx webhook endpoint
app.post("/webhook", (req, res) => {
  console.log("Telnyx event received:", req.body);

  res.status(200).json({
    received: true
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
