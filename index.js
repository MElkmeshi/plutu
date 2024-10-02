import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import crypto from "crypto";
dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
const APP_URL = `http://localhost:${port}`;
app.use(express.json());
const plutu_api_key = process.env.PLUTU_API_KEY;
const plutu_secret_key = process.env.PLUTU_SECRET_KEY;
const plutu_access_token = process.env.PLUTU_ACCESS_TOKEN;
if (!plutu_api_key || !plutu_secret_key || !plutu_access_token) {
  throw new Error("Please provide all the required environment variables");
}

function verifyPlutuCallbackHash(
  parameters,
  secretKey,
  isWebhook = false
) {
  if (!secretKey || secretKey.trim() === "") {
    throw new Error("Secret key is not configured");
  }
  let callbackParameters = [];
  if (isWebhook) {
    callbackParameters = [
      "gateway",
      "approved",
      "amount",
      "invoice_no",
      "canceled",
      "payment_method",
      "transaction_id",
    ];
  } else {
    callbackParameters = [
      "gateway",
      "approved",
      "canceled",
      "invoice_no",
      "amount",
      "transaction_id",
    ];
  }
  const data = callbackParameters
    .filter((key) => parameters.hasOwnProperty(key))
    .map((key) => `${key}=${parameters[key]}`)
    .join("&");

  const hashFromCallback =
    typeof parameters["hashed"] === "string" ? parameters["hashed"] : "";

  if (!hashFromCallback) {
    throw new Error("No hash provided in the callback");
  }

  const generatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(data)
    .digest("hex")
    .toUpperCase();

  if (
    !crypto.timingSafeEqual(
      Buffer.from(generatedHash),
      Buffer.from(hashFromCallback)
    )
  ) {
    return false;
  }
  return true;
}

app.post("/", async (req, res) => {
  if (
    req.body.payment_method === "localbankcards" ||
    req.body.payment_method === "tlync"
  ) {
    const form_data = new FormData();
    form_data.append("amount", req.body.amount);
    form_data.append("invoice_no", req.body.invoice_no);
    form_data.append("return_url", `${APP_URL}/return`);
    form_data.append("lang", "ar");
    if (req.body.payment_method === "tlync") {
      form_data.append("mobile_number", req.body.mobile_number);
      form_data.append("callback_url", req.body.callback_url);
    }
    const response = await axios.post(
      `https://api.plutus.ly/api/v1/transaction/${req.body.payment_method}/confirm`,
      form_data,
      {
        headers: {
          "x-api-key": plutu_api_key,
          lang: "ar",
          Authorization: `Bearer ${plutu_access_token}`,
        },
      }
    );
    res.send(response.data.result.redirect_url);
  } else {
    res.send("Payment method not supported");
  }
});

app.get("/return", (req, res) => {
  if (verifyPlutuCallbackHash(req.query, plutu_secret_key)) {
    console.log("Redirect : Payment successful");
    res.send("Payment successful");
  } else {
    console.log("Redirect : Payment failed");
    res.send("Payment failed");
  }
});

app.use("/webhook", (req, res) => {
  if (verifyPlutuCallbackHash(req.body, plutu_secret_key, true)) {
    console.log("Webhook : Payment successful");
  } else {
    console.log("Webhook : Payment failed");
  }
  res.send("Webhook received");
});

app.listen(port, () => {
  console.log(`Server is running on ${APP_URL} 🚀`);
});
