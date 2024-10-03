import express from "express";
import axios, { AxiosError } from "axios";
import dotenv from "dotenv";
import crypto from "crypto";
import { ParsedQs } from "qs";
import { z } from "zod";
import { validateRequest } from "zod-express-middleware";

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
  parameters: ParsedQs,
  secretKey: string,
  isWebhook = false
): boolean {
  if (!secretKey || secretKey.trim() === "") {
    throw new Error("Secret key is not configured");
  }
  let callbackParameters: string[] = [];
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

  return crypto.timingSafeEqual(
    Buffer.from(generatedHash),
    Buffer.from(hashFromCallback)
  );
}

const InitiatepaymentSchema = z.discriminatedUnion("payment_method", [
  z.object({
    payment_method: z.literal("sadadapi"),
    mobile_number: z.string(),
    birth_year: z.string(),
    amount: z.number(),
  }),
  z.object({
    payment_method: z.literal("edfali"),
    mobile_number: z.string(),
    amount: z.number(),
  }),
]);

app.post(
  "/payment/initiate",
  validateRequest({
    body: InitiatepaymentSchema,
  }),
  async (req, res) => {
    const form_data = new FormData();
    form_data.append("lang", "ar");
    for (const key in req.body) {
      // @ts-ignore
      form_data.append(key, req.body[key]);
    }
    try {
      const response = await axios.post(
        `https://api.plutus.ly/api/v1/transaction/${req.body.payment_method}/verify`,
        form_data,
        {
          headers: {
            "x-api-key": plutu_api_key,
            lang: "ar",
            Authorization: `Bearer ${plutu_access_token}`,
          },
        }
      );
      res.status(response.status).send(response.data);
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        if (error.response) {
          res.status(error.response.status).send(error.response.data);
        } else if (error.request) {
          res.status(500).send({
            message: "No response received from the server",
            error: error.message,
          });
        } else {
          res.status(500).send({
            message: "Error setting up the request",
            error: error.message,
          });
        }
      } else {
        res.status(500).send({
          message: "An unexpected error occurred",
          error: String(error),
        });
      }
    }
  }
);

const confirmPaymentSchema = z.discriminatedUnion("payment_method", [
  z.object({
    payment_method: z.literal("localbankcards"),
    amount: z.number(),
    invoice_no: z.string(),
    return_url: z.string(),
  }),
  z.object({
    payment_method: z.literal("tlync"),
    amount: z.number(),
    invoice_no: z.string(),
    callback_url: z.string(),
    mobile_number: z.string(),
    return_url: z.string(),
  }),
  z.object({
    payment_method: z.literal("sadadapi"),
    process_id: z.string(),
    invoice_no: z.string(),
    code: z.number(),
    amount: z.number(),
  }),
  z.object({
    payment_method: z.literal("edfali"),
    process_id: z.string(),
    invoice_no: z.string(),
    code: z.number(),
    amount: z.number(),
  }),
  z.object({
    payment_method: z.literal("mpgs"),
    amount: z.number(),
    invoice_no: z.string(),
    return_url: z.string(),
  }),
]);

app.post(
  "/payment/confirm",
  validateRequest({ body: confirmPaymentSchema }),
  async (req, res) => {
    const form_data = new FormData();
    form_data.append("lang", "ar");
    for (const key in req.body) {
      // @ts-ignore
      form_data.append(key, req.body[key]);
    }
    try {
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
      res.status(response.status).send(response.data);
    } catch (error: unknown) {
      if (axios.isAxiosError(error)) {
        if (error.response) {
          res.status(error.response.status).send(error.response.data);
        } else if (error.request) {
          res.status(500).send({
            message: "No response received from the server",
            error: error.message,
          });
        } else {
          res.status(500).send({
            message: "Error setting up the request",
            error: error.message,
          });
        }
      } else {
        res.status(500).send({
          message: "An unexpected error occurred",
          error: String(error),
        });
      }
    }
  }
);

app.get("/payment/return", (req, res) => {
  console.log(req.query);
  if (verifyPlutuCallbackHash(req.query, plutu_secret_key)) {
    console.log("Redirect : Payment successful");
    res.send("Payment successful");
  } else {
    console.log("Redirect : Payment failed");
    res.send("Payment failed");
  }
});

app.use("/payment/webhook", (req, res) => {
  console.log(req.body);
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
