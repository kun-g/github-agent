import "dotenv/config";
import express from "express";
import crypto from "crypto";

const app = express();

// 必须拿到原始 body 才能校验 GitHub 签名
app.use(express.raw({ type: "*/*" }));

const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;
const FEISHU_WEBHOOK_URL = process.env.FEISHU_WEBHOOK_URL;
// 开启飞书自定义机器人「签名校验」才需要
const FEISHU_SIGN_SECRET = process.env.FEISHU_SIGN_SECRET || "";
const ALLOWED_REPOS = new Set(
  (process.env.ALLOWED_REPOS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

function verifyGitHubSignature(req) {
  const sig = req.header("X-Hub-Signature-256") || "";
  const expected =
    "sha256=" +
    crypto
      .createHmac("sha256", GITHUB_WEBHOOK_SECRET)
      .update(req.body) // raw body
      .digest("hex");

  if (!sig || sig.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

// 飞书自定义机器人签名：HMAC-SHA256(secret, timestamp+"\n"+secret) 再 base64
function feishuSign(timestampSec, secret) {
  const stringToSign = `${timestampSec}\n${secret}`;
  return crypto.createHmac("sha256", secret).update(stringToSign).digest("base64");
}

async function sendFeishuText(text) {
  const payload = {
    msg_type: "text",
    content: { text },
  };

  if (FEISHU_SIGN_SECRET) {
    const ts = Math.floor(Date.now() / 1000).toString();
    payload.timestamp = ts;
    payload.sign = feishuSign(ts, FEISHU_SIGN_SECRET);
  }

  const resp = await fetch(FEISHU_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`Feishu webhook failed: ${resp.status} ${body}`);
  }
}

app.post("/github/webhook", async (req, res) => {
  if (!GITHUB_WEBHOOK_SECRET || !FEISHU_WEBHOOK_URL) {
    res.status(500).send("Server not configured");
    return;
  }

  if (!verifyGitHubSignature(req)) {
    res.status(401).send("Invalid signature");
    return;
  }

  const event = req.header("X-GitHub-Event") || "";
  const deliveryId = req.header("X-GitHub-Delivery") || "";
  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch {
    res.status(400).send("Bad JSON");
    return;
  }

  const repo = payload?.repository?.full_name || "";
  if (ALLOWED_REPOS.size && !ALLOWED_REPOS.has(repo)) {
    res.status(200).send("Ignored repo");
    return;
  }

  // 这里建议做 deliveryId 去重（Redis/DB），防止重放；略

  // issues.closed
  if (event === "issues" && payload?.action === "closed") {
    const issue = payload.issue;
    const text = `✅ [${repo}] Issue #${issue.number} closed\n${issue.title}\n${issue.html_url}\nby ${payload.sender?.login || "unknown"}`;

    res.status(202).send("Accepted");
    sendFeishuText(text).catch((err) => console.error("Feishu send failed:", err));
    return;
  }

  // issue_comment.created
  if (event === "issue_comment" && payload?.action === "created") {
    const issue = payload.issue;
    const comment = payload.comment;
    const text = `💬 [${repo}] Issue #${issue.number} 新评论\n${issue.title}\nby ${comment.user?.login || "unknown"}\n\n${comment.body?.slice(0, 200) || ""}${comment.body?.length > 200 ? "..." : ""}\n${comment.html_url}`;

    res.status(202).send("Accepted");
    sendFeishuText(text).catch((err) => console.error("Feishu send failed:", err));
    return;
  } else {
    console.log('Ignored Event', event, payload)
  }

  res.status(200).send("Ignored event");
});

app.listen(process.env.PORT || 3000, () => {
  console.log("listening");
});