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

// GitHub 用户名 -> 飞书 user_id 映射
let USER_MAPPING = {};
try {
  USER_MAPPING = JSON.parse(process.env.USER_MAPPING || "{}");
} catch {
  console.warn("Invalid USER_MAPPING JSON, using empty mapping");
}

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

// 发送富文本消息（支持 @ 人）
async function sendFeishuPost(title, contentLines) {
  const payload = {
    msg_type: "post",
    content: {
      post: {
        zh_cn: {
          title,
          content: [contentLines],
        },
      },
    },
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
    const opener = issue.user?.login || "";
    const feishuUserId = USER_MAPPING[opener];
    console.log(`Issue closed by ${opener}, feishuUserId:`, feishuUserId);

    const contentLines = [
      { tag: "text", text: `Issue #${issue.number} 已关闭\n` },
      { tag: "text", text: `${issue.title}\n` },
      { tag: "a", text: "查看详情", href: issue.html_url },
      { tag: "text", text: `\nby ${payload.sender?.login || "unknown"}` },
    ];

    // 如果有映射，@ 提 issue 的人
    if (feishuUserId) {
      contentLines.push({ tag: "text", text: "\n" });
      contentLines.push({ tag: "at", user_id: feishuUserId.id, user_name: feishuUserId.name });
    }

    res.status(202).send("Accepted");
    sendFeishuPost(`✅ [${repo}]`, contentLines).catch((err) => console.error("Feishu send failed:", err));
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