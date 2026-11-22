import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);
const importFromNodePath = (name) =>
  import(pathToFileURL(require.resolve(name)).href);
const [{ default: puppeteer }, { default: chromium }] = await Promise.all([
  importFromNodePath("puppeteer-core"),
  importFromNodePath("@sparticuz/chromium"),
]);

const {
  DynamoDBClient,
  BatchWriteItemCommand,
  ScanCommand,
} = require("@aws-sdk/client-dynamodb");
const { SSMClient, GetParameterCommand } = require("@aws-sdk/client-ssm");

const REGION = process.env.AWS_REGION || "us-east-1";
const TABLE_NAME = process.env.TABLE_NAME || "lodge104-keys";

// LodgeMaster credentials live in SSM Parameter Store (SecureString), never
// in plaintext Lambda env vars or CloudFormation parameters. Fetched once
// per execution environment (cold start) and reused across warm invocations.
const ssmClient = new SSMClient({ region: REGION });
const getParameter = (name) =>
  ssmClient
    .send(new GetParameterCommand({ Name: name, WithDecryption: true }))
    .then((res) => res.Parameter.Value);
const [USERNAME, PASSWORD] = await Promise.all([
  getParameter(process.env.USERNAME_PARAM_NAME),
  getParameter(process.env.PASSWORD_PARAM_NAME),
]);

// LodgeMaster now delegates login to an OpenID Connect identity server:
//   lodgemaster-client -> portal.oa-scouting.org -> id.oa-scouting.org (login)
const START_URL = "https://lodgemaster-client.oa-scouting.org/";
const APP_HOST = new URL(START_URL).host;
const IDENTITY_HOST = "id.oa-scouting.org";
// Includes id.oa-scouting.org itself: the identity server's own session
// cookie (set during the login redirect chain, since the page is briefly
// on that host) is required for later silent OIDC re-checks to succeed.
// Omitting it left consumers (e.g. lodge104-memberdata) with an auth
// cookie jar the app considered incomplete, which surfaced as an infinite
// redirect loop back to id.oa-scouting.org/connect/authorize rather than
// a clean "not logged in" response.
const COOKIE_URLS = [
  "https://lodgemaster-client.oa-scouting.org/",
  "https://portal.oa-scouting.org/",
  "https://id.oa-scouting.org/",
];

// Optional comma separated allow-list of cookie names to store. When unset,
// every cookie issued for the LodgeMaster/portal hosts is stored.
const COOKIE_NAMES = (process.env.COOKIE_NAMES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Cookies that must be present for a scrape to count as successful. Only the
// LodgeMaster app's own sign-in sets OA.LM.Lodge.Auth; the portal/identity
// cookies alone are not enough for consumers such as lodge104-memberdata,
// whose /api/app/login call returns 400 without it. If the login redirect
// chain ends somewhere other than the app (e.g. portal.oa-scouting.org, as
// happened from 2026-11-16), this check fails the invocation so the error
// alarm fires instead of the scrape "succeeding" with an unusable jar.
const REQUIRED_COOKIE_NAMES = ["OA.LM.Lodge.Auth"].filter(
  (n) => !COOKIE_NAMES.length || COOKIE_NAMES.includes(n),
);

const LOGIN_TIMEOUT_MS = 60000;
const MAX_BATCH_SIZE = 25; // DynamoDB BatchWriteItem limit
const MAX_RETRIES = 5;

const ddbClient = new DynamoDBClient({ region: REGION });

console.log("Loading function");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function login(page) {
  await page.setViewport({ width: 1080, height: 1024 });
  await page.goto(START_URL, { waitUntil: "networkidle2", timeout: 60000 });

  // The request is redirected to the identity server login form.
  await page.waitForSelector("#Username", { timeout: 30000 });
  await page.type("#Username", USERNAME);
  await page.type("#Password", PASSWORD);

  const submitSelector = "form.oa-form button[type=submit]";
  await page.waitForSelector(submitSelector);

  // Race: either we leave the identity server (success) or the form shows
  // a validation error (failure).
  const loggedIn = page.waitForFunction(
    (identityHost) => window.location.host !== identityHost,
    { timeout: LOGIN_TIMEOUT_MS },
    IDENTITY_HOST,
  );
  const failed = page
    .waitForSelector(".validation-summary-errors", {
      timeout: LOGIN_TIMEOUT_MS,
    })
    .then(() => {
      throw new Error("LodgeMaster rejected the login credentials");
    });
  // Avoid unhandled rejections from whichever promise loses the race.
  loggedIn.catch(() => {});
  failed.catch(() => {});

  await Promise.all([
    page.click(submitSelector),
    Promise.race([loggedIn, failed]),
  ]);

  // Let the redirect chain back to the app finish and cookies settle.
  await page.waitForNetworkIdle({ idleTime: 2000, timeout: LOGIN_TIMEOUT_MS });

  let finalUrl = new URL(page.url());
  if (finalUrl.host === IDENTITY_HOST) {
    throw new Error(`Login did not complete, still on ${page.url()}`);
  }
  console.log(`Logged in, landed on ${finalUrl.origin}${finalUrl.pathname}`);

  // The identity server sometimes sends us on to the portal rather than
  // back to LodgeMaster, which skips the app's own sign-in step (and so its
  // OA.LM.Lodge.Auth cookie). Revisit the app: with an identity session
  // already established, its OIDC challenge completes silently.
  if (finalUrl.host !== APP_HOST) {
    console.log(
      `Not on ${APP_HOST}; revisiting ${START_URL} to sign in to the app`,
    );
    await page.goto(START_URL, {
      waitUntil: "networkidle2",
      timeout: LOGIN_TIMEOUT_MS,
    });
    await page.waitForNetworkIdle({
      idleTime: 2000,
      timeout: LOGIN_TIMEOUT_MS,
    });

    finalUrl = new URL(page.url());
    if (finalUrl.host !== APP_HOST) {
      throw new Error(
        `App sign-in did not complete, ended on ${finalUrl.origin}${finalUrl.pathname}`,
      );
    }
    console.log(
      `App sign-in complete, landed on ${finalUrl.origin}${finalUrl.pathname}`,
    );
  }
}

async function collectCookies(page) {
  const all = await page.cookies(...COOKIE_URLS);
  const byName = new Map();
  for (const c of all) {
    if (COOKIE_NAMES.length && !COOKIE_NAMES.includes(c.name)) continue;
    if (!c.value) continue;
    byName.set(c.name, c.value);
  }
  if (byName.size === 0) {
    throw new Error(
      `No cookies captured after login (urls: ${COOKIE_URLS.join(", ")}` +
        `${COOKIE_NAMES.length ? `, filter: ${COOKIE_NAMES.join(",")}` : ""})`,
    );
  }
  console.log(`Captured cookies: ${[...byName.keys()].join(", ")}`);

  const missing = REQUIRED_COOKIE_NAMES.filter((n) => !byName.has(n));
  if (missing.length) {
    throw new Error(
      `Required cookie(s) missing after login: ${missing.join(", ")}` +
        ` (landed on ${new URL(page.url()).origin}). Not updating ${TABLE_NAME}.`,
    );
  }
  return byName;
}

async function listStoredCookieNames() {
  const names = [];
  let ExclusiveStartKey;
  do {
    const data = await ddbClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        ProjectionExpression: "#n",
        ExpressionAttributeNames: { "#n": "name" },
        ExclusiveStartKey,
      }),
    );
    for (const item of data.Items || []) names.push(item.name.S);
    ExclusiveStartKey = data.LastEvaluatedKey;
  } while (ExclusiveStartKey);
  return names;
}

async function writeCookies(cookies) {
  // Cookies from earlier runs that this login did not issue are removed, so
  // consumers never pick up an expired value left behind by a previous scrape.
  const stale = (await listStoredCookieNames()).filter((n) => !cookies.has(n));

  const requests = [
    ...[...cookies].map(([name, value]) => ({
      PutRequest: { Item: { name: { S: name }, value: { S: value } } },
    })),
    ...stale.map((name) => ({
      DeleteRequest: { Key: { name: { S: name } } },
    })),
  ];

  for (let i = 0; i < requests.length; i += MAX_BATCH_SIZE) {
    let pending = { [TABLE_NAME]: requests.slice(i, i + MAX_BATCH_SIZE) };

    for (let attempt = 0; Object.keys(pending).length > 0; attempt++) {
      if (attempt >= MAX_RETRIES) {
        throw new Error("Gave up writing unprocessed items to DynamoDB");
      }
      if (attempt > 0) await sleep(100 * 2 ** attempt);

      const data = await ddbClient.send(
        new BatchWriteItemCommand({ RequestItems: pending }),
      );
      pending = data.UnprocessedItems || {};
    }
  }
  console.log(
    `Success, ${cookies.size} items written to ${TABLE_NAME}` +
      (stale.length ? `; removed stale: ${stale.join(", ")}` : ""),
  );
}

export const handler = async () => {
  const browser = await puppeteer.launch({
    args: chromium.args,
    defaultViewport: chromium.defaultViewport,
    executablePath: await chromium.executablePath(
      process.env.AWS_EXECUTION_ENV
        ? "/opt/nodejs/node_modules/@sparticuz/chromium/bin"
        : undefined,
    ),
    headless: chromium.headless,
    ignoreHTTPSErrors: true,
  });
  try {
    const page = await browser.newPage();
    await login(page);
    const cookies = await collectCookies(page);
    // Awaited before the browser closes so failures surface to Lambda.
    await writeCookies(cookies);
    return { statusCode: 200, cookies: [...cookies.keys()] };
  } catch (err) {
    console.error("Scrape failed", err);
    throw err;
  } finally {
    await browser.close();
  }
};
