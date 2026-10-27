// すべてのリクエストの前に動く処理（Cloudflare Pages Functions）
// Basic認証：ユーザー名とパスワードを知っている人だけがページを開ける
// 認証情報はコードに書かず、Cloudflare の環境変数から読む
//   BASIC_AUTH_USER     … ユーザー名
//   BASIC_AUTH_PASSWORD … パスワード（「シークレット」として登録する）

const REALM = "mainichi-nikki";

// 検索エンジンに載せないための印（ページの中の robots メタタグと二重にしておく）
function withNoindex(response) {
  const res = new Response(response.body, response);
  res.headers.set("X-Robots-Tag", "noindex, nofollow");
  return res;
}

// 2つの文字列が同じかを、かかる時間で中身を推測されないように比べる
async function sameText(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

// ブラウザが送ってきた「ユーザー名:パスワード」を取り出す
function readCredentials(request) {
  const header = request.headers.get("Authorization") || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) return null;
  try {
    // 日本語などが混ざっても読めるように UTF-8 として戻す
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    const text = new TextDecoder().decode(bytes);
    const i = text.indexOf(":");
    if (i < 0) return null;
    return { user: text.slice(0, i), pass: text.slice(i + 1) };
  } catch {
    return null;
  }
}

// 入力を求める（ブラウザがユーザー名とパスワードの欄を出す）
function askLogin() {
  return new Response("ログインが必要です。", {
    status: 401,
    headers: {
      "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"`,
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // robots.txt だけは検索エンジンが読めるように、認証なしで返す
  if (url.pathname === "/robots.txt") return withNoindex(await next());

  // 環境変数が登録されていないときは、うっかり誰でも見られる状態にしないよう止める
  const user = env.BASIC_AUTH_USER;
  const pass = env.BASIC_AUTH_PASSWORD;
  if (!user || !pass) {
    return new Response("認証の設定がまだ済んでいません。", {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8", "X-Robots-Tag": "noindex, nofollow" },
    });
  }

  const cred = readCredentials(request);
  if (!cred) return askLogin();
  // ユーザー名とパスワードは両方とも比べる（片方だけ先に失敗させない）
  const [okUser, okPass] = await Promise.all([sameText(cred.user, user), sameText(cred.pass, pass)]);
  if (!(okUser && okPass)) return askLogin();

  return withNoindex(await next());
}
