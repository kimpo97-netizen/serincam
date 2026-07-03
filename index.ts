// supabase/functions/send-otp/index.ts
// 예약자 연락처로 솔라피(Solapi)를 통해 SMS 인증번호를 발송합니다.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function randomCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function randomHex(len = 16): string {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(key: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { phone } = await req.json();
    const cleanPhone = String(phone || "").replace(/[^0-9]/g, "");

    if (cleanPhone.length !== 11 || !cleanPhone.startsWith("010")) {
      return json({ ok: false, message: "올바른 휴대폰 번호를 입력해주세요." }, 400);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    // 60초 재전송 제한
    const { data: recent, error: recentErr } = await supabase
      .from("phone_verifications")
      .select("created_at")
      .eq("phone", cleanPhone)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (recentErr) throw recentErr;

    if (recent) {
      const elapsedSec = (Date.now() - new Date(recent.created_at).getTime()) / 1000;
      if (elapsedSec < 60) {
        return json(
          { ok: false, message: `${Math.ceil(60 - elapsedSec)}초 후 다시 시도해주세요.` },
          429,
        );
      }
    }

    const code = randomCode();
    const expiresAt = new Date(Date.now() + 3 * 60 * 1000).toISOString();

    const { error: insertErr } = await supabase.from("phone_verifications").insert({
      phone: cleanPhone,
      code,
      expires_at: expiresAt,
    });
    if (insertErr) throw insertErr;

    // ---- 솔라피(Solapi) SMS 발송 ----
    const apiKey = Deno.env.get("SOLAPI_API_KEY")!;
    const apiSecret = Deno.env.get("SOLAPI_API_SECRET")!;
    const sender = Deno.env.get("SOLAPI_SENDER_NUMBER")!; // 솔라피에 등록된 발신번호 (- 없이 숫자만, 예: 01012345678)

    const date = new Date().toISOString();
    const salt = randomHex();
    const signature = await hmacSha256Hex(apiSecret, date + salt);

    const solapiRes = await fetch("https://api.solapi.com/messages/v4/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `HMAC-SHA256 apiKey=${apiKey}, date=${date}, salt=${salt}, signature=${signature}`,
      },
      body: JSON.stringify({
        message: {
          to: cleanPhone,
          from: sender,
          text: `[세린캠] 인증번호는 [${code}] 입니다. 3분 이내에 입력해주세요.`,
        },
      }),
    });

    const solapiData = await solapiRes.json();
    if (!solapiRes.ok) {
      console.error("Solapi send error:", solapiData);
      return json({ ok: false, message: "문자 발송에 실패했습니다. 잠시 후 다시 시도해주세요." }, 500);
    }

    return json({ ok: true, message: "인증번호가 발송되었습니다." });
  } catch (e) {
    console.error("send-otp error:", e);
    return json({ ok: false, message: "서버 오류가 발생했습니다." }, 500);
  }
});
