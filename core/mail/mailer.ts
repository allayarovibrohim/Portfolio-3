import nodemailer from "nodemailer";
import { env } from "../../config/env";

export const mailTransport = nodemailer.createTransport({
  host: env.SMTP_HOST,
  port: env.SMTP_PORT,
  secure: false,
  auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined,
});

export const renderEmailLayout = (title: string, body: string) => `<!DOCTYPE html>
<html lang="en">
  <body style="margin:0;padding:0;background:#0f172a;font-family:Arial,Helvetica,sans-serif;color:#e2e8f0;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:32px 0;">
      <tr>
        <td align="center">
          <table role="presentation" width="640" cellspacing="0" cellpadding="0" style="background:#111827;border-radius:18px;overflow:hidden;border:1px solid rgba(255,255,255,0.08);">
            <tr>
              <td style="padding:32px 40px;background:linear-gradient(135deg,#0f172a,#1d4ed8);">
                <h1 style="margin:0;font-size:28px;color:#fff;">${title}</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:40px;color:#cbd5e1;line-height:1.7;">
                ${body}
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
