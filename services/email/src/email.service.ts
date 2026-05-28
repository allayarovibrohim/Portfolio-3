import { env } from "../../../config/env";
import { mailTransport, renderEmailLayout } from "../../../core/mail/mailer";
import { logger } from "../../../core/logger/winston";

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
}

export class EmailService {
  async send(payload: EmailPayload) {
    logger.info("email.send", { to: payload.to, subject: payload.subject });

    await mailTransport.sendMail({
      from: env.SMTP_FROM,
      to: payload.to,
      subject: payload.subject,
      html: payload.html,
    });
  }

  welcome(displayName: string) {
    return renderEmailLayout(
      "Welcome to Lunex Enterprise",
      `<p>Hello ${displayName},</p><p>Your account is ready. You can now configure security, connected devices, and your workspace.</p>`,
    );
  }

  securityAlert(title: string, body: string) {
    return renderEmailLayout(title, `<p>${body}</p><p>If this was not you, revoke active sessions immediately.</p>`);
  }

  magicLink(link: string) {
    return renderEmailLayout(
      "Your magic sign-in link",
      `<p>Use the secure link below to sign in:</p><p><a href="${link}" style="color:#60a5fa">${link}</a></p>`,
    );
  }
}
